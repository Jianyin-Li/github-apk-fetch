#!/usr/bin/env python3
"""Verify downloaded APK / XAPK / APKS / APKM / APKX containers.

Policy:
  * verification is best effort: if the tooling cannot run, the file is still
    publishable but marked "unverified" in the release notes;
  * a file whose signature was actually checked and does not match, and any
    file whose package name does not match, is rejected and never published.

Signer certificates are read from `apksigner --print-certs` first, then from
the APK Signing Block (v2/v3) with a small pure-Python parser, then from
`keytool -printcert -jarfile` for v1-only packages. That keeps fingerprint
pinning working even when the build-tools output format changes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile

PACKAGE_RE = re.compile(
    r"package: name='([^']*)' versionCode='([^']*)' versionName='([^']*)'"
    r"(?:[^\n]*split='([^']*)')?"
)
SDK_RE = re.compile(r"(?:sdkVersion|minSdkVersion):'(\d+)'")
TARGET_RE = re.compile(r"targetSdkVersion:'(\d+)'")
CERT_FIELD = "certificate SHA-256 digest:"
DN_FIELD = "certificate DN:"
# "Signer #1 certificate SHA-256 digest:" (build-tools <= 36)
# "V3.0 Signer: certificate SHA-256 digest:"  (build-tools 37+)
# "Source Stamp Signer: ..." is Play's source stamp, never the app key.
SIGNER_HINT = "Signer"
SCHEME_RE = re.compile(r"Verified using (v\d) scheme[^:]*:\s*(true|false)")
KEYTOOL_RE = re.compile(r"SHA256:\s*([0-9A-Fa-f:]+)")
BUNDLE_EXTS = {"xapk", "apks", "apkm", "apkx", "zip"}

SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0
V31_BLOCK_ID = 0x1B93AD61


class Unverifiable(Exception):
    """Verification could not be performed; the file may still be published."""


class Rejected(Exception):
    """Verification ran and failed; the file must not be published."""


def log(msg: str) -> None:
    print(msg, flush=True)


def normalize_cert(value: str) -> str:
    return re.sub(r"[^0-9a-f]", "", value.lower())


def _version_key(version: str) -> tuple:
    return tuple(int(part) if part.isdigit() else -1 for part in re.split(r"[.-]", version))


def find_build_tools() -> dict | None:
    roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")]
    roots += [os.path.expanduser("~/Android/Sdk"), "/usr/local/lib/android/sdk", "/opt/android-sdk"]
    for root in [item for item in roots if item and os.path.isdir(item)]:
        build_tools = os.path.join(root, "build-tools")
        if not os.path.isdir(build_tools):
            continue
        for version in sorted(os.listdir(build_tools), key=_version_key, reverse=True):
            folder = os.path.join(build_tools, version)
            apksigner = os.path.join(folder, "apksigner")
            aapt2 = os.path.join(folder, "aapt2")
            if os.path.isfile(apksigner) and os.path.isfile(aapt2):
                return {"apksigner": apksigner, "aapt2": aapt2, "build_tools": version}
    apksigner = shutil.which("apksigner")
    aapt2 = shutil.which("aapt2")
    if apksigner and aapt2:
        return {"apksigner": apksigner, "aapt2": aapt2, "build_tools": "PATH"}
    return None


def _run(command: list[str], timeout: float = 300.0) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Unverifiable(f"could not run {os.path.basename(command[0])}: {exc}") from exc
    return completed.returncode, completed.stdout, completed.stderr


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _length_prefixed(data: bytes, offset: int) -> tuple[bytes, int]:
    length = _u32(data, offset)
    start = offset + 4
    return data[start:start + length], start + length


def _certs_from_signing_block(path: str) -> list[str]:
    """Extract signer certificate digests from the APK Signing Block (v2/v3)."""
    with open(path, "rb") as handle:
        payload = handle.read()
    end_of_central = payload.rfind(b"PK\x05\x06")
    if end_of_central < 0:
        return []
    central_offset = _u32(payload, end_of_central + 16)
    if central_offset < 32 or payload[central_offset - 16:central_offset] != SIG_BLOCK_MAGIC:
        return []
    block_size = struct.unpack_from("<Q", payload, central_offset - 24)[0]
    block_start = central_offset - block_size - 8
    if block_start < 0:
        return []
    cursor = block_start + 8
    pairs_end = central_offset - 24

    certs: list[str] = []
    while cursor + 12 <= pairs_end:
        pair_length = struct.unpack_from("<Q", payload, cursor)[0]
        pair_id = _u32(payload, cursor + 8)
        value_start = cursor + 12
        value_end = cursor + 8 + pair_length
        if pair_length < 4 or value_end > pairs_end:
            break
        if pair_id in (V2_BLOCK_ID, V3_BLOCK_ID, V31_BLOCK_ID):
            try:
                signer_block, _ = _length_prefixed(payload[:value_end], value_start)
                signed_data, _ = _length_prefixed(signer_block, 0)
                _digests, offset = _length_prefixed(signed_data, 0)
                certificates, _ = _length_prefixed(signed_data, offset)
                certificate, _ = _length_prefixed(certificates, 0)
            except struct.error:
                pass
            else:
                certs.append(hashlib.sha256(certificate).hexdigest())
        cursor = value_end
    return sorted(set(certs))


def _certs_from_keytool(path: str) -> list[str]:
    if not shutil.which("keytool"):
        return []
    code, out, _err = _run(["keytool", "-printcert", "-jarfile", path])
    if code != 0:
        return []
    return sorted({normalize_cert(match) for match in KEYTOOL_RE.findall(out)})


def _apksigner_report(path: str, tools: dict) -> dict:
    if not tools:
        raise Unverifiable("Android build-tools unavailable")
    code, out, err = _run([tools["apksigner"], "verify", "--verbose", "--print-certs", path])
    combined = f"{out}\n{err}"
    if os.environ.get("DEBUG_VERIFY"):
        log(f"    apksigner rc={code}\n{combined}")
    if code != 0:
        lowered = combined.lower()
        tool_markers = (
            "java: not found",
            "command not found",
            "no such file",
            "unable to access jarfile",
            "could not find or load main class",
        )
        if any(marker in lowered for marker in tool_markers):
            raise Unverifiable(f"apksigner could not run: {combined.strip()[:300]}")
        raise Rejected(f"apksigner rejected the signature: {combined.strip()[:300]}")

    certs: set[str] = set()
    subjects: list[str] = []
    for line in out.splitlines():
        if "Source Stamp" in line:
            continue
        if SIGNER_HINT in line and CERT_FIELD in line:
            certs.add(normalize_cert(line.split(CERT_FIELD, 1)[1]))
        elif SIGNER_HINT in line and DN_FIELD in line:
            subjects.append(line.split(DN_FIELD, 1)[1].strip())
    if not certs:
        certs = set(_certs_from_signing_block(path))
    if not certs:
        certs = set(_certs_from_keytool(path))
    if not certs:
        raise Unverifiable("apksigner verified the APK but no signer certificate was found")
    schemes = sorted({scheme for scheme, ok in SCHEME_RE.findall(out) if ok == "true"})
    return {"certs": sorted(certs), "schemes": schemes, "cert_subjects": subjects}


def _split_required(path: str, tools: dict) -> bool | None:
    """Whether the manifest demands config splits to install."""
    if not tools:
        return None
    code, out, _err = _run([tools["aapt2"], "dump", "xmltree",
                            "--file", "AndroidManifest.xml", path])
    if code != 0:
        return None
    for line in out.splitlines():
        if "isSplitRequired" in line:
            return "0xffffffff" in line.lower()
        if "requiredSplitTypes" in line:
            return True
    return False


def _badging(path: str, tools: dict) -> dict:
    if not tools:
        raise Unverifiable("Android build-tools unavailable")
    code, out, err = _run([tools["aapt2"], "dump", "badging", path])
    if code != 0:
        aapt = shutil.which("aapt")
        if aapt:
            code, out, err = _run([aapt, "dump", "badging", path])
    if code != 0:
        raise Unverifiable(f"aapt2 could not read the manifest: {(err or out).strip()[:200]}")
    match = PACKAGE_RE.search(out)
    if not match:
        raise Unverifiable("manifest has no package/version information")
    min_sdk = SDK_RE.search(out)
    target_sdk = TARGET_RE.search(out)
    return {
        "package": match.group(1),
        "version_code": match.group(2),
        "version_name": match.group(3),
        "split": match.group(4) or "",
        "min_sdk": int(min_sdk.group(1)) if min_sdk else None,
        "target_sdk": int(target_sdk.group(1)) if target_sdk else None,
    }


def _verify_single_apk(path: str, tools: dict) -> dict:
    info: dict = {}
    problems: list[str] = []
    try:
        info.update(_badging(path, tools))
    except Unverifiable as exc:
        problems.append(str(exc))
    try:
        info.update(_apksigner_report(path, tools))
    except Unverifiable as exc:
        problems.append(str(exc))
    info["split_required"] = _split_required(path, tools)
    if not info.get("package") and not info.get("certs"):
        raise Unverifiable("; ".join(problems) or "nothing could be verified")
    info["problems"] = problems
    return info


def _container_kind(names: set[str], extension: str) -> tuple[str | None, list[str]]:
    if "AndroidManifest.xml" in names:
        return "apk", []
    inner = sorted(name for name in names if name.lower().endswith(".apk"))
    if not inner:
        return None, []
    if "manifest.json" in names:
        return "xapk", inner
    if "toc.pb" in names or any(name.startswith("splits/") for name in inner):
        return "apks", inner
    if any(name.endswith("meta.sai_v2.json") or name == "info.json" for name in names):
        return "apkm", inner
    if extension in BUNDLE_EXTS - {"zip"}:
        return extension, inner
    return "zip", inner


def _extract_members(zf: zipfile.ZipFile, names: list[str], tempdir: str) -> list[str]:
    extracted = []
    for index, name in enumerate(names):
        target = os.path.join(tempdir, f"{index:03d}-{os.path.basename(name)}")
        with zf.open(name) as source, open(target, "wb") as sink:
            shutil.copyfileobj(source, sink)
        extracted.append(target)
    return extracted


def _bundle_manifest(zf: zipfile.ZipFile) -> dict:
    for candidate in ("manifest.json", "info.json", "meta.sai_v2.json"):
        if candidate in zf.namelist():
            try:
                return json.loads(zf.read(candidate).decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001
                return {}
    return {}


def verify_file(path: str, expected_package: str, tools: dict | None) -> dict:
    result = {
        "path": path,
        "container": os.path.splitext(path)[1].lstrip(".").lower() or "apk",
        "package": None,
        "version_code": None,
        "version_name": None,
        "min_sdk": None,
        "target_sdk": None,
        "certs": [],
        "schemes": [],
        "cert_subjects": [],
        "split_required": None,
        "split_count": 0,
        "verified": False,
        "publishable": False,
        "verdict": "rejected",
        "error": None,
    }
    tempdir = None
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            extension = os.path.splitext(path)[1].lstrip(".").lower()
            kind, inner = _container_kind(names, extension)
            if kind is None:
                raise Rejected("container holds no APK payload")
            result["container"] = kind

            bundle = {}
            if kind == "apk":
                members = [(path, "")]
            else:
                tempdir = tempfile.mkdtemp(prefix="apk-bundle-")
                bundle = _bundle_manifest(zf)
                extracted = _extract_members(zf, inner, tempdir)
                members = [(member, os.path.basename(member)) for member in extracted]
                result["split_count"] = max(0, len(members) - 1)
                bundle_package = bundle.get("package_name") or bundle.get("package")
                if bundle_package and bundle_package != expected_package:
                    raise Rejected(
                        f"bundle manifest says {bundle_package}, expected {expected_package}"
                    )

        infos: list[dict] = []
        hard_error: str | None = None
        soft_errors: list[str] = []
        for member, label in members:
            try:
                info = _verify_single_apk(member, tools)
            except Rejected as exc:
                hard_error = f"{label or os.path.basename(member)}: {exc}"
                break
            except Unverifiable as exc:
                soft_errors.append(f"{label or os.path.basename(member)}: {exc}")
                continue
            info["member"] = label
            infos.append(info)

        if hard_error:
            raise Rejected(hard_error)

        if not infos:
            raise Unverifiable("; ".join(soft_errors) or "nothing could be verified")

        packages = {info["package"] for info in infos if info.get("package")}
        if packages and packages != {expected_package}:
            raise Rejected(
                f"package is {', '.join(sorted(packages))}, expected {expected_package}"
            )

        certs = sorted({cert for info in infos for cert in info.get("certs", [])})
        cert_sets = {tuple(sorted(info["certs"])) for info in infos if info.get("certs")}
        if len(cert_sets) > 1:
            raise Rejected("bundle members are signed with different keys")

        bases = [info for info in infos if not info.get("split")] or infos
        base = max(bases, key=lambda info: _version_key(info.get("version_code") or "0"))

        result.update({
            "package": base.get("package") or bundle.get("package_name"),
            "version_code": base.get("version_code") or bundle.get("version_code"),
            "version_name": base.get("version_name") or bundle.get("version_name"),
            "min_sdk": base.get("min_sdk"),
            "target_sdk": base.get("target_sdk"),
            "certs": certs,
            "schemes": sorted({scheme for info in infos for scheme in info.get("schemes", [])}),
            "cert_subjects": sorted({subject for info in infos
                                     for subject in info.get("cert_subjects", [])}),
            "split_required": base.get("split_required"),
        })

        incomplete = bool(soft_errors) or not certs or packages != {expected_package}
        if incomplete:
            result.update({
                "verified": False,
                "publishable": True,
                "verdict": "unverified",
                "error": ("only partially verified: "
                          + "; ".join(soft_errors or ["missing package/certificate info"]))[:400],
            })
        else:
            result.update({
                "verified": True,
                "publishable": True,
                "verdict": "verified",
                "error": None,
            })
    except Rejected as exc:
        result.update({"verdict": "rejected", "publishable": False, "verified": False,
                       "error": str(exc)})
    except Unverifiable as exc:
        # Cannot check -> publish anyway, clearly marked as unverified.
        result.update({"verdict": "unverified", "publishable": True, "verified": False,
                       "error": str(exc)})
    except zipfile.BadZipFile as exc:
        result.update({"verdict": "rejected", "publishable": False,
                       "error": f"not a readable zip container: {exc}"})
    except Exception as exc:  # noqa: BLE001
        result.update({"verdict": "unverified", "publishable": True,
                       "error": f"unexpected verification error: {exc}"})
    finally:
        if tempdir:
            shutil.rmtree(tempdir, ignore_errors=True)
    return result
