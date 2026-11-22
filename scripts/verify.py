#!/usr/bin/env python3
"""Verify downloaded APK / XAPK / APKS / APKM / APKX containers.

Policy (as requested):
  * verification is best effort: if the tooling cannot run, the file is still
    publishable but marked "unverified" in the release notes;
  * a file whose signature was actually checked and does not match, and any
    file whose package name does not match, is rejected and never published.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile

PACKAGE_RE = re.compile(
    r"package: name='([^']*)' versionCode='([^']*)' versionName='([^']*)'"
    r"(?:[^\n]*split='([^']*)')?"
)
SDK_RE = re.compile(r"(?:sdkVersion|minSdkVersion):'(\d+)'")
TARGET_RE = re.compile(r"targetSdkVersion:'(\d+)'")
CERT_RE = re.compile(r"Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F:]+)")
SCHEME_RE = re.compile(r"Verified using (v\d) scheme[^:]*:\s*(true|false)")
BUNDLE_EXTS = {"xapk", "apks", "apkm", "apkx", "zip"}


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


def _apksigner_report(path: str, tools: dict) -> dict:
    if not tools:
        raise Unverifiable("Android build-tools unavailable")
    code, out, err = _run([tools["apksigner"], "verify", "--verbose", "--print-certs", path])
    combined = f"{out}\n{err}"
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
        detail = combined.strip().replace("\n", " ")[:300]
        raise Rejected(f"apksigner rejected the signature: {detail}")
    certs = sorted({normalize_cert(match) for match in CERT_RE.findall(out)})
    if not certs:
        raise Unverifiable("apksigner reported no signer certificate")
    schemes = sorted({scheme for scheme, ok in SCHEME_RE.findall(out) if ok == "true"})
    return {"certs": certs, "schemes": schemes}


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
    info = _badging(path, tools)
    info.update(_apksigner_report(path, tools))
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

            if kind == "apk":
                members = [(path, "")]
            else:
                tempdir = tempfile.mkdtemp(prefix="apk-bundle-")
                manifest = _bundle_manifest(zf)
                extracted = _extract_members(zf, inner, tempdir)
                members = [(member, os.path.basename(member)) for member in extracted]
                result["split_count"] = max(0, len(members) - 1)
                bundle_package = manifest.get("package_name") or manifest.get("package")
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

        packages = {info["package"] for info in infos}
        if packages != {expected_package}:
            raise Rejected(f"package is {', '.join(sorted(packages))}, expected {expected_package}")

        cert_sets = {tuple(info["certs"]) for info in infos}
        if len(cert_sets) > 1:
            raise Rejected("bundle members are signed with different keys")

        bases = [info for info in infos if not info.get("split")] or infos
        base = max(bases, key=lambda info: _version_key(info["version_code"] or "0"))
        result.update({
            "package": base["package"],
            "version_code": base["version_code"],
            "version_name": base["version_name"],
            "min_sdk": base["min_sdk"],
            "target_sdk": base["target_sdk"],
            "certs": base["certs"],
            "schemes": sorted({scheme for info in infos for scheme in info["schemes"]}),
            "verified": True,
            "publishable": True,
            "verdict": "verified",
        })
        if soft_errors:
            result["error"] = "partially verified: " + "; ".join(soft_errors)[:300]
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
