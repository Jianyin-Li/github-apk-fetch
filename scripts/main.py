#!/usr/bin/env python3
"""Fetch, verify and stage APK files for a release.

Verification policy:
  * verified files must match the expected package and (when pinned) the
    expected signature; a mismatch is dropped and never published;
  * files that could not be verified because the tooling failed are still
    published, but flagged as unverified in the release notes.

Exit code 0 means at least one asset was staged in the publish directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fetch  # noqa: E402
import verify  # noqa: E402

DEFAULT_PACKAGE = "com.github.android"
DEFAULT_SLUG = "github"
SAFE_TAG_RE = re.compile(r"[^A-Za-z0-9._-]+")
EXTENSIONS = {
    "apk": ".apk",
    "xapk": ".xapk",
    "apks": ".apks",
    "apkm": ".apkm",
    "apkx": ".apkx",
    "zip": ".zip",
}


def log(msg: str) -> None:
    print(msg, flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch and verify APKs for a release")
    parser.add_argument("--package", default=os.environ.get("APP_PACKAGE", DEFAULT_PACKAGE))
    parser.add_argument("--slug", default=os.environ.get("APP_SLUG", DEFAULT_SLUG))
    parser.add_argument("--workdir", default="downloads")
    parser.add_argument("--publish-dir", default="publish")
    parser.add_argument("--sources", default=os.environ.get("SOURCES", ""))
    parser.add_argument("--budget", type=float, default=float(os.environ.get("FETCH_BUDGET", "900")))
    parser.add_argument("--workers", type=int, default=int(os.environ.get("FETCH_WORKERS", "6")))
    return parser.parse_args()


def expected_certs() -> set[str]:
    raw = os.environ.get("EXPECTED_CERT_SHA256", "")
    return {verify.normalize_cert(item) for item in re.split(r"[\s,;]+", raw) if item.strip()}


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]", "_", str(value)) or "unknown"


def dedupe(entries: list[dict]) -> list[dict]:
    kept: dict[str, dict] = {}
    for entry in entries:
        kept.setdefault(entry["sha256"], entry)
    return list(kept.values())


def drop(entry: dict, reason: str) -> None:
    entry["publishable"] = False
    entry["verdict"] = "rejected"
    entry["error"] = reason


def choose(entries: list[dict], pinned: set[str]) -> tuple[list[dict], str]:
    candidates = [entry for entry in entries if entry["publishable"]]
    verified = [entry for entry in candidates if entry["verified"]]
    unverified = [entry for entry in candidates if not entry["verified"]]

    if not candidates:
        return [], "nothing passed the minimum check"

    if pinned:
        matched = [entry for entry in verified if pinned.intersection(entry["certs"])]
        for entry in verified:
            if not pinned.intersection(entry["certs"]):
                drop(entry, "signed with an unexpected key: " + ", ".join(entry["certs"]))
        chosen = matched + unverified
        reason = (
            f"pinned signer {', '.join(sorted(pinned))}; "
            f"{len(matched)} verified + {len(unverified)} unverified published"
        )
        if not chosen:
            reason = "verified APKs exist but none matches the pinned certificate"
        return chosen, reason

    per_source: dict[str, dict] = {}
    for entry in verified:
        per_source.setdefault(entry["source"], entry)
    counts: dict[str, int] = {}
    for entry in per_source.values():
        for cert in entry["certs"]:
            counts[cert] = counts.get(cert, 0) + 1

    if counts:
        winner = max(counts, key=counts.get)
        matched = []
        for entry in verified:
            if winner in entry["certs"]:
                matched.append(entry)
            else:
                drop(entry, f"signed with {', '.join(entry['certs'])}, consensus is {winner}")
        chosen = matched + unverified
        reason = (
            f"unpinned: {counts[winner]} independent source(s) agree on signer {winner}; "
            f"{len(matched)} verified + {len(unverified)} unverified published. "
            "Pin the fingerprint with the EXPECTED_CERT_SHA256 repository variable."
        )
        return chosen, reason

    return unverified, (
        "verification unavailable for every download; publishing unverified files "
        f"({len(unverified)})"
    )


def prune_uninstallable(chosen: list[dict]) -> list[dict]:
    """Drop split-required base APKs when a full bundle exists for the version.

    A bare base APK of an App Bundle fails with INSTALL_FAILED_MISSING_SPLIT;
    the bundle (xapk/apks/apkm) carries the config splits and is installable.
    """
    bundle_versions = {
        str(entry["version_code"])
        for entry in chosen
        if entry["container"] != "apk" and entry["version_code"]
    }
    kept: list[dict] = []
    for entry in chosen:
        if (entry["container"] == "apk" and entry.get("split_required")
                and str(entry["version_code"]) in bundle_versions):
            drop(entry, "split-required base APK without config splits; "
                        "the bundle for this version is published instead")
            continue
        kept.append(entry)
    return kept


def install_state(entry: dict) -> str:
    if entry["container"] != "apk":
        return "bundle (SAI / APKPure)"
    if entry.get("split_required"):
        return "**base only**"
    return "apk"


def asset_name(package: str, entry: dict) -> str:
    extension = EXTENSIONS.get(entry["container"], ".apk")
    version = safe_filename(entry["version_name"] or "unknown")
    code = safe_filename(entry["version_code"] or "unknown")
    source = safe_filename(entry["source"])
    return f"{package}-{version}-{code}-{source}{extension}"


def make_tag(entries: list[dict], package: str) -> tuple[str, str]:
    def sort_key(entry: dict) -> tuple:
        return verify._version_key(entry["version_code"] or "0"), str(entry["version_name"] or "")

    best = max(entries, key=sort_key)
    version = safe_filename(best["version_name"] or "unknown")
    code = safe_filename(best["version_code"] or "0")
    tag = SAFE_TAG_RE.sub("-", f"v{version}-{code}").strip("-")
    title = f"{package} {best['version_name'] or '?'} ({best['version_code'] or '?'})"
    return tag, title


def write_notes(path: str, entries: list[dict], all_entries: list[dict], reason: str,
                package: str) -> None:
    lines = [
        f"# {package} APK",
        "",
        "These files were downloaded by GitHub Actions from public mirrors.",
        "",
        f"Verification policy: {reason}",
        "",
        "| Asset | Source | Version | Code | Signature | Install | Signer SHA-256 | File SHA-256 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for entry in entries:
        signature = "verified" if entry["verified"] else "**UNVERIFIED**"
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} | `{}` | `{}` |".format(
                asset_name(package, entry),
                entry["source"],
                entry["version_name"] or "?",
                entry["version_code"] or "?",
                signature,
                install_state(entry),
                ", ".join(entry["certs"]) or "-",
                entry["sha256"],
            )
        )
    lines += [
        "",
        "`UNVERIFIED` means the signature check could not be completed in CI; "
        "install at your own risk.",
        "",
        "`bundle` assets (`.xapk`, `.apks`, `.apkm`) contain the base APK plus the "
        "config splits; install them with Split APKs Installer (SAI) or APKPure. "
        "A plain `.apk` marked `**base only**` is the base of an App Bundle and "
        "will fail with `INSTALL_FAILED_MISSING_SPLIT` on its own.",
        "",
        f"Workflow run: #{os.environ.get('GITHUB_RUN_NUMBER', '?')}",
        "",
        "<details><summary>Every download, including rejected ones</summary>",
        "",
        "| Source | File | Verdict | Detail |",
        "| --- | --- | --- | --- |",
    ]
    for entry in all_entries:
        detail = (entry.get("error") or "").replace("|", "\\|")[:300]
        lines.append(f"| {entry['source']} | `{os.path.basename(entry['path'])}` | "
                     f"{entry['verdict']} | {detail} |")
    lines += ["", "</details>", ""]
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    args = parse_args()
    pinned = expected_certs()
    if pinned:
        log(f"pinned signer certificate: {', '.join(sorted(pinned))}")

    shutil.rmtree(args.workdir, ignore_errors=True)
    shutil.rmtree(args.publish_dir, ignore_errors=True)
    os.makedirs(args.workdir, exist_ok=True)
    os.makedirs(args.publish_dir, exist_ok=True)

    tools = verify.find_build_tools()
    if tools:
        log(f"using Android build-tools {tools['build_tools']}")
    else:
        log("WARNING: apksigner/aapt2 not found; downloads will be published as unverified")

    started = time.time()
    downloads = fetch.fetch_all(
        args.package, args.slug, args.workdir, only=args.sources,
        budget=args.budget, workers=args.workers,
    )
    log(f"downloaded {len(downloads)} container(s) in {time.time() - started:.0f}s")
    if not downloads:
        log("FATAL: no source returned an APK")
        write_notes(os.path.join(args.publish_dir, "release-notes.md"), [], [], 
                    "no download succeeded", args.package)
        return 1

    entries: list[dict] = []
    for item in downloads:
        result = verify.verify_file(item["path"], args.package, tools)
        result.update({key: item[key] for key in ("source", "sha256", "size", "url")})
        entries.append(result)
        cert = result["certs"][0][:16] if result["certs"] else "-"
        log(f"[{result['verdict'].upper():10}] {result['source']:16} "
            f"{os.path.basename(item['path'])[:48]:48} "
            f"v{result['version_name'] or '?'} ({result['version_code'] or '?'}) cert={cert}"
            + (f" :: {result['error']}" if result["error"] else ""))
        if result["cert_subjects"]:
            log(f"           signer DN: {result['cert_subjects'][0]}")

    chosen, reason = choose(entries, pinned)
    log(f"decision: {reason}")
    before = {entry["sha256"] for entry in chosen}
    chosen = prune_uninstallable(chosen)
    for entry in entries:
        if entry["sha256"] in before and entry["sha256"] not in {e["sha256"] for e in chosen}:
            log(f"pruned {os.path.basename(entry['path'])}: {entry['error']}")

    staged: list[dict] = []
    for entry in dedupe(chosen):
        name = asset_name(args.package, entry)
        dest = os.path.join(args.publish_dir, name)
        shutil.copy2(entry["path"], dest)
        entry["asset"] = name
        entry["asset_sha256"] = sha256_of(dest)
        staged.append(entry)
        log(f"staged {name} ({entry['size'] / 1048576:.1f} MiB, "
            f"{'verified' if entry['verified'] else 'UNVERIFIED'})")

    write_notes(
        os.path.join(args.publish_dir, "release-notes.md"),
        staged, entries, reason, args.package,
    )
    with open(os.path.join(args.publish_dir, "result.json"), "w", encoding="utf-8") as handle:
        json.dump({"package": args.package, "reason": reason, "entries": entries,
                   "published": [entry.get("asset") for entry in staged]},
                  handle, indent=2)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(f"## {args.package}\n\n{reason}\n\n")
            handle.write("| Source | Version | Code | Verdict | Error |\n")
            handle.write("| --- | --- | --- | --- | --- |\n")
            for entry in entries:
                error = (entry.get("error") or "").replace("|", "\\|")[:120]
                handle.write(f"| {entry['source']} | {entry['version_name'] or '?'} | "
                             f"{entry['version_code'] or '?'} | {entry['verdict']} | "
                             f"{error} |\n")
            handle.write("\n")

    if not staged:
        log("nothing to publish")
        return 1

    tag, title = make_tag(staged, args.package)
    with open(os.path.join(args.publish_dir, "release.env"), "w", encoding="utf-8") as handle:
        handle.write(f"TAG={shlex.quote(tag)}\nTITLE={shlex.quote(title)}\n")
    log(f"release tag: {tag} (title: {title})")
    log(f"published {len(staged)} asset(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
