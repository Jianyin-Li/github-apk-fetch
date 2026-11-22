#!/usr/bin/env python3
"""Optional Google Play source.

Enabled when GPLAY_EMAIL and GPLAY_AAS_TOKEN are configured. Play serves an App
Bundle as several split APKs, so the parts are zipped into an XAPK container and
verified like any other bundle.

Get an AAS token with gpapi/Aurora Store, then store the two values as
repository secrets. Nothing is written to the repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
import zipfile

PLAY_UA = (
    "AndroidDownloadManager/13 (Linux; U; Android 13; Pixel 7 Build/TQ3A.230805.001)"
)


def log(message: str) -> None:
    print(message, flush=True)


def enabled() -> bool:
    return bool(os.environ.get("GPLAY_EMAIL", "").strip()
                and os.environ.get("GPLAY_AAS_TOKEN", "").strip())


def _load_gpapi():
    try:
        from gpapi.googleplay import GooglePlayAPI  # noqa: F401
    except ImportError:
        log("[google-play] installing gpapi")
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "gpapi"],
                       check=False)
        from gpapi.googleplay import GooglePlayAPI  # noqa: F401
    from gpapi.googleplay import GooglePlayAPI
    return GooglePlayAPI


def _download(url: str, path: str, timeout: float) -> int:
    request = urllib.request.Request(url, headers={"User-Agent": PLAY_UA})
    total = 0
    with urllib.request.urlopen(request, timeout=timeout) as response, open(path, "wb") as sink:
        first = response.read(1 << 16)
        if not first.startswith(b"PK"):
            raise ValueError(f"play part is not a zip: {first[:24]!r}")
        sink.write(first)
        total += len(first)
        while True:
            chunk = response.read(1 << 16)
            if not chunk:
                break
            sink.write(chunk)
            total += len(chunk)
    return total


def fetch(package: str, dest_dir: str, deadline: float, version_code: str = "") -> list[dict]:
    if not enabled():
        return []
    os.makedirs(dest_dir, exist_ok=True)
    timeout = lambda: max(10.0, min(120.0, deadline - time.time()))  # noqa: E731

    GooglePlayAPI = _load_gpapi()
    api = GooglePlayAPI(locale="en_US", timezone="UTC", device_codename="bacon")
    api.login(email=os.environ["GPLAY_EMAIL"].strip(),
              aas_token=os.environ["GPLAY_AAS_TOKEN"].strip())

    doc = api.details(package)["docV2"]
    details = doc["details"]["appDetails"]
    code = int(version_code or details["versionCode"])
    name = details.get("versionString") or str(code)
    log(f"[google-play] {package} version {name} ({code})")

    parts = api.download(package, code)
    if not parts:
        raise ValueError("Play returned no download parts")

    files: list[tuple[str, str]] = []
    for part in parts:
        doc_id = part.get("docId") or f"part{len(files)}"
        target = os.path.join(dest_dir, f"{doc_id}.apk")
        size = _download(part["url"], target, timeout())
        if size == 0:
            raise ValueError(f"empty Play part {doc_id}")
        files.append((doc_id, target))
        log(f"[google-play] {doc_id}.apk {size / 1048576:.1f} MiB")

    if len(files) == 1:
        container = files[0][1]
    else:
        container = os.path.join(dest_dir, f"{package}-{name}-{code}-google-play.xapk")
        manifest = {
            "package_name": package,
            "version_code": code,
            "version_name": name,
            "split_apks": [{"file": os.path.basename(path), "id": doc_id}
                           for doc_id, path in files],
        }
        with zipfile.ZipFile(container, "w", zipfile.ZIP_DEFLATED) as archive:
            for _doc_id, path in files:
                archive.write(path, os.path.basename(path))
            archive.writestr("manifest.json", json.dumps(manifest, indent=2))
        log(f"[google-play] packaged {len(files)} parts into {os.path.basename(container)}")

    digest = hashlib.sha256()
    with open(container, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return [{
        "path": container,
        "sha256": digest.hexdigest(),
        "size": os.path.getsize(container),
        "url": "https://play.google.com/store/apps/details?id=" + package,
    }]
