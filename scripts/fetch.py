#!/usr/bin/env python3
"""Download APK/XAPK files for a package from several public mirrors.

Nothing in this module is trusted: a download only counts as a candidate when
the payload is a readable zip container that holds AndroidManifest.xml or
base.apk. Package name and signature checks live in verify.py.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

UA_MOBILE = (
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
)
UA_DESKTOP = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

MAX_APK_BYTES = 512 * 1024 * 1024
MAX_PAGE_BYTES = 4 * 1024 * 1024

APK_URL_RE = re.compile(
    r"https?://[^\s\"'<>()\\]+?\.(?:apk|xapk|apks|apkm|apkx)(?:\?[^\s\"'<>()\\]*)?", re.I
)
ATTR_RE = re.compile(
    r"(?:href|src|data-url|data-dt-url|data-download-url)\s*=\s*\"([^\"]+)\"", re.I
)
VERSION_PAGE_RE = re.compile(r"(?:/versions?|/download|/android/download/\d+)", re.I)


def log(msg: str) -> None:
    print(msg, flush=True)


def headers_for(ua: str) -> dict:
    return {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }


def _timeout(deadline: float, cap: float = 60.0) -> float:
    return max(5.0, min(cap, deadline - time.time()))


def _sanitize_filename(name: str) -> str:
    name = urllib.parse.unquote(name).strip().replace("\\", "_").replace("/", "_")
    name = re.sub(r"[^A-Za-z0-9._+-]", "_", name)
    return name or "payload"


def _filename_from(resp, url: str) -> str:
    disposition = resp.headers.get("Content-Disposition") or ""
    match = re.search(r"filename\*?=(?:UTF-8''|[\"']?)([^\"';]+)", disposition, re.I)
    if match:
        name = _sanitize_filename(match.group(1))
    else:
        name = _sanitize_filename(urllib.parse.urlparse(resp.geturl() or url).path.rsplit("/", 1)[-1])
    if not re.search(r"\.(?:apk|xapk|apks|apkm|apkx)$", name, re.I):
        name += ".apk"
    return name


def read_page(url: str, headers: dict, deadline: float) -> tuple[str, str]:
    """Fetch a small HTML/JSON page. Returns (text, final_url)."""
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=_timeout(deadline)) as resp:
        raw = resp.read(MAX_PAGE_BYTES)
        final = resp.geturl() or url
        charset = resp.headers.get_content_charset() or "utf-8"
    return raw.decode(charset, "replace"), final


def fetch_file(url: str, dest_dir: str, headers: dict, deadline: float) -> dict:
    """Stream a URL into dest_dir, validating that it is a zip based package."""
    req = urllib.request.Request(url, headers=headers)
    dest = None
    try:
        with urllib.request.urlopen(req, timeout=_timeout(deadline, 120.0)) as resp:
            final = resp.geturl() or url
            dest = os.path.join(dest_dir, _filename_from(resp, url))
            stem, ext = os.path.splitext(dest)
            counter = 1
            while os.path.exists(dest):
                dest = f"{stem}-{counter}{ext}"
                counter += 1

            digest = hashlib.sha256()
            total = 0
            with open(dest, "wb") as handle:
                first = resp.read(1 << 16)
                if not first.startswith(b"PK"):
                    raise ValueError(f"payload is not a zip container ({first[:24]!r})")
                handle.write(first)
                digest.update(first)
                total += len(first)
                while True:
                    chunk = resp.read(1 << 16)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_APK_BYTES:
                        raise ValueError("payload exceeds size limit")
                    handle.write(chunk)
                    digest.update(chunk)

        with zipfile.ZipFile(dest) as zf:
            names = set(zf.namelist())
        if "AndroidManifest.xml" not in names and not any(
            entry.lower().endswith(".apk") for entry in names
        ):
            raise ValueError("zip container has no AndroidManifest.xml and no inner APK")

        return {"path": dest, "sha256": digest.hexdigest(), "size": total, "url": final}
    except Exception:
        if dest and os.path.exists(dest):
            os.unlink(dest)
        raise


def extract_links(text: str, base_url: str) -> list[str]:
    seen: dict[str, None] = {}
    for match in APK_URL_RE.finditer(text):
        seen.setdefault(match.group(0), None)
    for match in ATTR_RE.finditer(text):
        candidate = urllib.parse.urljoin(base_url, html.unescape(match.group(1)))
        if candidate.startswith(("http://", "https://")):
            seen.setdefault(candidate, None)
    return list(seen)


def _is_download_candidate(url: str) -> bool:
    path = urllib.parse.urlparse(url).path.lower()
    if path.endswith((".apk", ".xapk", ".apks", ".apkm", ".apkx")):
        return True
    return any(marker in path for marker in ("/dwn/", "/download/", "/downloading/"))


def _json_download_urls(payload, base_url: str) -> list[str]:
    found: dict[str, None] = {}

    def walk(node):
        if isinstance(node, str):
            value = html.unescape(node.strip())
            if value.startswith(("http://", "https://")) and len(value) < 2000:
                if ".apk" in value.lower() or "/download" in value.lower():
                    found.setdefault(value, None)
            elif value.startswith("/") and ("download" in value.lower()):
                found.setdefault(urllib.parse.urljoin(base_url, value), None)
        elif isinstance(node, dict):
            for item in node.values():
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return list(found)


def _download_candidates(urls: list[str], dest_dir: str, headers: dict, deadline: float,
                         limit: int) -> list[dict]:
    found = []
    seen = set()
    ordered = sorted(urls, key=lambda u: (not u.lower().split("?")[0].endswith(
        (".apk", ".xapk", ".apks", ".apkm", ".apkx")), len(u)))
    for url in ordered:
        if len(found) >= limit or time.time() >= deadline:
            break
        if url in seen:
            continue
        seen.add(url)
        try:
            entry = fetch_file(url, dest_dir, headers, deadline)
        except Exception as exc:  # noqa: BLE001 - any failure just moves on
            log(f"    skip {url[:120]}: {exc}")
            continue
        log(f"    got {os.path.basename(entry['path'])} from {url[:120]}")
        found.append(entry)
    return found


def _try_files(src: dict, dest_dir: str, deadline: float) -> list[dict]:
    found = []
    for url in src["urls"]:
        if len(found) >= src.get("max_files", 2) or time.time() >= deadline:
            break
        try:
            entry = fetch_file(url, dest_dir, src["headers"], deadline)
        except Exception as exc:  # noqa: BLE001
            log(f"  [{src['name']}] {url[:110]} -> {exc}")
            continue
        log(f"  [{src['name']}] got {os.path.basename(entry['path'])}")
        found.append(entry)
    return found


def _try_json(src: dict, dest_dir: str, deadline: float) -> list[dict]:
    for url in src["urls"]:
        if time.time() >= deadline:
            break
        try:
            text, final = read_page(url, src["headers"], deadline)
            payload = json.loads(text)
        except Exception as exc:  # noqa: BLE001
            log(f"  [{src['name']}] {url[:110]} -> {exc}")
            continue
        urls = _json_download_urls(payload, final)
        if urls:
            entries = _download_candidates(urls, dest_dir, src["headers"], deadline,
                                           src.get("max_files", 2))
            if entries:
                return entries
    return []


def _try_html(src: dict, dest_dir: str, deadline: float) -> list[dict]:
    queue = [(url, 0) for url in src["urls"]]
    seen: set[str] = set()
    pages = 0
    found: list[dict] = []
    follow = re.compile(src["follow"], re.I) if src.get("follow") else VERSION_PAGE_RE
    while queue and pages < src.get("max_pages", 8) and time.time() < deadline:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        pages += 1
        try:
            text, final = read_page(url, src["headers"], deadline)
        except Exception as exc:  # noqa: BLE001
            log(f"  [{src['name']}] page {url[:110]} -> {exc}")
            continue
        links = extract_links(text, final)
        candidates = [link for link in links if _is_download_candidate(link)]
        if candidates:
            entries = _download_candidates(
                candidates, dest_dir, src["headers"], deadline, src.get("max_files", 2)
            )
            found.extend(entries)
            if len(found) >= src.get("max_files", 2):
                break
        if depth < 2:
            for link in links:
                if link in seen or "javascript:" in link:
                    continue
                if follow.search(urllib.parse.urlparse(link).path or "/"):
                    queue.append((link, depth + 1))
    return found


def crawl_source(src: dict, dest_root: str, deadline: float) -> list[dict]:
    dest_dir = os.path.join(dest_root, src["name"])
    os.makedirs(dest_dir, exist_ok=True)
    kind = src.get("kind", "html")
    if kind == "file":
        return _try_files(src, dest_dir, deadline)
    if kind == "json":
        return _try_json(src, dest_dir, deadline)
    return _try_html(src, dest_dir, deadline)


def _slugs(pkg: str, slug: str) -> list[str]:
    parts = pkg.split(".")
    guesses = [slug, parts[-1], parts[-2] if len(parts) > 1 else ""]
    guesses.append("-".join(reversed(parts[:2])))
    guesses.append("-".join(parts))
    ordered: list[str] = []
    for guess in guesses:
        if guess and guess not in ordered:
            ordered.append(guess)
    return ordered


def build_sources(pkg: str, slug: str) -> list[dict]:
    """Sources that are actually reachable from GitHub-hosted runners.

    Everything else (APKMirror, APKCombo, Uptodown, apkfab, ...) answers 403 or
    sits behind Cloudflare Turnstile, so it is not worth a request per run.
    """
    mobile = headers_for(UA_MOBILE)
    desktop = headers_for(UA_DESKTOP)
    referer = {"Referer": "https://apkpure.com/"}

    sources: list[dict] = [{
        "name": "apkpure-xapk",
        "kind": "file",
        "headers": {**mobile, **referer},
        "urls": [
            f"https://d.apkpure.com/b/XAPK/{pkg}?version=latest",
            f"https://d.apkpure.net/b/XAPK/{pkg}?version=latest",
            f"https://d.cdnpure.com/b/XAPK/{pkg}?version=latest",
        ],
        "max_files": 1,
    }, {
        # Bare App Bundle base. Usually not installable alone, but kept as a
        # cross-check of the bundle and as a fallback for non-split apps.
        "name": "apkpure-apk",
        "kind": "file",
        "headers": {**mobile, **referer},
        "urls": [
            f"https://d.apkpure.com/b/APK/{pkg}?version=latest",
            f"https://d.apkpure.net/b/APK/{pkg}?version=latest",
        ],
        "max_files": 1,
    }, {
        # The desktop site is Cloudflare-blocked; the mobile site still serves
        # version pages that can expose direct download links.
        "name": "apkpure-mobile",
        "kind": "html",
        "headers": mobile,
        "urls": [
            f"https://m.apkpure.com/{slug}/{pkg}",
            f"https://m.apkpure.com/{slug}/{pkg}/versions",
        ],
        "follow": r"/{}".format(re.escape(pkg)),
        "max_pages": 4,
        "max_files": 2,
    }]

    extra = [u.strip() for u in re.split(r"[\s,]+", os.environ.get("EXTRA_SOURCE_URLS", ""))
             if u.strip()]
    if extra:
        sources.append({
            "name": "extra-urls",
            "kind": "file",
            "headers": {**desktop, "Referer": "https://play.google.com/"},
            "urls": extra,
            "max_files": len(extra),
        })

    return sources


def fetch_all(pkg: str, slug: str, dest_root: str, only: str = "",
              budget: float = 600.0, workers: int = 6) -> list[dict]:
    sources = build_sources(pkg, slug)
    wanted = {item.strip() for item in only.split(",") if item.strip()} if only else set()
    if wanted:
        sources = [src for src in sources if src["name"] in wanted]

    google_play = None
    if (not wanted or "google-play" in wanted) and os.environ.get("GPLAY_EMAIL") \
            and os.environ.get("GPLAY_AAS_TOKEN"):
        import gplay
        google_play = gplay

    if not sources and not google_play:
        log("no sources selected")
        return []

    log(f"sources: {', '.join(src['name'] for src in sources)}"
        + (", google-play" if google_play else ""))
    deadline = time.time() + budget
    found: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(crawl_source, src, dest_root, deadline): src for src in sources}
        if google_play:
            futures[pool.submit(google_play.fetch, pkg,
                                os.path.join(dest_root, "google-play"), deadline)] = \
                {"name": "google-play"}
        for future in as_completed(futures):
            src = futures[future]
            try:
                entries = future.result()
            except Exception as exc:  # noqa: BLE001
                log(f"[{src['name']}] aborted: {exc}")
                entries = []
            for entry in entries:
                entry["source"] = src["name"]
                log(f"[{src['name']}] {os.path.basename(entry['path'])} "
                    f"{entry['size'] / 1048576:.1f} MiB sha256={entry['sha256'][:16]}")
            found.extend(entries)
    return found
