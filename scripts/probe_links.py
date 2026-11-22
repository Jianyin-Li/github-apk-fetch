#!/usr/bin/env python3
"""Dump the download-related links of the pages that responded with 200."""

from __future__ import annotations

import re
import urllib.parse
import urllib.request

PKG = "com.github.android"
UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
UA_MOBILE = (
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
)

PAGES = [
    ("uptodown-app", "https://github-com.en.uptodown.com/android", UA),
    ("uptodown-versions", "https://github-com.en.uptodown.com/android/versions", UA),
    ("apkcombo-search", f"https://apkcombo.com/search/{PKG}", UA),
    ("apkpure-mobile", f"https://m.apkpure.com/github/{PKG}", UA_MOBILE),
    ("apksfull", f"https://apksfull.com/github/{PKG}", UA),
]

LINK_RE = re.compile(r"""(?:href|src|data-url|data-dt-url|data-download-url)\s*=\s*["']([^"']+)["']""", re.I)
INTERESTING = re.compile(r"(download|\.apk|\.xapk|dw\.|/dwn/|version)", re.I)


def main() -> None:
    for name, url, ua in PAGES:
        print(f"\n===== {name} {url}")
        try:
            request = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"})
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read(3_000_000).decode("utf-8", "replace")
                final = response.geturl()
        except Exception as exc:  # noqa: BLE001
            print(f"  FAILED: {exc}")
            continue
        links = []
        for match in LINK_RE.finditer(body):
            link = urllib.parse.urljoin(final, match.group(1))
            if INTERESTING.search(link) and link not in links:
                links.append(link)
        for link in links[:40]:
            print(f"  {link[:190]}")
        print(f"  -- {len(links)} interesting links, page {len(body)} bytes")
        if name == "uptodown-app":
            after = re.search(r"data-url=[\"']([^\"']+)[\"']", body)
            print(f"  data-url: {after.group(1)[:190] if after else 'none'}")


if __name__ == "__main__":
    main()
