#!/usr/bin/env python3
"""Probe candidate APK mirrors from the CI network.

Prints one line per endpoint: status, content type, size, final URL and a
short body sniff. Used to decide which sources are worth keeping in fetch.py.
"""

from __future__ import annotations

import concurrent.futures
import json
import urllib.error
import urllib.request

PKG = "com.github.android"
SLUG = "github"

UA_ANDROID = (
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
)
UA_DESKTOP = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

UAL = '{"device_info":{"os_ver":"33"},"sdk_info":{"sdk_ver":"1.0.0"},' \
      '"host_info":{"app_ver":"1.0.0"},"business_info":{"business_id":"projecta"}}'


def mobile(**extra):
    return {"User-Agent": UA_ANDROID, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9", **extra}


def desktop(**extra):
    return {
        "User-Agent": UA_DESKTOP,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        **extra,
    }


ENDPOINTS = [
    # APKPure
    ("apkpure-direct-xapk", f"https://d.apkpure.com/b/XAPK/{PKG}?version=latest", mobile()),
    ("apkpure-net-xapk", f"https://d.apkpure.net/b/XAPK/{PKG}?version=latest", mobile()),
    ("cdnpure-xapk", f"https://d.cdnpure.com/b/XAPK/{PKG}?version=latest", mobile()),
    ("apkpure-api-plain", f"https://api.pureapk.com/m/v3/cms/app_version?hl=en-US&package_name={PKG}", mobile()),
    ("apkpure-api-ual", f"https://api.pureapk.com/m/v3/cms/app_version?hl=en-US&package_name={PKG}",
     mobile(**{"Ual-Access-Businessid": "projecta", "Ual-Access-ProjectA": UAL})),
    ("apkpure.com-app", f"https://apkpure.com/{SLUG}/{PKG}", desktop()),
    ("apkpure.net-app", f"https://apkpure.net/{SLUG}/{PKG}", desktop()),
    ("m.apkpure.com-app", f"https://m.apkpure.com/{SLUG}/{PKG}", mobile()),
    ("apkpure.co-app", f"https://apkpure.co/{SLUG}/{PKG}", desktop()),
    # APKCombo
    ("apkcombo-app", f"https://apkcombo.com/{SLUG}/{PKG}/", desktop()),
    ("apkcombo-download", f"https://apkcombo.com/{SLUG}/{PKG}/download/apk", desktop()),
    ("apkcombo-search", f"https://apkcombo.com/search/{PKG}", desktop()),
    ("apkcombo-app-domain", f"https://apkcombo.app/{SLUG}/{PKG}/", desktop()),
    ("apkcombo-me-domain", f"https://apkcombo.me/{SLUG}/{PKG}/", desktop()),
    # Uptodown
    ("uptodown-github-com", f"https://{SLUG}-com.en.uptodown.com/android", desktop()),
    ("uptodown-search", f"https://en.uptodown.com/search?q={PKG}", desktop()),
    ("uptodown-android-search", f"https://en.uptodown.com/android/search?q={PKG}", desktop()),
    # APKMirror
    ("apkmirror-app", "https://www.apkmirror.com/apk/github/github/", desktop()),
    ("apkmirror-search", f"https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s={PKG}", desktop()),
    # others
    ("apksos", f"https://apksos.com/app/{PKG}", desktop()),
    ("apkmonk", f"https://www.apkmonk.com/app/{PKG}/", desktop()),
    ("apk-support", f"https://apk.support/app/{PKG}", desktop()),
    ("apkfab-search", f"https://apkfab.com/search?q={PKG}", desktop()),
    ("apkfab-app", f"https://apkfab.com/{SLUG}/{PKG}", desktop()),
    ("apkdone", f"https://apkdone.com/{SLUG}/", desktop()),
    ("apkgk", f"https://apkgk.com/{PKG}", desktop()),
    ("androidfreeware", f"https://www.androidfreeware.net/download-{SLUG}-apk.html", desktop()),
    ("androidappsapk", f"https://androidappsapk.co/detail-{PKG}/", desktop()),
    ("apkfollow", f"https://apkfollow.com/{SLUG}/", desktop()),
    ("apksfull", f"https://apksfull.com/{SLUG}/{PKG}", desktop()),
    ("apkaward", f"https://apkaward.com/apk/{PKG}", desktop()),
    # Aptoide public API
    ("aptoide-getapp", f"https://ws75.aptoide.com/api/7/getApp/package_name={PKG}", desktop()),
    ("aptoide-search", f"https://ws75.aptoide.com/api/7/apps/search/query={PKG}/limit=3", desktop()),
    ("aptoide-getapp-alt", f"https://ws2.aptoide.com/api/7/getApp/package_name={PKG}", desktop()),
    # stores / meta
    ("f-droid-api", f"https://f-droid.org/api/v1/packages/{PKG}", desktop()),
    ("izzysoft-api", f"https://apt.izzysoft.de/fdroid/api/v1/packages/{PKG}", desktop()),
    ("play-store-page", f"https://play.google.com/store/apps/details?id={PKG}&hl=en", desktop()),
    ("apkeep-release", "https://api.github.com/repos/EFForg/apkeep/releases/latest", desktop()),
]


def probe(item):
    name, url, headers = item
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
            final = response.geturl()
            ctype = response.headers.get("Content-Type", "")
            body = response.read(262144)
        size = len(body)
        if body[:2] == b"PK":
            sniff = "ZIP/APK"
        else:
            text = body.decode("utf-8", "replace").replace("\n", " ")
            sniff = " ".join(text.split())[:110]
        return f"{status} {size:>7} {name:24} {ctype[:28]:28} {final[:80]} :: {sniff}"
    except urllib.error.HTTPError as exc:
        return f"{exc.code} {'':>7} {name:24} {str(exc.reason)[:28]:28} {url[:80]} :: {exc.headers.get('Content-Type', '') if exc.headers else ''}"
    except Exception as exc:  # noqa: BLE001
        return f"ERR {'':>7} {name:24} {type(exc).__name__:28} {url[:80]} :: {exc}"


def main() -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(probe, ENDPOINTS))
    for line in results:
        print(line, flush=True)


if __name__ == "__main__":
    main()
