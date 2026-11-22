#!/usr/bin/env bash
# Create the release for the staged APKs. The tag is created by this script,
# never by hand.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f publish/release.env ]; then
  echo "no verified APK staged, skipping release"
  exit 0
fi

set -a
# shellcheck disable=SC1091
. publish/release.env
set +a

shopt -s nullglob
assets=(publish/*.apk publish/*.xapk publish/*.apks publish/*.apkm publish/*.apkx publish/*.zip)
if [ ${#assets[@]} -eq 0 ]; then
  echo "no APK assets found, skipping release"
  exit 0
fi

if gh release view "$TAG" >/dev/null 2>&1; then
  echo "release $TAG already exists for this version"
  existing=$(gh release view "$TAG" --json assets --jq '.assets[].name')
  new=0
  for asset in "${assets[@]}"; do
    name=$(basename "$asset")
    if grep -qxF "$name" <<<"$existing"; then
      echo "  already published: $name"
    else
      gh release upload "$TAG" "$asset" --clobber
      echo "  uploaded: $name"
      new=$((new + 1))
    fi
  done
  [ "$new" -eq 0 ] && echo "nothing new for $TAG"
  exit 0
fi

gh release create "$TAG" "${assets[@]}" \
  --target "$GITHUB_SHA" \
  --title "$TITLE" \
  --notes-file publish/release-notes.md \
  --latest

echo "published release $TAG"
