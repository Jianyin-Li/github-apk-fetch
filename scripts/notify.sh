#!/usr/bin/env bash
# Optional ntfy notification. Skipped silently when the secrets are absent.
set -uo pipefail

if [ -z "${NTFY_URL:-}" ] || [ -z "${NTFY_TOKEN:-}" ]; then
  echo "ntfy secrets are not configured, skipping notification"
  exit 0
fi

cd "$(dirname "$0")/.."

status="${JOB_STATUS:-unknown}"
if [ "$status" = "success" ]; then
  priority=2
  title="APK CI 成功"
else
  priority=4
  title="APK CI 失败"
fi

message="${GITHUB_REPOSITORY:-repo} #${GITHUB_RUN_NUMBER:-?} ${status}"
message="${message}"$'\n'"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}"

if [ -f publish/release.env ]; then
  # shellcheck disable=SC1091
  tag="$(. publish/release.env && printf '%s' "$TAG")"
  message="${message}"$'\n'"发布: ${tag}"
fi

curl -sS -X POST "$NTFY_URL" \
  -H "Authorization: Bearer ${NTFY_TOKEN}" \
  -H "Title: ${title}" \
  -H "Priority: ${priority}" \
  -H "Tags: android,github" \
  --data-binary "$message" >/dev/null

echo "notification sent"
