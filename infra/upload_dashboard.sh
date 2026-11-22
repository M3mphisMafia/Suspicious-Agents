#!/usr/bin/env bash
# Upload every dashboard file to <bucket>/_undertow/, each with its content type and no-store caching.
# Usage: infra/upload_dashboard.sh <dashboard-bucket>
set -euo pipefail
cd "$(dirname "$0")/.."
for f in dashboard/*; do
  [[ -f "$f" ]] || continue
  [[ "$f" == *" 2."* ]] && continue      # an iCloud conflict copy, never published
  case "$f" in
    *.html) type=text/html ;;
    *.js) type=text/javascript ;;
    *.css) type=text/css ;;
    *.json) type=application/json ;;
    *.svg) type=image/svg+xml ;;
    *.png) type=image/png ;;
    *) echo "skipped $f: no content type for it" >&2; continue ;;
  esac
  aws s3 cp "$f" "s3://$1/_undertow/$(basename "$f")" --content-type "$type" --cache-control no-store
done
