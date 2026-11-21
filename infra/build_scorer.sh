#!/usr/bin/env bash
# Zip aa_ai + store (stdlib only; boto3 comes from the Lambda runtime) under a content-hashed key.
# Usage: infra/build_scorer.sh [s3-bucket]   (uploads only if a bucket is given)
# Writes the key to dist/KEY for the pipeline.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/dist"
rm -rf "$out" && mkdir -p "$out"
(cd "$root" && { find aa_ai store -name '*.py' -not -name '* 2.py'; ls aa_ai/data/*.json; } | sort \
  | TZ=UTC zip -q -X "$out/code.zip" -@)
hash_cmd="sha256sum"; command -v sha256sum >/dev/null || hash_cmd="shasum -a 256"
sha="$( (cd "$root" && { find aa_ai store -name '*.py' -not -name '* 2.py'; ls aa_ai/data/*.json; } | sort | xargs cat) | $hash_cmd | cut -c1-16)"
key="undertow/code-$sha.zip"
mv "$out/code.zip" "$out/code-$sha.zip"
echo "$key" > "$out/KEY"
echo "built dist/code-$sha.zip  ->  $key"
if [[ $# -ge 1 ]]; then
  aws s3 cp "$out/code-$sha.zip" "s3://$1/$key"
fi
