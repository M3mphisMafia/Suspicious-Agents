#!/usr/bin/env bash
# Lambda layer with the pinned model SDK for the LLM judge, plus awscrt
# (botocore[crt]) so the scorer can sign CloudFront KeyValueStore calls (SigV4A).
# Usage: infra/build_judge_layer.sh <s3-bucket>   -> prints the S3 key (skips the build if it exists)
set -euo pipefail
SDK_VERSION="2.10.0"            # pin; bump deliberately
KEY="undertow/judge-layer-anthropic-${SDK_VERSION}-crt-py314-x86_64.zip"
if aws s3api head-object --bucket "$1" --key "$KEY" >/dev/null 2>&1; then
  echo "$KEY"; exit 0
fi
work="$(mktemp -d)"
python -m pip install -q --target "$work/python" --platform manylinux2014_x86_64 --only-binary=:all: \
  --implementation cp --python-version 3.14 "anthropic[bedrock]==${SDK_VERSION}" "botocore[crt]" >&2
# keep the botocore the SDK resolved: the runtime's copy may be too old to sign bedrock-mantle
(cd "$work" && zip -q -r layer.zip python)
aws s3 cp "$work/layer.zip" "s3://$1/$KEY" >&2
echo "$KEY"
