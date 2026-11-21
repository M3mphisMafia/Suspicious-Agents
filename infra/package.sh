#!/usr/bin/env bash
# Pipeline Package stage: code to S3, each stack's parameters to cfn/*.json. Deploys nothing.
# Env: ARTIFACT_BUCKET ADMIN_CIDRS SCORER_MODE DECOY_PREFIX ALERT_EMAIL ADMIN_EMAIL EDGE_STACK
set -euo pipefail
cd "$(dirname "$0")/.."

out() { aws cloudformation describe-stacks --stack-name "$1" \
  --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text 2>/dev/null || true; }

bash infra/build_scorer.sh "$ARTIFACT_BUCKET"
export KEY=$(cat dist/KEY)
export JUDGE_LAYER=$(bash infra/build_judge_layer.sh "$ARTIFACT_BUCKET")
export JUDGE_MODEL=$(aws ssm get-parameter --name /undertow/judge/model --query Parameter.Value --output text 2>/dev/null || echo "")
export DDB_PL=$(aws ec2 describe-prefix-lists --filters "Name=prefix-list-name,Values=com.amazonaws.${AWS_REGION:-us-east-1}.dynamodb" \
  --query 'PrefixLists[0].PrefixListId' --output text)
export TABLE=$(out "$EDGE_STACK" ScorerTableName)      # empty on the first deploy
export DOM=$(out "$EDGE_STACK" DistributionDomain)     # invite emails link to the sign-in page
python infra/stack_params.py
