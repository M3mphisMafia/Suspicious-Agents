#!/usr/bin/env bash
# Pipeline Publish stage: what CloudFormation does not hold. Dashboard pages and sign-in config,
# decoy API files, bait files carrying the canary key, one protect-app stack per infra/apps.json
# entry (the scorer's 1-minute tick publishes the data). Env: DECOY_PREFIX APP_STACK EDGE_STACK CFN_ROLE_ARN
set -euo pipefail
cd "$(dirname "$0")/.."

out() { aws cloudformation describe-stacks --stack-name "$1" \
  --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text; }
# the edge's outputs come from its CloudFormation stage; describe-stacks only for a run outside the pipeline
EDGE_OUT="${CODEBUILD_SRC_DIR_EdgeOut:-/nonexistent}/outputs.json"
eo() { if [[ -f "$EDGE_OUT" ]]; then jq -r --arg k "$1" '.[$k] // empty' "$EDGE_OUT"; else out "$EDGE_STACK" "$1"; fi; }

DASH=$(eo DashboardBucketName); DECOY=$(eo DecoyBucketName); DOM=$(eo DistributionDomain)
bash infra/upload_dashboard.sh "$DASH"     # every page, script and stylesheet
# public sign-in settings (pool and client IDs are not secrets)
printf '{"region":"%s","userPoolId":"%s","clientId":"%s"}' "${AWS_REGION:-us-east-1}" "$(eo UserPoolId)" "$(eo UserPoolClientId)" \
  | aws s3 cp - "s3://$DASH/_undertow/config.json" --content-type application/json --cache-control no-store
python -m aa_ai decoys --prefix "$DECOY_PREFIX" --out /tmp/decoy-site
aws s3 sync /tmp/decoy-site/api "s3://$DECOY/api" --content-type application/json --delete
# bait files on the attackers' checklist, carrying the real (zero-permission) canary key
CAN=$(aws secretsmanager get-secret-value --secret-id "$(eo CanarySecretArn)" --query SecretString --output text)
CID=$(python -c "import json,sys;print(json.loads(sys.argv[1])['id'])" "$CAN")
CSK=$(python -c "import json,sys;print(json.loads(sys.argv[1])['secret'])" "$CAN")
printf 'APP_ENV=production\nDATABASE_URL=postgres://inventory:REDACTED@db.internal:5432/inventory\nAWS_REGION=us-east-1\nAWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nS3_BUCKET=inventory-exports-prod\n' "$CID" "$CSK" \
  | aws s3 cp - "s3://$DECOY/.env" --content-type text/plain --cache-control no-store
printf '[default]\naws_access_key_id = %s\naws_secret_access_key = %s\nregion = us-east-1\n' "$CID" "$CSK" \
  | aws s3 cp - "s3://$DECOY/.aws/credentials" --content-type text/plain --cache-control no-store
printf '{"apiBase":"%s","region":"us-east-1","uploadBucket":"inventory-exports-prod","accessKeyId":"%s"}' "$DECOY_PREFIX" "$CID" \
  | aws s3 cp - "s3://$DECOY/config.json" --content-type application/json --cache-control no-store
unset CAN CSK

# more apps behind the same engine: one protect-app stack per entry in infra/apps.json (see apps.example.json)
if [[ -f infra/apps.json ]]; then
  SECRET=$(out "$APP_STACK" OriginSecretArn)
  python -c "import json;[print(a['name'],a['origin'],a.get('domain','-'),a.get('cert','-')) for a in json.load(open('infra/apps.json'))]" |
  while read -r NAME ORIGIN_D DOMAIN CERT; do
    [[ "$DOMAIN" == "-" ]] && DOMAIN=""; [[ "$CERT" == "-" ]] && CERT=""
    aws cloudformation deploy --stack-name "undertow-app-$NAME" --template-file infra/protect-app.yaml --role-arn "$CFN_ROLE_ARN" \
      --no-fail-on-empty-changeset --tags undertow=engine --parameter-overrides AppName="$NAME" OriginDomainName="$ORIGIN_D" \
      OriginVerifySecretArn="$SECRET" EngineStack="$EDGE_STACK" DomainName="$DOMAIN" AcmCertificateArn="$CERT"
  done
fi

echo "Dashboard: https://$DOM/_undertow/index.html"
echo "App:       https://$DOM/"
