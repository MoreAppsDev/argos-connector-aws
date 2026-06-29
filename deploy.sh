#!/usr/bin/env bash
# =============================================================================
# Argos V2 — deploy do connector AWS CloudTrail (via AWS CloudShell / SAM)
# =============================================================================
# Pré-requisitos: AWS CloudShell (já vem com sam + aws cli) na região us-east-1.
# Uso:
#   export ARGOS_SOURCE_CONNECTION_ID="<uuid da fonte no painel Argos>"
#   export ARGOS_HMAC_SECRET="<secret exibido ao criar a fonte>"
#   ./deploy.sh
#
# Opcional:
#   export ARGOS_INGEST_URL="https://argos.moreapps.com.br/api/ingest/security-event"
#   export AWS_REGION="us-east-1"   # mantenha us-east-1 p/ capturar console sign-in
# =============================================================================
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
INGEST_URL="${ARGOS_INGEST_URL:-https://argos.moreapps.com.br/api/ingest/security-event}"
STACK="argos-cloudtrail-connector"

if [[ -z "${ARGOS_SOURCE_CONNECTION_ID:-}" || -z "${ARGOS_HMAC_SECRET:-}" ]]; then
  echo "ERRO: defina ARGOS_SOURCE_CONNECTION_ID e ARGOS_HMAC_SECRET antes de rodar." >&2
  echo "      (pegue os dois no painel Argos → Fontes de dados → ao criar a fonte)" >&2
  exit 1
fi

echo "→ Região:      $REGION"
echo "→ Endpoint:    $INGEST_URL"
echo "→ Fonte (id):  $ARGOS_SOURCE_CONNECTION_ID"
echo "→ Empacotando e publicando via SAM…"

sam deploy \
  --stack-name "$STACK" \
  --region "$REGION" \
  --resolve-s3 \
  --capabilities CAPABILITY_IAM \
  --no-confirm-changeset \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "IngestUrl=$INGEST_URL" \
    "SourceConnectionId=$ARGOS_SOURCE_CONNECTION_ID" \
    "HmacSecret=$ARGOS_HMAC_SECRET"

echo ""
echo "✓ Connector publicado. Gere atividade na conta (ex: login no console sem MFA)"
echo "  e confira em https://argos.moreapps.com.br/ → o evento aparece no dashboard."
