#!/usr/bin/env bash
# bootstrap.sh — generate Wazuh SSL certs, then bring the stack up.
set -e
cd "$(dirname "$0")"

echo "[bootstrap] Generating Wazuh TLS certs (first run only)..."
CERTS_DIR=config/wazuh_indexer_ssl_certs
if [ -f "$CERTS_DIR/root-ca.pem" ]; then
  echo "[bootstrap] certs already present, skipping."
else
  mkdir -p "$CERTS_DIR"
  docker compose -f generate-certs.yml up
  echo "[bootstrap] certs written to $CERTS_DIR"
fi

echo "[bootstrap] Starting Agentic SOC stack..."
docker compose up -d --build

echo "[bootstrap] Done. Waiting for manager API..."
for i in $(seq 1 30); do
  if curl -sk -u "${WAZUH_API_USER:-wazuh-wui}:${WAZUH_API_PASSWORD:-MyS3cr37P450r.*-}" https://localhost:55000/ >/dev/null 2>&1; then
    echo "[bootstrap] Manager API is up."
    break
  fi
  sleep 5
done

echo
echo "Endpoints:"
echo "  Wazuh Dashboard : https://localhost   (admin/${INDEXER_PASSWORD:-SecretPassword})"
echo "  Wazuh API       : https://localhost:55000"
echo "  OpenSearch      : https://localhost:9200"
echo "  n8n             : http://localhost:5678"
echo "  Linux endpoint  : docker logs agentic-soc-linux-endpoint-1"
