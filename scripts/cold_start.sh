#!/bin/bash
# ============================================================================
# Agentic SOC — Cold Start Script
# ============================================================================
# Brings up the entire SOC lab from scratch on a fresh Ubuntu 22.04 host.
# Run as a non-root user with sudo access.
#
# What it does:
#   1. Installs system dependencies (Docker, Python, vbox, etc.)
#   2. Clones required repos (agentic-soc, NOVA_Project)
#   3. Loads user-provided secrets from lab.env (prompts if missing)
#   4. Deploys the Wazuh single-node stack
#   5. Deploys the n8n workflow engine
#   6. Builds and starts the Linux endpoint container
#   7. Starts the bridge service
#   8. Starts the custom SOC dashboard
#   9. Starts YARAKIN
#  10. Loads Wazuh custom rules and decoders
#  11. Imports n8n workflows and sets credentials
#
# Usage:
#   ./cold_start.sh                    # full install
#   ./cold_start.sh --skip-deps        # skip apt/docker install
#   ./cold_start.sh --no-vm            # skip VirtualBox VM setup
#
# First time: copy lab.env.template to lab.env and fill in your API keys.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BRIDGE_DIR="${BRIDGE_DIR:-/home/dev/soc-lab/sample-bridge}"
DASHBOARD_DIR="${DASHBOARD_DIR:-/home/dev/soc-lab/soc-dashboard}"
YARAKIN_DIR="${YARAKIN_DIR:-/home/dev/PROJECT/DeepSeek/yarakin}"
NOVA_DIR="${NOVA_DIR:-/home/dev/PROJECT/NOVA_Project}"
WAZUH_TMP_DIR="${WAZUH_TMP_DIR:-/tmp/wazuh-restore}"
DOCKER_NETWORK="single-node_default"
WAZUH_WEBHOOK="e1a80abd-e35b-45cb-958a-e57dad1e144b"
PACKAGE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SKIP_DEPS=false
NO_VM=false
for arg in "$@"; do
  case $arg in
    --skip-deps) SKIP_DEPS=true ;;
    --no-vm) NO_VM=true ;;
    *) echo "Unknown arg: $arg"; exit 1 ;;
  esac
done

log()  { echo -e "\033[1;34m[cold-start]\033[0m $*"; }
warn() { echo -e "\033[1;33m[warn]\033[0m $*"; }
fail() { echo -e "\033[1;31m[fail]\033[0m $*"; exit 1; }

check_root() {
  if [ "$EUID" -eq 0 ]; then fail "Run as non-root user with sudo access"; fi
  if ! sudo -n true 2>/dev/null; then fail "sudo requires password; run with: sudo -v first"; fi
}

load_secrets() {
  log "Loading secrets..."
  if [ -f "$SCRIPT_DIR/lab.env" ]; then
    log "  Sourcing lab.env..."
    set -a; source "$SCRIPT_DIR/lab.env"; set +a
  elif [ -f "$PACKAGE_ROOT/11-cold-start/lab.env" ]; then
    log "  Sourcing package lab.env..."
    set -a; source "$PACKAGE_ROOT/11-cold-start/lab.env"; set +a
  else
    warn "No lab.env found. Using defaults for Wazuh/VM. You'll be prompted for the OpenRouter API key."
  fi

  export WAZUH_INDEXER_URL="${WAZUH_INDEXER_URL:-https://localhost:9200}"
  export WAZUH_INDEXER_USER="${WAZUH_INDEXER_USER:-admin}"
  export WAZUH_INDEXER_PASS="${WAZUH_INDEXER_PASS:-SecretPassword}"
  export WAZUH_MANAGER_URL="${WAZUH_MANAGER_URL:-https://localhost:55000}"
  export WAZUH_MANAGER_USER="${WAZUH_MANAGER_USER:-wazuh-wui}"
  export WAZUH_MANAGER_PASS="${WAZUH_MANAGER_PASS:-MyS3cr37P450r.*-}"
  export VM_USER="${VM_USER:-victim}"
  export VM_PASSWORD="${VM_PASSWORD:-m.m.m.m}"
  export YARAKIN_LLM_MODEL="${YARAKIN_LLM_MODEL:-cohere/north-mini-code:free}"

  if [ -z "${OPENROUTER_API_KEY:-}" ]; then
    echo ""
    echo "============================================================"
    echo " OpenRouter API key is REQUIRED for:"
    echo "   - n8n Tier-3 LLM analysis (workflow Agentic)"
    echo "   - YARAKIN forensic analysis"
    echo ""
    echo " Get a free key at: https://openrouter.ai/keys"
    echo "============================================================"
    read -r -p "Enter your OpenRouter API key (or 'skip' to continue without): " OPENROUTER_API_KEY
    if [ "$OPENROUTER_API_KEY" = "skip" ] || [ -z "$OPENROUTER_API_KEY" ]; then
      warn "Continuing without OpenRouter key. Tier-3 analysis will fail until you set it."
      OPENROUTER_API_KEY="sk-or-v1-REDACTED-PLACEHOLDER"
    fi
    export OPENROUTER_API_KEY
  fi

  export VT_API_KEY="${VT_API_KEY:-}"

  echo ""
  log "Secrets loaded:"
  log "  Wazuh indexer: $WAZUH_INDEXER_USER @ $WAZUH_INDEXER_URL"
  log "  Wazuh manager:  $WAZUH_MANAGER_USER @ $WAZUH_MANAGER_URL"
  log "  OpenRouter key: ${OPENROUTER_API_KEY:0:20}..."
  log "  VirusTotal key: ${VT_API_KEY:+set}${VT_API_KEY:-not set (optional)}"
  echo ""
}

install_deps() {
  log "Installing system dependencies..."
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    git curl wget vim jq python3 python3-pip python3-venv \
    ca-certificates gnupg lsb-release apt-transport-https \
    build-essential libffi-dev libssl-dev \
    net-tools unzip

  if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$USER"
    warn "Docker installed. Log out and back in for group, or run: newgrp docker"
    warn "Then re-run this script."
  fi
  docker --version || fail "Docker not available"

  if ! docker compose version &>/dev/null 2>&1; then
    log "Installing docker compose plugin..."
    sudo apt-get install -y -qq docker-compose-plugin
  fi
}

clone_repos() {
  log "Setting up repos..."
  mkdir -p /home/dev/soc-lab /home/dev/PROJECT
  cd /home/dev/soc-lab
  if [ ! -d "agentic-soc" ]; then
    log "Cloning agentic-soc..."
    git clone https://github.com/atrixi1337/agentic-soc.git
  else
    log "agentic-soc already exists, pulling latest..."
    cd agentic-soc && git pull origin main && cd ..
  fi
  cd /home/dev/PROJECT
  if [ ! -d "NOVA_Project" ]; then
    log "Cloning NOVA_Project..."
    git clone https://github.com/atrixi1337/NOVA_Project.git || warn "NOVA_Project clone failed (optional)"
  fi
}

install_python_deps() {
  log "Installing Python dependencies..."
  pip3 install --break-system-packages -q \
    fastapi "uvicorn[standard]" websockets httpx aiosqlite \
    pyyaml 2>&1 | tail -3
}

install_local_services() {
  log "Installing bridge and dashboard from package..."
  if [ -d "$PACKAGE_ROOT/02-bridge" ]; then
    mkdir -p "$BRIDGE_DIR"
    cp "$PACKAGE_ROOT/02-bridge/bridge.py" "$BRIDGE_DIR/"
    if [ ! -f "$BRIDGE_DIR/bridge.json" ]; then
      cp "$PACKAGE_ROOT/02-bridge/bridge.json.template" "$BRIDGE_DIR/bridge.json"
      warn "  Created $BRIDGE_DIR/bridge.json from template. Edit it with your VM creds and wazuh_basic."
    fi
  fi
  if [ -d "$PACKAGE_ROOT/03-dashboard" ]; then
    mkdir -p "$DASHBOARD_DIR"
    cp -r "$PACKAGE_ROOT/03-dashboard/"* "$DASHBOARD_DIR/" 2>/dev/null || true
  fi
  if [ -d "$PACKAGE_ROOT/04-yarakin/src" ]; then
    mkdir -p "$YARAKIN_DIR"
    cp -r "$PACKAGE_ROOT/04-yarakin/src" "$YARAKIN_DIR/"
    [ -f "$PACKAGE_ROOT/04-yarakin/.env.template" ] && cp "$PACKAGE_ROOT/04-yarakin/.env.template" "$YARAKIN_DIR/.env.template"
    log "  YARAKIN source copied to $YARAKIN_DIR"
    log "  Set up your .env: cp $YARAKIN_DIR/.env.template $YARAKIN_DIR/.env and add your keys"
  fi
}

deploy_wazuh() {
  log "Deploying Wazuh single-node stack..."
  WAZUH_DOCKER_DIR="/home/dev/PROJECT/wazuh-docker/single-node"
  if [ ! -d "$WAZUH_DOCKER_DIR" ]; then
    log "Cloning wazuh-docker v4.9.0..."
    sudo git clone --depth 1 --branch v4.9.0 https://github.com/wazuh/wazuh-docker.git /home/dev/PROJECT/wazuh-docker || fail "Wazuh clone failed"
  fi
  cd "$WAZUH_DOCKER_DIR"
  if [ -f "generate-indexer-certs.yml" ]; then
    sudo docker compose -f generate-indexer-certs.yml run --rm generator 2>&1 | tail -3 || true
  fi
  sudo docker compose up -d
  log "Waiting for Wazuh indexer..."
  for i in {1..60}; do
    if curl -sk -m 3 "https://localhost:9200/_cluster/health" 2>/dev/null | grep -q "green\|yellow"; then
      log "Wazuh indexer is ready"
      break
    fi
    sleep 5
  done

  if [ -d "$REPO_DIR/config/manager" ]; then
    log "Loading custom rules and decoders..."
    sudo docker exec -u root single-node-wazuh.manager-1 sh -c "
      cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak 2>/dev/null || true
      cat > /var/ossec/etc/rules/local_rules.xml << 'RULESEOF'
$(cat "$REPO_DIR/config/manager/local_rules.xml")
RULESEOF
      cp /var/ossec/etc/decoders/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml.bak 2>/dev/null || true
      cat > /var/ossec/etc/decoders/local_decoder.xml << 'DECEOF'
$(cat "$REPO_DIR/config/manager/local_decoder.xml")
DECEOF
      chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/decoders/local_decoder.xml
      chmod 660 /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/decoders/local_decoder.xml
    "
    sudo docker exec -u root single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
  fi
}

deploy_n8n() {
  log "Deploying n8n..."
  mkdir -p /home/dev/soc-lab/n8n
  cd /home/dev/soc-lab/n8n
  if [ ! -f "docker-compose.yml" ]; then
    cat > docker-compose.yml << 'EOF'
services:
  n8n:
    image: docker.n8n.io/n8nio/n8n
    container_name: n8n
    restart: always
    ports:
      - "5678:5678"
    environment:
      - N8N_CONCURRENCY=2
    volumes:
      - n8n_data:/home/node/.n8n
volumes:
  n8n_data:
EOF
  fi
  sudo docker compose up -d
  log "Waiting for n8n..."
  for i in {1..30}; do
    if curl -sf -m 3 "http://localhost:5678/" 2>/dev/null; then
      log "n8n is ready"
      break
    fi
    sleep 3
  done
  if [ -d "$PACKAGE_ROOT/07-n8n-workflows" ]; then
    log "Importing n8n workflows..."
    sudo docker cp "$PACKAGE_ROOT/07-n8n-workflows/workflows.json" n8n:/tmp/workflows.json
    sudo docker exec n8n n8n import:workflow --input=/tmp/workflows.json 2>&1 | tail -3 || warn "Workflow import failed"
  fi
}

configure_n8n_credentials() {
  log "Configuring n8n credentials..."
  if [ -n "$OPENROUTER_API_KEY" ] && [ "$OPENROUTER_API_KEY" != "sk-or-v1-REDACTED-PLACEHOLDER" ]; then
    log "  Injecting OpenRouter key into n8n workflows..."
    sudo docker exec n8n sh -c "
      WF_DIR=/home/node/.n8n/workflows
      if [ -d \"\$WF_DIR\" ]; then
        for f in \$WF_DIR/*.json; do
          sed -i 's|sk-or-v1-REDACTED|$OPENROUTER_API_KEY|g' \"\$f\" 2>/dev/null || true
        done
      fi
    "
    sudo docker restart n8n
    sleep 15
  fi
  cat <<'NOTE'

  ============================================================
   NOTE: n8n credentials
  ============================================================
   The imported workflows reference Wazuh credentials by ID.
   After cold start, open http://localhost:5678 and:
     1. Settings → Credentials → New
     2. Create "Wazuh Indexer" (Basic Auth, admin/SecretPassword)
     3. Create "Wazuh Manager" (Basic Auth, wazuh-wui/MyS3cr37P450r.*-)
     4. Re-open workflows and assign credentials to nodes
  ============================================================
NOTE
}

deploy_endpoint() {
  log "Building and starting Linux endpoint container..."
  cd "$REPO_DIR/endpoint"
  sudo docker build -t linux-agent-test .
  sudo docker run -d --name soc-linux-test \
    --network "$DOCKER_NETWORK" \
    -v "$REPO_DIR/endpoint/ossec.conf:/var/ossec/etc/ossec.conf:ro" \
    linux-agent-test || warn "Endpoint container start failed"
}

deploy_bridge() {
  log "Starting bridge service..."
  if [ ! -f "$BRIDGE_DIR/bridge.py" ]; then
    warn "Bridge not installed. Skipping."
    return
  fi
  BRIDGE_SECRET_FILE="/home/dev/soc-lab/configs/bridge/bridge_secret"
  if [ -f "$BRIDGE_SECRET_FILE" ]; then
    BRIDGE_SECRET=$(cat "$BRIDGE_SECRET_FILE")
  else
    BRIDGE_SECRET="br_$(openssl rand -hex 16)"
    mkdir -p "$(dirname "$BRIDGE_SECRET_FILE")"
    echo "$BRIDGE_SECRET" > "$BRIDGE_SECRET_FILE"
    chmod 600 "$BRIDGE_SECRET_FILE"
    log "Generated bridge secret: $BRIDGE_SECRET"
  fi
  pkill -f bridge.py 2>/dev/null || true
  sleep 1
  nohup env BRIDGE_SECRET="$BRIDGE_SECRET" python3 "$BRIDGE_DIR/bridge.py" > /tmp/bridge.log 2>&1 &
  sleep 2
  if curl -sf -m 3 "http://localhost:8765/" 2>/dev/null; then
    log "Bridge is running on :8765 (X-Bridge-Key: $BRIDGE_SECRET)"
  else
    warn "Bridge may not be ready yet. Check: tail -f /tmp/bridge.log"
  fi
}

deploy_dashboard() {
  log "Starting SOC dashboard..."
  if [ ! -f "$DASHBOARD_DIR/app.py" ]; then
    warn "Dashboard not installed. Skipping."
    return
  fi
  export CASE_DB_PATH="/home/dev/soc-lab/configs/dashboard/soc_cases.db"
  export WAZUH_INDEXER_URL WAZUH_INDEXER_USER WAZUH_INDEXER_PASS
  export WAZUH_MANAGER_URL WAZUH_MANAGER_USER WAZUH_MANAGER_PASS
  mkdir -p "$(dirname "$CASE_DB_PATH")"
  pkill -f "python3 app.py" 2>/dev/null || true
  sleep 1
  cd "$DASHBOARD_DIR"
  nohup python3 app.py > /tmp/dashboard.log 2>&1 &
  sleep 3
  if curl -sf -m 3 "http://localhost:8888/" 2>/dev/null; then
    log "Dashboard is running on :8888"
  else
    warn "Dashboard may not be ready. Check: tail -f /tmp/dashboard.log"
  fi
}

deploy_yarakin() {
  log "Starting YARAKIN..."
  if [ ! -d "$YARAKIN_DIR/src" ]; then
    warn "YARAKIN source not found at $YARAKIN_DIR. Skipping."
    return
  fi
  if [ -f "$YARAKIN_DIR/.env.template" ] && [ ! -f "$YARAKIN_DIR/.env" ]; then
    if [ -n "$OPENROUTER_API_KEY" ] && [ "$OPENROUTER_API_KEY" != "sk-or-v1-REDACTED-PLACEHOLDER" ]; then
      sed "s|sk-or-v1-REDACTED|$OPENROUTER_API_KEY|g" "$YARAKIN_DIR/.env.template" > "$YARAKIN_DIR/.env"
      log "  YARAKIN .env created with your OpenRouter key"
    else
      cp "$YARAKIN_DIR/.env.template" "$YARAKIN_DIR/.env"
      warn "  YARAKIN .env created but OpenRouter key is still REDACTED"
    fi
  fi
  pkill -f "uvicorn.*yarakin" 2>/dev/null || true
  sleep 1
  cd "$YARAKIN_DIR"
  nohup python3 -m uvicorn yarakin.web:app --host 0.0.0.0 --port 8501 > /tmp/yarakin.log 2>&1 &
  sleep 3
  if curl -sf -m 3 "http://localhost:8501/" 2>/dev/null; then
    log "YARAKIN is running on :8501"
  else
    warn "YARAKIN may not be ready. Check: tail -f /tmp/yarakin.log"
  fi
}

deploy_vms() {
  if [ "$NO_VM" = true ]; then
    log "Skipping VM setup (--no-vm)"
    return
  fi
  if ! command -v VBoxManage &>/dev/null; then
    log "VirtualBox not installed; skipping VM setup"
    log "  To install: sudo apt install -y virtualbox"
    return
  fi
  if VBoxManage showvminfo "SOC-Victim" &>/dev/null; then
    log "SOC-Victim VM exists; starting it..."
    VBoxManage startvm "SOC-Victim" --type headless 2>&1 | head -2 || true
  else
    log "SOC-Victim VM not found."
    log "  Create the VM in VirtualBox, then run 09-vm-scripts/SOC-SETUP.bat as Administrator"
  fi
}

log "=== Agentic SOC Cold Start ==="
check_root
load_secrets

if [ "$SKIP_DEPS" = false ]; then
  install_deps
fi

clone_repos
install_python_deps
install_local_services
deploy_wazuh
deploy_n8n
configure_n8n_credentials
deploy_endpoint
deploy_bridge
deploy_dashboard
deploy_yarakin
deploy_vms

log ""
log "=== Cold start complete ==="
log ""
log "Services:"
log "  Dashboard:     http://localhost:8888"
log "  n8n:           http://localhost:5678"
log "  Wazuh API:     https://localhost:55000"
log "  Wazuh Indexer: https://localhost:9200"
log "  Wazuh Web UI:  https://localhost"
log "  YARAKIN:       http://localhost:8501"
log "  Bridge:        http://localhost:8765 (X-Bridge-Key in /home/dev/soc-lab/configs/bridge/bridge_secret)"
log ""
log "Credentials:"
log "  Wazuh indexer: $WAZUH_INDEXER_USER / $WAZUH_INDEXER_PASS"
log "  Wazuh manager:  $WAZUH_MANAGER_USER / $WAZUH_MANAGER_PASS"
log "  SOC-Victim VM:  $VM_USER / $VM_PASSWORD"
log "  OpenRouter:     ${OPENROUTER_API_KEY:0:20}..."
log ""
log "Next steps:"
log "  1. Open http://localhost:8888 - should see the SOC Dashboard"
log "  2. If YARAKIN analysis fails, edit $YARAKIN_DIR/.env with your OpenRouter key"
log "  3. If bridge auth fails, check /home/dev/soc-lab/configs/bridge/bridge_secret"
log "  4. VM credentials and Wazuh defaults are in 12-docs/HANDOFF-ADDENDUM-v3.1.md"
