#!/bin/bash
# ============================================================================
# Agentic SOC — Cold Start Script
# ============================================================================
# Brings up the entire SOC lab from scratch on a fresh Ubuntu 22.04 host.
# Run as a non-root user with sudo access.
#
# What it does:
#   1. Installs system dependencies (Docker, Python, vbox, etc.)
#   2. Clones required repos (agentic-soc, NOVA_Project, YARAKIN)
#   3. Deploys the Wazuh single-node stack
#   4. Deploys the n8n workflow engine
#   5. Builds and starts the Linux endpoint container
#   6. Starts the bridge service
#   7. Starts the custom SOC dashboard
#   8. Starts YARAKIN
#   9. Loads Wazuh custom rules and decoders
#  10. Imports n8n workflows
#
# Usage:
#   chmod +x cold_start.sh
#   ./cold_start.sh                    # full install
#   ./cold_start.sh --skip-deps        # skip apt/docker install
#   ./cold_start.sh --no-vm            # skip VirtualBox VM setup
# ============================================================================

set -euo pipefail

# --- Config ----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BRIDGE_DIR="${BRIDGE_DIR:-/home/dev/soc-lab/sample-bridge}"
DASHBOARD_DIR="${DASHBOARD_DIR:-/home/dev/soc-lab/soc-dashboard}"
YARAKIN_DIR="${YARAKIN_DIR:-/home/dev/PROJECT/DeepSeek/yarakin}"
NOVA_DIR="${NOVA_DIR:-/home/dev/PROJECT/NOVA_Project}"
WAZUH_TMP_DIR="${WAZUH_TMP_DIR:-/tmp/wazuh-restore}"
BRIDGE_SECRET_FILE="${BRIDGE_SECRET_FILE:-/home/dev/soc-lab/configs/bridge/bridge_secret}"

DOCKER_NETWORK="single-node_default"
WAZUH_WEBHOOK="e1a80abd-e35b-45cb-958a-e57dad1e144b"

# --- Args ------------------------------------------------------------------
SKIP_DEPS=false
NO_VM=false
for arg in "$@"; do
  case $arg in
    --skip-deps) SKIP_DEPS=true ;;
    --no-vm) NO_VM=true ;;
    *) echo "Unknown arg: $arg"; exit 1 ;;
  esac
done

# --- Helpers ---------------------------------------------------------------
log()  { echo -e "\033[1;34m[cold-start]\033[0m $*"; }
warn() { echo -e "\033[1;33m[warn]\033[0m $*"; }
fail() { echo -e "\033[1;31m[fail]\033[0m $*"; exit 1; }

check_root() {
  if [ "$EUID" -eq 0 ]; then fail "Run as non-root user with sudo access"; fi
  if ! sudo -n true 2>/dev/null; then fail "sudo requires password; run with: sudo -v first"; fi
}

# --- Step 1: System dependencies -------------------------------------------
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
    warn "Log out and back in for docker group, or run: newgrp docker"
  fi
  docker --version || fail "Docker not available"

  if ! command -v docker compose &>/dev/null && ! docker compose version &>/dev/null; then
    log "Installing docker compose plugin..."
    sudo apt-get install -y -qq docker-compose-plugin
  fi
}

# --- Step 2: Clone repos (if not present) ----------------------------------
clone_repos() {
  log "Setting up repos..."
  mkdir -p /home/dev/soc-lab /home/dev/PROJECT
  cd /home/dev/soc-lab
  if [ ! -d "agentic-soc" ]; then
    log "Cloning agentic-soc..."
    git clone https://github.com/atrixi1337/agentic-soc.git
  fi
  cd /home/dev/PROJECT
  if [ ! -d "NOVA_Project" ]; then
    log "Cloning NOVA_Project..."
    git clone https://github.com/atrixi1337/NOVA_Project.git || warn "NOVA_Project clone failed"
  fi
  if [ ! -d "DeepSeek" ]; then
    warn "YARAKIN (DeepSeek) not found at $YARAKIN_DIR"
    warn "YARAKIN is local-only; you need to copy it from the Orico SSD or source"
  fi
}

# --- Step 3: Python deps for bridge + dashboard ----------------------------
install_python_deps() {
  log "Installing Python dependencies..."
  pip3 install --break-system-packages -q \
    fastapi "uvicorn[standard]" websockets httpx aiosqlite \
    pyyaml 2>&1 | tail -3
}

# --- Step 4: Wazuh single-node stack ---------------------------------------
deploy_wazuh() {
  log "Deploying Wazuh single-node stack..."
  # Use the wazuh-docker repo (official)
  WAZUH_DOCKER_DIR="/home/dev/PROJECT/wazuh-docker/single-node"
  if [ ! -d "$WAZUH_DOCKER_DIR" ]; then
    log "Cloning wazuh-docker..."
    sudo git clone --depth 1 --branch v4.9.0 https://github.com/wazuh/wazuh-docker.git /home/dev/PROJECT/wazuh-docker || fail "Wazuh clone failed"
  fi
  cd "$WAZUH_DOCKER_DIR"
  # Generate certs
  if [ -f "generate-indexer-certs.yml" ]; then
    sudo docker compose -f generate-indexer-certs.yml run --rm generator
  fi
  # Start the stack
  sudo docker compose up -d
  log "Waiting for Wazuh to be ready..."
  for i in {1..60}; do
    if curl -sk -m 3 "https://localhost:9200/_cluster/health" 2>/dev/null | grep -q "green\|yellow"; then
      log "Wazuh indexer is ready"
      break
    fi
    sleep 5
  done

  # Deploy custom rules and decoders
  if [ -d "$REPO_DIR/config/manager" ]; then
    log "Loading custom rules and decoders..."
    docker exec -u root single-node-wazuh.manager-1 sh -c "
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
    docker exec -u root single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
  fi
}

# --- Step 5: n8n -----------------------------------------------------------
deploy_n8n() {
  log "Deploying n8n..."
  cd "$REPO_DIR/../n8n" 2>/dev/null || mkdir -p /home/dev/soc-lab/n8n
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
  # Import workflows
  if [ -d "$REPO_DIR/n8n-workflows" ]; then
    log "Importing n8n workflows..."
    sudo docker exec n8n n8n import:workflow --input=/tmp/workflows.json 2>&1 | tail -3 || warn "Workflow import failed"
  fi
}

# --- Step 6: Linux endpoint container --------------------------------------
deploy_endpoint() {
  log "Building and starting Linux endpoint container..."
  cd "$REPO_DIR/endpoint"
  sudo docker build -t linux-agent-test .
  # Update /tmp/wazuh-restore with the bind-mount source
  sudo mkdir -p "$WAZUH_TMP_DIR/manager" "$WAZUH_TMP_DIR/wazuh_cluster"
  sudo cp "$REPO_DIR/config/manager/local_rules.xml" "$WAZUH_TMP_DIR/manager/" 2>/dev/null || true
  sudo cp "$REPO_DIR/config/manager/wazuh_manager.conf" "$WAZUH_TMP_DIR/wazuh_cluster/" 2>/dev/null || true
  # Start container on the Wazuh network
  sudo docker run -d --name soc-linux-test \
    --network "$DOCKER_NETWORK" \
    -v "$REPO_DIR/endpoint/ossec.conf:/var/ossec/etc/ossec.conf:ro" \
    linux-agent-test || warn "Endpoint container start failed"
}

# --- Step 7: Bridge service ------------------------------------------------
deploy_bridge() {
  log "Starting bridge service..."
  if [ ! -d "$BRIDGE_DIR" ]; then
    log "Bridge not found at $BRIDGE_DIR; skipping"
    return
  fi
  # Read or generate bridge secret
  if [ -f "$BRIDGE_SECRET_FILE" ]; then
    BRIDGE_SECRET=$(cat "$BRIDGE_SECRET_FILE")
  else
    BRIDGE_SECRET="br_$(openssl rand -hex 16)"
    mkdir -p "$(dirname "$BRIDGE_SECRET_FILE")"
    echo "$BRIDGE_SECRET" > "$BRIDGE_SECRET_FILE"
    chmod 600 "$BRIDGE_SECRET_FILE"
    log "Generated new bridge secret: $BRIDGE_SECRET"
  fi
  # Start bridge as a background process
  pkill -f bridge.py 2>/dev/null || true
  sleep 1
  nohup env BRIDGE_SECRET="$BRIDGE_SECRET" python3 "$BRIDGE_DIR/bridge.py" > /tmp/bridge.log 2>&1 &
  sleep 2
  if curl -sf -m 3 "http://localhost:8765/" 2>/dev/null; then
    log "Bridge is running"
  else
    warn "Bridge may not be ready yet"
  fi
}

# --- Step 8: Dashboard ------------------------------------------------------
deploy_dashboard() {
  log "Starting SOC dashboard..."
  if [ ! -d "$DASHBOARD_DIR" ]; then
    log "Dashboard not found at $DASHBOARD_DIR; skipping"
    return
  fi
  # Set persistent DB path
  export CASE_DB_PATH="/home/dev/soc-lab/configs/dashboard/soc_cases.db"
  mkdir -p "$(dirname "$CASE_DB_PATH")"
  pkill -f "python3 app.py" 2>/dev/null || true
  sleep 1
  cd "$DASHBOARD_DIR"
  nohup python3 app.py > /tmp/dashboard.log 2>&1 &
  sleep 3
  if curl -sf -m 3 "http://localhost:8888/" 2>/dev/null; then
    log "Dashboard is running"
  else
    warn "Dashboard may not be ready yet"
  fi
}

# --- Step 9: YARAKIN -------------------------------------------------------
deploy_yarakin() {
  log "Starting YARAKIN..."
  if [ ! -d "$YARAKIN_DIR" ]; then
    warn "YARAKIN not found at $YARAKIN_DIR; skipping"
    warn "Copy YARAKIN from the Orico SSD or source repo first"
    return
  fi
  pkill -f "uvicorn.*yarakin" 2>/dev/null || true
  sleep 1
  cd "$YARAKIN_DIR"
  nohup python3 -m uvicorn yarakin.web:app --host 0.0.0.0 --port 8501 > /tmp/yarakin.log 2>&1 &
  sleep 3
  if curl -sf -m 3 "http://localhost:8501/" 2>/dev/null; then
    log "YARAKIN is running"
  else
    warn "YARAKIN may not be ready yet"
  fi
}

# --- Step 10: VirtualBox VMs (optional) ------------------------------------
deploy_vms() {
  if [ "$NO_VM" = true ]; then
    log "Skipping VM setup (--no-vm)"
    return
  fi
  log "VirtualBox VMs..."
  if ! command -v VBoxManage &>/dev/null; then
    warn "VirtualBox not installed; skipping VM setup"
    return
  fi
  if VBoxManage showvminfo "SOC-Victim" &>/dev/null; then
    log "SOC-Victim VM exists; starting it..."
    VBoxManage startvm "SOC-Victim" --type headless 2>&1 | head -2 || true
  else
    warn "SOC-Victim VM not found; create it manually and run windows-ar/SOC-SETUP.bat"
  fi
}

# --- Main ------------------------------------------------------------------
log "=== Agentic SOC Cold Start ==="
check_root

if [ "$SKIP_DEPS" = false ]; then
  install_deps
fi

clone_repos
install_python_deps
deploy_wazuh
deploy_n8n
deploy_endpoint
deploy_bridge
deploy_dashboard
deploy_yarakin
deploy_vms

log ""
log "=== Cold start complete ==="
log "Dashboard:     http://localhost:8888"
log "n8n:           http://localhost:5678"
log "Wazuh API:     https://localhost:55000"
log "Wazuh Indexer: https://localhost:9200"
log "YARAKIN:       http://localhost:8501"
log "Bridge:        http://localhost:8765"
log ""
log "Bridge secret: $(cat "$BRIDGE_SECRET_FILE" 2>/dev/null || echo 'not set')"
log ""
log "VM credentials: see HANDOFF-ADDENDUM-v3.1.md in the repo"
