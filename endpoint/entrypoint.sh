#!/bin/bash
# endpoint entrypoint: start auditd, enroll agent to wazuh.manager, run agentd.
set -e

echo "[endpoint] Starting auditd..."
service auditd start || (mkdir -p /var/log/audit && auditd &) || true

echo "[endpoint] Configuring Wazuh agent to point at wazuh.manager..."
/var/ossec/bin/agent-auth -m wazuh.manager -p 1515 || echo "[endpoint] agent-auth failed (manager may still be booting)"

echo "[endpoint] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start

echo "[endpoint] Endpoint telemetry active. Tailing agent log..."
tail -f /var/ossec/logs/ossec.log
