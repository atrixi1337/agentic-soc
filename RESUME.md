# RESUME NOTES — Agentic SOC boot (saved end of day 1)

Repo: https://github.com/atrixi1337/agentic-soc  (local: /home/dev/soc-lab/agentic-soc)
Stack is docker-compose down. osint-hub container left running (separate project).

## STATUS (verified working)
- wazuh.indexer   : UP, cluster GREEN, admin:SecretPassword authenticates
- wazuh.manager   : UP, all daemons run, API on 55000 (JWT via /security/user/authenticate?raw=true)
- n8n             : UP on :5678 (HTTP 200)
- wazuh.dashboard : UP but 503 "not ready" — BLOCKED on missing `.wazuh` index (TRAP 7)
- linux-endpoint, falco : NOT yet booted

## UNCOMMITTED CHANGES (must commit+push before resuming)
git status shows modified: config/certs.yml, config/manager/ossec.conf,
config/wazuh_dashboard/opensearch_dashboards.yml, config/wazuh_dashboard/wazuh.yml,
config/wazuh_indexer/internal_users.yml, config/wazuh_indexer/wazuh.indexer.yml,
docker-compose.yml, generate-certs.yml  + new: config/manager/ar.conf, config/manager/patches/wazuh-control

## TOMORROW — RESUME STEPS
1. `cd /home/dev/soc-lab/agentic-soc && docker compose up -d wazuh.indexer wazuh.manager wazuh.dashboard n8n`
2. Close dashboard 503 (TRAP 7): indexer already GREEN, so just
   `curl -sk -u admin:SecretPassword -X PUT https://localhost:9200/.wazuh -H 'Content-Type: application/json' -d '{"settings":{"index":{"number_of_shards":1,"number_of_replicas":0}}}'`
   then `docker restart agentic-soc-wazuh.dashboard-1`; verify `curl -s http://localhost:443/api/status` shows version.
   NOTE: if indexer volume was wiped on `compose down`, re-run securityadmin.sh (TRAP 2) after up.
3. Boot endpoint: `docker compose up -d linux-endpoint` (builds from endpoint/Dockerfile; needs auditd + enroll to wazuh.manager). Watch for enrollment.
4. Fire EICAR + `curl|sh` test on endpoint; confirm alert hits n8n webhook (n8n execution list).
5. Import n8n workflow n8n/workflows/always-enrich.json; set VirusTotal + OpenRouter creds in n8n.
6. Commit all boot fixes + push.

## DEFAULT CREDS (lab)
- indexer/opensearch/dashboard: admin / SecretPassword
- manager API: wazuh-wui / MyS3cr37P450r.*-
- n8n webhook: http://n8n:5678/webhook/soc-alert  (manager integration, level>=10)

## DETAILED TRAP FIXES
Full procedure saved as Hermes skill `wazuh-soc-boot` (security category).
