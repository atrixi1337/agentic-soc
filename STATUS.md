# STATUS — Agentic SOC (live lab write-up)

_Generated 2026-08-28 from direct inspection of the running host
(`/home/dev/soc-lab/agentic-soc`). All green checks below were verified live._

## TL;DR

The lab is **up and actively processing telemetry**. The Wazuh → n8n → AI enrichment
chain is functioning end-to-end on the Linux EDR endpoint. The two Windows victims are
powered off (expected). Falco is not running. One cosmetic REST quirk (Wazuh `/alerts`
endpoint 404 on query) does not affect alert flow.

## Topology actually running

The live lab is **four separate compose projects** sharing the `single-node_default`
Docker network (not the single packaged `docker-compose.yml` in this repo):

| Container | Project | Image | Status | Notes |
|---|---|---|---|---|
| `single-node-wazuh.manager-1` | single-node | wazuh/wazuh-manager:4.9.0 | Up 26h | API :55000, agents 1514/1515 |
| `single-node-wazuh.indexer-1` | single-node | wazuh/wazuh-indexer:4.9.0 | Up 26h | OpenSearch :9200, cluster **yellow** (1 node) |
| `single-node-wazuh.dashboard-1` | single-node | wazuh/wazuh-dashboard:4.9.0 | Up 26h | :443 → 5601, HTTP 302 (login) |
| `n8n` | n8n | n8nio/n8n:latest | Up 20h | :5678, health OK |
| `soc-linux-test` | linux-agent-test | local build | Up 26h | Linux EDR endpoint, FIM active |
| `yarakin-web-1` | yarakin | yarakin/toolbox:latest | Up 20h | :8501 web UI (HTTP 200) |

**Not running:** Falco (defined in repo compose, not launched in live lab).

## Component health

### Wazuh manager / indexer / dashboard — ✅
- Manager API authenticates (JWT via `wazuh-wui`). Version **4.9.0**.
- Ruleset loaded: **4,487** rules.
- Indexer: OpenSearch cluster **yellow** (normal for single-node; 2 unassigned replica
  shards). Admin auth works.
- Dashboard: reachable on :443, returns 302 to login (expected).

### n8n "Always-Enrich" pipeline — ✅
- Health: `{"status":"ok"}`.
- Workflows (from the n8n sqlite DB):
  - **"Agentic"** — `active=1`, **1,281 executions**.
  - **"YARAKIN Sample Intake"** — `active=1`, **57 executions**.
  - "Akml" — `active=0` (inactive).
- The repo's `n8n/workflows/always-enrich.json` is the source-of-truth pipeline
  definition (webhook path `soc-alert`, POST; nodes: Extract IOCs → Get Wazuh
  Timeline → VirusTotal Lookup → Merge Intel → Tier-3 Analyst Agent → Parse & Score →
  Write Case). It references OpenRouter + VirusTotal as enrichment providers.

### Yarakin AI toolbox — ✅
- Web UI on :8501 returns HTTP 200. Backed by the `yarakin/toolbox` image; used as the
  AI analyst surface alongside the n8n Tier-3 LLM step.

### Linux EDR endpoint (`soc-linux-test`) — ✅ ACTIVE
- Registered as agent **010 `soc-linux-test`** (Ubuntu), status **Active**,
  last keep-alive 2026-08-28 03:41Z.
- Wazuh `syscheckd` FIM scans cycling normally (Download/Desktop realtime monitoring).

### Windows victims — ⚠️ DISCONNECTED (expected)
- Agent **001 `win11-victim`** (192.168.10.124) — disconnected (last seen 2026-08-15).
- Agent **002 `SOC-Victim`** (192.168.10.123) — disconnected (last seen 2026-08-27 14:27Z).
- These are the Windows 11 test VMs; they are simply powered off right now. Per the
  known lab limitation, Wazuh v15 Sysmon eventchannel only forwards EID 1 + 10
  (process create + thread inject) to Wazuh; FIM covers file-create.

## Alert pipeline — ✅ FLOWING
Verified directly against the OpenSearch indexer (the REST `/alerts` endpoint is
currently 404-ing on query — see Known Issues — so the indexer is the source of truth):

- **8,293** total alerts indexed (`wazuh-alerts-*`).
- **1,514** alerts in the last 24h.
- Most recent alert: `2026-08-27T22:52:26Z` (SCA CIS benchmark summary).
- Enrollment: 3 agents reported (2 Windows 11 + 1 Ubuntu) in `/overview/agents`.

## Git state
- Repo: `github.com/atrixi1337/agentic-soc`, local `/home/dev/soc-lab/agentic-soc`.
- Branch `master` is in sync with `origin/master` (nothing unpushed).
- The GitHub **default branch is `main`** and contained only a `LICENSE` file (the
  "Initial commit") — that is why the repo *appears* empty in the browser. The real
  code lives on `master`. This README/STATUS push merges `master` into `main` so the
  project is visible on the default branch.

## Known issues / follow-ups
1. **Wazuh REST `/alerts` 404** — every query variant (`?q=`, `?sort=`, `?limit=`)
   returns 404. The `/manager/info`, `/agents`, `/overview/*` and indexer endpoints all
   work, and alerts are provably flowing, so this is a query-format/version quirk, not
   an outage. Fix: use the correct v4.9 query syntax (or read alerts from the indexer).
2. **No Falco running** — behavioral detection currently relies on auditd + Wazuh
   custom rules. Launch the Falco service from the repo compose if kernel-hook-level
   detection is wanted.
3. **Windows victims down** — power on the VMs and confirm re-enrollment if you want
   Windows-side telemetry.
4. **Secrets** — lab defaults (`SecretPassword`, `MyS3cr37P450r.*-`) are committed as
   placeholders; replace before any non-lab use. `.env` is gitignored.

## How to cold-start from zero (summary)
See `README.md` → "Cold start — the split multi-project lab" for full commands. In
short: bring up `single-node` (Wazuh), `n8n`, `linux-agent-test` (endpoint), and
`yarakin` in that order, confirm the manager API + endpoint enrollment, then import
`n8n/workflows/always-enrich.json` and set VirusTotal / OpenRouter credentials.
