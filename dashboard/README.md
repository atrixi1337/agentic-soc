# SOC Dashboard

FastAPI + WebSocket dashboard for the Agentic SOC pipeline. Reads case data from the Wazuh indexer and provides case management, incident correlation, and real-time activity feed.

## Features

- **Live view**: Card-based case feed with verdict-colored borders, filter chips, search
- **Incidents view**: Auto-correlated clusters of cases (agent + MITRE technique + 30min window)
- **Activity feed**: Real-time event stream from Wazuh, YARAKIN, and case management
- **Case detail panel**: IOC, YARAKIN results, related cases, MITRE ATT&CK tags, behavior summary, YARA rule, timeline
- **Case management**: Status, assignee, comments (stored in SQLite)

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/cases?size=N` | List recent cases from Wazuh indexer |
| `GET /api/cases/{id}` | Full case detail |
| `GET /api/cases/{id}/comments` | List comments |
| `POST /api/cases/{id}/comments` | Add comment |
| `GET /api/cases/{id}/status` | Get case status |
| `POST /api/cases/{id}/status` | Update case status |
| `POST /api/cases/{id}/assign` | Assign case |
| `GET /api/cases/{id}/timeline` | Merged timeline (Wazuh + case events) |
| `POST /api/cases/{id}/fetch` | Re-fetch sample via bridge |
| `POST /api/cases/{id}/rerun` | Re-trigger n8n workflow |
| `GET /api/incidents` | Correlated incidents |
| `GET /api/incidents/{id}` | Incident detail with all cases |
| `GET /api/related/{id}` | Cases related by agent + technique |
| `GET /api/activity` | Live activity feed |
| `GET /api/health` | Health check for all services |
| `WS /ws` | WebSocket for real-time updates |

## Setup

```bash
# Install
pip install fastapi uvicorn[standard] websockets httpx aiosqlite

# Configure
export WAZUH_INDEXER_URL=https://localhost:9200
export WAZUH_INDEXER_USER=admin
export WAZUH_INDEXER_PASS=SecretPassword
export WAZUH_MANAGER_URL=https://localhost:55000
export WAZUH_MANAGER_USER=wazuh-wui
export WAZUH_MANAGER_PASS=MyS3cr37P450r.*-
export BRIDGE_URL=http://localhost:8765
export BRIDGE_KEY=br_xxx  # shared secret with bridge service
export CASE_DB_PATH=/var/lib/soc-dashboard/cases.db  # persistent path

# Run
uvicorn app:app --host 0.0.0.0 --port 8888
```

## Security notes

- Dashboard binds to `0.0.0.0:8888` by default. In production, bind to `127.0.0.1` and put behind a reverse proxy with auth.
- API endpoints `/fetch` and `/rerun` trigger bridge calls. Add auth/rate-limiting before exposing publicly.
- `CASE_DB_PATH` must be on persistent storage, not tmpfs.
