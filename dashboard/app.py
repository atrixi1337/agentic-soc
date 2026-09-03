#!/usr/bin/env python3
"""
SOC Dashboard — single-screen view of every node + every alert.

Reads:
  - Wazuh indexer  (https://localhost:9200)  — cases, alerts, agent health
  - Wazuh manager  (https://localhost:55000) — agent status
  - n8n            (http://localhost:5678)   — workflow executions
  - Bridge         (http://localhost:8765)   — /health, /fetch
  - YARAKIN        (http://localhost:8501)   — /api/samples
  - Docker         (via socket)              — container status
  - VirtualBox     (VBoxManage)              — VM state

Writes (actions):
  - POST /api/cases/{id}/rerun   — re-trigger n8n workflow
  - POST /api/cases/{id}/fetch   — call bridge /fetch for the sample path
  - POST /api/health/refresh     — force a health re-check

WebSocket:
  - /ws  — pushes new cases + health changes in real time
"""
import asyncio
import base64
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
import urllib3
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration — reads from the same env vars the rest of the stack uses.
# ---------------------------------------------------------------------------
INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "SecretPassword")
MANAGER_URL = os.getenv("WAZUH_MANAGER_URL", "https://localhost:55000")
MANAGER_USER = os.getenv("WAZUH_MANAGER_USER", "wazuh-wui")
MANAGER_PASS = os.getenv("WAZUH_MANAGER_PASS", "MyS3cr37P450r.*-")
N8N_URL = os.getenv("N8N_URL", "http://localhost:5678")
BRIDGE_URL = os.getenv("BRIDGE_URL", "http://localhost:8765")
YARAKIN_URL = os.getenv("YARAKIN_URL", "http://localhost:8501")
VM_NAME = os.getenv("SOC_VM_NAME", "SOC-Victim")

DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8888"))

CASES_INDEX = "agentic-soc-cases"
ALERTS_INDEX = "wazuh-alerts-4.x-*"

# ---------------------------------------------------------------------------
# Cached state
# ---------------------------------------------------------------------------
_cache_lock = asyncio.Lock()
_cache: Dict[str, Any] = {
    "cases": [],
    "cases_total": 0,
    "health": {},
    "yarakin_samples": 0,
    "last_check": None,
    "last_error": None,
}
_last_case_ts: Optional[str] = None
_subscribers: List[WebSocket] = []


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def _auth(u: str, p: str) -> tuple:
    return (u, p)


async def _get_json(client: httpx.AsyncClient, url: str, auth: tuple = None, **kw) -> Any:
    try:
        r = await client.get(url, auth=auth, timeout=10.0, **kw)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}"}


async def _post_json(client: httpx.AsyncClient, url: str, body: dict, auth: tuple = None) -> Any:
    try:
        r = await client.post(url, json=body, auth=auth, timeout=10.0)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# Data fetchers
# ---------------------------------------------------------------------------
async def fetch_cases(client: httpx.AsyncClient, size: int = 50) -> List[dict]:
    """Pull the most recent cases from the indexer."""
    q = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }
    r = await client.post(
        f"{INDEXER_URL}/{CASES_INDEX}/_search",
        auth=_auth(INDEXER_USER, INDEXER_PASS),
        json=q,

    )
    if r.status_code != 200:
        return [{"_error": f"indexer {r.status_code}: {r.text[:200]}"}]
    data = r.json()
    hits = data.get("hits", {}).get("hits", [])
    cases = []
    for h in hits:
        src = h.get("_source", {})
        # Normalize mitre_techniques (may be string or list)
        mt = src.get("mitre_techniques")
        if isinstance(mt, str):
            try:
                mt = json.loads(mt)
            except Exception:
                mt = [mt] if mt else []
        cases.append({
            "doc_id": h.get("_id"),
            "alert_id": src.get("alert_id"),
            "timestamp": src.get("timestamp"),
            "agent_name": src.get("agent_name"),
            "agent_ip": src.get("agent_ip"),
            "rule_id": src.get("rule_id"),
            "rule_description": src.get("rule_description"),
            "threat_name": src.get("threat_name"),
            "ioc": src.get("ioc"),
            "tier3_verdict": src.get("tier3_verdict"),
            "behavior_summary": src.get("behavior_summary"),
            "mitre_techniques": mt or [],
            "yara_rule": src.get("yara_rule"),
            "final_score": src.get("final_score"),
            "case_status": src.get("case_status"),
            "ai_summary": src.get("ai_summary"),
            "ai_verdict": src.get("ai_verdict"),
            "ai_severity": src.get("ai_severity"),
        })
    return cases


async def fetch_case_by_alert_id(client: httpx.AsyncClient, alert_id: str) -> Optional[dict]:
    q = {"size": 1, "query": {"term": {"alert_id.keyword": alert_id}}}
    r = await client.post(
        f"{INDEXER_URL}/{CASES_INDEX}/_search",
        auth=_auth(INDEXER_USER, INDEXER_PASS),
        json=q,

    )
    if r.status_code != 200:
        return None
    hits = r.json().get("hits", {}).get("hits", [])
    if not hits:
        return None
    return hits[0].get("_source")


async def fetch_cases_total(client: httpx.AsyncClient) -> int:
    r = await client.get(
        f"{INDEXER_URL}/{CASES_INDEX}/_count",
        auth=_auth(INDEXER_USER, INDEXER_PASS),

    )
    if r.status_code != 200:
        return 0
    return r.json().get("count", 0)


async def fetch_wazuh_token(client: httpx.AsyncClient) -> Optional[str]:
    r = await client.get(
        f"{MANAGER_URL}/security/user/authenticate?raw=true",
        auth=_auth(MANAGER_USER, MANAGER_PASS),

    )
    if r.status_code != 200:
        return None
    return r.text.strip()


async def fetch_agent_status(client: httpx.AsyncClient) -> List[dict]:
    token = await fetch_wazuh_token(client)
    if not token:
        return [{"_error": "could not get Wazuh manager token"}]
    r = await client.get(
        f"{MANAGER_URL}/agents?status=active",
        headers={"Authorization": f"Bearer {token}"},

    )
    if r.status_code != 200:
        return []
    data = r.json().get("data", {}).get("affected_items", [])
    return [
        {
            "id": a.get("id"),
            "name": a.get("name"),
            "ip": a.get("ip"),
            "status": a.get("status"),
            "os": (a.get("os") or {}).get("name", ""),
            "version": a.get("version"),
            "lastKeepAlive": a.get("lastKeepAlive"),
        }
        for a in data
    ]


async def fetch_n8n_status(client: httpx.AsyncClient) -> dict:
    """Hit the n8n webhook path with a probe and check health endpoint."""
    out = {"reachable": False, "executions_recent": 0, "last_exec": None}
    try:
        r = await client.get(f"{N8N_URL}/healthz", timeout=5.0)
        out["reachable"] = r.status_code == 200
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


async def fetch_bridge_status(client: httpx.AsyncClient) -> dict:
    """Probe bridge with a harmless POST."""
    out = {"reachable": False}
    try:
        r = await client.post(
            f"{BRIDGE_URL}/fetch",
            json={"vm": "SOC-Victim", "path": "C:\\__probe__", "alert_id": "probe"},
            timeout=5.0,
        )
        out["reachable"] = True
        out["status_code"] = r.status_code
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        out["responds"] = body.get("ok") is False or body.get("stage") == "copyfrom"
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


async def fetch_yarakin_status(client: httpx.AsyncClient) -> dict:
    out = {"reachable": False, "samples": 0}
    try:
        r = await client.get(f"{YARAKIN_URL}/api/samples?limit=1", timeout=5.0)
        if r.status_code == 200:
            out["reachable"] = True
            data = r.json()
            out["samples"] = data.get("samples", [])
        else:
            out["status_code"] = r.status_code
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def fetch_container_status_sync() -> List[dict]:
    """Sync docker ps for container health (called from thread)."""
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=5,
        )
        lines = [l.split("\t", 1) for l in out.stdout.strip().splitlines() if "\t" in l]
        return [{"name": n, "status": s, "healthy": "Up" in s} for n, s in lines]
    except Exception as e:
        return [{"_error": f"{type(e).__name__}: {e}"}]


def fetch_vm_state_sync() -> dict:
    try:
        out = subprocess.run(
            ["VBoxManage", "showvminfo", VM_NAME, "--machinereadable"],
            capture_output=True, text=True, timeout=5,
        )
        state = "unknown"
        for line in out.stdout.splitlines():
            if line.startswith("VMState="):
                state = line.split("=", 1)[1].strip().strip('"')
        return {"name": VM_NAME, "state": state, "running": state == "running"}
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# Poller — refreshes cache every 3s and broadcasts to WS subscribers
# ---------------------------------------------------------------------------
async def poller(app: FastAPI):
    global _last_case_ts
    async with httpx.AsyncClient(verify=False) as client:
        while True:
            try:
                # Fetch everything in parallel
                cases_task = asyncio.create_task(fetch_cases(client, size=50))
                total_task = asyncio.create_task(fetch_cases_total(client))
                agents_task = asyncio.create_task(fetch_agent_status(client))
                n8n_task = asyncio.create_task(fetch_n8n_status(client))
                bridge_task = asyncio.create_task(fetch_bridge_status(client))
                yarakin_task = asyncio.create_task(fetch_yarakin_status(client))
                containers_task = asyncio.create_task(asyncio.to_thread(fetch_container_status_sync))
                vm_task = asyncio.create_task(asyncio.to_thread(fetch_vm_state_sync))

                cases, total, agents, n8n, bridge, yarakin, containers, vm = await asyncio.gather(
                    cases_task, total_task, agents_task, n8n_task,
                    bridge_task, yarakin_task, containers_task, vm_task,
                    return_exceptions=True,
                )

                health = {
                    "wazuh_indexer": {"reachable": isinstance(total, int) and total > -1,
                                       "cases_total": total if isinstance(total, int) else 0},
                    "wazuh_manager": {"reachable": isinstance(agents, list) and bool(agents) and not (isinstance(agents[0], dict) and "_error" in agents[0]),
                                      "agents": agents if isinstance(agents, list) else []},
                    "n8n": n8n if not isinstance(n8n, Exception) else {"error": str(n8n)},
                    "bridge": bridge if not isinstance(bridge, Exception) else {"error": str(bridge)},
                    "yarakin": yarakin if not isinstance(yarakin, Exception) else {"error": str(yarakin)},
                    "containers": containers if not isinstance(containers, Exception) else [],
                    "vm": vm if not isinstance(vm, Exception) else {"error": str(vm)},
                }

                # Detect new case(s) for WS push
                new_cases = []
                if isinstance(cases, list) and cases and not (len(cases) == 1 and "_error" in cases[0]):
                    for c in cases[:5]:
                        ts = c.get("timestamp")
                        if ts and ts != _last_case_ts:
                            if _last_case_ts is not None:
                                new_cases.append(c)
                            break
                    if cases:
                        _last_case_ts = cases[0].get("timestamp")

                async with _cache_lock:
                    _cache["cases"] = cases if isinstance(cases, list) else []
                    _cache["cases_total"] = total if isinstance(total, int) else 0
                    _cache["health"] = health
                    _cache["yarakin_samples"] = len(yarakin.get("samples", [])) if isinstance(yarakin, dict) else 0
                    _cache["last_check"] = datetime.now(timezone.utc).isoformat()
                    _cache["last_error"] = None

                # Broadcast to WS subscribers
                if new_cases and _subscribers:
                    msg = json.dumps({"type": "new_case", "cases": new_cases})
                    await _broadcast(msg)
                # Also push a heartbeat with health every cycle (for status dots)
                hb = json.dumps({"type": "health", "health": health,
                                  "cases_total": _cache["cases_total"]})
                await _broadcast(hb)

            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                print(f"[poller error] {type(e).__name__}: {e}\n{tb}", flush=True)
                async with _cache_lock:
                    _cache["last_error"] = f"{type(e).__name__}: {e}"
            await asyncio.sleep(3.0)


async def _broadcast(msg: str):
    if not _subscribers:
        return
    dead = []
    for ws in list(_subscribers):
        try:
            await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        try:
            _subscribers.remove(ws)
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="SOC Dashboard", version="1.0")
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


@app.on_event("startup")
async def _start():
    asyncio.create_task(poller(app))


@app.get("/")
async def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))


@app.get("/history.html")
async def history_page():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "history.html"))


@app.get("/api/cases")
async def api_cases(size: int = 50):
    async with _cache_lock:
        cached_cases = _cache["cases"]
        cached_total = _cache["cases_total"]
    # If the requested size is larger than what we have cached, fetch fresh from indexer
    if size > len(cached_cases) and size > 50:
        async with httpx.AsyncClient(verify=False) as client:
            fresh = await fetch_cases(client, size=size)
        return {"cases": fresh, "total": cached_total}
    return {"cases": cached_cases[:size], "total": cached_total}


# Case management - SQLite-backed comments, status, assignments
# ============================================================================
import sqlite3 as _sqlite3
import os as _os
import asyncio as _asyncio

CASE_DB_PATH = _os.getenv("CASE_DB_PATH", "/home/dev/soc-lab/configs/dashboard/soc_cases.db")
_case_db_lock = _asyncio.Lock()

def _get_case_db():
    """Get or create the case management SQLite DB."""
    conn = _sqlite3.connect(CASE_DB_PATH)
    conn.row_factory = _sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            author TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_status (
            alert_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'open',
            assignee TEXT,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    return conn


@app.get("/api/cases/{alert_id}/comments")
async def api_get_comments(alert_id: str):
    conn = _get_case_db()
    rows = conn.execute(
        "SELECT id, author, comment, created_at FROM case_comments WHERE alert_id=? ORDER BY id ASC",
        (alert_id,)
    ).fetchall()
    return {"comments": [dict(r) for r in rows]}


@app.post("/api/cases/{alert_id}/comments")
async def api_add_comment(alert_id: str, request: Request):
    body = await request.json()
    author = body.get("author", "analyst")
    comment = body.get("comment", "").strip()
    if not comment:
        return JSONResponse({"error": "comment is required"}, status_code=400)
    conn = _get_case_db()
    conn.execute(
        "INSERT INTO case_comments (alert_id, author, comment) VALUES (?, ?, ?)",
        (alert_id, author, comment)
    )
    conn.execute(
        "INSERT INTO case_events (alert_id, event_type, actor, details) VALUES (?, ?, ?, ?)",
        (alert_id, "comment", author, comment[:200])
    )
    conn.commit()
    return {"success": True}


@app.get("/api/cases/{alert_id}/status")
async def api_get_status(alert_id: str):
    conn = _get_case_db()
    row = conn.execute(
        "SELECT status, assignee, updated_at FROM case_status WHERE alert_id=?",
        (alert_id,)
    ).fetchone()
    if row:
        return dict(row)
    return {"status": "open", "assignee": None, "updated_at": None}


@app.post("/api/cases/{alert_id}/status")
async def api_set_status(alert_id: str, request: Request):
    body = await request.json()
    new_status = body.get("status", "open")
    if new_status not in ("open", "investigating", "contained", "closed", "false_positive"):
        return JSONResponse({"error": "invalid status"}, status_code=400)
    actor = body.get("author", "analyst")
    conn = _get_case_db()
    # Get old status
    old = conn.execute(
        "SELECT status FROM case_status WHERE alert_id=?", (alert_id,)
    ).fetchone()
    old_status = old["status"] if old else "open"
    # Upsert
    conn.execute("""
        INSERT INTO case_status (alert_id, status, updated_at) VALUES (?, ?, datetime('now'))
        ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at
    """, (alert_id, new_status))
    conn.execute(
        "INSERT INTO case_events (alert_id, event_type, actor, details) VALUES (?, ?, ?, ?)",
        (alert_id, "status_change", actor, f"{old_status} -> {new_status}")
    )
    conn.commit()
    return {"success": True, "old_status": old_status, "new_status": new_status}


@app.post("/api/cases/{alert_id}/assign")
async def api_assign(alert_id: str, request: Request):
    body = await request.json()
    assignee = body.get("assignee", "").strip()
    actor = body.get("author", "analyst")
    if not assignee:
        return JSONResponse({"error": "assignee is required"}, status_code=400)
    conn = _get_case_db()
    # Ensure status row exists
    conn.execute("""
        INSERT OR IGNORE INTO case_status (alert_id, status) VALUES (?, 'open')
    """, (alert_id,))
    conn.execute("""
        UPDATE case_status SET assignee=?, updated_at=datetime('now') WHERE alert_id=?
    """, (assignee, alert_id))
    conn.execute(
        "INSERT INTO case_events (alert_id, event_type, actor, details) VALUES (?, ?, ?, ?)",
        (alert_id, "assigned", actor, f"assigned to {assignee}")
    )
    conn.commit()
    return {"success": True, "assignee": assignee}


@app.get("/api/cases/{alert_id}/timeline")
async def api_get_timeline(alert_id: str):
    """Return a merged timeline of Wazuh alerts + local case events."""
    conn = _get_case_db()
    events = []
    # Local case events
    for r in conn.execute(
        "SELECT event_type, actor, details, created_at FROM case_events WHERE alert_id=? ORDER BY id ASC",
        (alert_id,)
    ).fetchall():
        events.append({
            "timestamp": r["created_at"],
            "source": "case",
            "type": r["event_type"],
            "actor": r["actor"],
            "details": r["details"],
        })
    # Wazuh alerts for this alert_id (from indexer)
    try:
        async with httpx.AsyncClient(verify=False) as client:
            q = {
                "size": 20,
                "query": {"term": {"alert_id.keyword": alert_id}},
                "sort": [{"timestamp": {"order": "asc"}}],
            }
            r = await client.post(
                f"{INDEXER_URL}/wazuh-alerts-4.x-*/_search",
                auth=_auth(INDEXER_USER, INDEXER_PASS),
                json=q,
            )
            if r.status_code == 200:
                hits = r.json().get("hits", {}).get("hits", [])
                for h in hits:
                    src = h["_source"]
                    events.append({
                        "timestamp": src.get("timestamp"),
                        "source": "wazuh",
                        "type": "alert",
                        "actor": "wazuh",
                        "details": f"Rule {src.get('rule',{}).get('id','?')}: {src.get('rule',{}).get('description','')[:120]} (level {src.get('rule',{}).get('level','?')})",
                    })
    except Exception:
        pass
    events.sort(key=lambda e: e.get("timestamp") or "")
    return {"events": events}


@app.get("/api/cases/{alert_id}")
async def api_case_detail(alert_id: str):
    """Fetch full case by alert_id (includes the large yara_rule etc.)."""
    async with httpx.AsyncClient(verify=False) as client:
        case = await fetch_case_by_alert_id(client, alert_id)
    if not case:
        return JSONResponse({"error": "not found"}, status_code=404)
    return case


# ============================================================================
# Alert correlation: group cases into incidents by agent+technique+time window
# ============================================================================
from datetime import datetime, timedelta
from collections import defaultdict

CORRELATION_WINDOW_MIN = 30  # Cases within 30min on same agent+technique cluster

def _correlate_cases(cases: list) -> list:
    """Group cases into incidents using agent+technique+time window clustering.
    
    Two cases cluster together if:
      - same agent_name AND
      - share at least one MITRE technique OR same threat family AND
      - within CORRELATION_WINDOW_MIN of each other
    """
    if not cases:
        return []
    
    # Parse timestamps and build adjacency
    parsed = []
    for c in cases:
        ts = c.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            continue
        parsed.append({"case": c, "dt": dt})
    
    if not parsed:
        return []
    
    # Sort by time
    parsed.sort(key=lambda x: x["dt"])
    
    # Union-find for clustering
    parent = list(range(len(parsed)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra
    
    for i in range(len(parsed)):
        for j in range(i + 1, len(parsed)):
            time_gap = (parsed[j]["dt"] - parsed[i]["dt"]).total_seconds() / 60
            if time_gap > CORRELATION_WINDOW_MIN:
                break
            ci, cj = parsed[i]["case"], parsed[j]["case"]
            # Same agent?
            if ci.get("agent_name") != cj.get("agent_name"):
                continue
            # Shared technique OR shared threat family?
            ti = set(ci.get("mitre_techniques") or [])
            tj = set(cj.get("mitre_techniques") or [])
            shared_tech = ti & tj
            same_threat = (
                ci.get("threat_name") and ci.get("threat_name") == cj.get("threat_name")
                and ci.get("threat_name") not in ("Unknown", "unknown", None, "")
            )
            if shared_tech or same_threat:
                union(i, j)
    
    # Build incidents from clusters
    clusters = defaultdict(list)
    for i in range(len(parsed)):
        clusters[find(i)].append(parsed[i])
    
    incidents = []
    for cluster_cases in clusters.values():
        if len(cluster_cases) == 1:
            continue  # Skip singletons - only show multi-case incidents
        case_list = [c["case"] for c in cluster_cases]
        first = case_list[0]
        verdicts = [c.get("tier3_verdict", "UNKNOWN") for c in case_list]
        techniques = set()
        for c in case_list:
            for t in (c.get("mitre_techniques") or []):
                techniques.add(t)
        threats = set()
        for c in case_list:
            t = c.get("threat_name")
            if t and t not in ("Unknown", "unknown"):
                threats.add(t)
        # Determine incident severity
        if "Malicious" in verdicts:
            severity = "critical"
        elif "Suspicious" in verdicts:
            severity = "high"
        else:
            severity = "medium"
        # Build kill chain narrative
        kill_chain = sorted(techniques)
        incidents.append({
            "incident_id": f"inc_{first.get('alert_id','')}",
            "agent_name": first.get("agent_name", "unknown"),
            "agent_ip": first.get("agent_ip", ""),
            "case_count": len(case_list),
            "alert_ids": [c.get("alert_id") for c in case_list],
            "first_seen": min(c.get("timestamp") for c in case_list),
            "last_seen": max(c.get("timestamp") for c in case_list),
            "severity": severity,
            "verdicts": verdicts,
            "verdict_counts": {v: verdicts.count(v) for v in set(verdicts)},
            "mitre_techniques": sorted(techniques),
            "threats": sorted(threats),
            "kill_chain": kill_chain,
            "max_score": max((c.get("final_score") or 0) for c in case_list),
        })
    
    # Sort by severity then by last_seen
    sev_order = {"critical": 0, "high": 1, "medium": 2}
    incidents.sort(key=lambda i: (sev_order.get(i["severity"], 3), i["last_seen"]), reverse=False)
    return incidents


@app.get("/api/incidents")
async def api_incidents(size: int = 200):
    """Correlate recent cases into incidents (multi-case clusters)."""
    async with httpx.AsyncClient(verify=False) as client:
        r = await client.post(
            f"{INDEXER_URL}/agentic-soc-cases/_search",
            auth=_auth(INDEXER_USER, INDEXER_PASS),
            json={
                "size": min(size, 500),
                "sort": [{"timestamp": {"order": "desc"}}],
                "_source": [
                    "alert_id", "timestamp", "agent_name", "agent_ip",
                    "tier3_verdict", "threat_name", "mitre_techniques",
                    "final_score", "case_status", "rule_id", "rule_description",
                    "yarakin_status", "yarakin_verdict", "yarakin_family",
                ],
            },
        )
        cases = [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
    incidents = _correlate_cases(cases)
    return {"incidents": incidents, "total": len(incidents), "cases_analyzed": len(cases)}


@app.get("/api/incidents/{incident_id}")
async def api_incident_detail(incident_id: str):
    """Fetch all cases belonging to a specific incident."""
    # incident_id format: inc_{first_alert_id}
    # We re-run the correlation and find the matching incident
    async with httpx.AsyncClient(verify=False) as client:
        r = await client.post(
            f"{INDEXER_URL}/agentic-soc-cases/_search",
            auth=_auth(INDEXER_USER, INDEXER_PASS),
            json={
                "size": 500,
                "sort": [{"timestamp": {"order": "desc"}}],
            },
        )
        cases = [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
    incidents = _correlate_cases(cases)
    for inc in incidents:
        if inc["incident_id"] == incident_id:
            # Fetch full details for each case in the incident
            detailed = []
            for aid in inc["alert_ids"]:
                case = await fetch_case_by_alert_id(client, aid)
                if case:
                    detailed.append(case)
            inc["cases"] = detailed
            return inc
    return JSONResponse({"error": "not found"}, status_code=404)


@app.get("/api/related/{alert_id}")
async def api_related_cases(alert_id: str):
    """Find cases related to the given alert_id (same agent + same technique within 1h)."""
    async with httpx.AsyncClient(verify=False) as client:
        # First fetch the target case
        target = await fetch_case_by_alert_id(client, alert_id)
        if not target:
            return JSONResponse({"error": "not found"}, status_code=404)
        agent = target.get("agent_name")
        techniques = target.get("mitre_techniques") or []
        # Search for related cases
        must = [{"term": {"agent_name.keyword": agent}}]
        if techniques:
            should = [{"terms": {"mitre_techniques": techniques}}]
        else:
            should = []
        r = await client.post(
            f"{INDEXER_URL}/agentic-soc-cases/_search",
            auth=_auth(INDEXER_USER, INDEXER_PASS),
            json={
                "size": 20,
                "query": {"bool": {"must": must + should, "must_not": [{"term": {"alert_id.keyword": alert_id}}]}},
                "sort": [{"timestamp": {"order": "desc"}}],
            },
        )
        related = [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
    return {"related": related, "count": len(related), "shared_techniques": techniques}


@app.get("/api/activity")
async def api_activity_feed(limit: int = 30):
    """Live pipeline activity feed — latest events from all sources."""
    events = []
    async with httpx.AsyncClient(verify=False) as client:
        # Recent cases
        r = await client.post(
            f"{INDEXER_URL}/agentic-soc-cases/_search",
            auth=_auth(INDEXER_USER, INDEXER_PASS),
            json={"size": limit, "sort": [{"timestamp": {"order": "desc"}}],
                  "_source": ["alert_id", "timestamp", "agent_name", "tier3_verdict", "threat_name", "rule_description", "yarakin_status", "yarakin_verdict", "yarakin_family"]},
        )
        for h in r.json().get("hits", {}).get("hits", []):
            src = h["_source"]
            ts = src.get("timestamp", "")
            verdict = src.get("tier3_verdict", "UNKNOWN")
            threat = src.get("threat_name") or src.get("rule_description", "event")
            agent = src.get("agent_name", "unknown")
            events.append({
                "ts": ts,
                "type": "case",
                "severity": "critical" if verdict == "Malicious" else "warning" if verdict == "Suspicious" else "info",
                "message": f"{verdict} on {agent}: {threat[:60]}",
                "alert_id": src.get("alert_id"),
                "verdict": verdict,
                "threat": threat,
            })
            # Add YARAKIN sub-event if completed
            if src.get("yarakin_status") == "completed":
                events.append({
                    "ts": ts,
                    "type": "yarakin",
                    "severity": "critical" if src.get("yarakin_verdict") == "malicious" else "info",
                    "message": f"YARAKIN: {src.get('yarakin_verdict','?')} — {src.get('yarakin_family','?')}",
                    "alert_id": src.get("alert_id"),
                })
    # Also pull case management events from SQLite
    conn = _get_case_db()
    for r in conn.execute(
        "SELECT alert_id, event_type, actor, details, created_at FROM case_events ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall():
        events.append({
            "ts": r["created_at"],
            "type": r["event_type"],
            "severity": "info",
            "message": f"{r['actor']} {r['event_type']}: {(r['details'] or '')[:60]}",
            "alert_id": r["alert_id"],
        })
    # Sort by timestamp descending
    events.sort(key=lambda e: e.get("ts", ""), reverse=True)
    return {"events": events[:limit], "total": len(events)}



@app.get("/api/health")
async def api_health():
    async with _cache_lock:
        return {
            "health": _cache["health"],
            "cases_total": _cache["cases_total"],
            "yarakin_samples": _cache["yarakin_samples"],
            "last_check": _cache["last_check"],
            "last_error": _cache["last_error"],
        }


@app.post("/api/cases/{alert_id}/fetch")
async def api_case_fetch(alert_id: str):
    """Re-trigger bridge /fetch for the IOC path in a case."""
    async with httpx.AsyncClient() as client:
        case = await fetch_case_by_alert_id(client, alert_id)
    if not case:
        return JSONResponse({"error": "case not found"}, status_code=404)
    ioc = case.get("ioc", "")
    # Heuristic: extract a file:_C:\... path
    path = None
    if "file:_" in ioc:
        # IOC format: "file:_C:\path; webfile:..."
        for part in ioc.split(";"):
            part = part.strip()
            if part.startswith("file:_"):
                path = part[len("file:_"):].strip()
                break
    if not path:
        return JSONResponse({"error": "no file path in IOC"}, status_code=400)
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BRIDGE_URL}/fetch",
            json={"vm": VM_NAME, "path": path, "alert_id": alert_id},
            timeout=60.0,
        )
    return {"bridge_response": r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text}


@app.post("/api/cases/{alert_id}/rerun")
async def api_case_rerun(alert_id: str):
    """Re-fire the n8n workflow webhook for this alert."""
    # The n8n webhook ID from the workflow is hardcoded in the Wazuh integration.
    # We just POST a synthetic alert to the n8n webhook.
    async with httpx.AsyncClient() as client:
        # Get the original alert
        q = {"size": 1, "query": {"term": {"_id": alert_id}}}
        r = await client.post(
            f"{INDEXER_URL}/{ALERTS_INDEX}/_search",
            auth=_auth(INDEXER_USER, INDEXER_PASS),
            json=q,
        )
        if r.status_code != 200:
            return JSONResponse({"error": f"indexer {r.status_code}"}, status_code=502)
        hits = r.json().get("hits", {}).get("hits", [])
        if not hits:
            return JSONResponse({"error": "alert not found"}, status_code=404)
        alert = hits[0]["_source"]
    # The n8n webhook URL is hardcoded in the Wazuh integration; we re-fire it.
    webhook_url = os.getenv("N8N_RERUN_WEBHOOK",
                             "http://n8n:5678/webhook/e1a80abd-e35b-45cb-958a-e57dad1e144b")
    async with httpx.AsyncClient() as client:
        r = await client.post(webhook_url, json=alert, timeout=10.0)
    return {"status": r.status_code, "body": r.text[:300]}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    _subscribers.append(ws)
    # Send initial state
    async with _cache_lock:
        await ws.send_text(json.dumps({
            "type": "init",
            "cases": _cache["cases"][:50],
            "health": _cache["health"],
            "cases_total": _cache["cases_total"],
        }))
    try:
        while True:
            # We don't expect messages from the client; receive_text() detects
            # disconnects. Use a timeout so a stuck client doesn't hang here.
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send a ping-like keepalive so the connection stays open
                await ws.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        pass
    except Exception:
        # Any other error (connection reset, etc.) — just clean up
        pass
    finally:
        try:
            _subscribers.remove(ws)
        except ValueError:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=DASHBOARD_PORT, log_level="info")


