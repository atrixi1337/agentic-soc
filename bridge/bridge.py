#!/usr/bin/env python3
"""Sample-fetch bridge for the Agentic SOC lab.

n8n -> POST /fetch {vm, path, alert_id}  ->  VBoxManage guestcontrol copyfrom
     -> base64 -> POST to n8n YARAKIN-sample-intake webhook.
Config: bridge.json next to this file.
"""
import json, subprocess, base64, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(HERE, "bridge.json")))
FETCH_DIR = CFG.get("fetch_dir", "/home/dev/soc-lab/samples-fetched")
os.makedirs(FETCH_DIR, exist_ok=True)


def log(msg):
    print(f"[bridge] {msg}", flush=True)


def run_vbox(args):
    p = subprocess.run(["VBoxManage", "guestcontrol"] + args,
                       capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


LINUX_AGENT = str(CFG.get("linux_agent_id", "010"))
LINUX_CONTAINER = CFG.get("linux_container", "soc-linux-test")


def _fetch_from_container(path, local):
    p = subprocess.run(["docker", "cp", f"{LINUX_CONTAINER}:{path}", local],
                       capture_output=True, text=True, timeout=120)
    return p.returncode


# Security: path allowlist — only /testbed, /tmp, /var/tmp paths are fetchable.
# This prevents the bridge from reading sensitive files like /etc/shadow,
# Wazuh agent keys, etc., when called by the n8n workflow.
ALLOWED_PATH_PREFIXES = ("/testbed/", "/tmp/", "/var/tmp/")

def _check_path_allowed(path):
    """Reject paths outside the allowed prefixes. Prevents arbitrary file read."""
    # Resolve any .. or symlinks would need realpath; for now just check the prefix.
    if not path:
        return False, "empty path"
    if ".." in path.split("/"):
        return False, "path traversal not allowed"
    if not any(path.startswith(p) for p in ALLOWED_PATH_PREFIXES):
        return False, f"path not in allowlist (allowed: {ALLOWED_PATH_PREFIXES})"
    return True, None


def handle_fetch(req):
    vm = req.get("vm") or CFG["default_vm"]
    user = CFG["vm_user"]
    pw = CFG["vm_password"]
    path = req["path"]
    alert_id = str(req.get("alert_id") or "no-alert")
    agent = str(req.get("agent") or CFG.get("agent", "002"))

    # Security gate: enforce path allowlist
    allowed, err = _check_path_allowed(path)
    if not allowed:
        log(f"REJECTED fetch: path={path} reason={err}")
        return {"ok": False, "stage": "allowlist", "error": err}

    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in os.path.basename(path)) or "sample.bin"
    local = os.path.join(FETCH_DIR, f"{alert_id}_{safe}")

    # Linux endpoint: pull straight out of the docker container (no VM/AR dance)
    if agent == LINUX_AGENT:
        rc = _fetch_from_container(path, local)
        if rc != 0 or not os.path.exists(local):
            return {"ok": False, "stage": "docker_cp", "error": "docker cp failed"}
    else:
        rc, out, err = run_vbox([vm, "copyfrom", path, local,
                                 "--username", user, "--password", pw])
        if rc != 0 or not os.path.exists(local):
            return {"ok": False, "stage": "copyfrom", "error": err or out or "unknown"}

    size = os.path.getsize(local)
    if size > CFG.get("max_bytes", 10 * 1024 * 1024):
        return {"ok": False, "stage": "size", "error": f"{size} bytes exceeds cap"}

    b64 = base64.b64encode(open(local, "rb").read()).decode()
    import hashlib
    sha = hashlib.sha256(base64.b64decode(b64)).hexdigest()

    body = json.dumps({
        "alert_id": alert_id,
        "path": path,
        "sha256": sha,
        "size": size,
        "data_b64": b64,
    }).encode()

    r = urllib.request.Request(CFG["intake_webhook"], data=body,
                               headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=60) as resp:
        n8n_reply = resp.read().decode()[:200]

    log(f"fetched {path} ({size}B, sha {sha[:12]}) alert={alert_id} -> {n8n_reply}")
    return {"ok": True, "sha256": sha, "size": size, "n8n": n8n_reply}


def handle_stage(req):
    """Write pending_fetch.json rendezvous file onto the VM, then trigger the
    SYSTEM shim via Wazuh AR so it can recover a Defender-quarantined file."""
    vm = req.get("vm") or CFG["default_vm"]
    user = CFG["vm_user"]
    pw = CFG["vm_password"]
    path = req["path"]
    alert_id = str(req.get("alert_id") or "no-alert")
    dst = "C:\\Users\\victim\\soc-ar\\pending_fetch.json"

    payload = json.dumps({"path": path, "alert_id": alert_id, "staged": True})
    local = "/tmp/pending_fetch.json"
    with open(local, "w") as f:
        f.write(payload)

    # write to the VM (overwrite via rm+copyto)
    if os.path.exists(dst):
        run_vbox([vm, "rm", dst, "--username", user, "--password", pw])
    rc, out, err = run_vbox([vm, "copyto", local, dst,
                             "--username", user, "--password", pw])
    if rc != 0:
        return {"ok": False, "stage": "copyto", "error": err or out}

    # trigger the shim over the Wazuh API (fresh bearer)
    try:
        import ssl
        ctx = ssl._create_unverified_context()  # self-signed Wazuh cert
        import urllib.request as ur
        auth_s = ur.Request(CFG["wazuh_api"] + "/security/user/authenticate?raw=true",
                            headers={"Authorization": "Basic " + CFG["wazuh_basic"]})
        with ur.urlopen(auth_s, timeout=15, context=ctx) as r:
            token = r.read().decode().strip()
        req2 = ur.Request(CFG["wazuh_api"] + f"/active-response?agents_list={CFG.get('agent','002')}",
                          data=json.dumps({"command": "!soc-fetch-sample.exe", "arguments": []}).encode(),
                          headers={"Authorization": "Bearer " + token,
                                   "Content-Type": "application/json"}, method="PUT")
        with ur.urlopen(req2, timeout=30, context=ctx) as r2:
            body = r2.read().decode()
        log(f"staged {path} (alert={alert_id}) and dispatched AR -> {body[:120]}")
        return {"ok": True, "ar": body[:200]}
    except Exception as e:  # noqa: BLE001
        log(f"stage AR error: {e}")
        return {"ok": False, "stage": "ar_dispatch", "error": str(e)}


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True})
        else:
            self._json(404, {"ok": False})

    def do_POST(self):
        # Shared-secret auth: require X-Bridge-Key header if BRIDGE_SECRET is set.
        bridge_secret = os.getenv("BRIDGE_SECRET", "")
        if bridge_secret:
            provided = self.headers.get("X-Bridge-Key", "")
            if provided != bridge_secret:
                self._json(401, {"ok": False, "error": "invalid or missing X-Bridge-Key"})
                return
        if self.path == "/fetch":
            try:
                length = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(length) or b"{}")
                result = handle_fetch(req)
                self._json(200 if result.get("ok") else 500, result)
            except Exception as e:  # noqa: BLE001
                log(f"ERROR /fetch: {e}")
                self._json(500, {"ok": False, "error": str(e)})
            return
        if self.path == "/stage":
            try:
                length = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(length) or b"{}")
                result = handle_stage(req)
                self._json(200 if result.get("ok") else 500, result)
            except Exception as e:  # noqa: BLE001
                log(f"ERROR /stage: {e}")
                self._json(500, {"ok": False, "error": str(e)})
            return
        self._json(404, {"ok": False})

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else CFG.get("port", 8765)
    log(f"listening on :{port}, fetching from VM '{CFG['default_vm']}'")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
