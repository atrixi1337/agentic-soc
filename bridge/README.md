# Bridge

Python HTTP service that fetches samples from endpoints (Docker containers or VirtualBox VMs) and forwards them to the YARAKIN Sample Intake n8n webhook.

## Endpoints

- `POST /fetch` — Pull a file from an endpoint, base64-encode, POST to YARAKIN
- `POST /stage` — Stage a file (similar to /fetch, used by Wazuh active response)

## Security

- **Path allowlist**: Only `/testbed/`, `/tmp/`, `/var/tmp/` paths can be fetched. Path traversal (`..`) is blocked.
- **Shared-secret auth**: Set `BRIDGE_SECRET` env var. All requests must include `X-Bridge-Key: <secret>` header.
- **Config secrets**: Copy `bridge.json` to `bridge.local.json` and fill in `vm_password` and `wazuh_basic`. The `.gitignore` excludes local configs.

## Setup

```bash
# Install
pip install -r requirements.txt  # or just: no deps, stdlib only

# Configure
cp bridge.json bridge.local.json
# Edit bridge.local.json with your VM creds and Wazuh basic auth
echo -n "wazuh-wui:MyS3cr37P450r.*-" | base64  # generate wazuh_basic

# Run
BRIDGE_SECRET=$(openssl rand -hex 16) python3 bridge.py
```

## Docker endpoints

If `agent == "010"` (Linux Wazuh agent ID), the bridge uses `docker cp` to pull from the `soc-linux-test` container. For other agent IDs, it uses `VBoxManage guestcontrol copyfrom`.
