# CarThing SOC — Home Lab Monitoring Backend

A **read-only, lightweight FastAPI backend** designed to turn a repurposed Spotify Car Thing into a home-lab security console. Includes a browser dashboard for testing while the Car Thing firmware/UI is built later.

**Current status:** Backend MVP complete; the actual Car Thing firmware client/driver is **not included**. Hardware connectivity and on-device performance have not been tested. All monitors return `unavailable`/`disabled` rather than presenting pretend readings when a source is missing.

## Monitors

| Source | Data | Configuration |
|---|---|---|
| Ubuntu host | CPU, RAM, root disk %, free space, uptime | Works when installed on the **host OS** |
| Docker | Running/stopped/missing containers and configured health status | Docker socket must be readable |
| Tailscale | Backend state, online status, tailnet IPs and peer count | `tailscale status --json` available |
| Wazuh | Recent alerts with timestamp, description, agent, level and source IP | Docker Manager JSON alerts, locally readable `alerts.json`, **or** HTTPS indexer query |
| Ubuntu auth log | Recent failed-login messages (optional) | Readable local log path |

**Not provided:** automatic incident response, restarts, automatic rule creation, or a native Car Thing app. These would require a separate, safely designed second phase.

## 1. Install on your Ubuntu/CasaOS server (native install)

Python 3.10+ required. Native install is important: if run *inside a Docker container*, CPU/RAM and Tailscale may represent the container instead of the Ubuntu host.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip
# Unzip the downloaded CarThing-SOC-Backend.zip and enter its folder
cd CarThing-SOC-Backend
bash scripts/setup.sh
```

The setup script creates `.venv`, installs packages, copies `.env.example` to `.env` **if missing**, generates a random 43-character API key, and makes `.env` readable by your user only. It will not overwrite an existing `.env`.

To start:

```bash
bash scripts/run.sh
```

It listens on `127.0.0.1:8765` by default. From the server itself, open:

- `http://127.0.0.1:8765/` — browser preview; enter your API key (from `.env`).
- `http://127.0.0.1:8765/healthz` — simple liveness check (does not report data source health).

The backend requires a valid `X-API-Key` header for **all monitoring endpoints**.

### Access the dashboard from your Windows PC, over Tailscale

If your Ubuntu server is already on Tailscale, enable **Tailscale Serve** on the server:

```bash
sudo tailscale serve --bg 8765
sudo tailscale serve status
```

Tailscale prints the private `https://<your-machine>.<your-tailnet>.ts.net` URL. Visit that URL from your Windows PC while connected to the **same tailnet**, and enter your API key. Tailscale Serve provides encrypted access within your tailnet (it is *not* Tailscale Funnel). Depending on your tailnet settings, HTTPS certificates may need enabling.

> Do **not** port-forward the API on your router, expose it with Funnel, or configure a wildcard CORS origin. Keep `CARTHING_HOST=127.0.0.1`; `tailscale serve` proxies to localhost.

### Example API calls

Read your API key directly from your local `.env` without pasting it into a public transcript:

```bash
# Run on the Ubuntu server from the project directory.
CARTHING_API_KEY="$(sed -n 's/^CARTHING_API_KEY=//p' .env)"
curl -sS -H "X-API-Key: $CARTHING_API_KEY" http://127.0.0.1:8765/api/v1/overview | python3 -m json.tool
curl -sS -H "X-API-Key: $CARTHING_API_KEY" http://127.0.0.1:8765/api/v1/alerts?limit=5 | python3 -m json.tool
```

The overview is the main endpoint the future Car Thing client will poll approximately every 10–15 seconds.

## 2. Turn on your existing monitors

Edit `.env` (`nano .env`), save, and **restart the app** when changing configuration.

### Docker / CasaOS / osTicket / Jellyfin

The backend uses the local Docker socket and runs without `sudo`. If Docker is unavailable or permission is denied, the API will clearly report `unavailable`.

```bash
# Find your precise container names
sudo docker ps -a --format '{{.Names}}'
```

Optionally set `MONITORED_CONTAINERS` to **exact** container names in `.env`:

```ini
MONITORED_CONTAINERS=jellyfin,osticket,mariadb
```

Leave it blank to show up to 30 containers alphabetically.

**Security note:** membership in the `docker` group or direct access to `/var/run/docker.sock` effectively grants root-level privileges to the backend process. The API contains no mutating Docker actions, but a compromised process with socket access can still control Docker. For a security-focused deployment, favor a Docker socket proxy with read-only endpoints or a dedicated restricted data collector. Do not blindly run this application as root. See Docker's official daemon/socket security guidance.

If you accept this tradeoff **in your isolated lab**, the usual Ubuntu setup is to add your user to the docker group (log out/in afterward):

```bash
sudo usermod -aG docker "$USER"
```

### Tailscale

No extra configuration. It runs `tailscale status --json`, which must be installed and available to the backend user on the Ubuntu host. If disconnected, the backend reports this rather than hiding it.

### Wazuh alerts — choose **one** method

**A. Wazuh Manager running inside Docker on the monitored host (CarThing SOC v1.1):**

If the Docker services already appear in the CarThing SOC dashboard, the backend likely has Docker socket access. Set:

```ini
WAZUH_MODE=docker
WAZUH_DOCKER_CONTAINER=single-node-wazuh.manager-1
WAZUH_ALERTS_FILE=/var/ossec/logs/alerts/alerts.json
ALERT_WINDOW_HOURS=24
```

The backend runs a read-only `tail -n 2000` command inside the chosen Wazuh Manager container every cache interval and parses the last 2 MB of records. It does **not** create or modify Wazuh alerts, require Wazuh credentials, or need direct access to Docker's protected host volume paths. It reads only recent alerts. The default time window is the last 24 hours; for a low-traffic lab, consider `ALERT_WINDOW_HOURS=168` (7 days).

**Security:** Access to Docker socket is effectively root on the host even though the API routes are read-only. Keep the service restricted to localhost/Tailscale, protect the API key, and do not grant Docker access to untrusted users.

**B. Wazuh manager is installed directly on this Ubuntu machine:**

Set:

```ini
WAZUH_MODE=file
WAZUH_ALERTS_FILE=/var/ossec/logs/alerts/alerts.json
```

The backend user needs read permission to the existing file. Don't make the alert file world-readable or run the whole backend as root. For Wazuh running in a separate Docker container, the path must be made accessible to the host/user safely, or use Option B.

**C. Wazuh is on another machine or uses a remote Indexer (recommended for remote):**

Set:

```ini
WAZUH_MODE=indexer
WAZUH_INDEXER_URL=https://YOUR-WAZUH-INDEXER-IP:9200
WAZUH_INDEXER_USER=YOUR_READ_ONLY_USER
WAZUH_INDEXER_PASSWORD=YOUR_PASSWORD
WAZUH_CA_BUNDLE=/path/to/your/wazuh-indexer-ca.pem
```

Use a **read-only indexer role** with search permission scoped to `wazuh-alerts-*`; do not use Wazuh's `admin` credentials for a long-running dashboard. TLS verification stays on; point `WAZUH_CA_BUNDLE` at a trusted Wazuh indexer CA if it uses a private certificate. The indexer must be reachable through your private LAN/Tailscale. This queries `POST /wazuh-alerts-*/_search` using the Wazuh Indexer / OpenSearch API, not the Wazuh Manager API.

Recent alerts are searched within `ALERT_WINDOW_HOURS=24` by default, with the 15 newest returned in the combined overview. **Counts are only for the returned alerts**, not all alerts in the index/window. The local-file method reads at most the last ~2 MB of the alerts file and may miss earlier matching events on very busy systems.

Reference: https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html

### SSH authentication failures (optional)

Ubuntu's `/var/log/auth.log` is often protected. If you safely give the backend user read access, set:

```ini
AUTH_LOG_PATH=/var/log/auth.log
```

It returns the number of matching failures in up to the **last 1,000 log lines**, not the number of failures within a time interval. Don't give the application broad privileged access for this feature; leave disabled until you have a safe log feed.

## 3. API for the Car Thing display

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Public liveness ping (no telemetry) |
| `GET` | `/api/v1/overview` | All monitors in one JSON response (best for Car Thing) |
| `GET` | `/api/v1/server` | Host health |
| `GET` | `/api/v1/docker` | Docker containers |
| `GET` | `/api/v1/tailscale` | Tailscale status |
| `GET` | `/api/v1/alerts?limit=15` | Wazuh alerts; limit 1–50 |
| `GET` | `/api/v1/auth` | Optional SSH auth failure snapshot |

All `/api/v1/` calls require `X-API-Key`. Allowed CORS origins are **none** by default; specify exact trusted origins in `.env` only if a cross-origin on-device app truly needs them. Caching is set to 10 seconds; this isn't a low-latency intrusion detection mechanism.

Example response format (illustrative, not real telemetry):

```json
{
  "schema_version": 1,
  "generated_at": "2026-10-19T05:00:00+00:00",
  "server": {"status":"ok", "cpu_percent":12.3, "ram_percent":54.0, "disk_percent":67.1},
  "docker": {"status":"ok", "running":2, "total":2, "containers":[{"name":"jellyfin","state":"running","health":"not_configured"}]},
  "tailscale": {"status":"ok", "backend_state":"Running", "connected":true, "peer_count":2, "tailscale_ips":["100.x.x.x"]},
  "wazuh": {"status":"disabled", "alerts":[], "returned":0, "severity_in_returned":{}},
  "auth": {"status":"disabled", "recent_failures":null}
}
```

## 4. Optional auto-start with systemd

To run unattended, create a *user-specific* systemd service. Replace `YOUR_USER` and `YOUR_PATH` and avoid root ownership:

```ini
# /etc/systemd/system/carthing-soc.service
[Unit]
Description=CarThing SOC Backend
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=YOUR_USER
WorkingDirectory=YOUR_PATH/CarThing-SOC-Backend
ExecStart=YOUR_PATH/CarThing-SOC-Backend/.venv/bin/python -m app.run
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now carthing-soc
sudo systemctl status carthing-soc
```

Do not start the service until `bash scripts/run.sh` runs successfully for your Ubuntu user. To review logs: `journalctl -u carthing-soc -n 50 --no-pager`.

## 5. Run automated tests

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Tests use mocked data and do not access your server. **Passing tests does not establish live Wazuh/Docker or Car Thing hardware compatibility**; test each source on the actual host.

## Project structure

```text
CarThing-SOC-Backend/
├── .env.example       # safe template; real .env is NOT bundled
├── .gitignore
├── app/
│   ├── config.py      # settings and validation
│   ├── collectors.py  # host, Docker, Tailscale, Wazuh, auth log readers
│   ├── main.py        # authenticated REST endpoints + cache
│   ├── run.py         # starts server with .env host/port
│   └── static/index.html # live browser dashboard preview
├── scripts/
│   ├── setup.sh       # venv/dependency/key setup
│   └── run.sh
├── tests/
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Security checklist

- Leave the HTTP listener on `127.0.0.1` and access it with private Tailscale Serve HTTPS.
- Keep `.env` secret; don't commit it or hard-code the key in the Car Thing UI if it will be published. For a future Car Thing integration, use a backend proxy or short-lived client auth arrangement.
- Use least-privilege indexer credentials and CA-verified TLS.
- Avoid broadly sharing `/var/run/docker.sock` or protected auth logs.
- No endpoint starts scans, executes user-provided shell commands, acknowledges alerts, or restarts containers.
- The preview does not persist your API key in local storage or cookies.

## Next phase

Once real data shows up in the browser preview, build a DeskThing-compatible Car Thing UI or other compatible flashed client that polls `/api/v1/overview` through a secure local connection. Firmware capabilities, button/knob input support and networking vary by custom firmware; this backend does not assume a particular one.
