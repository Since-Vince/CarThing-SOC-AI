# CarThing SOC — 5-minute starting checklist

The backend goes on your **Ubuntu/CasaOS server** (not on the Car Thing yet). This phase gives you a working API and browser preview. No firmware flashing is required to test it.

### 1. Put this project on Ubuntu

Transfer `CarThing-SOC-Backend.zip` to the Ubuntu machine. In its terminal:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip
unzip CarThing-SOC-Backend.zip
cd CarThing-SOC-Backend
```

### 2. Setup & start

```bash
bash scripts/setup.sh
bash scripts/run.sh
```

The setup script writes a **private random API key** to `.env`. Don't share the `.env` file or upload it to GitHub. The process runs on localhost port 8765.

### 3. Open it from your Tailscale-connected PC

In another Ubuntu server terminal:

```bash
sudo tailscale serve --bg 8765
sudo tailscale serve status
```

Open the HTTPS address reported by Tailscale Serve (only devices on your tailnet can access it). Enter the `CARTHING_API_KEY` value from `CarThing-SOC-Backend/.env` into the browser prompt. Tailscale Serve may ask you to enable HTTPS certificates.

### 4. Confirm live sources

- **Ubuntu server:** CPU, RAM, disk and uptime should appear immediately.
- **Docker:** If unavailable, see the Docker permissions/security note in README.md.
- **Tailscale:** The server must already be connected to your tailnet.
- **Wazuh:** Disabled at first by design. For Wazuh Manager in Docker, set `WAZUH_MODE=docker` and `WAZUH_DOCKER_CONTAINER=single-node-wazuh.manager-1` in `.env`, then restart. Also supports local alert files and a read-only Indexer connection.
- **Failed SSH:** Disabled at first because auth logs can require additional privileges.

You can stop the API with `Ctrl+C`; Tailscale Serve persists when started with `--bg`. To stop Tailscale Serve: `sudo tailscale serve off`.

### 5. Next milestone

Once the browser preview displays actual host/Docker/Tailscale data, connect Wazuh. Only then is it useful to start building the native Car Thing screen and button support.

For configuration, security considerations, endpoints, troubleshooting and systemd auto-start, see **README.md**.
