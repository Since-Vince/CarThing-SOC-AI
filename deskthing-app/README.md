# CarThing SOC — DeskThing Application v1.3 (Source Project)

Custom DeskThing v0.11.x app for a Spotify Car Thing running ThingLabs firmware.

## What it does

- **Overview:** Ubuntu CPU/RAM/disk, Wazuh severity counts, Docker and Tailscale status.
- **Security:** 15 recent Wazuh events with severity and agent name.
- **Services:** Up to 30 Docker containers (read-only).
- **Network:** Tailscale peers, Tailscale IP, server uptime and free disk.
- Auto-refresh every 15 seconds. Touch navigation; DeskThing actions for optional knob/button mappings.
- **No API key is included in the device client or project ZIP.** The Windows worker reads `%LOCALAPPDATA%\CarThingSOC\config.json` and makes authenticated HTTPS requests to your Ubuntu backend.

## Requirements

1. DeskThing desktop server v0.11.17 running on Windows, paired with a working Car Thing client v0.11.2.
2. Ubuntu CarThing SOC backend v1.1 running and available via Tailscale Serve HTTPS.
3. Tailscale connected on Windows.
4. **Node.js LTS** and npm on Windows to build this project (nodejs.org).

## IMPORTANT: This ZIP contains SOURCE, not a prebuilt DeskThing app

The container used to prepare these files cannot access the npm registry, so a production client bundle **has not been generated or hardware-tested**. Build the app on your Windows PC before trying to upload it to DeskThing.

## Installation (Windows)

1. Extract this source ZIP to a new folder such as `C:\Users\ExampleUser\Downloads\CarThing-SOC-DeskThing-App`.
2. Open a Terminal/PowerShell **in that folder** and verify `node -v` and `npm -v` work.
3. Run the Windows configuration helper. Enter your **rotated, private** API key; never paste it into chat or a public repository:
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\configure-windows.ps1
   ```
   Default URL is `https://your-server.your-tailnet.ts.net`. If your Tailscale machine name changes, enter the actual new Serve URL.
4. Install dependencies and create the official DeskThing package:
   ```powershell
   npm install
   npm run build
   ```
   The `@deskthing/cli` tool creates a packaged DeskThing ZIP in the build/output directory it reports. Do not upload the original SOURCE ZIP.
5. In DeskThing desktop, go to **Downloads → Apps → Upload App**, select the **built** ZIP, and initialize/install CarThing SOC.
6. Open **Apps** → CarThing SOC on the physical device. You should see server health, alerts, services, and network screens.

## Troubleshooting

- **Waiting for SOC data:** Recheck `%LOCALAPPDATA%\CarThingSOC\config.json` and ensure Tailscale is connected on Windows. Open the Ubuntu dashboard URL in Windows browser.
- **401 / API key rejected:** Rerun the configuration PowerShell script with your latest Ubuntu `.env` key and restart the SOC app.
- **No security alerts:** Check the Ubuntu browser dashboard. The Car Thing app uses the same `/api/v1/overview` endpoint.
- **Page buttons work but knob doesn't:** In DeskThing's input mapping settings, map Knob CW/CCW or preset buttons to `SOC: Next screen` and `SOC: Previous screen` actions. The client supports touch navigation regardless.
- **No package produced:** Read the build output for the generated ZIP location; if npm commands fail, verify Node LTS and your internet connection. Do not try to upload the source archive as an app.
- **Connected but old readings:** If the Windows DeskThing server loses Tailscale, the device shows STALE/OFFLINE rather than inventing readings.

## Security notes

- Keep the Ubuntu API on `127.0.0.1:8765` and use **tailnet-only Tailscale Serve**; do not enable public Funnel.
- The API key is stored locally as a Windows file with limited permissions, not encrypted. Anyone with access to that Windows user account could potentially read it. Don't distribute that file.
- This app only issues GET requests to a read-only backend. No execute/restart/remediation endpoints.
- Even though the device displays security alert metadata, it never receives the API key.
- The Wazuh severity cards show counts **within the sampled 15 latest alerts**, not all alerts in the entire time window.

## Development

Use `npm run dev` for the DeskThing development environment; `npm test` runs the schema/security unit tests without npm packages. Built according to the official DeskThing CLI template and DeskThing SDK v0.11.x conventions. The v1.3 production build is not verified on your physical device; run the local Windows DeskThing packaging command.


## v1.1 fix notes

- Screen tabs and footer Prev/Next now switch immediately even when the Windows worker has no data.
- Windows worker tolerates a UTF-8 BOM in config.json, which PowerShell 5.1 may add when saving the original configuration.
- The Windows configure script now saves UTF-8 without BOM.
- Tries multiple Windows user-profile paths when locating the private configuration.
- Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-bridge.ps1` in CMD to verify the Windows bridge safely (API key never printed).
- Knob rotation still requires a DeskThing hardware action mapping; map clockwise to `SOC: Next screen` and counterclockwise to `SOC: Previous screen` in its input mapping controls.
- These source changes need to be rebuilt with npm on Windows and re-imported into DeskThing; this file is not a pre-built installable ZIP.


## v1.2 updates (2026-10-20)

- **Offline fix:** DeskThing v0.11.17 app worker threads strip most Windows environment variables. v1.1 was using those variables to find `%LOCALAPPDATA%`. v1.2 adds native `os.homedir()` / `os.userInfo().homedir` fallback so the worker can locate your EXISTING `%LOCALAPPDATA%\CarThingSOC\config.json`. No new API key or setup required.
- **Navigation fix:** Client touch/footer page changes are now synchronized to the Windows worker via `soc_set_page`, preventing the next physical knob turn from jumping to an out-of-sync index.
- **Highlight fix:** Wheel-driven screen changes blur stale focused buttons; CSS removes the residual blue browser focus outline. The active tab is indicated consistently by the mint-green selected style.
- **Tests:** Added Windows worker environment-isolation config-path tests.
- **Build:** Run `npm install`, `npm test`, `npm run build` on Windows, then install the generated `dist\carthing-soc-deskthing-v1.2.0.zip` in DeskThing (the source ZIP itself is not installable). Existing Windows config is preserved outside the app project.
- **Do not copy** `%LOCALAPPDATA%\CarThingSOC\config.json` into the project, dist ZIP, or GitHub.

## v1.3 — Alert investigation

- Tap a Wazuh alert on Security to open its read-only investigation screen.
- See severity, time, rule ID, Windows Event ID, account, source IP, logon type, failure reason and MITRE IDs when Wazuh supplies them. Missing fields show "Not reported" rather than guesses.
- Use Back to return; while viewing a detail, the knob cycles through real alerts (your saved Previous/Next screen mappings are reused). The footer can also browse records.
- **TRY 4625 EXAMPLE** is a clearly labeled local demonstration that cannot be mistaken for a real Wazuh alert.
- Existing backend will still work (basic metadata only); for full Windows event fields apply the separate optional Ubuntu backend patch, restart systemd and verify the app.
- Alert metadata is sent to the physical Car Thing, but never the API key or raw event JSON. Avoid screenshots if the alert shows an internal username/IP you don't want to share.

### Upgrade from working v1.2 on Windows

Download the v1.3 DeskThing patch ZIP. Open CMD *inside your existing v1.2 app source directory* and run `tar -xf "%USERPROFILE%\Downloads\CarThing-SOC-DeskThing-PATCH-v1.3.zip"`, then `npm test` and `npm run build`. Import `dist\carthing-soc-deskthing-v1.3.0.zip` into DeskThing. No reconfiguration or new API key is needed.

### Optional: richer Wazuh fields from Ubuntu

Copy the included updated collectors file to Ubuntu, making a backup of the existing `~/CarThing-SOC-Backend/app/collectors.py` first. Restart the existing `carthing-soc` service. The backend patch only expands an allowlisted subset of Wazuh alert metadata and indexer source fields; it does **not** expose raw records, mutate Wazuh, or change the API key. See `README-BACKEND.md`.
