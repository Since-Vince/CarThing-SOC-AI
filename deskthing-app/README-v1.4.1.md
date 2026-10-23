# CarThing SOC v1.4.1 — On-device AI summary display and request feedback

This patch applies **over working DeskThing v1.4.0** (same Windows source directory used in previous builds). It changes the Windows DeskThing app only. It does not modify Ubuntu/Wazuh/Ollama or Windows secrets.

## What's new

- AI SUMMARY appears **at the top of the selected alert's investigation screen** on the physical Car Thing once Ollama has returned the report; the verdict is explicitly provisional.
- Shows KEY EVIDENCE immediately; VIEW FULL REPORT expands related events, alternatives, next steps, and limitations.
- Distinguishes REQUESTING ANALYSIS from OLLAMA ANALYZING.
- If the DeskThing app worker does not acknowledge the request within **15 seconds**, the device shows an error instead of remaining stuck.
- If no result arrives within **four minutes**, the device shows an error instead of remaining stuck. The Ubuntu job may still be running; restarting the Car Thing does not cancel jobs on Ubuntu.
- Worker prints a safe log line when receiving the AI request (no keys and no alert contents).
- Restores an event-specific investigation checklist for Code Integrity events (5038/3004) instead of always giving login-only advice.
- Preserves existing navigation and knob action IDs; the server worker must be running for mapped hardware actions to work.

## Install on Windows

1. Save `CarThing-SOC-DeskThing-PATCH-v1.4.1.zip` to `C:\Users\ExampleUser\Downloads`.
2. In Command Prompt:

   ```cmd
   cd /d "%USERPROFILE%\Downloads\CarThing-SOC-DeskThing-App-SOURCE-v1.1\CarThing-SOC-DeskThing-App-v1.1"
   tar -xf "%USERPROFILE%\Downloads\CarThing-SOC-DeskThing-PATCH-v1.4.1.zip"
   node -p "require('./package.json').version"
   npm test
   npm run build
   ```

3. The version should read `1.4.1`; `dist\carthing-soc-deskthing-v1.4.1.zip` is the installable DeskThing package.
4. Install via DeskThing -> Downloads -> Add App, then pause/resume CarThing SOC in Apps to restart its worker.

## How to test

- Select a **real** Security alert and tap Investigate with AI once.
- If Ubuntu accepts and completes the request, the Car Thing displays the summary and provisional verdict at the top. Tap VIEW FULL REPORT for more.
- If you get "DeskThing did not acknowledge", open DeskThing -> Dev -> Logs. A known precursor is `Tried to send message to app carthing-soc but it wasn't found or is not running`. The UI update cannot repair a stopped/crashing background app process; gather the newest worker errors and ensure the app is running.
- On Ubuntu, inspect `sudo journalctl -u carthing-soc --since '15 minutes ago' --no-pager` for POST to `/api/v1/ai/investigate`. Dashboard GET `/api/v1/overview` is **not** evidence of an AI request.

The AI report is provisional; it cannot automatically confirm a true or false positive. No new credentials or public server exposure are required.
