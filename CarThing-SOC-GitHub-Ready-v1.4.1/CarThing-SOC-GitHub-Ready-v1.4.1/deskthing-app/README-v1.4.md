# CarThing SOC v1.4 — On-demand AI Investigation

## What's new
- Open a **real** Wazuh alert from the SECURITY tab, then tap **INVESTIGATE WITH AI**.
- DeskThing's Windows worker uses your existing private HTTPS CarThing API key and fetches a queued job from Ubuntu.
- Ubuntu reads only the selected Wazuh manager alert and a bounded recent event sample, then asks the local Ollama endpoint for a provisional analysis.
- The Car Thing displays a tentative TP/FP/inconclusive hypothesis, supporting evidence, related-event sample count, alternatives, next steps, and limitations.
- No automatic analyses; no remote shell; no Docker modification. Demo alert cannot be sent to AI.
- The existing knob mapping, four tabs, 15-second dashboard polling, and event-details navigation are retained.

## IMPORTANT
The AI is not ground truth. A false negative or true negative can't be proven from a clicked Wazuh alert; these require a separate validation/hunting workflow. Any AI interpretation may contain errors, especially with small local models. Known Windows Event ID meanings are fixed in backend code; recognized contradictions are blocked. Manual analyst verification is required.

## Installation
**First update Ubuntu** using `CarThing-SOC-AI-Backend-PATCH-v1.4.zip`. Run its `install_ai_v14.py` inside `~/CarThing-SOC-Backend` and restart the existing `carthing-soc` systemd service only after syntax checks.

**Then update DeskThing (Windows)** using `CarThing-SOC-DeskThing-PATCH-v1.4.zip`, extracted into the same project folder used to build v1.1/v1.2/v1.3. Run `npm test` and `npm run build`; install `dist/carthing-soc-deskthing-v1.4.0.zip` through DeskThing's app installer.

On Ubuntu, `SOC_AI_MODEL` can optionally be set in the backend `.env` to the output of `docker exec ollama ollama list`, e.g. `SOC_AI_MODEL=qwen3:1.7b` (installed by the user). Keep `.env` private and restart `carthing-soc` after changing it. The default is `qwen3:1.7b`.

Ollama must remain accessible from Ubuntu at `127.0.0.1:11434`. The API remains available only through your existing private Tailscale Serve and authenticated CarThing SOC backend; do not make it public.

## Workflow
- Security → real alert → Details → Investigate with AI.
- The button initiates **one** job. It shows `ANALYZING` while Ollama runs; this may take a minute or more on CPU.
- The backend allows only one concurrent analysis and keeps job results temporarily in memory (30 minutes); it performs **no background monitoring** and writes no persistent AI reports.
- AI output is deliberately labeled `PROVISIONAL`; incidents are never closed automatically.

## Troubleshooting
- HTTP 404 on POST means the Ubuntu backend hasn't been patched or the alert is missing; 401 means API authentication is wrong.
- `AI backend returned HTTP 404`: run the Ubuntu installer and restart service.
- Error contacting Ollama: check `docker ps --filter name=ollama`, `docker exec ollama ollama list`, and `curl http://127.0.0.1:11434/api/tags` on Ubuntu.
- Wazuh alert not found: older selected alert may fall outside the latest 2000 manager records / 2 MB window. Choose a recent alert.
- If the backend fails after installing, restore `app/main.py.pre-ai-v14.bak` and restart `carthing-soc`.
