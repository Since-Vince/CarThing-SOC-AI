# Screenshots to add before publishing

Recommended order:

1. `01-carthing-overview.jpg`: physical Car Thing showing live Overview, entire device visible
2. `02-security-alerts.png`: Security page listing anonymized Wazuh alerts
3. `03-alert-details.png`: selected example/verified alert (remove usernames, addresses, private paths)
4. `04-ai-summary.png`: Ollama generated summary with clearly visible Provisional / Inconclusive status

Optional 20–30 second video: rotate physical knob between tabs, select Security event, tap Investigate with AI, show report. Avoid filming computer screen with exposed secrets or private network information.

After adding redacted images, embed them at the top of `README.md`:

```markdown
![CarThing SOC Overview](docs/screenshots/01-carthing-overview.jpg)
![Wazuh security alerts](docs/screenshots/02-security-alerts.png)
![AI-assisted investigation](docs/screenshots/04-ai-summary.png)
```
