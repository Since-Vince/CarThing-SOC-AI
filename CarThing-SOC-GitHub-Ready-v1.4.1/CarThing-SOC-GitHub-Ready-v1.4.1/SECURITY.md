# Security notes

This project is a home-lab learning tool. AI findings are hypotheses, not incident verdicts.

- Use a randomly generated API key; never add it to client source or screenshots.
- Run Ubuntu API on localhost and reach it only through authenticated Tailscale Serve HTTPS.
- Avoid exposing port 11434 (Ollama) to public or untrusted networks.
- The backend Docker integration carries elevated privileges even when invoked for read-only alert collection. Consider a separate Wazuh log export and dedicated restricted reader.
- Treat Wazuh event fields and AI outputs as untrusted input; do not give the model command execution abilities.
- Review the whole repository and Git history for secrets before making it public.
- Consider key rotation before publishing if any keys have ever been shared.
- Report security concerns privately to the repository owner through GitHub messages or a designated private channel once configured.
