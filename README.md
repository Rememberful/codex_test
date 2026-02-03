# OWASP AI Scanner (Hosted Web App)

This is a hosted-ready web application vulnerability scanner that maps results to the OWASP Top 10 and can optionally generate AI remediation guidance using the OpenAI API.

## What it does

- Crawls authorized targets (same-origin only)
- Optional domain allowlist for multi-domain scans
- Performs safe, lightweight checks mapped to OWASP Top 10 categories
- Provides a web UI for scan configuration and results
- Scan history page and report export (CSV/JSON)
- Optionally generates AI summaries and remediation steps

## Quick start (local dev)

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r backend/requirements.txt
set OPENAI_API_KEY=your_key_here
uvicorn backend.app:app --host 0.0.0.0 --port 8080
```

Open: `http://localhost:8080`

## Docker

```bash
docker build -t owasp-ai-scanner .
docker run -p 8080:8080 --env-file .env owasp-ai-scanner
```

## Environment variables

- `OPENAI_API_KEY` (optional): Enables AI summaries
- `OPENAI_MODEL` (optional): Default `gpt-5-mini`

## Notes

- Only scan targets you own or have explicit permission to test.
- Findings are heuristic. Use manual validation before taking action.
- Scan history is stored in memory per server instance; use a database if you need persistence.
