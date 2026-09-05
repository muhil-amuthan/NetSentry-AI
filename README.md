# NetSentry-AI

Telecom Network Incident Triage Assistant

TRACK_ID=PS07

NetSentry-AI will:

1. Process network alerts.
2. Group related alerts into incidents.
3. Prioritize incidents.
4. Retrieve troubleshooting runbooks.
5. Generate evidence-backed recommendations.
6. Escalate unknown incidents to human engineers.

> Status: This project is under initial development. The repository currently
> contains only the project scaffold — a minimal FastAPI backend and a simple
> static frontend. Business logic will be added in upcoming steps.

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server (starts on port 8000)
python app.py

# 3. Open the UI
#    http://localhost:8000

# 4. Health check
#    http://localhost:8000/api/health
```

The health endpoint returns:

```json
{
  "status": "ok",
  "project": "NetSentry-AI"
}
```

## Project structure

```
NetSentry-AI/
├── app.py                 # Entry point — starts Uvicorn on port 8000
├── requirements.txt       # Python dependencies
├── src/                   # Backend modules (stubs for now)
│   ├── config.py          # Central configuration
│   ├── models.py          # Data models (future)
│   ├── topology.py        # Network topology handling (future)
│   ├── generator.py       # Synthetic alert generator (future)
│   ├── database.py        # Persistence layer (future)
│   ├── processor.py       # Alert processing pipeline (future)
│   ├── scorer.py          # Incident scoring engine (future)
│   ├── priority.py        # Incident prioritization (future)
│   ├── runbook_engine.py  # Runbook retrieval (future)
│   ├── escalation.py      # Escalation to engineers (future)
│   ├── nlp_handler.py     # Natural language handling (future)
│   └── api.py             # API routes
├── frontend/              # Static frontend (HTML/CSS/JS)
├── data/                  # Topology, runbooks, sample alerts
└── tests/                 # Tests
```
