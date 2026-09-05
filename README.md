# NetSentry-AI

**Telecom Network Incident Triage Assistant — PS07**

Deterministic alert processing → topology-aware correlation → prioritisation → grounded runbook retrieval (FAISS + Gemini embeddings) → evidence-backed AI recommendation → human escalation when needed — all served through a single FastAPI + static-dashboard app.

TRACK_ID=PS07

---

## 1. Problem — PS07

Telecom NOCs drown in noisy, duplicated, multi-collector alerts. The same fiber cut appears as `LINK_DOWN` traps, `DEVICE_UNREACHABLE` ICMP, `PACKET_LOSS` netflow and `HIGH_LATENCY` probes — across core → distribution → access — within minutes. Operators must decide in seconds: is this one incident or many? How critical? What to check first? When to escalate instead of hallucinating an answer? NetSentry-AI automates the triage while keeping every decision explainable and grounded in local runbooks.

## 2. Solution

```
Raw Alerts
   ↓  processor.py : validate → normalize → fingerprint (device:interface:type) → dedup window 60s (collapse repeats, preserve count/sources)
   ↓  scorer.py    : four-signal correlation (same_device +30, related_device +20 via topology.json, time_proximity +20 within 5 min, related_type +30) → threshold 60 → connected components → candidate incidents INC-0001…
   ↓  priority.py  : device_impact 40 (core 40 vs access 10 via topology layer) + severity 30 + alert_volume 20 + duration 10 → 0-100 → CRITICAL 90-100 / HIGH 70-89 / MEDIUM 40-69 / LOW 0-39
   ↓  runbook_engine.py : load 8 local markdown runbooks → chunk → FAISS (local embedding fallback) + Gemini gemini-embedding-001 when GEMINI_API_KEY set → keyword + semantic blended retrieval (never invents a runbook)
   ↓  → gemini generation (gemini-2.0-flash, grounded prompt) or deterministic fallback → structured recommendation with evidence citations
   ↓  escalation.py : escalate when no runbook, low confidence, UNKNOWN types, weak correlation on large blast radius, or Gemini unavailable on HIGH/CRITICAL
   ↓  nlp_handler.py : Ask NetSentry over live incidents/priorities/evidence/recommendations/escalations (deterministic intents, Gemini only to rephrase, never to invent)
   ↓  NOC Dashboard (FastAPI serves frontend/ → http://localhost:8000)
```

Every stage exposes its reasoning (score breakdowns, affected devices, runbook section, confidence) so a judge can answer *why were these grouped? why is this critical? which runbook and why escalated?*

## 3. Architecture

```
NetSentry-AI/
├── app.py                 # Uvicorn entry — mounts /api + frontend/
├── requirements.txt       # fastapi, uvicorn, pydantic, numpy, faiss-cpu, google-genai, python-dotenv, pytest
├── src/
│   ├── config.py          # HOST/PORT, paths, GEMINI keys/models
│   ├── models.py          # Severity, Alert, Incident, Topology schemas
│   ├── topology.py        # Graph over data/topology.json (neighbors, downstream, impact_of_failure)
│   ├── generator.py       # Deterministic fixture: duplicate_alerts / cascade_failure / unknown_escalation
│   ├── processor.py       # normalize + fingerprint + dedup (60s window)
│   ├── scorer.py          # four-signal correlation → candidate incidents
│   ├── priority.py        # four-signal prioritisation → CRITICAL/HIGH/MEDIUM/LOW
│   ├── runbook_engine.py  # load/parse/chunk runbooks → local FAISS + Gemini retrieval → grounded recommendation
│   ├── escalation.py      # when to refuse to answer and build escalation payload
│   ├── nlp_handler.py     # Ask NetSentry intent router over live state
│   ├── database.py        # in-memory StateStore (alerts→processed→incidents→priority→evidence→recommendation→escalation)
│   └── api.py             # /api/health, /alerts, /incidents, /runbooks, /topology, /statistics, /process, /analyze/{id}, /ask, /escalate/{id}
├── frontend/
│   ├── index.html         # premium NOC UI — scenario selector, health, kpis, incidents, alert stream, topology, AI panel, timeline, Ask
│   ├── style.css          # dark mission-control theme — no external fonts/assets
│   ├── data.js            # API data layer — fetches from /api/* with mock fallbacks (the only frontend data seam)
│   └── app.js             # rendering, filtering, alert-stream replay, topology SVG, AI panel (deterministic vs AI split), Ask console
├── data/
│   ├── topology.json      # 9 nodes (INTERNET, CORE-R1/R2, SW-S1/S2, ACC-R3..R6) + 9 links
│   ├── sample_alerts.json # committed deterministic fixture (all 46 alerts)
│   ├── runbooks/*.md      # 8 project-created telecom runbooks (see §8)
│   └── faiss_index/       # local FAISS index (IndexFlatIP) + meta.json — generated at startup or committed (86KB)
└── tests/                 # unittest suite — 213 tests covering topology, generator, processor, scorer, and app shell
```

No `npm`, no Docker, no Postgres, no external vector DB — everything runs with `pip install -r requirements.txt && python app.py`.

## 4. Deterministic vs AI — Explicit Separation

**Deterministic (no LLM, no embeddings, always exact):**
- validation, normalisation, fingerprint, deduplication
- topology relationships (uses `data/topology.json`, never hardcoded)
- correlation scoring and incident grouping (connected components, transitive)
- device role / severity / volume / duration prioritisation
- incident IDs `INC-0001`… (no UUID, no wall time, no randomness)
- stored application state (StateStore)

**AI (Gemini is the ONLY external API; everything else is local):**
- `gemini-embedding-001` → semantic retrieval over runbook chunks (FAISS, NumPy, local `faiss-cpu`)
- Gemini generation (`gemini-2.0-flash`) → grounded natural-language explanation *after* deterministic grouping and retrieval, citing supplied evidence only
- optional semantic assist for Ask NetSentry interpretation — never invents incident data

**Failure handling:** if `GEMINI_API_KEY` missing/invalid, or FAISS unavailable, or a bad alert arrives, the pipeline falls through: `Gemini semantic → local keyword/runbook matching → deterministic recommendation → escalate if confidence insufficient`. The NOC app never crashes because the API is down.

## 5. Grounding

All recommendations cite project-created runbooks in `data/runbooks/` — not copied external docs. Each runbook declares `Applicable Alert Types`, `Symptoms`, `Likely Causes`, `Initial Checks`, `Recommended Actions`, `Escalation Conditions`. Retrieval never invents a runbook; an incident with `UNKNOWN` types (unknown_escalation) correctly returns *no suitable runbook* and triggers escalation. The AI prompt is instructed to only use supplied evidence and the JSON response is validated to strip hallucinated runbooks.

## 6. Escalation — When the System Refuses to Answer

Escalation fires when any of:
- no matching runbook / empty evidence
- `UNKNOWN` alert types with no coverage
- high priority with low confidence (deterministic fallback on HIGH/CRITICAL)
- ambiguous multi-device incident with weak correlation and large blast radius
- Gemini unavailable and evidence insufficient
- the recommendation itself sets `needs_escalation`

An escalation payload always contains:
- `incident_id`, `reason` (why automation stopped)
- `summary` (what happened)
- `grouped_alerts` (what was grouped — alert_id, device, type, severity, message)
- `already_suggested` (what was already tried)
- `next_step: "Manual NOC investigation required"`
- `correlation_score/reasons`, `priority`, `affected_devices`, `first_seen/last_seen`

The UI renders escalation as a crit banner in the AI panel and in the Ask answers.

## 7. Installation

```bash
git clone https://github.com/muhil-amuthan/NetSentry-AI.git
cd NetSentry-AI
pip install -r requirements.txt
```

Requires Python 3.11+. `faiss-cpu` and `numpy` install via pip wheel — no compile step.

## 8. Environment

```bash
# optional — enables semantic retrieval + grounded generation
export GEMINI_API_KEY="your-gemini-key"

# optional overrides (defaults shown)
export GEMINI_MODEL_EMBEDDING="gemini-embedding-001"
export GEMINI_MODEL_GENERATION="gemini-2.0-flash"
export NETSENTRY_HOST="0.0.0.0"
export NETSENTRY_PORT="8000"
export NETSENTRY_SCENARIO="all"   # default triage view; UI selector can override
```

Never commit `.env` — it is in `.gitignore`. Never expose the key to frontend JavaScript (all Gemini calls are server-side in `src/runbook_engine.py`).

Without a key, the app remains fully usable via the deterministic fallback.

## 9. Run — One Command

```bash
pip install -r requirements.txt && python app.py
# → http://localhost:8000              (dashboard)
# → http://localhost:8000/api/health   (health)
# → http://localhost:8000/docs         (OpenAPI)
```

Startup is <5s (FAISS index builds on first request if not cached; otherwise loaded from `data/faiss_index/`). No `npm`, no Docker.

## 10. API

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | `{status, project, version, scenario}` |
| GET | `/api/topology` | Network graph (nodes/links) — same shape as `data/topology.json` |
| GET | `/api/runbooks` | List local runbooks `{id, title, applicable_types, sections}` |
| GET | `/api/statistics` | `{stats: {total_alerts, processed_alerts, duplicate_collapsed, incident_count, critical_count, high_count, escalated_count, affected_devices}, health, kpis}` |
| GET | `/api/alerts?scenario=&limit=` | Raw alerts (optionally filtered by `scenario` label) |
| GET | `/api/processed` | Deduplicated `ProcessedAlert`s |
| GET | `/api/incidents?priority=&device=&scenario=` | Enriched incidents (priority, evidence, recommendation, escalation, timeline, alerts) — filterable |
| GET | `/api/incidents/{incident_id}` | Full incident detail (same enrichment) |
| POST | `/api/process` | Re-run pipeline. Body: `{"scenario":"cascade_failure"}` or `{"scenario":"all"}` or `{"alerts":[...]}`. Returns incident list + stats. |
| POST | `/api/analyze/{incident_id}` | Regenerate grounded recommendation for an incident (retries Gemini if configured). Returns `{recommendation, evidence, escalation, deterministic_facts, ai_generated}`. |
| POST | `/api/ask` | Ask NetSentry. Body: `{"question":"Why is INC-0001 critical?"}`. Returns `{answer, refs, intent, incident_id}` grounded in live state. |
| GET/POST | `/api/escalate/{incident_id}` | Get or force escalation. POST body optional `{"reason":"..."}`. Returns escalation payload. |

All responses are deterministic for the same input (no wall time in incident IDs).

## 11. Demo Scenarios — Deterministic & Reproducible

`data/sample_alerts.json` is the hand-authored fixture; `src/generator.py` is the source of truth — regenerate with `python -m src.generator --write`. The dashboard has a **Demo Scenario selector** (All / duplicate_alerts / cascade_failure / unknown_escalation) that POSTs to `/api/process`.

| Scenario (`--scenario` alias) | Raw | Processed | Incidents | Expected behavior |
|---|---|---|---|---|
| `duplicate_alerts` (`duplicates`, `1`) | 10 alerts on `R1` (3 fingerprints, 4 collectors) | 5 groups (`R1:Te0/1:LINK_DOWN` collapsed) — 5 deduped | 1 incident `INC-0001` — HIGH (score 89) | duplicates collapse, one meaningful incident, no inflation, runbook `link_down.md` |
| `cascade_failure` (`cascade`, `2`) | 26 alerts, 7 devices `R1, S1/S2, R3..R6` within ~3.5 min, core→distribution→access order | 26 (no dedup) | 3 incidents — major `INC-0001` CRITICAL 94 (23 alerts, 7 devices) + 2 smaller AUTH_FAILURE groups | strong correlation, transitive grouping, core role drives critical, runbooks `core_router_failure.md` + `multi_device_cascade.md`, grounded recommendation with evidence citing `Initial Checks` |
| `unknown_escalation` (`unknown`, `3`) | 10 alerts: 6 `UNKNOWN` types with preserved `labels.raw_type` (optical sync anomaly, PTP drift, protocol anomaly, microloop, abnormal traffic, unmapped trap) + 4 unrelated known-type noise | 10 | 10 isolated `INC-000*` — each LOW/MEDIUM, none correlated | unknown alerts survive processing, no invented correlation, no invented runbook, every uncovered incident escalates (`No matching runbook found`) while noise stays separate; no escalation inflation |

Other ad-hoc checks (`python -m src.generator --summary`, custom alert POST) work without drift because timestamps are fixed to `2026-09-05T09:00:00Z` plus deterministic offsets.

```bash
# CLI inspection
python -m src.generator --summary
python -m src.generator --scenario cascade_failure
python -m src.generator --scenario 3 --format json
```

**Runbooks (`data/runbooks/`):** `link_down.md`, `device_unreachable.md`, `packet_loss.md`, `high_latency.md`, `auth_failure.md`, `core_router_failure.md`, `multi_device_cascade.md`, `switch_failure.md` — each has Title, Symptoms, Likely Causes, Initial Checks, Recommended Actions, Escalation Conditions, Applicable Alert Types.

## 12. Testing

```bash
# Full suite (213 tests) — deterministic, no network
pytest -q
# or
python -m pytest -q

# Coverage highlights
# - topology loading / graph queries (neighbors, downstream, impact_of_failure)
# - generator determinism & scenario shape
# - processor: normalisation, fingerprint, dedup window, source preservation
# - scorer: four signals, threshold, topology-driven, transitive grouping, deterministic IDs
# - app shell: FastAPI routes, health, static frontend still served
```

Integration checks (not in `pytest` but verified via `/api/*`):

```
Raw alerts → processor → dedup → correlation → candidate incident → priority → runbook retrieval (keyword + FAISS) → recommendation (Gemini or deterministic) → escalation — tested for zero/one/duplicate/malformed/unknown/missing-interface/no-runbook/Gemini-unavailable/empty-question/unknown-intent/missing-id/empty-state and deterministic repeat.
```

## 13. Failure Handling & Demo Flow

The judge can run the canonical demo:

1. `python app.py` → open `http://localhost:8000`
2. Scenario selector → `cascade_failure` → Load → 26 alerts appear in stream, dedup 0, correlation 23-alert `INC-0001` CRITICAL 94, devices `R1,S1,S2,R3..R6`, timeline ordered core→access, topology marks `R1` down/`S1,S2` warn
3. AI panel: **DETERMINISTIC FACTS** (correlation 73, priority 94, affected devices) vs **AI-GENERATED EXPLANATION** (Gemini or deterministic fallback) with 2–3 recommended actions citing `core_router_failure.md — Initial Checks` and `multi_device_cascade.md — Initial Checks`
4. Ask: “Why is this incident critical?” → explains device_impact 40 + severity 30 + alert_volume 20 + duration 4, citing same evidence
5. Scenario selector → `unknown_escalation` → Load → 10 single-alert incidents, each escalated with payload `No matching runbook found` + grouped 1 alert + `already_suggested: []` + `next_step: Manual NOC investigation required`
6. Ask: “Why was this incident escalated?” → grounded escalation reason, no hallucinated runbook

If Gemini is disabled, steps 3–4 still work (deterministic recommendation with same citations, confidence `high` only when evidence supports it).

## 14. Security

- No secret is committed: `grep -R AIza` empty, `GEMINI_API_KEY` only via `os.getenv`, `.env` is gitignored.
- Frontend never sees the key — all `google-genai` calls are server-side.
- `/docs` and `/api/*` are unauthenticated for the hackathon demo; add auth in production.

## 15. Known Limitations

- State is in-memory (`src/database.py` `StateStore`) — not persisted across restarts beyond the fixture; suitable for the demo.
- Gemini generation is best-effort grounded; invalid JSON responses fall back to the deterministic template.
- FAISS index uses cosine (Inner Product on normalized vectors); for the deterministic local embedding the threshold is low (0.12) to retain keyword-filtered matches. Semantic quality improves with a real `GEMINI_API_KEY`.
- Access topology is simplified (9 nodes) — intentionally small for explainability.

---

*Runbook grounding, escalation honesty, and explainability are the core evaluation criteria — not black-box “AI says CRITICAL”.*
