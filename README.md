# NetSentry-AI

## Telecom Network Incident Triage Assistant — PS07

> **From Alert Noise to Actionable Network Intelligence**

NetSentry-AI is an intelligent Network Operations Center (NOC) incident triage platform designed for telecom networks.

It transforms large volumes of noisy, duplicated, and related network alerts into meaningful incidents, determines their priority and impact, retrieves relevant troubleshooting evidence, generates grounded AI recommendations, and escalates cases to human NOC engineers when sufficient evidence is not available.

The system combines a **deterministic incident intelligence pipeline** with **FAISS-based retrieval and Gemini AI assistance**, while keeping network facts, correlation, incident grouping, and priority decisions deterministic and explainable.

**TRACK_ID: PS07**

---

# 1. Problem Statement

Telecom networks continuously generate alerts from multiple monitoring systems and collectors.

A single underlying network failure can produce multiple alerts such as:

```text
LINK_DOWN
DEVICE_UNREACHABLE
PACKET_LOSS
HIGH_LATENCY
AUTH_FAILURE
```

For example, a single fiber or core-router failure may generate:

```text
LINK_DOWN
      ↓
DEVICE_UNREACHABLE
      ↓
PACKET_LOSS
      ↓
HIGH_LATENCY
```

across several connected devices.

This creates a major challenge for NOC engineers.

They need to quickly determine:

* Which alerts are duplicates?
* Which alerts belong to the same incident?
* Which alerts are unrelated noise?
* Which incident has the largest impact?
* Which devices are affected?
* What should be checked first?
* Which troubleshooting procedure applies?
* Is there enough evidence to provide an automated recommendation?
* When should the system stop and escalate to a human?

Traditional alert dashboards often show thousands of alerts but do not provide enough context to understand the underlying incident.

---

# 2. Our Solution

NetSentry-AI provides an end-to-end incident triage pipeline:

```text
                    RAW NETWORK ALERTS
                            │
                            ▼
                ┌──────────────────────┐
                │  ALERT PROCESSOR     │
                │ Validate + Normalize │
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │    DEDUPLICATION     │
                │ Fingerprint + 60 sec │
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │ CORRELATION ENGINE   │
                │ Topology + Time +    │
                │ Alert Relationships  │
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │  INCIDENT BUILDER    │
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │   PRIORITY ENGINE    │
                │ Impact + Severity    │
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │   RUNBOOK ENGINE     │
                │ Local Docs + FAISS   │
                │ + Gemini Embeddings  │
                └──────────┬───────────┘
                           │
                    ┌──────┴───────┐
                    │              │
                    ▼              ▼
          ┌────────────────┐  ┌────────────────┐
          │ GROUNDED AI    │  │   ESCALATION   │
          │ RECOMMENDATION │  │  Human NOC     │
          └───────┬────────┘  └───────┬────────┘
                  │                   │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │  ASK NETSENTRY    │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │    NOC DASHBOARD  │
                  └───────────────────┘
```

The system is designed around three principles:

### 1. Reduce Noise

Duplicate and related alerts are grouped into meaningful incidents.

### 2. Explain Every Decision

Correlation scores, affected devices, priority factors, runbook evidence, and escalation reasons are visible.

### 3. Know When to Stop

When evidence is insufficient, the system escalates instead of inventing an answer.

---

# 3. End-to-End Architecture

The complete application is divided into several processing layers.

```text
┌─────────────────────────────────────────────────────────────┐
│                        NOC DASHBOARD                        │
│ Overview │ Alerts │ Incidents │ Topology │ AI │ Ask        │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                         FASTAPI API                          │
│ health │ alerts │ incidents │ process │ analyze │ ask       │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                      STATE STORE                             │
│ Alerts → Processed → Incidents → Priority → Evidence       │
│ → Recommendation → Escalation                               │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                   INCIDENT INTELLIGENCE                      │
│                                                             │
│ Processor → Deduplicator → Correlation → Priority          │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                     KNOWLEDGE LAYER                          │
│                                                             │
│ Project Runbooks → Chunking → Embeddings → FAISS Retrieval  │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                         AI LAYER                             │
│                                                             │
│ Grounded Gemini Recommendation + Ask NetSentry              │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    ESCALATION LAYER                          │
│                                                             │
│ Insufficient Evidence → Human NOC Investigation              │
└─────────────────────────────────────────────────────────────┘
```

---

# 4. Core Processing Pipeline

## Step 1 — Alert Ingestion

NetSentry-AI accepts familiar telecom alert events such as:

```text
LINK_DOWN
DEVICE_UNREACHABLE
PACKET_LOSS
HIGH_LATENCY
AUTH_FAILURE
```

Alerts contain information such as:

```text
Alert ID
Timestamp
Device
Interface
Alert Type
Severity
Source
Message
Status
Labels
```

---

# 5. Alert Normalization

Incoming alert records are converted into a consistent internal representation.

The processor validates and normalizes fields before the alert enters the incident intelligence pipeline.

Unknown alert types are preserved safely instead of being silently discarded.

---

# 6. Deterministic Deduplication

Multiple collectors may report the same underlying failure.

NetSentry-AI creates a deterministic alert fingerprint using:

```text
device + interface + alert_type
```

A configurable deduplication window is used.

Default:

```text
60 seconds
```

Example:

```text
Collector A → CORE-R1 → LINK_DOWN
Collector B → CORE-R1 → LINK_DOWN
Collector C → CORE-R1 → LINK_DOWN
Collector D → CORE-R1 → LINK_DOWN
```

becomes:

```text
One representative alert
+
Duplicate count
+
Original alert IDs
+
Source collectors
+
First seen
+
Last seen
```

This prevents duplicate observations from artificially increasing incident impact.

### Important Design Decision

```text
DEDUPLICATION ≠ CORRELATION
```

Deduplication removes repeated observations of the same event.

Correlation determines whether different events are related to the same incident.

---

# 7. Topology-Aware Correlation

NetSentry-AI uses the actual network topology stored in:

```text
data/topology.json
```

The demonstration topology contains:

```text
INTERNET
    │
    ▼
CORE-R1 ───── CORE-R2
   │
   ├──── SW-S1 ─── ACC-R3
   │          └── ACC-R4
   │
   └──── SW-S2 ─── ACC-R5
              └── ACC-R6
```

The topology layer provides relationships such as:

* Neighbors
* Downstream devices
* Device roles
* Impact relationships

The correlation engine does not rely on hardcoded device relationships.

---

# 8. Correlation Scoring

Each pair of alerts is evaluated using deterministic signals.

| Correlation Signal         | Score |
| -------------------------- | ----: |
| Same device                |   +30 |
| Related topology device    |   +20 |
| Time proximity ≤ 5 minutes |   +20 |
| Related alert type         |   +30 |

Correlation threshold:

```text
60
```

The related alert types are explicitly defined.

For example:

```text
LINK_DOWN
    ↕
DEVICE_UNREACHABLE
    ↕
PACKET_LOSS
    ↕
HIGH_LATENCY
```

Authentication failures are handled as their own related category.

---

# 9. Transitive Incident Grouping

NetSentry-AI supports transitive relationships.

For example:

```text
Alert A ↔ Alert B
Alert B ↔ Alert C
Alert C ↔ Alert D
```

can become:

```text
INC-0001

A
│
B
│
C
│
D
```

even when every pair is not directly related.

This is implemented using deterministic connected-component grouping.

Incident IDs are deterministic:

```text
INC-0001
INC-0002
INC-0003
```

No random UUIDs are required for incident identity.

---

# 10. Incident Representation

A candidate incident contains information such as:

```text
Incident ID
Alert IDs
Grouped Alerts
Correlation Score
Correlation Reasons
First Seen
Last Seen
Affected Devices
```

This information is later used by the priority, runbook, AI, and escalation layers.

---

# 11. Incident Priority Engine

After correlation, NetSentry-AI determines the impact of each incident.

Priority levels:

```text
CRITICAL
HIGH
MEDIUM
LOW
```

Priority considers:

```text
Device Impact
+
Severity
+
Alert Volume
+
Incident Duration
```

The priority calculation is deterministic.

---

## Priority Model

### Device Impact

Device role contributes to the incident score.

Example:

```text
Core device       → high impact
Distribution      → medium-high impact
Access device     → lower impact
Unknown           → minimal impact
```

### Severity

Alert severity contributes to the score.

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

### Alert Volume

A larger correlated alert group can indicate broader impact.

### Duration

Incident duration is calculated from:

```text
last_seen - first_seen
```

The system does not use the current wall-clock time for incident duration.

---

# 12. Priority Levels

The final score is mapped to:

```text
90–100 → CRITICAL
70–89  → HIGH
40–69  → MEDIUM
0–39   → LOW
```

Every priority result contains an explainable breakdown.

Example:

```text
INC-0001
Priority: CRITICAL
Score: 94

Device Impact     +40
Severity          +30
Alert Volume      +20
Duration           +4
──────────────────────
Total              94
```

This allows NOC engineers and judges to understand why an incident received its priority.

---

# 13. Local Runbook Knowledge Base

NetSentry-AI uses project-created troubleshooting documents.

Runbooks are stored locally in:

```text
data/runbooks/
```

The system contains runbooks covering scenarios such as:

```text
Link Down
Device Unreachable
Packet Loss
High Latency
Authentication Failure
Core Router Failure
Switch Failure
Multi-Device Cascade
```

Each runbook contains structured sections such as:

```text
Title
Symptoms
Likely Causes
Initial Checks
Recommended Actions
Escalation Conditions
Applicable Alert Types
```

The runbooks are created specifically for the project and are used as the grounding source for AI recommendations.

---

# 14. FAISS Retrieval

The runbook knowledge base is indexed locally.

The retrieval pipeline is:

```text
Local Runbooks
      ↓
Document Chunking
      ↓
Gemini Embeddings
      ↓
FAISS Index
      ↓
Relevant Runbook Evidence
```

The project uses:

```text
FAISS
NumPy
gemini-embedding-001
```

The vector index is stored locally under:

```text
data/faiss_index/
```

The system does not require an external vector database.

---

# 15. Grounded Gemini AI

Gemini is used only after deterministic incident processing and evidence retrieval.

The AI pipeline is:

```text
Incident
    ↓
Priority
    ↓
Affected Devices
    ↓
Correlation Evidence
    ↓
Runbook Retrieval
    ↓
Evidence
    ↓
Gemini
    ↓
Grounded Recommendation
```

The AI receives known facts from the system.

It does not determine:

```text
Incident grouping
Correlation score
Priority
Topology
Incident IDs
```

This keeps the critical network intelligence deterministic.

---

# 16. Deterministic vs AI Architecture

This separation is one of the most important design decisions in NetSentry-AI.

## Deterministic Layer

The following operations do not require an LLM:

```text
Alert validation
Alert normalization
Fingerprinting
Deduplication
Topology relationships
Correlation scoring
Incident grouping
Priority calculation
Incident IDs
Application state
```

Therefore:

```text
Same Input
    ↓
Same Processing
    ↓
Same Incident
    ↓
Same Priority
```

---

## AI Layer

Gemini is used for:

```text
Semantic runbook retrieval
Grounded natural-language explanation
AI recommendation
Natural-language assistance
```

The AI operates on evidence generated by the deterministic system.

---

# 17. Evidence-Backed Recommendation

A recommendation contains structured information such as:

```json
{
  "incident_id": "INC-0001",
  "priority": "CRITICAL",
  "summary": "Core network connectivity failure detected.",
  "what_happened": "Multiple related alerts indicate a cascading network failure.",
  "affected_devices": [
    "CORE-R1",
    "SW-S1",
    "SW-S2"
  ],
  "recommended_actions": [
    "Verify core router interface status",
    "Check upstream connectivity",
    "Inspect downstream device reachability"
  ],
  "evidence": [
    {
      "runbook": "core_router_failure.md",
      "section": "Initial Checks"
    }
  ],
  "confidence": "high",
  "needs_escalation": false
}
```

The dashboard clearly distinguishes:

```text
DETERMINISTIC SYSTEM FACTS
```

from:

```text
AI-GENERATED EXPLANATION
```

---

# 18. Human Escalation

NetSentry-AI is designed not only to answer, but also to know when it should not answer.

Escalation can occur when:

* No matching runbook exists
* Evidence is empty
* Alert types are unknown and uncovered
* A high-priority incident has low confidence
* A multi-device incident has weak correlation
* The blast radius is large but evidence is insufficient
* Gemini is unavailable and deterministic evidence is insufficient
* The recommendation explicitly requires escalation

The escalation payload includes:

```text
Incident ID
Reason
Summary
Grouped Alerts
Already Suggested Actions
Next Step
Correlation Score
Correlation Reasons
Priority
Affected Devices
First Seen
Last Seen
```

The standard next step is:

```text
Manual NOC investigation required
```

---

# 19. Graceful AI Failure

Gemini is optional.

If Gemini is available:

```text
Gemini
   ↓
Semantic Retrieval
   ↓
FAISS
   ↓
Grounded Recommendation
```

If Gemini is unavailable:

```text
Gemini unavailable
       ↓
Local keyword/runbook matching
       ↓
Deterministic recommendation
       ↓
Escalation if evidence is insufficient
```

The NOC application should continue operating even when the Gemini API is unavailable.

This prevents the AI dependency from becoming a single point of failure.

---

# 20. Ask NetSentry

The application includes a natural-language NOC assistant.

Operators can ask:

```text
Why is INC-0001 critical?

What devices are affected?

Which alerts were grouped?

What should I check first?

Which runbook was selected?

Why was this incident escalated?

What is the highest priority incident?
```

Ask NetSentry operates over the application's live state:

```text
Incidents
Priorities
Alerts
Correlation Evidence
Runbook Evidence
Recommendations
Escalations
```

The natural-language layer is not allowed to invent incident information.

---

# 21. NOC Dashboard

NetSentry-AI provides a dark, mission-control-style NOC dashboard.

The dashboard includes:

## Overview

```text
Network Health
Active Incidents
Critical Incidents
Total Alerts
Alert Stream
```

## Live Alerts

Displays incoming and processed network events.

## Incidents

Displays:

```text
Incident ID
Priority
Score
Affected Devices
Alert Count
First Seen
Last Seen
Status
```

## Incident Details

Displays:

```text
Grouped Alerts
Correlation Score
Correlation Reasons
Priority Breakdown
Affected Devices
Timeline
Runbook Evidence
AI Recommendation
Escalation Status
```

## Network Topology

Displays the network graph and affected devices.

## AI Analysis

Displays:

```text
What Happened
Why It Matters
Recommended Actions
Evidence
Confidence
Escalation
```

## Ask NetSentry

Allows operators to query the incident intelligence system using natural language.

---

# 22. Backend Architecture

```text
src/
│
├── config.py
│   └── Application configuration, paths, environment variables
│
├── models.py
│   └── Pydantic data models and schemas
│
├── topology.py
│   └── Network graph and topology relationships
│
├── generator.py
│   └── Deterministic telecom alert scenarios
│
├── processor.py
│   └── Validation, normalization, fingerprinting and deduplication
│
├── scorer.py
│   └── Correlation scoring and incident grouping
│
├── priority.py
│   └── Incident impact and priority calculation
│
├── runbook_engine.py
│   └── Runbook loading, chunking, retrieval and grounded AI
│
├── escalation.py
│   └── Human escalation decisions and payload generation
│
├── nlp_handler.py
│   └── Ask NetSentry intent handling
│
├── database.py
│   └── In-memory application StateStore
│
└── api.py
    └── FastAPI endpoints
```

---

# 23. Frontend Architecture

```text
frontend/
│
├── index.html
│   └── Dashboard structure
│
├── style.css
│   └── NOC mission-control styling
│
├── data.js
│   └── Backend API data layer
│
└── app.js
    └── UI rendering, filtering, topology,
       alerts, AI panel, timeline and Ask NetSentry
```

The frontend is served directly by FastAPI.

No separate frontend server is required.

---

# 24. Complete Project Structure

```text
NetSentry-AI/
│
├── app.py
├── requirements.txt
├── README.md
│
├── src/
│   ├── __init__.py
│   ├── config.py
│   ├── models.py
│   ├── topology.py
│   ├── generator.py
│   ├── database.py
│   ├── processor.py
│   ├── scorer.py
│   ├── priority.py
│   ├── runbook_engine.py
│   ├── escalation.py
│   ├── nlp_handler.py
│   └── api.py
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   ├── data.js
│   └── app.js
│
├── data/
│   ├── topology.json
│   ├── sample_alerts.json
│   ├── runbooks/
│   │   ├── link_down.md
│   │   ├── device_unreachable.md
│   │   ├── packet_loss.md
│   │   ├── high_latency.md
│   │   ├── auth_failure.md
│   │   ├── core_router_failure.md
│   │   ├── switch_failure.md
│   │   └── multi_device_cascade.md
│   │
│   └── faiss_index/
│
└── tests/
    ├── test_generator.py
    ├── test_processor.py
    ├── test_scorer.py
    ├── test_priority.py
    ├── test_escalation.py
    └── ...
```

---

# 25. Technology Stack

| Layer                | Technology                    |
| -------------------- | ------------------------------ |
| Backend              | Python 3.11+                  |
| API                  | FastAPI                       |
| Server               | Uvicorn                       |
| Data Validation      | Pydantic                      |
| Frontend             | HTML5 + CSS3 + JavaScript     |
| Vector Search        | FAISS                         |
| Numerical Processing | NumPy                         |
| Embeddings           | Gemini `gemini-embedding-001` |
| AI Generation        | Gemini                        |
| Configuration        | python-dotenv                 |
| Testing              | Pytest                        |
| Topology             | JSON + Python                 |
| State Management     | In-memory StateStore          |
| External AI API      | Gemini only                   |

The application does not require:

```text
Docker
Kubernetes
PostgreSQL
Redis
npm
External Vector Database
```

---

# 26. Demo Network

The project uses a deterministic demonstration topology:

```text
                         INTERNET
                            │
                            ▼
                         CORE-R1
                        /       \
                       /         \
                   SW-S1         SW-S2
                  /     \       /     \
             ACC-R3  ACC-R4 ACC-R5  ACC-R6
```

The topology is defined in:

```text
data/topology.json
```

The project contains 9 topology nodes and 9 links, including the internet edge, core routers, switches, and access routers.

---

# 27. Demo Scenarios

NetSentry-AI provides deterministic scenarios for repeatable demonstrations.

## Scenario 1 — Duplicate Alerts

Purpose:

```text
Demonstrate alert noise reduction
```

Flow:

```text
Multiple Collectors
       ↓
Same Underlying Event
       ↓
Fingerprinting
       ↓
Deduplication
       ↓
One Meaningful Event
```

---

## Scenario 2 — Cascade Failure

This is the primary demonstration scenario.

```text
CORE-R1
   │
   ├──── SW-S1
   │       ├── ACC-R3
   │       └── ACC-R4
   │
   └──── SW-S2
           ├── ACC-R5
           └── ACC-R6
```

The system demonstrates:

```text
Raw Alerts
    ↓
Deduplication
    ↓
Topology Correlation
    ↓
Incident Grouping
    ↓
Priority Calculation
    ↓
Runbook Retrieval
    ↓
AI Recommendation
```

The deterministic fixture contains:

```text
26 cascade alerts
7 affected devices
```

The resulting major incident is designed to demonstrate high-impact/critical incident triage.

---

## Scenario 3 — Unknown Escalation

Purpose:

```text
Demonstrate responsible AI behavior
```

Flow:

```text
Unknown Alert
      ↓
No Matching Runbook
      ↓
Insufficient Evidence
      ↓
Human Escalation
```

The system does not invent a troubleshooting procedure.

---

# 28. API Architecture

NetSentry-AI exposes a REST API through FastAPI.

| Method   | Endpoint                       | Purpose                         |
| -------- | ------------------------------- | -------------------------------- |
| GET      | `/api/health`                  | Application health              |
| GET      | `/api/topology`                | Network topology                |
| GET      | `/api/runbooks`                | Available runbooks              |
| GET      | `/api/statistics`              | NOC statistics                  |
| GET      | `/api/alerts`                  | Raw alerts                      |
| GET      | `/api/processed`               | Deduplicated alerts             |
| GET      | `/api/incidents`               | Incident list                   |
| GET      | `/api/incidents/{incident_id}` | Full incident details           |
| POST     | `/api/process`                 | Process a scenario or alert set |
| POST     | `/api/analyze/{incident_id}`   | Analyze an incident             |
| POST     | `/api/ask`                     | Ask NetSentry                   |
| GET/POST | `/api/escalate/{incident_id}`  | Retrieve or trigger escalation  |

Interactive API documentation:

```text
http://localhost:8000/docs
```

---

# 29. Installation

## Requirements

```text
Python 3.11+
pip
```

Clone the repository:

```bash
git clone https://github.com/muhil-amuthan/NetSentry-AI.git
```

Enter the project:

```bash
cd NetSentry-AI
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# 30. Gemini Configuration

Gemini is optional.

To enable semantic retrieval and grounded AI generation, configure:

```text
GEMINI_API_KEY
```

### Windows PowerShell

```powershell
$env:GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
```

### Linux / macOS

```bash
export GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
```

Optional configuration:

```bash
GEMINI_MODEL_EMBEDDING=gemini-embedding-001
GEMINI_MODEL_GENERATION=gemini-2.0-flash
NETSENTRY_HOST=0.0.0.0
NETSENTRY_PORT=8000
NETSENTRY_SCENARIO=all
```

Never commit the API key to GitHub.

All Gemini calls are handled server-side.

The frontend never receives the Gemini API key.

---

# 31. Run the Application

The entire application can be started with:

```bash
pip install -r requirements.txt && python app.py
```

Then open:

```text
http://localhost:8000
```

Useful URLs:

```text
Dashboard:
http://localhost:8000

Health:
http://localhost:8000/api/health

API Documentation:
http://localhost:8000/docs
```

The frontend is served directly by FastAPI.

No `npm install` or separate frontend server is required.

---

# 32. Demo Data Commands

View available scenarios:

```bash
python -m src.generator --summary
```

Run the cascade failure scenario:

```bash
python -m src.generator --scenario cascade_failure
```

Generate JSON output:

```bash
python -m src.generator --scenario cascade_failure --format json
```

Regenerate deterministic sample data:

```bash
python -m src.generator --write
```

The sample data is deterministic and reproducible.

---

# 33. Testing

Run the complete test suite:

```bash
pytest -q
```

The test suite covers the major project components, including:

```text
Topology
Alert Generator
Alert Normalization
Fingerprinting
Deduplication
Correlation
Incident Grouping
Priority
Runbooks
Escalation
API
Application Shell
Edge Cases
Determinism
Failure Handling
```

The final project includes extensive automated coverage across the deterministic processing pipeline.

---

# 34. Determinism

The core incident intelligence is designed to be reproducible.

The deterministic layers do not depend on:

```text
Random numbers
Current wall-clock time
Random UUIDs
External APIs
LLM decisions
```

Therefore:

```text
Same Input
     ↓
Same Processing
     ↓
Same Correlation
     ↓
Same Incident
     ↓
Same Priority
```

This makes the project easier to test, debug, and demonstrate.

---

# 35. Failure Handling

NetSentry-AI is designed to fail gracefully.

### Gemini unavailable

```text
Gemini unavailable
       ↓
Local retrieval
       ↓
Deterministic recommendation
       ↓
Escalate if confidence is insufficient
```

### Unknown alert type

```text
Unknown alert
       ↓
Preserve alert
       ↓
Attempt safe processing
       ↓
No invented runbook
       ↓
Escalation when required
```

### No matching runbook

```text
Incident
   ↓
No evidence
   ↓
Do not hallucinate
   ↓
Escalate
```

---

# 36. Security

NetSentry-AI follows basic security practices for the prototype.

* Gemini API keys are provided through environment variables.
* `.env` is not committed.
* API keys are never exposed to frontend JavaScript.
* Gemini calls are performed server-side.
* Secrets are not included in demo data.
* The system does not require an external database or vector service.
* The AI layer is not trusted to invent network facts.

---

# 37. Why the Architecture Matters

A key design decision is that the LLM is **not responsible for the most critical network decisions**.

Instead:

```text
                    NETWORK FACTS
                         │
                         ▼
              ┌─────────────────────┐
              │ DETERMINISTIC CORE  │
              ├─────────────────────┤
              │ Deduplication       │
              │ Correlation         │
              │ Topology            │
              │ Incident Grouping   │
              │ Priority            │
              └──────────┬──────────┘
                         │
                         ▼
                     EVIDENCE
                         │
                         ▼
              ┌─────────────────────┐
              │       GEMINI        │
              ├─────────────────────┤
              │ Explain             │
              │ Recommend           │
              │ Retrieve            │
              │ Assist              │
              └──────────┬──────────┘
                         │
                         ▼
                 GROUNDED RESPONSE
```

This architecture provides:

```text
Consistency
+
Explainability
+
Grounding
+
Graceful Failure
```

---

# 38. What Makes NetSentry-AI Different?

Traditional alert systems often produce:

```text
Alert
Alert
Alert
Alert
Alert
Alert
Alert
Alert
```

NetSentry-AI attempts to produce:

```text
                    INCIDENT
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       Impact       Evidence     Priority
          │            │            │
          ▼            ▼            ▼
      Devices       Runbook      CRITICAL
          │            │            │
          └────────────┼────────────┘
                       ▼
              Recommended Actions
                       │
                       ▼
               Human Escalation
                if necessary
```

The goal is not simply to use AI.

The goal is to make AI useful **after the system has established reliable network evidence**.

---

# 39. PS07 Requirement Mapping

| PS07 Requirement         | NetSentry-AI Implementation                                             |
| ------------------------- | ------------------------------------------------------------------------ |
| Network alert ingestion  | Alert generator + API                                                   |
| Familiar telecom alerts  | LINK_DOWN, DEVICE_UNREACHABLE, PACKET_LOSS, HIGH_LATENCY, AUTH_FAILURE  |
| Duplicate grouping       | Deterministic fingerprint + deduplication                               |
| Related alert grouping   | Topology-aware correlation                                              |
| Incident creation        | Connected-component grouping                                            |
| Impact prioritization    | Deterministic priority engine                                           |
| Troubleshooting runbooks | Local project-created runbooks                                          |
| Runbook retrieval        | FAISS + Gemini embeddings                                               |
| Grounded recommendations | Gemini using retrieved evidence                                         |
| Citations/evidence       | Runbook evidence in recommendation                                      |
| Unknown incidents        | Safe handling + escalation                                              |
| Human escalation         | Structured escalation payload                                           |
| Explainability           | Score breakdowns + reasons                                              |
| Structured output        | JSON/API models                                                         |
| Working application      | FastAPI + dashboard                                                     |
| Reproducible scenarios   | Deterministic demo fixtures                                             |
| Graceful AI failure      | Local fallback + escalation                                             |

---

# 40. Complete Demo Flow

The recommended demonstration flow is:

```text
1. Open NetSentry-AI
             ↓
2. Show NOC dashboard
             ↓
3. Select Cascade Failure
             ↓
4. Network alerts appear
             ↓
5. Duplicate observations are collapsed
             ↓
6. Related alerts are correlated
             ↓
7. Incident INC-0001 is created
             ↓
8. Priority score is calculated
             ↓
9. Incident becomes Critical/High based on evidence
             ↓
10. Show affected devices on topology
             ↓
11. Open incident details
             ↓
12. Show correlation score and reasons
             ↓
13. Show priority breakdown
             ↓
14. Retrieve relevant runbook
             ↓
15. Show runbook evidence
             ↓
16. Generate grounded AI recommendation
             ↓
17. Ask NetSentry:
       "Why is this incident critical?"
             ↓
18. System explains using actual evidence
             ↓
19. Load Unknown Escalation scenario
             ↓
20. System finds insufficient evidence
             ↓
21. System refuses to invent an answer
             ↓
22. Incident is escalated to the NOC engineer
```

---

# 41. Project Goals

NetSentry-AI is designed to demonstrate how an intelligent NOC system can combine:

```text
Network Engineering
        +
Deterministic Algorithms
        +
Topology Intelligence
        +
Information Retrieval
        +
Generative AI
        +
Human-in-the-Loop Safety
```

The project focuses on making incident triage:

```text
Faster
Clearer
More Explainable
More Grounded
More Reliable
```

---

# 42. Future Enhancements

Potential future improvements include:

* Real-time SNMP integration
* Syslog ingestion
* Streaming alert processing
* Real network device integration
* Historical incident analytics
* Root-cause analysis
* Predictive failure detection
* Operator feedback loops
* Incident ticketing integration
* Role-based NOC access
* Enterprise monitoring integration
* Larger telecom knowledge bases

These are outside the current prototype scope.

---

# 43. Final Architecture Summary

The complete NetSentry-AI architecture can be summarized as:

```text
┌─────────────────────────────────────────────────────┐
│                  TELECOM ALERTS                     │
└────────────────────────┬────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────┐
│                 ALERT PROCESSOR                     │
│          Validate → Normalize → Fingerprint         │
└────────────────────────┬────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────┐
│                  DEDUPLICATION                      │
│                  60 Second Window                   │
└────────────────────────┬────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────┐
│              TOPOLOGY-AWARE CORRELATION             │
│                                                     │
│ Same Device + Related Device + Time + Alert Type   │
└────────────────────────┬────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────┐
│                  INCIDENT BUILDER                   │
│              INC-0001, INC-0002 ...                 │
└────────────────────────┬────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────┐
│                  PRIORITY ENGINE                    │
│          Impact + Severity + Volume + Duration      │
└────────────────────────┬────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────┐
│                  RUNBOOK ENGINE                     │
│              Local Docs + FAISS + Gemini            │
└────────────────────────┬────────────────────────────┘
                         ▼
                ┌────────┴────────┐
                ▼                 ▼
┌────────────────────────┐  ┌────────────────────────┐
│   GROUNDED AI          │  │   HUMAN ESCALATION     │
│   RECOMMENDATION       │  │   WHEN NEEDED          │
└────────────┬───────────┘  └────────────┬───────────┘
             │                           │
             └─────────────┬─────────────┘
                           ▼
                ┌─────────────────────┐
                │   ASK NETSENTRY     │
                └──────────┬──────────┘
                           ▼
                ┌─────────────────────┐
                │    NOC DASHBOARD    │
                └─────────────────────┘
```

---

# 44. Final Statement

NetSentry-AI is built around a simple idea:

> **Don't just show the NOC engineer more alerts. Show them the incident, explain why it matters, provide evidence for what to do next, and know when to ask a human for help.**

```text
Alert Noise
     ↓
Signal
     ↓
Incident
     ↓
Impact
     ↓
Evidence
     ↓
Action
     ↓
Human Escalation When Necessary
```

---

## Built For

**PS07 — Telecom Network Incident Triage Assistant**

## Project

**NetSentry-AI**

## Technology

```text
Python
FastAPI
FAISS
Gemini
NumPy
JavaScript
HTML
CSS
Pytest
```

---

**NetSentry-AI**

### From Alert Noise to Actionable Network Intelligence.
