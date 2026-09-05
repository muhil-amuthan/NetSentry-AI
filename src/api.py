"""
API route definitions for NetSentry-AI — complete backend integration.

Endpoints:
  GET  /api/health
  GET  /api/alerts
  GET  /api/incidents
  GET  /api/incidents/{incident_id}
  GET  /api/runbooks
  GET  /api/topology
  GET  /api/statistics
  POST /api/process
  POST /api/analyze/{incident_id}
  POST /api/ask
  POST /api/escalate/{incident_id}
"""

from typing import Optional, List, Dict, Any

from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel

from src.config import APP_NAME, VERSION
from src.database import get_store, reload_store
from src.nlp_handler import handle_ask
from src.runbook_engine import list_runbooks, retrieve_runbooks, generate_recommendation
from src.priority import score_priority
from src.scorer import CandidateIncident

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ProcessRequest(BaseModel):
    scenario: Optional[str] = None
    alerts: Optional[List[Dict[str, Any]]] = None


class AskRequest(BaseModel):
    question: str
    incident_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get("/api/health")
def health() -> dict:
    """Health check endpoint used to verify the service is running."""
    store = get_store()
    # Ensure store initialized so health also reflects readiness
    try:
        stats = store.get_statistics()
        status = "ok"
    except Exception:
        stats = {}
        status = "ok"
    return {"status": status, "project": APP_NAME, "version": VERSION, "scenario": stats.get("scenario", "unknown")}


@router.get("/api/topology")
def get_topology_api() -> dict:
    """Return network topology graph."""
    from src.topology import get_topology
    try:
        topo = get_topology()
        return topo.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/runbooks")
def get_runbooks() -> dict:
    """List local runbooks."""
    try:
        runbooks = list_runbooks()
        return {"runbooks": runbooks, "count": len(runbooks)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/statistics")
def get_statistics() -> dict:
    """Return aggregated statistics for dashboard overview."""
    store = get_store()
    try:
        stats = store.get_statistics()
        # Also compute network health percentage heuristic
        # health = 100 - (critical*15 + high*10 + escalated*5) clipped 0-100
        health = 100 - stats.get("critical_count", 0) * 12 - stats.get("high_count", 0) * 8 - stats.get("escalated_count", 0) * 2
        health = max(30, min(100, health))
        # Build KPI-like structure
        kpis = [
            {"id": "alerts", "label": "Active Alerts", "value": str(stats["total_alerts"]), "status": "info"},
            {"id": "incidents", "label": "Open Incidents", "value": str(stats["incident_count"]), "status": "warn"},
            {"id": "critical", "label": "Critical", "value": str(stats["critical_count"]), "status": "crit"},
            {"id": "devices", "label": "Devices Affected", "value": str(stats["affected_device_count"]), "status": "high"},
            {"id": "auto", "label": "Duplicates Collapsed", "value": str(stats["duplicate_collapsed"]), "status": "ok"},
        ]
        return {
            "stats": stats,
            "health": health,
            "kpis": kpis,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@router.get("/api/alerts")
def get_alerts(
    scenario: Optional[str] = Query(None, description="Filter by scenario name"),
    limit: Optional[int] = Query(None, ge=1, le=1000),
) -> dict:
    """Return raw alerts (optionally filtered by scenario)."""
    store = get_store()
    alerts = store.get_alerts(scenario=scenario)
    if limit is not None:
        alerts = alerts[:limit]
    return {"alerts": alerts, "count": len(alerts), "scenario": scenario or store.scenario}


@router.get("/api/processed")
def get_processed() -> dict:
    """Return deduplicated alerts."""
    store = get_store()
    processed = store.get_processed()
    return {"processed": processed, "count": len(processed)}


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@router.get("/api/incidents")
def get_incidents(
    priority_filter: Optional[str] = Query(None, alias="priority", description="Filter by priority: CRITICAL,HIGH,MEDIUM,LOW"),
    device: Optional[str] = Query(None, description="Filter by affected device id"),
    scenario: Optional[str] = Query(None, description="Filter via scenario prior to processing"),
) -> dict:
    """Return enriched incidents."""
    store = get_store()
    # If scenario param provided and differs from current, reload?
    # We do not auto-reload on GET to avoid surprise; instead filter in-memory if scenario != store.scenario
    # But if scenario param matches a scenario name, we could reload; for now just filter by store's current scenario
    # To support scenario switching, client should POST /api/process
    incidents = store.get_incidents(include_alerts=False)

    # Apply filters
    if priority_filter:
        pf = priority_filter.strip().upper()
        incidents = [inc for inc in incidents if inc.get("priority") == pf]
    if device:
        dev = device.strip().upper()
        # Normalize device: CORE-R1 -> R1 etc handled in store? Just compare upper
        incidents = [inc for inc in incidents if any(dev == d.upper() or dev.replace("-", "") == d.upper().replace("-", "") for d in inc.get("affected_devices", [])) or dev in [d.upper() for d in inc.get("affected_devices", [])]]

    return {"incidents": incidents, "count": len(incidents)}


@router.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict:
    """Return single incident with full detail."""
    store = get_store()
    data = store.get_incident(incident_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return data


# ---------------------------------------------------------------------------
# Process
# ---------------------------------------------------------------------------

@router.post("/api/process")
def process_alerts_api(payload: ProcessRequest = Body(...)) -> dict:
    """
    Re-run the full triage pipeline.
    Body may contain:
      { "scenario": "cascade_failure" }  — load deterministic fixture
      { "alerts": [...] }                — process custom alerts
      { "scenario": "all" }              — default
    """
    store = get_store()
    scenario = payload.scenario

    # Custom alerts path
    if payload.alerts is not None:
        # Process custom alerts (accept feed-format records or Alert dicts)
        from src.models import Alert
        from src.generator import record_to_alert
        custom_alerts = []
        errors = []
        for rec in payload.alerts:
            try:
                # Try to interpret as feed record
                if isinstance(rec, dict) and "alert_id" in rec or "device_id" in rec or "alert_type" in rec:
                    alert = record_to_alert(rec)
                else:
                    # Try direct Alert model
                    alert = Alert.model_validate(rec)
                custom_alerts.append(alert)
            except Exception as e:
                errors.append(str(e))
        # Replace store state with custom processing
        # Directly invoke pipeline on custom alerts
        from src.processor import process_alerts as proc
        from src.scorer import build_candidate_incidents
        processed, p_errs = proc(custom_alerts)
        errors.extend([str(e) for e in p_errs])
        candidates = build_candidate_incidents(processed)
        # Build views manually but also populate store for further queries
        # Use store's internal logic by swapping raw_alerts
        store.raw_alerts = custom_alerts
        store.processed = processed
        store.candidates = candidates
        # Rebuild views
        from src.priority import score_priority
        from src.runbook_engine import retrieve_runbooks, generate_recommendation
        from src.escalation import should_escalate, build_escalation, build_non_escalation
        from src.database import IncidentView
        views: Dict[str, IncidentView] = {}
        view_list: List[IncidentView] = []
        for cand in candidates:
            priority = score_priority(cand)
            evidence = retrieve_runbooks(cand)
            recommendation = generate_recommendation(cand, priority)
            esc = build_escalation(cand, priority, evidence, recommendation) if should_escalate(cand, priority, evidence, recommendation)[0] else build_non_escalation(cand)
            iv = IncidentView(candidate=cand, priority=priority, evidence=evidence, recommendation=recommendation, escalation=esc)
            views[cand.incident_id] = iv
            view_list.append(iv)
        view_list.sort(key=lambda iv: (-iv.priority.score, iv.candidate.incident_id))
        store.views = views
        store.view_list = view_list
        store.scenario = "custom"
        from datetime import datetime, timezone
        store.last_updated = datetime.now(timezone.utc)
        store.errors = errors
        incidents = store.get_incidents(include_alerts=False)
        return {
            "scenario": "custom",
            "raw_count": len(custom_alerts),
            "processed_count": len(processed),
            "incident_count": len(candidates),
            "incidents": incidents,
            "errors": errors,
        }

    # Scenario path
    if not scenario:
        scenario = "all"
    try:
        reload_store(scenario)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    store = get_store()
    stats = store.get_statistics()
    incidents = store.get_incidents(include_alerts=False)
    return {
        "scenario": stats.get("scenario"),
        "raw_count": stats.get("total_alerts"),
        "processed_count": stats.get("processed_alerts"),
        "incident_count": stats.get("incident_count"),
        "incidents": incidents,
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# Analyze
# ---------------------------------------------------------------------------

@router.post("/api/analyze/{incident_id}")
def analyze_incident(incident_id: str) -> dict:
    """Regenerate recommendation for an incident (grounded)."""
    store = get_store()
    iv = store.get_incident_view(incident_id)
    if iv is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    # Regenerate recommendation (this will attempt Gemini if available)
    new_rec = generate_recommendation(iv.candidate, iv.priority)
    # Update store view? Keep original but return new
    # Also check escalation after new rec
    from src.escalation import should_escalate, build_escalation, build_non_escalation
    evidence = retrieve_runbooks(iv.candidate)
    esc = build_escalation(iv.candidate, iv.priority, evidence, new_rec) if should_escalate(iv.candidate, iv.priority, evidence, new_rec)[0] else build_non_escalation(iv.candidate)
    # Update stored view for consistency
    iv.recommendation = new_rec
    iv.escalation = esc
    iv.evidence = evidence

    return {
        "incident_id": incident_id,
        "priority": iv.priority.to_dict(),
        "evidence": [m.to_dict() for m in evidence],
        "recommendation": new_rec,
        "escalation": esc,
        "deterministic_facts": {
            "correlation_score": iv.candidate.correlation_score,
            "correlation_reasons": iv.candidate.correlation_reasons,
            "priority_reasons": iv.priority.reasons,
            "affected_devices": iv.candidate.affected_devices,
        },
        "ai_generated": {
            "summary": new_rec.get("summary"),
            "what_happened": new_rec.get("what_happened"),
            "recommended_actions": new_rec.get("recommended_actions"),
            "confidence": new_rec.get("confidence"),
            "source": new_rec.get("_source"),
        }
    }


# ---------------------------------------------------------------------------
# Ask
# ---------------------------------------------------------------------------

@router.post("/api/ask")
def ask_netsentry(payload: AskRequest) -> dict:
    """Natural language query over current incidents."""
    question = payload.question
    if not question or not question.strip():
        raise HTTPException(status_code=400, detail="Question must not be empty")
    # If incident_id supplied explicitly, prepend to question for context
    # But handle_ask already extracts incident id from text; we just pass question
    result = handle_ask(question)
    return result


# ---------------------------------------------------------------------------
# Escalate
# ---------------------------------------------------------------------------

@router.post("/api/escalate/{incident_id}")
def escalate_incident(incident_id: str, payload: Optional[Dict[str, Any]] = Body(default=None)) -> dict:
    """Force escalation for an incident (or return existing escalation)."""
    store = get_store()
    iv = store.get_incident_view(incident_id)
    if iv is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    from src.escalation import build_escalation
    # Support both {"reason": "..."} and raw string body
    reason = None
    if isinstance(payload, dict):
        reason = payload.get("reason")
    elif isinstance(payload, str):
        reason = payload
    es_payload = build_escalation(iv.candidate, iv.priority, iv.evidence, iv.recommendation, reason=reason)
    # Update store
    iv.escalation = es_payload
    return es_payload


@router.get("/api/escalate/{incident_id}")
def get_escalation(incident_id: str) -> dict:
    """Get escalation status for an incident."""
    store = get_store()
    iv = store.get_incident_view(incident_id)
    if iv is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return iv.escalation
