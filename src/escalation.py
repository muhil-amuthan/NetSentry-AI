"""
Human Escalation Engine (Step 11).

Decides when automation must stop and a human NOC engineer must take over,
and constructs the escalation payload that explains what happened, what was
grouped, what was already suggested, and why automation stopped.

Escalation is deterministic and never hallucinates an answer when evidence
is insufficient.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Any

from src.scorer import CandidateIncident
from src.priority import PriorityResult
from src.runbook_engine import RunbookMatch

# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------

def should_escalate(
    incident: CandidateIncident,
    priority: Optional[PriorityResult] = None,
    evidence: Optional[List[RunbookMatch]] = None,
    recommendation: Optional[Dict[str, Any]] = None,
) -> tuple[bool, str]:
    """
    Determine whether an incident should be escalated.
    Returns (escalated: bool, reason: str).

    Conditions (any true → escalate):
      * no suitable runbook / evidence empty
      * evidence is insufficient (single low-score match and confidence low)
      * AI cannot provide grounded recommendation (recommendation needs_escalation)
      * incident is ambiguous (UNKNOWN alert types, zero correlation but high priority)
      * Gemini unavailable and deterministic fallback confidence insufficient for HIGH/CRITICAL
      * incident requires human investigation (explicit via recommendation)
    """
    evidence = evidence or []
    reasons: List[str] = []

    # 1. No matching runbook
    if not evidence:
        reasons.append("No matching runbook found")

    # 2. Recommendation explicitly asks for escalation
    if recommendation is not None:
        if recommendation.get("needs_escalation"):
            r = recommendation.get("escalation_reason") or "Recommendation indicates escalation"
            if r not in reasons:
                reasons.append(r)
        # If recommendation has no evidence and confidence low
        if not recommendation.get("evidence") and not evidence:
            if "No matching runbook found" not in reasons:
                reasons.append("No evidence available for grounded recommendation")

    # 3. UNKNOWN alert types → uncovered
    incident_types = {av.alert_type.upper() if isinstance(av.alert_type, str) else str(av.alert_type).upper() for av in incident.alerts}
    if "UNKNOWN" in incident_types:
        # If evidence empty already flagged, but also if low confidence
        if not evidence:
            # already escalated, ensure reason mentions uncovered type
            if not any("UNKNOWN" in rr or "uncovered" in rr.lower() for rr in reasons):
                reasons.append("Uncovered alert types (UNKNOWN) require human triage")
        else:
            # Has some evidence but still UNKNOWN dominant and confidence low
            if recommendation and recommendation.get("confidence") == "low":
                reasons.append("Uncovered alert type with low confidence — human investigation required")

    # 4. Insufficient evidence for high priority incidents
    if priority is not None and priority.priority in ("CRITICAL", "HIGH"):
        if recommendation and recommendation.get("confidence") == "low":
            # Check if deterministic fallback
            if recommendation.get("_source") == "deterministic":
                reasons.append("Low confidence deterministic recommendation for high priority incident — Gemini unavailable or insufficient evidence")
            else:
                # Even with Gemini, low confidence high priority should escalate
                if not any("confidence" in rr.lower() for rr in reasons):
                    reasons.append("High priority incident with low confidence")
        # Also if correlation is weak but priority high (ambiguous grouping)
        if incident.correlation_score == 0 and len(incident.alert_ids) == 1 and priority.priority in ("MEDIUM", "HIGH"):
            # Single isolated alert with medium priority but no correlation — maybe ambiguous but not necessarily escalation unless UNKNOWN
            pass

    # 5. Ambiguous multi-root: many devices but correlation low
    if len(incident.affected_devices) >= 3 and incident.correlation_score < 20:
        if not evidence:
            reasons.append("Ambiguous multi-device incident with weak correlation and no runbook")
        elif len(evidence) == 1 and evidence[0].score < 0.3:
            reasons.append("Ambiguous incident — weak evidence for large blast radius")

    # 6. Gemini unavailable fallback insufficient
    if recommendation and recommendation.get("_source") == "deterministic" and not evidence:
        if "No matching runbook found" not in reasons:
            reasons.append("Deterministic fallback cannot provide grounded recommendation without runbook evidence")

    if reasons:
        return True, "; ".join(reasons)
    return False, ""


def build_escalation(
    incident: CandidateIncident,
    priority: Optional[PriorityResult] = None,
    evidence: Optional[List[RunbookMatch]] = None,
    recommendation: Optional[Dict[str, Any]] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build the escalation payload for an incident.
    Always contains what happened, what was grouped, what was already suggested,
    and why automation stopped.
    """
    escalated, auto_reason = should_escalate(incident, priority, evidence, recommendation)
    final_reason = reason or auto_reason or "Escalation requested"
    if not escalated and reason is None:
        # If caller forced escalation payload but shouldn't auto-escalate, still allow explicit reason
        escalated = True

    # Gather grouped alerts info
    grouped_alerts = []
    for av in incident.alerts:
        src = av.source
        msg = ""
        sev = "UNKNOWN"
        if hasattr(src, "representative"):
            msg = getattr(src.representative, "message", "")
            sev_obj = getattr(src.representative, "severity", "UNKNOWN")
            sev = sev_obj.value if hasattr(sev_obj, "value") else str(sev_obj)
        elif hasattr(src, "message"):
            msg = getattr(src, "message", "")
            sev_obj = getattr(src, "severity", "UNKNOWN")
            sev = sev_obj.value if hasattr(sev_obj, "value") else str(sev_obj)
        grouped_alerts.append({
            "alert_id": av.alert_id,
            "device_id": av.device_id,
            "alert_type": av.alert_type,
            "severity": sev,
            "timestamp": av.timestamp.isoformat() if hasattr(av.timestamp, "isoformat") else str(av.timestamp),
            "message": msg[:200],
        })

    # Already suggested actions (from recommendation if any)
    already_suggested: List[str] = []
    if recommendation:
        already_suggested = recommendation.get("recommended_actions", []) or []
        # Also include evidence tried
        if not already_suggested and recommendation.get("evidence"):
            already_suggested = [f"Consulted {e.get('runbook')} section {e.get('section')}" for e in recommendation.get("evidence", [])]

    # Summary of what happened
    type_set = sorted({av.alert_type for av in incident.alerts})
    summary = f"Incident {incident.incident_id} grouped {len(incident.alert_ids)} alerts of types {', '.join(type_set)} across {len(incident.affected_devices)} devices ({', '.join(incident.affected_devices) if incident.affected_devices else 'unknown'}). First seen {incident.first_seen.isoformat()}, last seen {incident.last_seen.isoformat()}."
    if recommendation and recommendation.get("what_happened"):
        summary = recommendation.get("what_happened", summary)

    # Priority context
    priority_label = priority.priority if priority else "UNKNOWN"
    priority_score = priority.score if priority else None

    payload: Dict[str, Any] = {
        "escalated": True,
        "reason": final_reason,
        "incident_id": incident.incident_id,
        "summary": summary,
        "affected_devices": list(incident.affected_devices),
        "grouped_alerts": grouped_alerts,
        "already_suggested": already_suggested,
        "next_step": "Manual NOC investigation required",
        "priority": priority_label,
        "priority_score": priority_score,
        "correlation_score": incident.correlation_score,
        "correlation_reasons": list(incident.correlation_reasons),
        "alert_count": len(incident.alert_ids),
        "first_seen": incident.first_seen.isoformat() if hasattr(incident.first_seen, "isoformat") else str(incident.first_seen),
        "last_seen": incident.last_seen.isoformat() if hasattr(incident.last_seen, "isoformat") else str(incident.last_seen),
    }

    # Add escalation-specific metadata
    if recommendation and recommendation.get("confidence"):
        payload["confidence"] = recommendation.get("confidence")

    return payload


def build_non_escalation(incident: CandidateIncident) -> Dict[str, Any]:
    """Helper for incidents that do NOT need escalation."""
    return {
        "escalated": False,
        "reason": "",
        "incident_id": incident.incident_id,
        "summary": f"Incident {incident.incident_id} has sufficient evidence and does not require escalation",
        "affected_devices": list(incident.affected_devices),
        "grouped_alerts": [],
        "already_suggested": [],
        "next_step": "Follow AI recommendation",
    }


__all__ = [
    "should_escalate",
    "build_escalation",
    "build_non_escalation",
]
