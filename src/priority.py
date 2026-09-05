"""
Incident Priority Engine (Step 7).

Deterministic, explainable prioritisation of candidate incidents produced by
the correlation engine. No LLM, no randomness.

Scoring uses four signals weighted to sum to 100:

* device_impact (40) — most critical role among affected devices
* severity      (30) — most severe alert severity in the incident
* alert_volume  (20) — number of alerts grouped
* duration      (10) — span between first_seen and last_seen

Priority bands:
  90-100 → CRITICAL
  70-89  → HIGH
  40-69  → MEDIUM
  0-39   → LOW
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from src.models import Alert, Severity
from src.processor import ProcessedAlert
from src.scorer import AlertView, CandidateIncident, as_alert_view
from src.topology import NetworkTopology, get_topology

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEVICE_ROLE_WEIGHTS: Dict[str, int] = {
    "core": 40,
    "distribution": 25,
    "access": 10,
    "unknown": 5,
}

SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 20,
    "LOW": 10,
    "INFO": 5,
}

PRIORITY_WEIGHTS: Dict[str, int] = {
    "device_impact": 40,
    "severity": 30,
    "alert_volume": 20,
    "duration": 10,
}

# Map topology layer values to role weight keys
_LAYER_TO_ROLE: Dict[str, str] = {
    "core": "core",
    "distribution": "distribution",
    "access": "access",
    "external": "unknown",
}

# Priority thresholds (inclusive lower bound)
_PRIORITY_THRESHOLDS = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (40, "MEDIUM"),
    (0, "LOW"),
]

# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PriorityResult:
    score: int
    priority: str
    signals: Dict[str, int]
    reasons: List[str]

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "priority": self.priority,
            "signals": dict(self.signals),
            "reasons": list(self.reasons),
        }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_severity(value) -> str:
    """Map any severity spelling to canonical upper-cased key."""
    if isinstance(value, Severity):
        return value.value.upper()
    if isinstance(value, str):
        s = value.strip().lower()
        # Use Severity.normalize to get canonical
        sev = Severity.normalize(value)
        return sev.value.upper()
    try:
        sev = Severity.normalize(value)
        return sev.value.upper()
    except Exception:
        return "INFO"


def _device_role_weight(device_id: str, topology: Optional[NetworkTopology]) -> Tuple[int, str]:
    """
    Return (weight, role_name) for a device.
    Uses topology layer when available, otherwise 'unknown'.
    """
    if topology is None:
        try:
            topology = get_topology()
        except Exception:
            topology = None
    if topology is not None and device_id in topology:
        node = topology.get_node(device_id)
        if node is not None:
            layer_val = node.layer.value if hasattr(node.layer, "value") else str(node.layer)
            role_key = _LAYER_TO_ROLE.get(layer_val.lower(), "unknown")
            weight = DEVICE_ROLE_WEIGHTS.get(role_key, DEVICE_ROLE_WEIGHTS["unknown"])
            return weight, role_key
    return DEVICE_ROLE_WEIGHTS["unknown"], "unknown"


def _severity_for_alert_view(view) -> str:
    """
    Extract severity string from an AlertView's source.
    Handles Alert, ProcessedAlert, AlertView, or any hybrid.
    """
    # Direct cases: view itself is Alert or ProcessedAlert
    if isinstance(view, ProcessedAlert):
        try:
            return _normalize_severity(view.representative.severity)
        except Exception:
            pass
    if isinstance(view, Alert):
        try:
            return _normalize_severity(view.severity)
        except Exception:
            pass
    # For AlertView-like, inspect source
    src = getattr(view, 'source', None)
    if isinstance(src, ProcessedAlert):
        try:
            sev = src.representative.severity
            return _normalize_severity(sev)
        except Exception:
            pass
    if isinstance(src, Alert):
        try:
            return _normalize_severity(src.severity)
        except Exception:
            pass
    if src is not None and hasattr(src, "severity"):
        try:
            return _normalize_severity(getattr(src, "severity"))
        except Exception:
            pass
    if hasattr(view, "severity"):
        try:
            return _normalize_severity(getattr(view, "severity"))
        except Exception:
            pass
    # Fallback: try to infer from type? default INFO
    return "INFO"


def _max_severity_weight(alert_views: Sequence[AlertView]) -> Tuple[int, str]:
    """Return (max_weight, severity_key) among alert views."""
    max_weight = 0
    max_key = "INFO"
    for v in alert_views:
        key = _severity_for_alert_view(v)
        w = SEVERITY_WEIGHTS.get(key, SEVERITY_WEIGHTS["INFO"])
        if w > max_weight:
            max_weight = w
            max_key = key
    if not alert_views:
        return SEVERITY_WEIGHTS["INFO"], "INFO"
    return max_weight, max_key


def _alert_volume_score(count: int) -> int:
    """Map alert count to 0-20 score."""
    if count >= 20:
        return 20
    if count >= 10:
        return 18
    if count >= 5:
        return 15
    if count >= 3:
        return 12
    if count == 2:
        return 8
    if count == 1:
        return 4
    return 0


def _duration_score(first_seen: datetime, last_seen: datetime) -> int:
    """Map incident span to 0-10 score."""
    try:
        delta = (last_seen - first_seen).total_seconds()
    except Exception:
        delta = 0
    if delta < 0:
        delta = 0
    if delta >= 1800:
        return 10
    if delta >= 600:
        return 8
    if delta >= 300:
        return 6
    if delta >= 60:
        return 4
    if delta >= 10:
        return 2
    if delta > 0:
        return 1
    return 0  # single point or zero span


def _classify_priority(score: int) -> str:
    for threshold, label in _PRIORITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"

# ---------------------------------------------------------------------------
# Core scoring
# ---------------------------------------------------------------------------

def score_priority(
    incident: CandidateIncident,
    *,
    topology: Optional[NetworkTopology] = None,
) -> PriorityResult:
    """
    Score a candidate incident deterministically.

    Returns a PriorityResult with total score 0-100, priority label, per-signal
    breakdown and human-readable reasons.
    """
    # Resolve topology lazily
    graph = topology
    if graph is None:
        try:
            graph = get_topology()
        except Exception:
            graph = None

    # --- device impact ---
    max_role_weight = 0
    max_role_name = "unknown"
    max_device = None
    for dev in incident.affected_devices:
        w, role = _device_role_weight(dev, graph)
        if w > max_role_weight:
            max_role_weight = w
            max_role_name = role
            max_device = dev
    # If no devices (empty incident) -> unknown 5
    if not incident.affected_devices:
        max_role_weight = DEVICE_ROLE_WEIGHTS["unknown"]
        max_role_name = "unknown"
    device_impact = min(max_role_weight, PRIORITY_WEIGHTS["device_impact"])

    # --- severity ---
    max_weight, max_sev_key = _max_severity_weight(incident.alerts)
    # Scale severity weight (max 40) to priority weight scale (max 30)
    severity_contrib = round((max_weight / 40) * PRIORITY_WEIGHTS["severity"])
    severity_contrib = min(severity_contrib, PRIORITY_WEIGHTS["severity"])

    # --- alert volume ---
    alert_volume = _alert_volume_score(len(incident.alert_ids))
    alert_volume = min(alert_volume, PRIORITY_WEIGHTS["alert_volume"])

    # --- duration ---
    duration = _duration_score(incident.first_seen, incident.last_seen)
    duration = min(duration, PRIORITY_WEIGHTS["duration"])

    total = device_impact + severity_contrib + alert_volume + duration
    total = max(0, min(100, total))
    priority_label = _classify_priority(total)

    signals = {
        "device_impact": device_impact,
        "severity": severity_contrib,
        "alert_volume": alert_volume,
        "duration": duration,
    }

    # Build reasons
    reasons: List[str] = []
    if max_device:
        reasons.append(f"Device impact: {max_role_name} device {max_device} affected: +{device_impact}")
    else:
        reasons.append(f"Device impact: {max_role_name}: +{device_impact}")

    reasons.append(f"Severity: highest severity {max_sev_key}: +{severity_contrib}")
    reasons.append(f"Alert volume: {len(incident.alert_ids)} alerts grouped: +{alert_volume}")

    # Duration reason with human span
    try:
        span_s = int((incident.last_seen - incident.first_seen).total_seconds())
    except Exception:
        span_s = 0
    if span_s >= 60:
        reasons.append(f"Incident duration: {span_s}s span: +{duration}")
    elif span_s > 0:
        reasons.append(f"Incident duration: {span_s}s span: +{duration}")
    else:
        reasons.append(f"Incident duration: single point: +{duration}")

    # Add extra context: affected device count if >1
    if len(incident.affected_devices) > 1:
        reasons.append(f"Affected devices: {len(incident.affected_devices)} devices ({', '.join(incident.affected_devices)}): included in device impact")

    # Add correlation score context
    reasons.append(f"Correlation score: {incident.correlation_score}")

    return PriorityResult(score=total, priority=priority_label, signals=signals, reasons=reasons)


def prioritize_incidents(
    incidents: Sequence[CandidateIncident],
    *,
    topology: Optional[NetworkTopology] = None,
) -> List[Tuple[CandidateIncident, PriorityResult]]:
    """
    Score a list of incidents and return them sorted by priority descending
    (highest score first, then incident_id for stability).
    """
    graph = topology
    if graph is None:
        try:
            graph = get_topology()
        except Exception:
            graph = None
    results: List[Tuple[CandidateIncident, PriorityResult]] = []
    for inc in incidents:
        pr = score_priority(inc, topology=graph)
        results.append((inc, pr))
    # Sort by score descending, then incident_id ascending for determinism
    results.sort(key=lambda x: (-x[1].score, x[0].incident_id))
    return results


__all__ = [
    "DEVICE_ROLE_WEIGHTS",
    "SEVERITY_WEIGHTS",
    "PRIORITY_WEIGHTS",
    "PriorityResult",
    "score_priority",
    "prioritize_incidents",
]
