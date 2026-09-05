"""
Persistence layer — in-memory state store for NetSentry-AI.

This is not a real database; it holds the last processed pipeline state in memory
so the API, NLP handler and frontend can query current incidents, priorities,
recommendations and escalations.

All operations are deterministic and synchronous. The store can be reset or
reloaded with a different scenario for demo purposes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Sequence
import threading

from src.models import Alert
from src.processor import ProcessedAlert, process_alerts
from src.scorer import CandidateIncident, build_candidate_incidents
from src.priority import PriorityResult, score_priority
from src.runbook_engine import RunbookMatch, retrieve_runbooks, generate_recommendation
from src.escalation import should_escalate, build_escalation, build_non_escalation


@dataclass
class IncidentView:
    """Enriched incident ready for API/frontend consumption."""
    candidate: CandidateIncident
    priority: PriorityResult
    evidence: List[RunbookMatch]
    recommendation: Dict[str, Any]
    escalation: Dict[str, Any]

    def to_dict(self, include_alerts: bool = True) -> dict:
        base = self.candidate.to_dict()
        base.update({
            "priority": self.priority.priority,
            "priority_score": self.priority.score,
            "priority_signals": dict(self.priority.signals),
            "priority_reasons": list(self.priority.reasons),
            "severity": self.priority.priority,  # alias for frontend
            "state": "open",  # default
            "devices": len(self.candidate.affected_devices),
            "title": self._title(),
            "summary": self.recommendation.get("summary", ""),
            "what_happened": self.recommendation.get("what_happened", ""),
            "affected_devices": list(self.candidate.affected_devices),
            "recommended_actions": self.recommendation.get("recommended_actions", []),
            "evidence": self.recommendation.get("evidence", []) or [m.to_dict() for m in self.evidence],
            "confidence": self.recommendation.get("confidence", "low"),
            "needs_escalation": self.recommendation.get("needs_escalation", False),
            "escalation": self.escalation,
            "escalated": self.escalation.get("escalated", False),
            "correlation_score": self.candidate.correlation_score,
            "correlation_reasons": list(self.candidate.correlation_reasons),
            # Deterministic ordering fields
            "alert_count": len(self.candidate.alert_ids),
            "correlated": len(self.candidate.alert_ids),
        })
        if include_alerts:
            alerts_info = []
            for av in self.candidate.alerts:
                src = av.source
                msg = ""
                sev = "INFO"
                source = "snmp"
                if hasattr(src, "representative"):
                    rep = src.representative  # type: ignore
                    msg = getattr(rep, "message", "")
                    sev_obj = getattr(rep, "severity", "INFO")
                    sev = sev_obj.value if hasattr(sev_obj, "value") else str(sev_obj)
                    source = getattr(rep, "source", "snmp")
                elif hasattr(src, "message"):
                    msg = getattr(src, "message", "")
                    sev_obj = getattr(src, "severity", "INFO")
                    sev = sev_obj.value if hasattr(sev_obj, "value") else str(sev_obj)
                    source = getattr(src, "source", "snmp")
                alerts_info.append({
                    "alert_id": av.alert_id,
                    "node_id": av.device_id,
                    "device_name": av.device_name or av.device_id,
                    "alert_type": av.alert_type,
                    "severity": sev,
                    "timestamp": av.timestamp.isoformat() if hasattr(av.timestamp, "isoformat") else str(av.timestamp),
                    "interface": av.interface,
                    "message": msg,
                    "source": source,
                })
            base["alerts"] = alerts_info
            base["alert_ids"] = list(self.candidate.alert_ids)
            # Timeline for UI
            timeline = []
            sorted_av = sorted(self.candidate.alerts, key=lambda x: x.timestamp)
            for av in sorted_av:
                sev = "info"
                src = av.source
                if hasattr(src, "representative"):
                    sev_obj = getattr(src.representative, "severity", "INFO")
                    sev = (sev_obj.value if hasattr(sev_obj, "value") else str(sev_obj)).lower()
                elif hasattr(src, "severity"):
                    sev_obj = getattr(src, "severity", "INFO")
                    sev = (sev_obj.value if hasattr(sev_obj, "value") else str(sev_obj)).lower()
                timeline.append({
                    "time": av.timestamp.strftime("%H:%M:%S") if hasattr(av.timestamp, "strftime") else str(av.timestamp),
                    "text": f"{av.alert_type} on {av.device_id} — {sev}",
                    "kind": "crit" if sev == "critical" else ("high" if sev == "high" else ("medium" if sev == "medium" else "info")),
                    "alert_id": av.alert_id,
                })
            # Add synthetic timeline entries for incident creation and recommendation
            if timeline:
                timeline.append({"time": self.candidate.last_seen.strftime("%H:%M:%S"), "text": "Incident created", "kind": "info", "alert_id": None})
                if self.recommendation.get("evidence"):
                    timeline.append({"time": self.candidate.last_seen.strftime("%H:%M:%S"), "text": "Runbook recommendation generated", "kind": "ok", "alert_id": None})
                if self.escalation.get("escalated"):
                    timeline.append({"time": self.candidate.last_seen.strftime("%H:%M:%S"), "text": f"Escalated: {self.escalation.get('reason','')[:60]}", "kind": "crit", "alert_id": None})
            base["timeline"] = timeline
        return base

    def _title(self) -> str:
        # Generate title from affected devices and types
        if len(self.candidate.affected_devices) >= 3:
            if "R1" in self.candidate.affected_devices:
                return "Core Router R1 Failure"
            if "S1" in self.candidate.affected_devices or "S2" in self.candidate.affected_devices:
                return "Multi-Device Cascade"
        if len(self.candidate.alert_ids) == 1:
            av = self.candidate.alerts[0]
            sev = self.priority.priority
            return f"{av.alert_type} on {av.device_id}"
        # Use priority + device
        dev = self.candidate.affected_devices[0] if self.candidate.affected_devices else "Unknown"
        return f"{self.priority.priority.title()} Incident on {dev}"


class StateStore:
    def __init__(self):
        self._lock = threading.RLock()
        self.raw_alerts: List[Alert] = []
        self.processed: List[ProcessedAlert] = []
        self.candidates: List[CandidateIncident] = []
        self.views: Dict[str, IncidentView] = {}
        self.view_list: List[IncidentView] = []
        self.scenario: str = "all"
        self.last_updated: Optional[datetime] = None
        self.errors: List[str] = []
        self._initialized = False

    def initialize(self, scenario: str = "all"):
        """
        Load and process alerts for a scenario.
        scenario: one of 'duplicate_alerts', 'cascade_failure', 'unknown_escalation', 'all', 'noise', or 'empty'
        """
        from src.generator import generate_scenario, get_all_sample_alerts, SCENARIOS
        from src.topology import get_topology

        with self._lock:
            self.scenario = scenario
            self.errors = []
            try:
                if scenario == "all":
                    raw = get_all_sample_alerts()
                elif scenario == "empty":
                    raw = []
                elif scenario in SCENARIOS or scenario in {"duplicate_alerts", "cascade_failure", "unknown_escalation"}:
                    # Normalize alias via generator
                    from src.generator import normalize_scenario_name
                    canonical = normalize_scenario_name(scenario)
                    raw = generate_scenario(canonical)
                else:
                    # Try normalize, fallback to all
                    try:
                        from src.generator import normalize_scenario_name
                        canonical = normalize_scenario_name(scenario)
                        raw = generate_scenario(canonical)
                    except Exception:
                        raw = get_all_sample_alerts()
                        self.scenario = "all"
            except Exception as e:
                raw = []
                self.errors.append(str(e))

            self.raw_alerts = list(raw)
            # Process pipeline
            processed, p_errors = process_alerts(self.raw_alerts)
            self.errors.extend([str(e) for e in p_errors])
            self.processed = processed

            candidates = build_candidate_incidents(self.processed)
            self.candidates = candidates

            # Build enriched views
            views: Dict[str, IncidentView] = {}
            view_list: List[IncidentView] = []
            for cand in candidates:
                priority = score_priority(cand)
                evidence = retrieve_runbooks(cand)
                recommendation = generate_recommendation(cand, priority)
                esc_payload = build_escalation(cand, priority, evidence, recommendation) if should_escalate(cand, priority, evidence, recommendation)[0] else build_non_escalation(cand)
                iv = IncidentView(candidate=cand, priority=priority, evidence=evidence, recommendation=recommendation, escalation=esc_payload)
                views[cand.incident_id] = iv
                view_list.append(iv)

            # Sort views by priority score descending then incident_id
            view_list.sort(key=lambda iv: (-iv.priority.score, iv.candidate.incident_id))
            self.views = views
            self.view_list = view_list
            self.last_updated = datetime.now(timezone.utc)
            self._initialized = True

    def ensure_initialized(self):
        if not self._initialized:
            self.initialize("all")

    def get_incidents(self, include_alerts: bool = False) -> List[dict]:
        self.ensure_initialized()
        with self._lock:
            return [v.to_dict(include_alerts=include_alerts) for v in self.view_list]

    def get_incident(self, incident_id: str) -> Optional[dict]:
        self.ensure_initialized()
        with self._lock:
            iv = self.views.get(incident_id)
            if iv is None:
                return None
            return iv.to_dict(include_alerts=True)

    def get_incident_view(self, incident_id: str) -> Optional[IncidentView]:
        self.ensure_initialized()
        with self._lock:
            return self.views.get(incident_id)

    def get_alerts(self, scenario: Optional[str] = None) -> List[dict]:
        self.ensure_initialized()
        with self._lock:
            # Return raw alerts as dicts
            alerts = self.raw_alerts
            # If scenario filter provided, filter by labels scenario
            if scenario and scenario != "all":
                alerts = [a for a in alerts if a.labels.get("scenario") == scenario or scenario in a.labels.get("scenario","")]
            result = []
            for a in alerts:
                result.append({
                    "alert_id": a.id,
                    "id": a.id,
                    "timestamp": a.timestamp.isoformat() if hasattr(a.timestamp, "isoformat") else str(a.timestamp),
                    "device_id": a.node_id,
                    "node": a.node_id,
                    "device_name": a.device_name,
                    "alert_type": a.type.value if hasattr(a.type, "value") else str(a.type),
                    "type": a.type.value if hasattr(a.type, "value") else str(a.type),
                    "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
                    "message": a.message,
                    "source": a.source,
                    "interface": a.interface,
                    "labels": dict(a.labels),
                    "metrics": dict(a.metrics),
                })
            return result

    def get_processed(self) -> List[dict]:
        self.ensure_initialized()
        with self._lock:
            return [
                {
                    "fingerprint": p.fingerprint,
                    "count": p.count,
                    "alert_ids": list(p.alert_ids),
                    "first_seen": p.first_seen.isoformat(),
                    "last_seen": p.last_seen.isoformat(),
                    "sources": list(p.sources),
                    "representative": {
                        "id": p.representative.id,
                        "node_id": p.representative.node_id,
                        "type": p.representative.type.value if hasattr(p.representative.type, "value") else str(p.representative.type),
                        "severity": p.representative.severity.value if hasattr(p.representative.severity, "value") else str(p.representative.severity),
                        "message": p.representative.message,
                    }
                } for p in self.processed
            ]

    def get_statistics(self) -> dict:
        self.ensure_initialized()
        with self._lock:
            total_alerts = len(self.raw_alerts)
            processed_cnt = len(self.processed)
            incident_cnt = len(self.view_list)
            critical_cnt = sum(1 for v in self.view_list if v.priority.priority == "CRITICAL")
            high_cnt = sum(1 for v in self.view_list if v.priority.priority == "HIGH")
            escalated_cnt = sum(1 for v in self.view_list if v.escalation.get("escalated"))
            # Dedup ratio
            duplicate_collapsed = total_alerts - processed_cnt
            # Affected devices total unique
            all_devices = set()
            for v in self.view_list:
                all_devices.update(v.candidate.affected_devices)
            return {
                "total_alerts": total_alerts,
                "processed_alerts": processed_cnt,
                "duplicate_collapsed": duplicate_collapsed,
                "incident_count": incident_cnt,
                "critical_count": critical_cnt,
                "high_count": high_cnt,
                "escalated_count": escalated_cnt,
                "affected_devices": sorted(all_devices),
                "affected_device_count": len(all_devices),
                "scenario": self.scenario,
                "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            }

    def reset(self):
        with self._lock:
            self._initialized = False
            self.raw_alerts = []
            self.processed = []
            self.candidates = []
            self.views = {}
            self.view_list = []
            self.errors = []
            self.scenario = "all"
            self.last_updated = None


# Global singleton
_store: Optional[StateStore] = None
_store_lock = threading.Lock()

def get_store() -> StateStore:
    global _store
    with _store_lock:
        if _store is None:
            _store = StateStore()
            # Auto-initialize with default scenario
            _store.initialize("all")
        return _store

def reload_store(scenario: str = "all") -> StateStore:
    store = get_store()
    store.initialize(scenario)
    return store

__all__ = ["StateStore", "IncidentView", "get_store", "reload_store"]
