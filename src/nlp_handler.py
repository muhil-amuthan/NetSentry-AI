"""
Natural Language Handler — Ask NetSentry (Step 12).

Queries actual application state (incidents, priorities, evidence, recommendations,
escalations) via the StateStore. Uses deterministic intent handling; Gemini may
assist with semantic interpretation only where useful, never inventing incident data.

All answers are grounded in current pipeline output.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Any, Tuple

from src.database import get_store
from src.config import GEMINI_API_KEY

try:
    from google import genai
    HAS_GENAI = True
except Exception:
    HAS_GENAI = False
    genai = None  # type: ignore

# ---------------------------------------------------------------------------
# Intent patterns
# ---------------------------------------------------------------------------

_INC_RE = re.compile(r"INC[-\s]?(\d+)", re.IGNORECASE)
_DEVICE_RE = re.compile(r"\b(CORE[-\s]?R\d+|SW[-\s]?S\d+|ACC[-\s]?R\d+|R\d+|S\d+|INTERNET)\b", re.IGNORECASE)

# Mapping of intents to regex patterns
INTENT_PATTERNS: Dict[str, List[re.Pattern]] = {
    "highest_priority": [
        re.compile(r"highest priority", re.IGNORECASE),
        re.compile(r"most critical", re.IGNORECASE),
        re.compile(r"top incident", re.IGNORECASE),
        re.compile(r"worst incident", re.IGNORECASE),
    ],
    "why_critical": [
        re.compile(r"why.*critical", re.IGNORECASE),
        re.compile(r"why.*high", re.IGNORECASE),
        re.compile(r"why is.*INC", re.IGNORECASE),
        re.compile(r"why.*priority", re.IGNORECASE),
    ],
    "affected_devices": [
        re.compile(r"what devices.*affected", re.IGNORECASE),
        re.compile(r"affected devices", re.IGNORECASE),
        re.compile(r"which devices", re.IGNORECASE),
        re.compile(r"show.*devices", re.IGNORECASE),
        re.compile(r"impact.*devices", re.IGNORECASE),
    ],
    "what_to_check": [
        re.compile(r"what.*check.*first", re.IGNORECASE),
        re.compile(r"what should.*check", re.IGNORECASE),
        re.compile(r"first step", re.IGNORECASE),
        re.compile(r"next step", re.IGNORECASE),
        re.compile(r"what to do", re.IGNORECASE),
        re.compile(r"recommended.*action", re.IGNORECASE),
    ],
    "grouped_alerts": [
        re.compile(r"which alerts.*group", re.IGNORECASE),
        re.compile(r"alerts.*group", re.IGNORECASE),
        re.compile(r"grouped alerts", re.IGNORECASE),
        re.compile(r"correlated alerts", re.IGNORECASE),
        re.compile(r"how many alerts", re.IGNORECASE),
    ],
    "escalation_reason": [
        re.compile(r"why.*escalat", re.IGNORECASE),
        re.compile(r"escalation.*reason", re.IGNORECASE),
        re.compile(r"why.*human", re.IGNORECASE),
    ],
    "filter_by_device": [
        re.compile(r"show.*incidents.*affecting", re.IGNORECASE),
        re.compile(r"incidents.*affecting", re.IGNORECASE),
        re.compile(r"incidents.*on.*R\d", re.IGNORECASE),
        re.compile(r"affecting\s+CORE", re.IGNORECASE),
    ],
    "incident_summary": [
        re.compile(r"summary.*INC", re.IGNORECASE),
        re.compile(r"tell.*about.*INC", re.IGNORECASE),
        re.compile(r"what happened.*INC", re.IGNORECASE),
    ],
    "list_incidents": [
        re.compile(r"list.*incidents", re.IGNORECASE),
        re.compile(r"show.*incidents", re.IGNORECASE),
        re.compile(r"how many incidents", re.IGNORECASE),
    ],
    "statistics": [
        re.compile(r"statistics", re.IGNORECASE),
        re.compile(r"how many alerts", re.IGNORECASE),
        re.compile(r"network health", re.IGNORECASE),
        re.compile(r"overview", re.IGNORECASE),
    ],
}


def _detect_intent(question: str) -> str:
    q = question.strip()
    for intent, patterns in INTENT_PATTERNS.items():
        for pat in patterns:
            if pat.search(q):
                return intent
    return "general"


def _extract_incident_id(question: str, store) -> Optional[str]:
    m = _INC_RE.search(question)
    if m:
        num = m.group(1).zfill(4)
        cand = f"INC-{num}"
        # Verify exists in store; if not, try to find closest?
        if store.get_incident_view(cand) is not None:
            return cand
        # If not found, return the formatted id anyway for error message
        return cand
    return None


def _normalize_device_token(token: str) -> str:
    t = token.upper().replace(" ", "").replace("-", "")
    # Map CORE-R1 -> R1, CORE-R1 stays? For incidents we store affected_devices as ids like R1, S1 etc.
    # But users may say CORE-R1 -> normalize to R1
    mapping = {
        "CORER1": "R1",
        "CORER2": "R2",
        "SWS1": "S1",
        "SWS2": "S2",
        "ACCR3": "R3",
        "ACCR4": "R4",
        "ACCR5": "R5",
        "ACCR6": "R6",
    }
    if t in mapping:
        return mapping[t]
    # Already normalized like R1, S1
    if re.match(r"^R\d+$", t):
        return t
    if re.match(r"^S\d+$", t):
        return t
    return t


def _extract_device(question: str) -> Optional[str]:
    m = _DEVICE_RE.search(question)
    if m:
        raw = m.group(1)
        return _normalize_device_token(raw)
    return None


def _incident_to_refs(incident_id: str, evidence_runbooks: List[str]) -> List[str]:
    refs = [incident_id]
    refs.extend(evidence_runbooks[:2])
    return refs


def _answer_highest_priority(store) -> Tuple[str, List[str]]:
    incidents = store.view_list
    if not incidents:
        return "There are currently no active incidents.", []
    top = max(incidents, key=lambda iv: iv.priority.score)
    # top is IncidentView
    d = top.to_dict()
    answer = (
        f"The highest priority incident is {d['incident_id']} — {d['title']} — "
        f"priority {d['priority']} (score {d['priority_score']}/100). "
        f"It affects {d['devices']} devices ({', '.join(d['affected_devices'])}) and groups {d['alert_count']} alerts. "
        f"Reason: {'; '.join(d['priority_reasons'][:2])}. "
        f"Correlation score {d['correlation_score']}."
    )
    refs = _incident_to_refs(d['incident_id'], [e.get('runbook','') for e in d['evidence']])
    return answer, refs


def _answer_why_critical(incident_id: str, store) -> Tuple[str, List[str]]:
    iv = store.get_incident_view(incident_id)
    if iv is None:
        return f"No incident found with ID {incident_id}. Available incidents: {', '.join([v.candidate.incident_id for v in store.view_list][:5])}.", []
    d = iv.to_dict()
    # Explain priority
    signals = d['priority_signals']
    reasons = d['priority_reasons']
    # Build explanation
    answer = (
        f"{incident_id} is {d['priority']} (score {d['priority_score']}/100). Breakdown: "
        f"Device impact {signals.get('device_impact',0)}/40, Severity {signals.get('severity',0)}/30, "
        f"Alert volume {signals.get('alert_volume',0)}/20, Duration {signals.get('duration',0)}/10. "
        f"Reasons: {'; '.join(reasons[:3])}. "
        f"Affected devices: {', '.join(d['affected_devices'])}."
    )
    if d['evidence']:
        answer += f" Evidence: {d['evidence'][0].get('runbook')} section {d['evidence'][0].get('section')}."
    refs = _incident_to_refs(incident_id, [e.get('runbook','') for e in d['evidence']])
    return answer, refs


def _answer_affected_devices(incident_id: Optional[str], store) -> Tuple[str, List[str]]:
    if incident_id:
        iv = store.get_incident_view(incident_id)
        if iv is None:
            return f"No incident {incident_id} found.", []
        d = iv.to_dict()
        devs = d['affected_devices']
        # Add topology context: try to get subscriber impact
        try:
            from src.topology import get_topology
            topo = get_topology()
            subs = topo.affected_subscribers(devs)
            return f"Incident {incident_id} affects {len(devs)} devices: {', '.join(devs)} ({subs} subscribers total).", _incident_to_refs(incident_id, [])
        except Exception:
            return f"Incident {incident_id} affects {len(devs)} devices: {', '.join(devs)}.", _incident_to_refs(incident_id, [])
    else:
        # Overall
        stats = store.get_statistics()
        devs = stats.get("affected_devices", [])
        if not devs:
            return "No devices are currently affected — no active incidents.", []
        return f"Across all incidents, {len(devs)} unique devices are affected: {', '.join(devs)}.", []


def _answer_what_to_check(incident_id: Optional[str], store) -> Tuple[str, List[str]]:
    if incident_id is None:
        # Default to highest priority incident
        if not store.view_list:
            return "No active incidents to check.", []
        iv = max(store.view_list, key=lambda x: x.priority.score)
        incident_id = iv.candidate.incident_id
    else:
        iv = store.get_incident_view(incident_id)
        if iv is None:
            return f"No incident {incident_id} found.", []

    iv = store.get_incident_view(incident_id)
    assert iv is not None
    d = iv.to_dict()
    actions = d.get("recommended_actions", [])
    if not actions:
        # Fall back to escalation
        esc = d.get("escalation", {})
        if esc.get("escalated"):
            return f"Incident {incident_id} has been escalated: {esc.get('reason','No runbook — manual investigation required')}. Next step: {esc.get('next_step')}.", _incident_to_refs(incident_id, [])
        return f"No specific checks available for {incident_id}. See runbook evidence for guidance.", _incident_to_refs(incident_id, [])
    first = actions[0]
    rest = ""
    if len(actions) > 1:
        rest = f" Then: {actions[1][:120]}."
    ev = d.get("evidence", [])
    ref_str = ""
    if ev:
        ref_str = f" Evidence: {ev[0].get('runbook')} — {ev[0].get('section')}."
    answer = f"For {incident_id}, first check: {first}.{rest}{ref_str}"
    refs = _incident_to_refs(incident_id, [e.get('runbook','') for e in ev])
    return answer, refs


def _answer_grouped_alerts(incident_id: Optional[str], store) -> Tuple[str, List[str]]:
    if incident_id is None:
        if not store.view_list:
            return "No incidents currently.", []
        iv = max(store.view_list, key=lambda x: x.priority.score)
        incident_id = iv.candidate.incident_id
    iv = store.get_incident_view(incident_id)
    if iv is None:
        return f"No incident {incident_id} found.", []
    d = iv.to_dict()
    count = d.get("alert_count", 0)
    types = {}
    for a in d.get("alerts", []):
        t = a.get("alert_type", "UNKNOWN")
        types[t] = types.get(t, 0) + 1
    types_str = ", ".join([f"{k} ×{v}" for k, v in types.items()])
    corr = d.get("correlation_score", 0)
    answer = f"{incident_id} groups {count} alerts: {types_str}. Correlation score {corr}. Reasons: {'; '.join(d.get('correlation_reasons', [])[:2])}"
    refs = _incident_to_refs(incident_id, [])
    return answer, refs


def _answer_escalation(incident_id: Optional[str], store) -> Tuple[str, List[str]]:
    if incident_id is None:
        # Find escalated incidents
        escalated = [iv for iv in store.view_list if iv.escalation.get("escalated")]
        if not escalated:
            return "No incidents are currently escalated. All have sufficient evidence.", []
        iv = escalated[0]
        incident_id = iv.candidate.incident_id
    else:
        iv = store.get_incident_view(incident_id)
        if iv is None:
            return f"No incident {incident_id} found.", []
    assert iv is not None
    d = iv.to_dict()
    esc = d.get("escalation", {})
    if not esc.get("escalated"):
        return f"{incident_id} is not escalated. It has evidence {', '.join([e.get('runbook','') for e in d.get('evidence',[])])} and confidence {d.get('confidence')}.", _incident_to_refs(incident_id, [])
    reason = esc.get("reason", "No reason provided")
    what = esc.get("summary", "")[:150]
    answer = f"{incident_id} was escalated because: {reason}. {what} Next step: {esc.get('next_step')}. Grouped alerts: {len(esc.get('grouped_alerts',[]))}."
    refs = _incident_to_refs(incident_id, [])
    return answer, refs


def _answer_filter_by_device(device: str, store) -> Tuple[str, List[str]]:
    # Find incidents affecting device
    matches = []
    for iv in store.view_list:
        if device in iv.candidate.affected_devices:
            matches.append(iv)
    if not matches:
        return f"No active incidents affect device {device}. Total incidents: {len(store.view_list)}.", []
    ids = [iv.candidate.incident_id for iv in matches]
    titles = [iv.to_dict().get("title","") for iv in matches]
    ans = f"Incidents affecting {device}: {', '.join(ids)}. " + "; ".join([f"{i} — {t} ({iv.priority.priority})" for i, t, iv in zip(ids, titles, matches)])
    refs = ids
    return ans, refs


def _answer_list_incidents(store) -> Tuple[str, List[str]]:
    if not store.view_list:
        return "No active incidents.", []
    lines = []
    for iv in store.view_list:
        d = iv.to_dict()
        lines.append(f"{d['incident_id']}: {d['title']} — {d['priority']} ({d['priority_score']}) {d['devices']} devices")
    ans = f"{len(store.view_list)} active incidents: " + "; ".join(lines[:5])
    refs = [iv.candidate.incident_id for iv in store.view_list[:3]]
    return ans, refs


def _answer_statistics(store) -> Tuple[str, List[str]]:
    stats = store.get_statistics()
    ans = (
        f"Network overview: {stats['total_alerts']} raw alerts, {stats['processed_alerts']} after deduplication "
        f"({stats['duplicate_collapsed']} duplicates collapsed), {stats['incident_count']} incidents "
        f"({stats['critical_count']} critical, {stats['high_count']} high, {stats['escalated_count']} escalated), "
        f"{stats['affected_device_count']} devices affected."
    )
    return ans, []


def _fallback_answer(question: str, store) -> Tuple[str, List[str]]:
    suggestions = [
        "What is the highest priority incident?",
        "Why is INC-0001 critical?",
        "What devices are affected?",
        "What should I check first?",
        "Which alerts were grouped?",
        "Why was this incident escalated?",
        "Show me incidents affecting CORE-R1",
    ]
    return (
        f"I couldn't map your question to a known incident query. Try one of: {'; '.join(suggestions[:4])}. "
        f"Current state: {len(store.view_list)} incidents, {store.get_statistics()['total_alerts']} alerts. "
        f"Ask about a specific incident ID like INC-0001.",
        []
    )


def handle_ask(question: str) -> Dict[str, Any]:
    """
    Main entry point for POST /api/ask.
    Returns {answer, refs, intent, incident_id} .
    Never invents incident data; all answers come from the store.
    """
    store = get_store()
    store.ensure_initialized()

    if not question or not question.strip():
        return {
            "question": question,
            "answer": "Please ask a question about incidents, alerts, devices or runbooks. Example: 'What is the highest priority incident?'",
            "refs": [],
            "intent": "empty",
            "incident_id": None,
        }

    intent = _detect_intent(question)
    incident_id = _extract_incident_id(question, store)
    device = _extract_device(question)

    # Dispatch
    try:
        if intent == "highest_priority":
            ans, refs = _answer_highest_priority(store)
        elif intent == "why_critical" and incident_id:
            ans, refs = _answer_why_critical(incident_id, store)
        elif intent == "why_critical" and not incident_id:
            # No ID, treat as highest priority explanation
            if store.view_list:
                top = max(store.view_list, key=lambda iv: iv.priority.score)
                ans, refs = _answer_why_critical(top.candidate.incident_id, store)
            else:
                ans, refs = "No incidents to explain.", []
        elif intent == "affected_devices":
            ans, refs = _answer_affected_devices(incident_id, store)
        elif intent == "what_to_check":
            ans, refs = _answer_what_to_check(incident_id, store)
        elif intent == "grouped_alerts":
            ans, refs = _answer_grouped_alerts(incident_id, store)
        elif intent == "escalation_reason":
            ans, refs = _answer_escalation(incident_id, store)
        elif intent == "filter_by_device" and device:
            ans, refs = _answer_filter_by_device(device, store)
        elif intent == "filter_by_device" and not device and incident_id:
            ans, refs = _answer_affected_devices(incident_id, store)
        elif intent == "incident_summary" and incident_id:
            # Summary intent same as why_critical but more general
            iv = store.get_incident_view(incident_id)
            if iv is None:
                ans, refs = f"No incident {incident_id} found.", []
            else:
                d = iv.to_dict()
                ans = d.get("summary", "") or d.get("what_happened", "")
                refs = _incident_to_refs(incident_id, [e.get('runbook','') for e in d.get('evidence',[])])
        elif intent == "list_incidents":
            ans, refs = _answer_list_incidents(store)
        elif intent == "statistics":
            ans, refs = _answer_statistics(store)
        else:
            # General fallback: try to route based on presence of incident_id/device
            if incident_id:
                # Default to summary for incident
                iv = store.get_incident_view(incident_id)
                if iv:
                    d = iv.to_dict()
                    ans = f"{incident_id} — {d.get('title','')}: {d.get('summary','')[:200]} Priority {d.get('priority')} confidence {d.get('confidence')}. Affected: {', '.join(d.get('affected_devices',[]))}."
                    refs = _incident_to_refs(incident_id, [])
                else:
                    ans, refs = _fallback_answer(question, store)
            elif device:
                ans, refs = _answer_filter_by_device(device, store)
            else:
                ans, refs = _fallback_answer(question, store)
    except Exception as e:
        ans = f"Error handling question: {e}. Please try rephrasing."
        refs = []

    # Optional Gemini semantic rewrite (grounded, not inventing)
    # If Gemini available, we could polish the answer but keep refs and facts.
    # For deterministic fallback we skip to avoid latency and hallucination.
    # If needed, we could call Gemini here with system prompt to not invent.
    # We leave deterministic answer as final, but note _source.

    return {
        "question": question,
        "answer": ans,
        "refs": refs,
        "intent": intent,
        "incident_id": incident_id,
    }


__all__ = ["handle_ask"]
