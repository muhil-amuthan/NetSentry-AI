"""
Correlation scoring engine (Step 6).

This module is the core intelligence of NetSentry-AI: it converts a flat list
of *processed* alerts (already deduplicated by an earlier step) into groups of
related alerts — **candidate incidents**.

Design rules
------------
1. **No LLM, no randomness, no wall-clock reads.** Correlation is a pure
   function of the alerts and the network topology. Two runs over the same
   input always produce the same scores, the same groups and the same
   incident ids.

2. **Explainable.** Every pairwise comparison returns a structured score
   *breakdown* (:class:`CorrelationSignals`), not just a number, so the UI can
   show exactly why two alerts were (or were not) linked.

3. **Four signals only**, each worth a fixed, configurable number of points
   (see :data:`CORRELATION_WEIGHTS`):

   * ``same_device``   — the two alerts were raised by the same device.
   * ``related_device`` — the two devices are directly linked in
     ``data/topology.json`` (:func:`are_devices_related`).
   * ``time_proximity`` — the alerts occurred within
     :data:`TIME_PROXIMITY_WINDOW_SECONDS` of each other.
   * ``related_type``  — the alert types are explicitly related, per
     :data:`RELATED_ALERT_TYPES`.

   A pair is *correlated* once its total score reaches
   :data:`CORRELATION_THRESHOLD`.

4. **Grouping is graph-based, not "everything nearby".** Alerts are nodes;
   a correlated pair is an edge. Candidate incidents are the connected
   components of that graph (:func:`build_candidate_incidents`), so cascading
   failures link up *transitively* (``R1 -> S1 -> R3``) even when the two ends
   of the chain (``R1`` and ``R3``) never score above the threshold directly.

Scope note
----------
This step stops at *candidate* incidents: alert ids, affected devices, a
correlation score and a human-readable reason. Priority, root cause, runbook
retrieval, recommendations and escalation are later steps and are
deliberately **not** implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from src.models import Alert, AlertType
from src.topology import NetworkTopology, get_topology

__all__ = [
    "ScorerError",
    "CORRELATION_WEIGHTS",
    "CORRELATION_THRESHOLD",
    "TIME_PROXIMITY_WINDOW_SECONDS",
    "RELATED_ALERT_TYPES",
    "CorrelationSignals",
    "CorrelationResult",
    "CandidateIncident",
    "are_devices_related",
    "score_same_device",
    "score_topology_relationship",
    "score_time_proximity",
    "score_alert_type_relationship",
    "score_alert_pair",
    "score_all_pairs",
    "build_candidate_incidents",
]


class ScorerError(RuntimeError):
    """Raised when the correlation engine is given input it cannot use at all."""


# ---------------------------------------------------------------------------
# Tunable configuration — the ONLY place the scoring weights live.
# ---------------------------------------------------------------------------

#: Points awarded per signal. Total possible score is 100. Keep these as the
#: single source of truth; nothing else in this module hard-codes a weight.
CORRELATION_WEIGHTS: Dict[str, int] = {
    "same_device": 30,
    "related_device": 20,
    "time_proximity": 20,
    "related_type": 30,
}

#: Minimum total score for a pair of alerts to be considered correlated.
CORRELATION_THRESHOLD: int = 60

#: Alerts within this many seconds of each other earn the time-proximity signal.
TIME_PROXIMITY_WINDOW_SECONDS: int = 5 * 60

#: Explicit, symmetric-by-construction relationship map between alert types.
#: Deliberately sparse: an alert type is only "related" to another type when
#: there is real operational evidence connecting them (e.g. a link outage
#: plausibly explains a device becoming unreachable). Being exhaustive here
#: would let unrelated alerts correlate just because they share a type.
RELATED_ALERT_TYPES: Dict[AlertType, FrozenSet[AlertType]] = {
    AlertType.LINK_DOWN: frozenset(
        {AlertType.DEVICE_UNREACHABLE, AlertType.PACKET_LOSS, AlertType.HIGH_LATENCY}
    ),
    AlertType.DEVICE_UNREACHABLE: frozenset(
        {AlertType.LINK_DOWN, AlertType.PACKET_LOSS, AlertType.HIGH_LATENCY}
    ),
    AlertType.PACKET_LOSS: frozenset(
        {AlertType.LINK_DOWN, AlertType.DEVICE_UNREACHABLE, AlertType.HIGH_LATENCY}
    ),
    AlertType.HIGH_LATENCY: frozenset(
        {AlertType.LINK_DOWN, AlertType.PACKET_LOSS, AlertType.DEVICE_UNREACHABLE}
    ),
    AlertType.AUTH_FAILURE: frozenset({AlertType.AUTH_FAILURE}),
}

#: Incident id formatting, e.g. ``INC-0001``.
_INCIDENT_ID_PREFIX = "INC-"
_INCIDENT_ID_WIDTH = 4

#: Deterministic fallback for an alert whose timestamp cannot be interpreted
#: at all. Never derived from the wall clock.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

#: Human-readable labels for the score breakdown, in the fixed display order
#: used by :func:`CorrelationResult.explain` (matches the product spec).
_EXPLANATION_ORDER: Tuple[Tuple[str, str], ...] = (
    ("same_device", "Same device"),
    ("time_proximity", "Within 5 minutes"),
    ("related_type", "Related alert types"),
    ("related_device", "Topology relationship"),
)

#: Labels used for the shorter, per-signal reason strings on an incident.
_SIGNAL_LABELS: Dict[str, str] = {
    "same_device": "Same device",
    "related_device": "Topology relationship (directly connected devices)",
    "time_proximity": "Time proximity (within 5 minutes)",
    "related_type": "Related alert types",
}


# ---------------------------------------------------------------------------
# Structured results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationSignals:
    """The individual, explainable contributions to a pairwise score."""

    same_device: int = 0
    related_device: int = 0
    time_proximity: int = 0
    related_type: int = 0

    @property
    def total(self) -> int:
        """Sum of every signal — the pairwise correlation score."""
        return self.same_device + self.related_device + self.time_proximity + self.related_type

    def as_dict(self) -> Dict[str, int]:
        """Plain dict, in the canonical (same_device/related_device/...) order."""
        return {
            "same_device": self.same_device,
            "related_device": self.related_device,
            "time_proximity": self.time_proximity,
            "related_type": self.related_type,
        }

    def reasons(self) -> List[str]:
        """Human-readable reasons for every signal that actually fired."""
        return [
            f"{_SIGNAL_LABELS[key]}: +{value}"
            for key, value in self.as_dict().items()
            if value
        ]


@dataclass(frozen=True)
class CorrelationResult:
    """The full, explainable outcome of scoring one pair of alerts."""

    alert_a_id: str
    alert_b_id: str
    signals: CorrelationSignals
    correlated: bool

    @property
    def score(self) -> int:
        return self.signals.total

    def explain(self) -> str:
        """Multi-line, judge-readable explanation of the score breakdown."""
        lines = [f"Correlation score: {self.score}", ""]
        for key, label in _EXPLANATION_ORDER:
            lines.append(f"{label}: +{getattr(self.signals, key)}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_a": self.alert_a_id,
            "alert_b": self.alert_b_id,
            "score": self.score,
            "correlated": self.correlated,
            "signals": self.signals.as_dict(),
            "explanation": self.explain(),
        }


@dataclass(frozen=True)
class CandidateIncident:
    """A connected group of alerts believed to describe one network event.

    This is intentionally a thin, structural container: priority, root cause,
    runbook retrieval and recommendations are populated by later steps.
    """

    incident_id: str
    alert_ids: List[str]
    alerts: List[Alert]
    correlation_score: int
    correlation_reasons: List[str]
    first_seen: datetime
    last_seen: datetime
    affected_devices: List[str]

    @property
    def alert_count(self) -> int:
        return len(self.alert_ids)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "alert_ids": list(self.alert_ids),
            "alerts": [alert.model_dump(mode="json") for alert in self.alerts],
            "alert_count": self.alert_count,
            "affected_devices": list(self.affected_devices),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "correlation_score": self.correlation_score,
            "correlation_reasons": list(self.correlation_reasons),
        }


# ---------------------------------------------------------------------------
# Small, safe helpers
# ---------------------------------------------------------------------------


def _default_topology() -> Optional[NetworkTopology]:
    """The cached default topology, or ``None`` if it cannot be loaded.

    A missing/broken topology file must degrade the ``related_device`` signal
    to zero, never crash the scorer.
    """
    try:
        return get_topology()
    except Exception:
        return None


def _safe_timestamp(alert: Alert) -> datetime:
    """A timezone-aware timestamp for ``alert``, tolerating odd input.

    Naive datetimes are treated as UTC (matching how the rest of the codebase
    parses feeds). Anything that is not a ``datetime`` at all — which should
    not happen once :class:`Alert` has validated it, but defends against
    malformed data reaching this module directly — falls back to a fixed
    epoch rather than raising.
    """
    ts = getattr(alert, "timestamp", None)
    if not isinstance(ts, datetime):
        return _EPOCH
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)


def _coerce_alert(item: Any) -> Optional[Alert]:
    """Best-effort conversion of ``item`` into an :class:`Alert`.

    Returns ``None`` (rather than raising) for anything that cannot be turned
    into a valid alert, so one malformed record cannot sink the whole batch.
    """
    if isinstance(item, Alert):
        return item
    try:
        return Alert.model_validate(item)
    except Exception:
        return None


def _prepare_alerts(alerts: Optional[Iterable[Any]]) -> List[Alert]:
    """Validate, de-duplicate (by id) and return a plain list of alerts.

    Order of the *input* is not relied upon; callers get a deterministically
    sorted list back from :func:`build_candidate_incidents`.
    """
    if alerts is None:
        return []
    prepared: List[Alert] = []
    seen_ids: set = set()
    for item in alerts:
        alert = _coerce_alert(item)
        if alert is None:
            continue  # malformed alert: skip it, do not crash the batch
        if alert.id in seen_ids:
            continue  # a duplicate alert id reaching the scorer: keep the first
        seen_ids.add(alert.id)
        prepared.append(alert)
    return prepared


class _UnionFind:
    """Minimal disjoint-set structure for deterministic connected components."""

    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, x: int) -> int:
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a == root_b:
            return
        # Always attach the higher index under the lower one: deterministic
        # regardless of the order union() happens to be called in.
        if root_a < root_b:
            self._parent[root_b] = root_a
        else:
            self._parent[root_a] = root_b


# ---------------------------------------------------------------------------
# Signal 1 — same device
# ---------------------------------------------------------------------------


def score_same_device(alert_a: Alert, alert_b: Alert) -> int:
    """``CORRELATION_WEIGHTS['same_device']`` if both alerts share a device."""
    if alert_a.node_id and alert_a.node_id == alert_b.node_id:
        return CORRELATION_WEIGHTS["same_device"]
    return 0


# ---------------------------------------------------------------------------
# Signal 2 — topology relationship
# ---------------------------------------------------------------------------


def are_devices_related(
    device_a: str, device_b: str, topology: Optional[NetworkTopology] = None
) -> bool:
    """True when two *different* devices are directly linked in the topology.

    Uses the real network graph (``data/topology.json`` via
    :mod:`src.topology`) — never a hard-coded pair list. Unknown devices, a
    missing topology, or the same device on both sides all resolve to
    ``False`` rather than raising.
    """
    if not device_a or not device_b or device_a == device_b:
        return False
    topo = topology if topology is not None else _default_topology()
    if topo is None:
        return False
    try:
        if device_a not in topo or device_b not in topo:
            return False
        return topo.get_link(device_a, device_b) is not None
    except Exception:
        return False


def score_topology_relationship(
    alert_a: Alert, alert_b: Alert, topology: Optional[NetworkTopology] = None
) -> int:
    """``CORRELATION_WEIGHTS['related_device']`` for directly linked devices."""
    if are_devices_related(alert_a.node_id, alert_b.node_id, topology):
        return CORRELATION_WEIGHTS["related_device"]
    return 0


# ---------------------------------------------------------------------------
# Signal 3 — time proximity
# ---------------------------------------------------------------------------


def score_time_proximity(alert_a: Alert, alert_b: Alert) -> int:
    """``CORRELATION_WEIGHTS['time_proximity']`` within the 5-minute window.

    Never reads the system clock — only the two alerts' own timestamps.
    Malformed/unparseable timestamps are treated as "not proximate" (0
    points) instead of raising.
    """
    try:
        delta = abs((_safe_timestamp(alert_a) - _safe_timestamp(alert_b)).total_seconds())
    except Exception:
        return 0
    return CORRELATION_WEIGHTS["time_proximity"] if delta <= TIME_PROXIMITY_WINDOW_SECONDS else 0


# ---------------------------------------------------------------------------
# Signal 4 — related alert types
# ---------------------------------------------------------------------------


def score_alert_type_relationship(type_a: AlertType, type_b: AlertType) -> int:
    """``CORRELATION_WEIGHTS['related_type']`` for explicitly related types.

    Looks the pair up in :data:`RELATED_ALERT_TYPES` in both directions so the
    map only needs to be authored once per relationship. Unmodelled/unknown
    types (which never appear in the map) score 0 — they need other evidence
    to correlate.
    """
    if type_b in RELATED_ALERT_TYPES.get(type_a, frozenset()):
        return CORRELATION_WEIGHTS["related_type"]
    if type_a in RELATED_ALERT_TYPES.get(type_b, frozenset()):
        return CORRELATION_WEIGHTS["related_type"]
    return 0


# ---------------------------------------------------------------------------
# Pairwise scoring
# ---------------------------------------------------------------------------


def score_alert_pair(
    alert_a: Alert, alert_b: Alert, topology: Optional[NetworkTopology] = None
) -> CorrelationResult:
    """Score one pair of alerts against all four signals.

    Returns a :class:`CorrelationResult` carrying the total score, the
    individual signal breakdown, whether the pair clears
    :data:`CORRELATION_THRESHOLD`, and a human-readable explanation.
    """
    signals = CorrelationSignals(
        same_device=score_same_device(alert_a, alert_b),
        related_device=score_topology_relationship(alert_a, alert_b, topology),
        time_proximity=score_time_proximity(alert_a, alert_b),
        related_type=score_alert_type_relationship(alert_a.type, alert_b.type),
    )
    return CorrelationResult(
        alert_a_id=alert_a.id,
        alert_b_id=alert_b.id,
        signals=signals,
        correlated=signals.total >= CORRELATION_THRESHOLD,
    )


def score_all_pairs(
    alerts: Sequence[Alert], topology: Optional[NetworkTopology] = None
) -> List[CorrelationResult]:
    """Score every unordered pair in ``alerts``. Handy for inspection/tests."""
    results: List[CorrelationResult] = []
    for i in range(len(alerts)):
        for j in range(i + 1, len(alerts)):
            results.append(score_alert_pair(alerts[i], alerts[j], topology))
    return results


# ---------------------------------------------------------------------------
# Grouping alerts into candidate incidents
# ---------------------------------------------------------------------------


def _group_sort_key(prepared: Sequence[Alert], indices: Sequence[int]) -> Tuple[datetime, str]:
    """Deterministic ordering key for a connected component."""
    earliest = min(_safe_timestamp(prepared[i]) for i in indices)
    smallest_id = min(prepared[i].id for i in indices)
    return (earliest, smallest_id)


def _best_pair(
    group_alerts: Sequence[Alert], topology: Optional[NetworkTopology]
) -> Optional[CorrelationResult]:
    """The strongest-scoring internal pair in a group (for the incident's headline score)."""
    best: Optional[CorrelationResult] = None
    for i in range(len(group_alerts)):
        for j in range(i + 1, len(group_alerts)):
            result = score_alert_pair(group_alerts[i], group_alerts[j], topology)
            if best is None or result.score > best.score:
                best = result
    return best


def _build_incident(
    sequence: int,
    group_alerts: Sequence[Alert],
    topology: Optional[NetworkTopology],
) -> CandidateIncident:
    timestamps = [_safe_timestamp(a) for a in group_alerts]
    affected_devices = sorted({(a.device_name or a.node_id) for a in group_alerts})

    if len(group_alerts) < 2:
        correlation_score = 0
        correlation_reasons: List[str] = ["Single alert — no correlated evidence yet."]
    else:
        best = _best_pair(group_alerts, topology)
        correlation_score = best.score if best else 0
        correlation_reasons = best.signals.reasons() if best else []

    return CandidateIncident(
        incident_id=f"{_INCIDENT_ID_PREFIX}{sequence:0{_INCIDENT_ID_WIDTH}d}",
        alert_ids=[a.id for a in group_alerts],
        alerts=list(group_alerts),
        correlation_score=correlation_score,
        correlation_reasons=correlation_reasons,
        first_seen=min(timestamps),
        last_seen=max(timestamps),
        affected_devices=affected_devices,
    )


def build_candidate_incidents(
    alerts: Optional[Iterable[Any]], topology: Optional[NetworkTopology] = None
) -> List[CandidateIncident]:
    """Group processed alerts into candidate incidents.

    Builds a graph where alerts are nodes and a correlated pair
    (:func:`score_alert_pair` scoring >= :data:`CORRELATION_THRESHOLD`) is an
    edge, then returns the connected components. This supports *transitive*
    correlation: ``R1`` and ``R3`` end up in the same incident via an
    intermediate ``S1`` alert even if ``R1``/``R3`` never score above the
    threshold directly — the hallmark of a cascading network failure.

    Fully deterministic: given the same alerts, the same groups, scores and
    ``INC-000N`` ids come out every time. No random ids, no clock reads, no
    LLM calls.
    """
    prepared = _prepare_alerts(alerts)
    if not prepared:
        return []

    prepared.sort(key=lambda a: (_safe_timestamp(a), a.id))
    n = len(prepared)

    uf = _UnionFind(n)
    for i in range(n):
        for j in range(i + 1, n):
            if score_alert_pair(prepared[i], prepared[j], topology).correlated:
                uf.union(i, j)

    components: Dict[int, List[int]] = {}
    for idx in range(n):
        components.setdefault(uf.find(idx), []).append(idx)

    ordered_components = sorted(
        components.values(), key=lambda idxs: _group_sort_key(prepared, idxs)
    )

    incidents: List[CandidateIncident] = []
    for sequence, idxs in enumerate(ordered_components, start=1):
        idxs_sorted = sorted(idxs, key=lambda i: (_safe_timestamp(prepared[i]), prepared[i].id))
        group_alerts = [prepared[i] for i in idxs_sorted]
        incidents.append(_build_incident(sequence, group_alerts, topology))
    return incidents
