"""
Correlation scoring engine — the core intelligence of NetSentry-AI.

Turns *processed alerts* into *candidate incidents* using deterministic,
evidence-based rules. No LLM, no embeddings, no randomness, no wall-clock
time: the same input always produces the same scores, the same groups, the
same incident ids and the same ordering.

Pipeline position::

    raw alerts -> processor/deduplication -> PROCESSED ALERTS
               -> correlation scoring (this module) -> CANDIDATE INCIDENTS

Four explainable signals decide whether two alerts belong together:

===================  ======  =========================================
signal               weight  fires when
===================  ======  =========================================
``same_device``       +30    both alerts were raised by the same node
``related_device``    +20    the two nodes are directly linked in the
                             topology (``data/topology.json``)
``time_proximity``    +20    the alerts are within 5 minutes
``related_type``      +30    the alert types are explicitly related
===================  ======  =========================================

Maximum score is 100; the default correlation threshold is 60. Every
pairwise result carries its full signal breakdown so the UI can show the
reasoning instead of an opaque number.

Scope note (Step 6)
-------------------
This module produces **candidate** incidents only. Priority, severity
classification, root-cause analysis, runbook retrieval and LLM explanation
are later steps and are deliberately absent here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from src.models import Alert, AlertType
from src.processor import ProcessedAlert
from src.topology import NetworkTopology, TopologyError, get_topology

# ---------------------------------------------------------------------------
# Configuration — tune the engine here, never inline in the logic below.
# ---------------------------------------------------------------------------

#: Points contributed by each correlation signal.
CORRELATION_WEIGHTS: Dict[str, int] = {
    "same_device": 30,
    "related_device": 20,
    "time_proximity": 20,
    "related_type": 30,
}

#: Total score at or above which a pair of alerts is considered correlated.
CORRELATION_THRESHOLD: int = 60

#: Width of the "these happened together" window, in seconds (5 minutes).
TIME_PROXIMITY_WINDOW_SECONDS: int = 300

#: Guard rail: two alerts far apart in time are never auto-correlated even if
#: the remaining signals add up to the threshold. Scoring is unaffected — this
#: only gates the boolean verdict, so the breakdown stays honest.
REQUIRE_TIME_PROXIMITY: bool = True

#: Highest score any pair can reach (used for display/normalisation).
MAX_CORRELATION_SCORE: int = sum(CORRELATION_WEIGHTS.values())

#: Explicit, explainable alert-type relationships. Types absent from this map
#: (including ``UNKNOWN``) correlate with nothing on type alone.
RELATED_ALERT_TYPES: Dict[str, Set[str]] = {
    "LINK_DOWN": {
        "DEVICE_UNREACHABLE",
        "PACKET_LOSS",
        "HIGH_LATENCY",
    },
    "DEVICE_UNREACHABLE": {
        "LINK_DOWN",
        "PACKET_LOSS",
        "HIGH_LATENCY",
    },
    "PACKET_LOSS": {
        "LINK_DOWN",
        "DEVICE_UNREACHABLE",
        "HIGH_LATENCY",
    },
    "HIGH_LATENCY": {
        "LINK_DOWN",
        "PACKET_LOSS",
        "DEVICE_UNREACHABLE",
    },
    "AUTH_FAILURE": {
        "AUTH_FAILURE",
    },
}

#: Prefix used for deterministic candidate incident ids (``INC-0001``, ...).
INCIDENT_ID_PREFIX: str = "INC"
INCIDENT_ID_WIDTH: int = 4


class ScorerError(ValueError):
    """Raised when an alert cannot be scored (malformed input)."""


# ---------------------------------------------------------------------------
# Input adaptation — the engine accepts Alert or ProcessedAlert
# ---------------------------------------------------------------------------

ScorableAlert = Union[Alert, ProcessedAlert]


@dataclass(frozen=True)
class AlertView:
    """The minimal, normalised view of an alert the scorer reasons about."""

    alert_id: str
    device_id: str
    alert_type: str
    timestamp: datetime
    interface: Optional[str] = None
    device_name: Optional[str] = None
    source: ScorableAlert = None  # type: ignore[assignment]


def _coerce_timestamp(value: object, *, alert_id: str) -> datetime:
    """Return an aware UTC datetime, or raise :class:`ScorerError`."""
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ScorerError(f"alert {alert_id}: malformed timestamp {value!r}") from exc
    else:
        raise ScorerError(f"alert {alert_id}: missing or malformed timestamp {value!r}")

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def as_alert_view(alert: ScorableAlert) -> AlertView:
    """Normalise an :class:`Alert` or :class:`ProcessedAlert` into an :class:`AlertView`.

    Raises :class:`ScorerError` when the record is too malformed to score
    (no device, no usable timestamp). Callers that batch-process should use
    :func:`build_alert_views`, which collects errors instead of raising.
    """
    if isinstance(alert, AlertView):
        return alert

    if isinstance(alert, ProcessedAlert):
        base: Alert = alert.representative
        alert_id = base.id
        first_seen = alert.first_seen
    elif isinstance(alert, Alert):
        base = alert
        alert_id = base.id
        first_seen = base.timestamp
    else:
        raise ScorerError(f"unsupported alert object: {type(alert).__name__}")

    device_id = (base.node_id or "").strip()
    if not device_id:
        raise ScorerError(f"alert {alert_id}: missing device/node id")

    alert_type = base.type.value if isinstance(base.type, AlertType) else str(base.type)

    return AlertView(
        alert_id=alert_id,
        device_id=device_id,
        alert_type=alert_type,
        timestamp=_coerce_timestamp(first_seen, alert_id=alert_id),
        interface=base.interface,
        device_name=base.device_name,
        source=alert,
    )


def build_alert_views(
    alerts: Sequence[ScorableAlert],
) -> Tuple[List[AlertView], List[ScorerError]]:
    """Normalise a batch, skipping (and reporting) records that cannot be scored."""
    views: List[AlertView] = []
    errors: List[ScorerError] = []
    for alert in alerts:
        try:
            views.append(as_alert_view(alert))
        except ScorerError as exc:
            errors.append(exc)
    return views, errors


# ---------------------------------------------------------------------------
# Topology relationship
# ---------------------------------------------------------------------------


def are_devices_related(
    device_a: str,
    device_b: str,
    *,
    topology: Optional[NetworkTopology] = None,
) -> bool:
    """True when two *different* devices are directly linked in the topology.

    Uses the real graph from ``data/topology.json`` — never a hardcoded pair
    list. Unknown devices, disconnected devices and the same device twice all
    return ``False`` (the "same device" case is a separate signal).
    """
    if not device_a or not device_b or device_a == device_b:
        return False
    graph = topology or _default_topology()
    if graph is None:
        return False
    if device_a not in graph or device_b not in graph:
        return False
    return graph.get_link(device_a, device_b) is not None


def _default_topology() -> Optional[NetworkTopology]:
    """Load the shared topology, degrading to ``None`` if it is unavailable."""
    try:
        return get_topology()
    except TopologyError:
        return None


# ---------------------------------------------------------------------------
# Individual signals — each returns its point contribution
# ---------------------------------------------------------------------------


def score_same_device(a: AlertView, b: AlertView) -> int:
    """+30 when both alerts come from the same device."""
    return CORRELATION_WEIGHTS["same_device"] if a.device_id == b.device_id else 0


def score_topology_relationship(
    a: AlertView, b: AlertView, *, topology: Optional[NetworkTopology] = None
) -> int:
    """+20 when the two (different) devices are directly linked."""
    return (
        CORRELATION_WEIGHTS["related_device"]
        if are_devices_related(a.device_id, b.device_id, topology=topology)
        else 0
    )


def score_time_proximity(
    a: AlertView, b: AlertView, *, window_seconds: int = TIME_PROXIMITY_WINDOW_SECONDS
) -> int:
    """+20 when the alerts are within the proximity window (default 5 minutes)."""
    return CORRELATION_WEIGHTS["time_proximity"] if within_window(a, b, window_seconds) else 0


def within_window(
    a: AlertView, b: AlertView, window_seconds: int = TIME_PROXIMITY_WINDOW_SECONDS
) -> bool:
    """True when ``|a.timestamp - b.timestamp| <= window_seconds`` (inclusive)."""
    return abs(a.timestamp - b.timestamp) <= timedelta(seconds=window_seconds)


def are_types_related(type_a: str, type_b: str) -> bool:
    """True when the two alert types are explicitly declared related."""
    return type_b in RELATED_ALERT_TYPES.get(type_a, frozenset())


def score_alert_type_relationship(a: AlertView, b: AlertView) -> int:
    """+30 when the alert types are explicitly related to each other."""
    return (
        CORRELATION_WEIGHTS["related_type"]
        if are_types_related(a.alert_type, b.alert_type)
        else 0
    )


# ---------------------------------------------------------------------------
# Pairwise result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationResult:
    """Structured, explainable outcome of scoring one pair of alerts."""

    alert_a: str
    alert_b: str
    score: int
    signals: Dict[str, int]
    correlated: bool
    reasons: List[str] = field(default_factory=list)

    @property
    def explanation(self) -> str:
        """Human-readable, multi-line breakdown suitable for the UI."""
        lines = [f"Correlation score: {self.score}", ""]
        lines.extend(self.reasons)
        lines.append("")
        lines.append(
            f"Correlated (threshold {CORRELATION_THRESHOLD}): "
            f"{'yes' if self.correlated else 'no'}"
        )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "alert_a": self.alert_a,
            "alert_b": self.alert_b,
            "score": self.score,
            "max_score": MAX_CORRELATION_SCORE,
            "signals": dict(self.signals),
            "correlated": self.correlated,
            "reasons": list(self.reasons),
        }


_SIGNAL_LABELS: Dict[str, str] = {
    "same_device": "Same device",
    "related_device": "Topology relationship",
    "time_proximity": "Within 5 minutes",
    "related_type": "Related alert types",
}


def _build_reasons(signals: Dict[str, int]) -> List[str]:
    """One ``+points`` line per signal, always in the same order."""
    return [
        f"{_SIGNAL_LABELS[name]}: +{signals[name]}" for name in CORRELATION_WEIGHTS
    ]


def score_alert_pair(
    alert_a: ScorableAlert,
    alert_b: ScorableAlert,
    *,
    topology: Optional[NetworkTopology] = None,
    threshold: int = CORRELATION_THRESHOLD,
    window_seconds: int = TIME_PROXIMITY_WINDOW_SECONDS,
) -> CorrelationResult:
    """Score two alerts against the four correlation signals.

    Returns the total score, the per-signal breakdown, the correlated verdict
    and human-readable reasons. Pure and deterministic.
    """
    a = as_alert_view(alert_a)
    b = as_alert_view(alert_b)

    signals: Dict[str, int] = {
        "same_device": score_same_device(a, b),
        "related_device": score_topology_relationship(a, b, topology=topology),
        "time_proximity": score_time_proximity(a, b, window_seconds=window_seconds),
        "related_type": score_alert_type_relationship(a, b),
    }
    total = sum(signals.values())

    correlated = total >= threshold
    if correlated and REQUIRE_TIME_PROXIMITY and signals["time_proximity"] == 0:
        # Strong evidence but the events are far apart in time: not the same
        # network event. The score is kept as-is so the breakdown stays honest.
        correlated = False

    return CorrelationResult(
        alert_a=a.alert_id,
        alert_b=b.alert_id,
        score=total,
        signals=signals,
        correlated=correlated,
        reasons=_build_reasons(signals),
    )


def score_all_pairs(
    alerts: Sequence[ScorableAlert],
    *,
    topology: Optional[NetworkTopology] = None,
    threshold: int = CORRELATION_THRESHOLD,
    window_seconds: int = TIME_PROXIMITY_WINDOW_SECONDS,
) -> List[CorrelationResult]:
    """Score every unordered pair, in deterministic order."""
    views = _sorted_views(alerts)
    graph = topology or _default_topology()
    results: List[CorrelationResult] = []
    for i in range(len(views)):
        for j in range(i + 1, len(views)):
            results.append(
                score_alert_pair(
                    views[i],
                    views[j],
                    topology=graph,
                    threshold=threshold,
                    window_seconds=window_seconds,
                )
            )
    return results


def _sorted_views(alerts: Sequence[ScorableAlert]) -> List[AlertView]:
    """Normalise and order alerts by (timestamp, alert_id) — order-independent."""
    views, _errors = build_alert_views(alerts)
    deduped: Dict[str, AlertView] = {}
    for view in views:
        # A duplicate that somehow reaches the scorer is collapsed on identity.
        deduped.setdefault(view.alert_id, view)
    return sorted(deduped.values(), key=lambda v: (v.timestamp, v.alert_id))


# ---------------------------------------------------------------------------
# Candidate incidents
# ---------------------------------------------------------------------------


@dataclass
class CandidateIncident:
    """A group of alerts the engine believes describe one network event."""

    incident_id: str
    alert_ids: List[str]
    alerts: List[AlertView]
    correlation_score: int
    correlation_reasons: List[str]
    first_seen: datetime
    last_seen: datetime
    affected_devices: List[str]

    @property
    def alert_count(self) -> int:
        return len(self.alert_ids)

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "alert_ids": list(self.alert_ids),
            "alert_count": self.alert_count,
            "affected_devices": list(self.affected_devices),
            "correlation_score": self.correlation_score,
            "correlation_reasons": list(self.correlation_reasons),
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
        }


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _UnionFind:
    """Tiny deterministic union-find used for connected components."""

    def __init__(self, items: Iterable[str]) -> None:
        self._parent: Dict[str, str] = {item: item for item in items}

    def find(self, item: str) -> str:
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != root:  # path compression
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a == root_b:
            return
        # Deterministic merge: the lexicographically smaller root wins.
        if root_b < root_a:
            root_a, root_b = root_b, root_a
        self._parent[root_b] = root_a


def build_candidate_incidents(
    alerts: Sequence[ScorableAlert],
    *,
    topology: Optional[NetworkTopology] = None,
    threshold: int = CORRELATION_THRESHOLD,
    window_seconds: int = TIME_PROXIMITY_WINDOW_SECONDS,
) -> List[CandidateIncident]:
    """Group alerts into candidate incidents via correlated-pair components.

    Every pair is scored; pairs at or above the threshold become edges of a
    graph, and each connected component becomes one candidate incident. This
    gives transitive grouping (A-B, B-C => one incident) without ever using a
    naive "everything within N minutes is one incident" rule — time proximity
    is only one of four signals.

    Alerts that correlate with nothing become single-alert incidents, so noise
    stays separate instead of being absorbed into a major event.

    Incident ids are assigned deterministically (``INC-0001``, ``INC-0002``,
    ...) after ordering groups by (first_seen, first alert id).
    """
    views = _sorted_views(alerts)
    if not views:
        return []

    graph = topology or _default_topology()
    by_id: Dict[str, AlertView] = {v.alert_id: v for v in views}

    union = _UnionFind(by_id)
    edges: Dict[str, List[CorrelationResult]] = {v.alert_id: [] for v in views}

    for i in range(len(views)):
        for j in range(i + 1, len(views)):
            result = score_alert_pair(
                views[i],
                views[j],
                topology=graph,
                threshold=threshold,
                window_seconds=window_seconds,
            )
            if result.correlated:
                union.union(result.alert_a, result.alert_b)
                edges[result.alert_a].append(result)
                edges[result.alert_b].append(result)

    components: Dict[str, List[AlertView]] = {}
    for view in views:  # views are already in deterministic order
        components.setdefault(union.find(view.alert_id), []).append(view)

    groups = sorted(
        components.values(),
        key=lambda members: (members[0].timestamp, members[0].alert_id),
    )

    incidents: List[CandidateIncident] = []
    for index, members in enumerate(groups, start=1):
        incidents.append(
            _build_incident(_incident_id(index), members, edges)
        )
    return incidents


def _incident_id(index: int) -> str:
    return f"{INCIDENT_ID_PREFIX}-{index:0{INCIDENT_ID_WIDTH}d}"


def _build_incident(
    incident_id: str,
    members: List[AlertView],
    edges: Dict[str, List[CorrelationResult]],
) -> CandidateIncident:
    member_ids = [v.alert_id for v in members]
    member_set = set(member_ids)

    # Collect the correlated pairs that live inside this group, once each.
    pairs: Dict[Tuple[str, str], CorrelationResult] = {}
    for alert_id in member_ids:
        for result in edges.get(alert_id, []):
            if result.alert_a in member_set and result.alert_b in member_set:
                pairs[(result.alert_a, result.alert_b)] = result

    if pairs:
        ordered = [pairs[key] for key in sorted(pairs)]
        score = round(sum(r.score for r in ordered) / len(ordered))
        reasons = [
            f"{r.alert_a} <-> {r.alert_b}: score {r.score} "
            f"(" + ", ".join(f"{name}+{r.signals[name]}" for name in CORRELATION_WEIGHTS) + ")"
            for r in ordered
        ]
    else:
        score = 0
        reasons = ["Single alert: no correlated pairs above threshold."]

    timestamps = [v.timestamp for v in members]
    return CandidateIncident(
        incident_id=incident_id,
        alert_ids=member_ids,
        alerts=list(members),
        correlation_score=score,
        correlation_reasons=reasons,
        first_seen=min(timestamps),
        last_seen=max(timestamps),
        affected_devices=sorted({v.device_id for v in members}),
    )


def correlate(
    alerts: Sequence[ScorableAlert],
    *,
    topology: Optional[NetworkTopology] = None,
    threshold: int = CORRELATION_THRESHOLD,
    window_seconds: int = TIME_PROXIMITY_WINDOW_SECONDS,
) -> Tuple[List[CandidateIncident], List[ScorerError]]:
    """Convenience entry point: candidate incidents plus per-alert errors."""
    _views, errors = build_alert_views(alerts)
    incidents = build_candidate_incidents(
        alerts, topology=topology, threshold=threshold, window_seconds=window_seconds
    )
    return incidents, errors


__all__ = [
    "CORRELATION_WEIGHTS",
    "CORRELATION_THRESHOLD",
    "TIME_PROXIMITY_WINDOW_SECONDS",
    "REQUIRE_TIME_PROXIMITY",
    "MAX_CORRELATION_SCORE",
    "RELATED_ALERT_TYPES",
    "ScorerError",
    "AlertView",
    "CorrelationResult",
    "CandidateIncident",
    "as_alert_view",
    "build_alert_views",
    "are_devices_related",
    "are_types_related",
    "within_window",
    "score_same_device",
    "score_topology_relationship",
    "score_time_proximity",
    "score_alert_type_relationship",
    "score_alert_pair",
    "score_all_pairs",
    "build_candidate_incidents",
    "correlate",
]
