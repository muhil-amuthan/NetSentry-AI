"""
Correlation Scoring Engine (Step 6).

Responsibility
--------------
Convert processed alerts into **candidate incidents** by scoring every pair of
alerts against four explainable evidence signals and then grouping correlated
pairs using a connected-components algorithm.

Pipeline
--------
::

    Raw Alerts
        ↓
    Processor / Deduplication   (src/processor.py)
        ↓
    Processed Alerts
        ↓
    CORRELATION SCORING ENGINE  (this module)
        ↓
    Candidate Incidents

Design rules
------------
1. **Deterministic.** Same input → same scores, same grouping, same incident
   IDs, same ordering. No random numbers, no UUID generation, no clock reads,
   no external services.
2. **Explainable.** Every correlation result carries an explicit score
   breakdown (per-signal contributions) so the UI can show the reasoning.
3. **Topology-aware.** Devices directly linked in ``data/topology.json`` score
   higher than disconnected devices. Topology is loaded once and shared.
4. **Threshold-gated.** Only alert pairs whose total score meets
   :data:`CORRELATION_THRESHOLD` are considered correlated.

Scope note (Step 6)
-------------------
This module does NOT implement:

* incident priority or severity classification
* root-cause analysis
* runbook retrieval
* Gemini / LLM reasoning
* FAISS / embeddings
* escalation
* NLP / natural language
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from src.models import Alert, AlertType
from src.processor import ProcessedAlert
from src.topology import NetworkTopology, get_topology


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

#: Per-signal weights — edit here to tune the engine; do not scatter magic
#: numbers through the code.
CORRELATION_WEIGHTS: Dict[str, int] = {
    "same_device": 30,
    "related_device": 20,
    "time_proximity": 20,
    "related_type": 30,
}

#: Minimum score required to consider two alerts correlated.
CORRELATION_THRESHOLD: int = 60

#: Maximum elapsed seconds between two alerts for the time-proximity signal.
TIME_PROXIMITY_WINDOW_SECONDS: int = 300  # 5 minutes

#: Explicit, bidirectional alert-type relationship map.
#: Only types listed here will score ``related_type`` points together.
RELATED_ALERT_TYPES: Dict[str, Set[str]] = {
    AlertType.LINK_DOWN.value: {
        AlertType.DEVICE_UNREACHABLE.value,
        AlertType.PACKET_LOSS.value,
        AlertType.HIGH_LATENCY.value,
        AlertType.IF_FLAP.value,
        AlertType.CRC_ERRORS.value,
        AlertType.OPTICAL_RX_LOW.value,
    },
    AlertType.DEVICE_UNREACHABLE.value: {
        AlertType.LINK_DOWN.value,
        AlertType.PACKET_LOSS.value,
        AlertType.HIGH_LATENCY.value,
        AlertType.AUTH_FAILURE.value,
    },
    AlertType.PACKET_LOSS.value: {
        AlertType.LINK_DOWN.value,
        AlertType.DEVICE_UNREACHABLE.value,
        AlertType.HIGH_LATENCY.value,
        AlertType.JITTER_THRESHOLD.value,
    },
    AlertType.HIGH_LATENCY.value: {
        AlertType.LINK_DOWN.value,
        AlertType.DEVICE_UNREACHABLE.value,
        AlertType.PACKET_LOSS.value,
        AlertType.JITTER_THRESHOLD.value,
    },
    AlertType.AUTH_FAILURE.value: {
        AlertType.AUTH_FAILURE.value,
        AlertType.RADIUS_TIMEOUT.value,
        AlertType.DEVICE_UNREACHABLE.value,
    },
    AlertType.JITTER_THRESHOLD.value: {
        AlertType.PACKET_LOSS.value,
        AlertType.HIGH_LATENCY.value,
    },
    AlertType.IF_FLAP.value: {
        AlertType.LINK_DOWN.value,
        AlertType.CRC_ERRORS.value,
        AlertType.OPTICAL_RX_LOW.value,
    },
    AlertType.CRC_ERRORS.value: {
        AlertType.LINK_DOWN.value,
        AlertType.IF_FLAP.value,
        AlertType.OPTICAL_RX_LOW.value,
    },
    AlertType.OPTICAL_RX_LOW.value: {
        AlertType.LINK_DOWN.value,
        AlertType.IF_FLAP.value,
        AlertType.CRC_ERRORS.value,
    },
    AlertType.RADIUS_TIMEOUT.value: {
        AlertType.AUTH_FAILURE.value,
    },
    AlertType.BGP_SESSION_DROP.value: {
        AlertType.LINK_DOWN.value,
        AlertType.DEVICE_UNREACHABLE.value,
    },
    AlertType.CPU_HIGH.value: {
        AlertType.MEMORY_HIGH.value,
    },
    AlertType.MEMORY_HIGH.value: {
        AlertType.CPU_HIGH.value,
    },
    AlertType.POWER_SUPPLY_FAILURE.value: {
        AlertType.DEVICE_UNREACHABLE.value,
        AlertType.TEMPERATURE_HIGH.value,
    },
    AlertType.TEMPERATURE_HIGH.value: {
        AlertType.POWER_SUPPLY_FAILURE.value,
    },
    # UNKNOWN, LINK_UP, CONFIG_CHANGE intentionally absent: they correlate
    # with nothing by default, so they stay isolated unless same-device or
    # topology rules lift them to threshold.
}


# ---------------------------------------------------------------------------
# Individual signal scorers
# ---------------------------------------------------------------------------


def score_same_device(alert_a: Alert, alert_b: Alert) -> int:
    """Return ``CORRELATION_WEIGHTS["same_device"]`` when both alerts originate
    from the same device, ``0`` otherwise.

    Comparison is on the normalised ``node_id`` field.
    """
    if alert_a.node_id == alert_b.node_id:
        return CORRELATION_WEIGHTS["same_device"]
    return 0


def score_topology_relationship(
    alert_a: Alert,
    alert_b: Alert,
    topology: Optional[NetworkTopology] = None,
) -> int:
    """Return ``CORRELATION_WEIGHTS["related_device"]`` when the two devices
    are directly connected by a link in the network topology.

    Uses ``data/topology.json`` via the shared :func:`~src.topology.get_topology`
    cache.  Devices not present in the topology (e.g. ``INTERNET``) are handled
    gracefully — the function returns ``0`` rather than raising.

    Same-device pairs always return ``0`` here (same-device is a separate
    signal).
    """
    if alert_a.node_id == alert_b.node_id:
        return 0
    topo = topology or get_topology()
    # get_link returns None for both unknown nodes and genuinely absent links.
    link = topo.get_link(alert_a.node_id, alert_b.node_id)
    if link is not None:
        return CORRELATION_WEIGHTS["related_device"]
    return 0


def score_time_proximity(alert_a: Alert, alert_b: Alert) -> int:
    """Return ``CORRELATION_WEIGHTS["time_proximity"]`` when the two alerts
    arrive within :data:`TIME_PROXIMITY_WINDOW_SECONDS` of each other.

    Uses absolute delta to handle out-of-order timestamps.
    """
    try:
        delta = abs((alert_a.timestamp - alert_b.timestamp).total_seconds())
    except (AttributeError, TypeError):
        return 0
    if delta <= TIME_PROXIMITY_WINDOW_SECONDS:
        return CORRELATION_WEIGHTS["time_proximity"]
    return 0


def score_alert_type_relationship(alert_a: Alert, alert_b: Alert) -> int:
    """Return ``CORRELATION_WEIGHTS["related_type"]`` when the alert types are
    related according to :data:`RELATED_ALERT_TYPES`.

    Same-type alerts also score here only when the type appears in the map as
    its own relation (e.g. ``AUTH_FAILURE`` relates to ``AUTH_FAILURE``).
    Types absent from the map score ``0`` (conservative — no false positives).
    """
    type_a = alert_a.type.value
    type_b = alert_b.type.value
    related_to_a = RELATED_ALERT_TYPES.get(type_a, set())
    if type_b in related_to_a:
        return CORRELATION_WEIGHTS["related_type"]
    return 0


# ---------------------------------------------------------------------------
# Pair scoring
# ---------------------------------------------------------------------------


@dataclass
class SignalScores:
    """Individual contribution from each correlation signal."""

    same_device: int = 0
    related_device: int = 0
    time_proximity: int = 0
    related_type: int = 0

    @property
    def total(self) -> int:
        return (
            self.same_device
            + self.related_device
            + self.time_proximity
            + self.related_type
        )

    def to_dict(self) -> Dict[str, int]:
        return {
            "same_device": self.same_device,
            "related_device": self.related_device,
            "time_proximity": self.time_proximity,
            "related_type": self.related_type,
        }


@dataclass
class PairScore:
    """Correlation result for a single alert pair."""

    alert_id_a: str
    alert_id_b: str
    signals: SignalScores
    correlated: bool
    explanation: str

    @property
    def score(self) -> int:
        return self.signals.total

    def to_dict(self) -> dict:
        return {
            "alert_id_a": self.alert_id_a,
            "alert_id_b": self.alert_id_b,
            "score": self.score,
            "correlated": self.correlated,
            "signals": self.signals.to_dict(),
            "explanation": self.explanation,
        }


def _build_explanation(signals: SignalScores, correlated: bool) -> str:
    """Human-readable summary of how the score was computed."""
    lines = [f"Correlation score: {signals.total}"]
    lines.append(
        f"Same device: +{signals.same_device}"
        if signals.same_device
        else "Same device: +0"
    )
    lines.append(
        f"Topology relationship: +{signals.related_device}"
        if signals.related_device
        else "Topology relationship: +0"
    )
    lines.append(
        f"Within 5 minutes: +{signals.time_proximity}"
        if signals.time_proximity
        else "Within 5 minutes: +0"
    )
    lines.append(
        f"Related alert types: +{signals.related_type}"
        if signals.related_type
        else "Related alert types: +0"
    )
    lines.append(
        f"Decision: {'CORRELATED' if correlated else 'NOT correlated'} "
        f"(threshold={CORRELATION_THRESHOLD})"
    )
    return "\n".join(lines)


def score_alert_pair(
    alert_a: Alert,
    alert_b: Alert,
    topology: Optional[NetworkTopology] = None,
) -> PairScore:
    """Score the correlation between two alerts.

    Parameters
    ----------
    alert_a, alert_b:
        Any two :class:`~src.models.Alert` objects.
    topology:
        Optional pre-loaded topology; uses the shared cache when ``None``.

    Returns
    -------
    PairScore
        Structured result with total score, per-signal breakdown, a
        ``correlated`` boolean and a human-readable explanation string.
    """
    signals = SignalScores(
        same_device=score_same_device(alert_a, alert_b),
        related_device=score_topology_relationship(alert_a, alert_b, topology),
        time_proximity=score_time_proximity(alert_a, alert_b),
        related_type=score_alert_type_relationship(alert_a, alert_b),
    )
    correlated = signals.total >= CORRELATION_THRESHOLD
    explanation = _build_explanation(signals, correlated)
    return PairScore(
        alert_id_a=alert_a.id,
        alert_id_b=alert_b.id,
        signals=signals,
        correlated=correlated,
        explanation=explanation,
    )


def are_devices_related(
    device_a: str,
    device_b: str,
    topology: Optional[NetworkTopology] = None,
) -> bool:
    """Return ``True`` when two device IDs are directly connected in the topology.

    Reusable helper for callers that need a topology adjacency check without
    constructing dummy :class:`~src.models.Alert` objects.
    """
    if device_a == device_b:
        return False
    topo = topology or get_topology()
    return topo.get_link(device_a, device_b) is not None


# ---------------------------------------------------------------------------
# Candidate incident structure
# ---------------------------------------------------------------------------


@dataclass
class CandidateIncident:
    """A group of correlated alerts that likely stem from the same root event.

    This is a **candidate** — it is not yet scored for priority, analysed for
    root cause, or matched to a runbook.  Those come in later steps.
    """

    incident_id: str
    alert_ids: List[str]
    alerts: List[Alert]
    correlation_score: float           # average pairwise score inside the group
    correlation_reasons: List[str]     # per-pair explanation strings
    first_seen: datetime
    last_seen: datetime
    affected_devices: List[str]        # ordered, unique device names

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "alert_ids": list(self.alert_ids),
            "affected_devices": list(self.affected_devices),
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "correlation_score": round(self.correlation_score, 2),
            "correlation_reasons": list(self.correlation_reasons),
        }


def _iso(dt: datetime) -> str:
    """UTC ISO-8601 string with a trailing ``Z``."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Connected-components grouping
# ---------------------------------------------------------------------------


def _union_find_group(
    alert_ids: List[str],
    correlated_pairs: Set[FrozenSet[str]],
) -> List[List[str]]:
    """Partition ``alert_ids`` into connected components.

    Two alerts are in the same component when their IDs appear in a correlated
    pair, directly or transitively.  The result is deterministic: components
    are sorted internally and the list of components is sorted by the first
    member of each component.

    Uses Union-Find (path compression + union by rank) for efficiency.
    """
    # parent / rank maps for Union-Find.
    parent: Dict[str, str] = {aid: aid for aid in alert_ids}
    rank: Dict[str, int] = {aid: 0 for aid in alert_ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path compression
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx == ry:
            return
        if rank[rx] < rank[ry]:
            rx, ry = ry, rx
        parent[ry] = rx
        if rank[rx] == rank[ry]:
            rank[rx] += 1

    for pair in correlated_pairs:
        pair_list = sorted(pair)  # deterministic iteration
        if len(pair_list) == 2:
            a, b = pair_list
            if a in parent and b in parent:
                union(a, b)

    # Collect components.
    groups: Dict[str, List[str]] = {}
    for aid in alert_ids:
        root = find(aid)
        groups.setdefault(root, []).append(aid)

    # Sort each component and the list of components for determinism.
    result = [sorted(members) for members in groups.values()]
    result.sort()
    return result


# ---------------------------------------------------------------------------
# Main grouping function
# ---------------------------------------------------------------------------


def build_candidate_incidents(
    alerts: List[Alert],
    topology: Optional[NetworkTopology] = None,
    *,
    threshold: int = CORRELATION_THRESHOLD,
) -> List[CandidateIncident]:
    """Score every alert pair and group correlated alerts into candidate incidents.

    Algorithm
    ---------
    1. Score every (i, j) pair (i < j) with :func:`score_alert_pair`.
    2. Build a set of correlated pairs (score ≥ ``threshold``).
    3. Use Union-Find to identify connected components.
    4. Each component becomes one :class:`CandidateIncident`.
    5. Singleton components (alerts that correlate with nothing) each become
       their own incident — they are not dropped.

    Determinism
    -----------
    Input is sorted by ``(timestamp, id)`` before processing so the output is
    independent of the order the caller passes alerts in.  Incident IDs are
    assigned as ``INC-0001``, ``INC-0002``, … in component-first-seen order.

    Parameters
    ----------
    alerts:
        Normalised :class:`~src.models.Alert` objects (typically the
        ``representative`` field from each :class:`~src.processor.ProcessedAlert`).
    topology:
        Optional pre-loaded :class:`~src.topology.NetworkTopology`; uses the
        shared cache when ``None``.
    threshold:
        Override the default :data:`CORRELATION_THRESHOLD`.

    Returns
    -------
    List[CandidateIncident]
        One candidate incident per connected component, ordered by
        ``first_seen``.
    """
    if not alerts:
        return []

    topo = topology or get_topology()

    # Stable sort for determinism.
    sorted_alerts: List[Alert] = sorted(alerts, key=lambda a: (a.timestamp, a.id))
    alert_by_id: Dict[str, Alert] = {a.id: a for a in sorted_alerts}
    alert_ids = [a.id for a in sorted_alerts]

    # Score every pair; collect correlated pairs and their explanations.
    correlated_pairs: Set[FrozenSet[str]] = set()
    pair_scores: Dict[FrozenSet[str], PairScore] = {}

    for i in range(len(sorted_alerts)):
        for j in range(i + 1, len(sorted_alerts)):
            a, b = sorted_alerts[i], sorted_alerts[j]
            ps = score_alert_pair(a, b, topo)
            key = frozenset((a.id, b.id))
            pair_scores[key] = ps
            if ps.correlated:
                correlated_pairs.add(key)

    # Group into connected components.
    components = _union_find_group(alert_ids, correlated_pairs)

    # Build CandidateIncident for each component, ordered by first_seen.
    incidents: List[CandidateIncident] = []
    for members in components:
        member_alerts = [alert_by_id[aid] for aid in members]
        # Sort member alerts by timestamp for consistent ordering.
        member_alerts.sort(key=lambda a: (a.timestamp, a.id))

        first_seen = min(a.timestamp for a in member_alerts)
        last_seen = max(a.timestamp for a in member_alerts)

        # Unique device names, preserving first-seen order.
        seen_devices: Set[str] = set()
        affected_devices: List[str] = []
        for a in member_alerts:
            name = a.device_name or a.node_id
            if name not in seen_devices:
                affected_devices.append(name)
                seen_devices.add(name)

        # Gather per-pair explanations for pairs inside this component.
        reasons: List[str] = []
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                key = frozenset((members[i], members[j]))
                if key in pair_scores and pair_scores[key].correlated:
                    reasons.append(pair_scores[key].explanation)

        # Average pairwise score within the group.
        internal_pairs = [
            pair_scores[frozenset((members[i], members[j]))]
            for i in range(len(members))
            for j in range(i + 1, len(members))
            if frozenset((members[i], members[j])) in pair_scores
        ]
        avg_score = (
            sum(ps.score for ps in internal_pairs) / len(internal_pairs)
            if internal_pairs
            else 0.0
        )

        incidents.append(
            CandidateIncident(
                incident_id="",           # assigned after sorting
                alert_ids=[a.id for a in member_alerts],
                alerts=member_alerts,
                correlation_score=avg_score,
                correlation_reasons=reasons,
                first_seen=first_seen,
                last_seen=last_seen,
                affected_devices=affected_devices,
            )
        )

    # Sort incidents by first_seen, then by first alert_id for total determinism.
    incidents.sort(key=lambda inc: (inc.first_seen, inc.alert_ids[0]))

    # Assign deterministic IDs.
    for idx, inc in enumerate(incidents, start=1):
        inc.incident_id = f"INC-{idx:04d}"

    return incidents


# ---------------------------------------------------------------------------
# Convenience entry points
# ---------------------------------------------------------------------------


def correlate_processed_alerts(
    processed: List[ProcessedAlert],
    topology: Optional[NetworkTopology] = None,
    *,
    threshold: int = CORRELATION_THRESHOLD,
) -> List[CandidateIncident]:
    """Convenience wrapper: extract the representative alert from each
    :class:`~src.processor.ProcessedAlert` and run the correlation engine.

    This is the natural entry point when the caller has already passed alerts
    through :func:`~src.processor.process_alerts`.
    """
    representatives = [pa.representative for pa in processed]
    return build_candidate_incidents(representatives, topology, threshold=threshold)


__all__ = [
    # Configuration
    "CORRELATION_WEIGHTS",
    "CORRELATION_THRESHOLD",
    "TIME_PROXIMITY_WINDOW_SECONDS",
    "RELATED_ALERT_TYPES",
    # Signal scorers
    "score_same_device",
    "score_topology_relationship",
    "score_time_proximity",
    "score_alert_type_relationship",
    # Pair scoring
    "SignalScores",
    "PairScore",
    "score_alert_pair",
    "are_devices_related",
    # Grouping
    "CandidateIncident",
    "build_candidate_incidents",
    "correlate_processed_alerts",
]
