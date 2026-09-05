"""
Alert processing pipeline (Step 5).

Responsibility
--------------
Transform a list of raw :class:`~src.models.Alert` objects (as produced by
``src/generator.py``) into a deduplicated list of :class:`ProcessedAlert`
records ready for the future correlation engine.

Pipeline
--------
::

    Raw Alerts
        ↓
    Validation          (reject / surface obviously bad records)
        ↓
    Normalization       (canonical type / severity / device-id strings)
        ↓
    Deduplication       (group same-fingerprint observations inside a window)
        ↓
    Processed Alerts

Scope note (Step 5)
-------------------
This module:

* normalises alert type, severity and device-id strings so that
  ``LINK_DOWN``, ``link_down`` and ``Link_Down`` all resolve to the same
  canonical form.
* builds a **deterministic fingerprint** from ``node_id``, ``interface`` and
  ``alert_type``.
* groups alerts that share a fingerprint and arrive within a configurable
  **deduplication window** (default 60 seconds).
* preserves the representative alert, the occurrence count, all original alert
  IDs, first/last timestamps and the set of reporting sources for every group.

This module does NOT:

* create incidents, assign scores, calculate priority, do root-cause analysis,
  call Gemini, use FAISS, embeddings, runbooks, NLP or any external service.

All public functions are deterministic: same input → same output, always.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from src.models import Alert, AlertType, Severity


# ---------------------------------------------------------------------------
# Public configuration
# ---------------------------------------------------------------------------

#: Default deduplication window in seconds (configurable per call).
DEFAULT_DEDUP_WINDOW_SECONDS: int = 60


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ProcessorError(ValueError):
    """Raised when an alert is so malformed that it cannot be processed.

    Unlike normalisation (which is tolerant), this signals a structural
    problem — e.g. a missing ``id`` or ``node_id`` — that the pipeline cannot
    paper over.
    """


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

#: Case-folded spellings → canonical AlertType.value string.
#: Complements :meth:`~src.models.AlertType._missing_` which returns UNKNOWN
#: for unrecognised values; here we handle common vendor spellings *before*
#: the enum lookup so the canonical value is set correctly.
_ALERT_TYPE_ALIASES: Dict[str, str] = {
    # LINK_DOWN variants
    "link_down": AlertType.LINK_DOWN.value,
    "linkdown": AlertType.LINK_DOWN.value,
    "link-down": AlertType.LINK_DOWN.value,
    "if_down": AlertType.LINK_DOWN.value,
    "interface_down": AlertType.LINK_DOWN.value,
    "port_down": AlertType.LINK_DOWN.value,
    # LINK_UP variants
    "link_up": AlertType.LINK_UP.value,
    "linkup": AlertType.LINK_UP.value,
    "link-up": AlertType.LINK_UP.value,
    "if_up": AlertType.LINK_UP.value,
    "interface_up": AlertType.LINK_UP.value,
    "port_up": AlertType.LINK_UP.value,
    # DEVICE_UNREACHABLE variants
    "device_unreachable": AlertType.DEVICE_UNREACHABLE.value,
    "device-unreachable": AlertType.DEVICE_UNREACHABLE.value,
    "unreachable": AlertType.DEVICE_UNREACHABLE.value,
    "node_down": AlertType.DEVICE_UNREACHABLE.value,
    "host_unreachable": AlertType.DEVICE_UNREACHABLE.value,
    "ping_failure": AlertType.DEVICE_UNREACHABLE.value,
    # PACKET_LOSS variants
    "packet_loss": AlertType.PACKET_LOSS.value,
    "packet-loss": AlertType.PACKET_LOSS.value,
    "packetloss": AlertType.PACKET_LOSS.value,
    "pkt_loss": AlertType.PACKET_LOSS.value,
    # HIGH_LATENCY variants
    "high_latency": AlertType.HIGH_LATENCY.value,
    "high-latency": AlertType.HIGH_LATENCY.value,
    "highlatency": AlertType.HIGH_LATENCY.value,
    "latency_high": AlertType.HIGH_LATENCY.value,
    # JITTER_THRESHOLD variants
    "jitter_threshold": AlertType.JITTER_THRESHOLD.value,
    "jitter": AlertType.JITTER_THRESHOLD.value,
    # CRC_ERRORS variants
    "crc_errors": AlertType.CRC_ERRORS.value,
    "crc-errors": AlertType.CRC_ERRORS.value,
    "crc_error": AlertType.CRC_ERRORS.value,
    # IF_FLAP variants
    "if_flap": AlertType.IF_FLAP.value,
    "interface_flap": AlertType.IF_FLAP.value,
    "link_flap": AlertType.IF_FLAP.value,
    # BGP_SESSION_DROP variants
    "bgp_session_drop": AlertType.BGP_SESSION_DROP.value,
    "bgp-session-drop": AlertType.BGP_SESSION_DROP.value,
    "bgp_drop": AlertType.BGP_SESSION_DROP.value,
    "bgp_down": AlertType.BGP_SESSION_DROP.value,
    # OPTICAL_RX_LOW variants
    "optical_rx_low": AlertType.OPTICAL_RX_LOW.value,
    "optical-rx-low": AlertType.OPTICAL_RX_LOW.value,
    "rx_low": AlertType.OPTICAL_RX_LOW.value,
    # AUTH_FAILURE variants
    "auth_failure": AlertType.AUTH_FAILURE.value,
    "auth-failure": AlertType.AUTH_FAILURE.value,
    "authentication_failure": AlertType.AUTH_FAILURE.value,
    # RADIUS_TIMEOUT variants
    "radius_timeout": AlertType.RADIUS_TIMEOUT.value,
    "radius-timeout": AlertType.RADIUS_TIMEOUT.value,
    # CPU_HIGH variants
    "cpu_high": AlertType.CPU_HIGH.value,
    "cpu-high": AlertType.CPU_HIGH.value,
    "cpu_utilization_high": AlertType.CPU_HIGH.value,
    # MEMORY_HIGH variants
    "memory_high": AlertType.MEMORY_HIGH.value,
    "memory-high": AlertType.MEMORY_HIGH.value,
    "mem_high": AlertType.MEMORY_HIGH.value,
    # POWER_SUPPLY_FAILURE variants
    "power_supply_failure": AlertType.POWER_SUPPLY_FAILURE.value,
    "psu_failure": AlertType.POWER_SUPPLY_FAILURE.value,
    # TEMPERATURE_HIGH variants
    "temperature_high": AlertType.TEMPERATURE_HIGH.value,
    "temp_high": AlertType.TEMPERATURE_HIGH.value,
    # CONFIG_CHANGE variants
    "config_change": AlertType.CONFIG_CHANGE.value,
    "configuration_change": AlertType.CONFIG_CHANGE.value,
}


def _normalize_alert_type(raw: str) -> AlertType:
    """Map a raw type string onto the canonical :class:`~src.models.AlertType`.

    Normalisation order:
    1. Strip surrounding whitespace and case-fold.
    2. Try the vendor alias table (covers common spellings).
    3. Fall back to :class:`~src.models.AlertType` enum lookup, which itself
       falls back to ``UNKNOWN`` for anything unrecognised.

    The raw string is **never silently discarded**: if the canonical type
    becomes ``UNKNOWN``, callers are expected to preserve the original string
    in ``Alert.labels["raw_type"]`` (the generator already does this).
    """
    if not isinstance(raw, str):
        return AlertType.UNKNOWN
    normalised = raw.strip().lower()
    if normalised in _ALERT_TYPE_ALIASES:
        return AlertType(_ALERT_TYPE_ALIASES[normalised])
    # AlertType._missing_ returns UNKNOWN for anything it doesn't know.
    return AlertType(raw.strip().upper())


def _normalize_node_id(node_id: str) -> str:
    """Normalise a device/node id for reliable comparison.

    Strips surrounding whitespace. Does NOT lower-case because node IDs in
    ``data/topology.json`` are uppercase (``R1``, ``S1`` …) and the generator
    uses them verbatim; we want fingerprints to match without mapping.
    """
    return node_id.strip()


def _normalize_interface(interface: Optional[str]) -> Optional[str]:
    """Normalise an interface name for fingerprinting.

    Strips whitespace; preserves original capitalisation because interface
    names such as ``Te0/1``, ``et-0/0/1``, ``ge-0/0/10`` are case-sensitive
    in practice and the generator uses them as-is.  Returns ``None`` when no
    interface is present so the fingerprint branch is clear.
    """
    if interface is None:
        return None
    stripped = interface.strip()
    return stripped if stripped else None


# ---------------------------------------------------------------------------
# Public normalisation API
# ---------------------------------------------------------------------------


def normalize_alert(alert: Alert) -> Alert:
    """Return a new :class:`~src.models.Alert` with normalised fields.

    The following fields are normalised in-place on a fresh copy:

    * ``type``   — via :func:`_normalize_alert_type` (case / synonym mapping).
    * ``node_id`` — whitespace stripped.
    * ``interface`` — whitespace stripped; empty string → ``None``.
    * ``severity`` — already normalised by the Pydantic model's validator; no
      extra work needed here, but we call ``Severity.normalize`` defensively.

    The original alert is **not mutated**; ``Alert.model_copy`` produces a
    shallow copy with the changed fields.

    Raises
    ------
    ProcessorError
        If the alert is missing an ``id`` or ``node_id``.
    """
    if not alert.id or not alert.id.strip():
        raise ProcessorError("alert is missing a required 'id' field")
    if not alert.node_id or not alert.node_id.strip():
        raise ProcessorError(
            f"alert {alert.id!r} is missing a required 'node_id' field"
        )

    # Re-normalise type — catches any case / spelling that slipped through
    # the model validator (e.g. a manually constructed alert with 'link_down').
    canonical_type = _normalize_alert_type(alert.type.value)

    # If normalisation changed the type AND a raw_type is not yet recorded,
    # preserve the original.  (The generator already does this for UNKNOWN
    # transitions; this covers any future non-generator paths.)
    updated_labels = dict(alert.labels)
    if canonical_type != alert.type and "raw_type" not in updated_labels:
        updated_labels["raw_type"] = alert.type.value

    normalised_node_id = _normalize_node_id(alert.node_id)
    normalised_interface = _normalize_interface(alert.interface)
    normalised_severity = Severity.normalize(alert.severity)

    return alert.model_copy(
        update={
            "type": canonical_type,
            "node_id": normalised_node_id,
            "interface": normalised_interface,
            "severity": normalised_severity,
            "labels": updated_labels,
        }
    )


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------


def build_fingerprint(alert: Alert) -> str:
    """Build a stable, deterministic identity string for an alert condition.

    Format::

        <node_id>:<interface_or_dash>:<alert_type>

    * ``node_id`` — the normalised device identifier.
    * ``interface`` — the normalised interface name, or ``-`` when absent.
    * ``alert_type`` — the canonical :class:`~src.models.AlertType` value
      string (e.g. ``LINK_DOWN``).

    Two alerts sharing the same fingerprint describe **the same condition on
    the same device/interface**.  The deduplication step uses fingerprints to
    decide whether observations should be grouped.

    This function is intentionally identical in structure to
    ``Alert.fingerprint`` (which is a model property) so the two can be used
    interchangeably; it exists as a standalone, reusable function so tests and
    future pipeline stages can call it without a model instance.
    """
    node_id = _normalize_node_id(alert.node_id)
    iface = _normalize_interface(alert.interface) or "-"
    alert_type = _normalize_alert_type(alert.type.value).value
    return f"{node_id}:{iface}:{alert_type}"


# ---------------------------------------------------------------------------
# ProcessedAlert — the deduplication output unit
# ---------------------------------------------------------------------------


@dataclass
class ProcessedAlert:
    """The result of grouping one or more duplicate alert observations.

    Every :class:`ProcessedAlert` has exactly one *representative* alert —
    the first observation in the deduplication window — plus aggregated
    metadata about all observations in the group.

    Fields
    ------
    fingerprint:
        Stable identity string (``node_id:interface_or_dash:alert_type``).
    representative:
        The first :class:`~src.models.Alert` in the group, normalised.
        This is the object the future correlation engine will work with.
    count:
        Total number of raw alert observations collapsed into this group.
    alert_ids:
        All original alert ``id`` values in arrival order (oldest first).
    first_seen:
        Timestamp of the earliest observation in the group.
    last_seen:
        Timestamp of the latest observation in the group.
    sources:
        Ordered list of unique ``source`` strings that reported this condition
        (insertion order = order of first appearance).
    """

    fingerprint: str
    representative: Alert
    count: int
    alert_ids: List[str]
    first_seen: datetime
    last_seen: datetime
    sources: List[str]

    # ------------------------------------------------------------------
    # Convenience / serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain JSON-serialisable representation of this group."""
        return {
            "fingerprint": self.fingerprint,
            "count": self.count,
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "sources": list(self.sources),
            "alert_ids": list(self.alert_ids),
        }


def _iso(dt: datetime) -> str:
    """UTC ISO-8601 string with a trailing ``Z``."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Internal grouping state
# ---------------------------------------------------------------------------


@dataclass
class _Group:
    """Mutable accumulator used while scanning alerts."""

    fingerprint: str
    representative: Alert          # first arrival (normalised)
    alert_ids: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    # ordered unique sources: use List + a companion set for O(1) membership
    sources: List[str] = field(default_factory=list)
    _source_set: set = field(default_factory=set, repr=False)

    def add(self, alert: Alert) -> None:
        self.alert_ids.append(alert.id)
        ts = alert.timestamp
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts
        if alert.source not in self._source_set:
            self.sources.append(alert.source)
            self._source_set.add(alert.source)

    def to_processed(self) -> ProcessedAlert:
        return ProcessedAlert(
            fingerprint=self.fingerprint,
            representative=self.representative,
            count=len(self.alert_ids),
            alert_ids=list(self.alert_ids),
            first_seen=self.first_seen or self.representative.timestamp,
            last_seen=self.last_seen or self.representative.timestamp,
            sources=list(self.sources),
        )


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def deduplicate_alerts(
    alerts: Sequence[Alert],
    *,
    window_seconds: int = DEFAULT_DEDUP_WINDOW_SECONDS,
) -> List[ProcessedAlert]:
    """Group duplicate alert observations within a configurable time window.

    An alert is considered a **duplicate** of an earlier observation when:

    * same ``node_id`` (after normalisation),
    * same ``alert_type`` (after normalisation),
    * same ``interface`` (after normalisation — ``None`` matches ``None``),
    * its timestamp falls within ``window_seconds`` of the **first** observation
      in the candidate group.

    Observations that fall outside the window open a **new group** with the
    same fingerprint.

    The function is deterministic: it sorts the input by timestamp before
    processing, so the output is independent of the order the caller passes
    alerts in.

    Parameters
    ----------
    alerts:
        Raw (or already normalised) :class:`~src.models.Alert` objects.
    window_seconds:
        Width of the deduplication window in seconds.  Default: 60.

    Returns
    -------
    List[ProcessedAlert]
        One :class:`ProcessedAlert` per unique (fingerprint, window-slot).
        Alerts from different devices or with different types are never merged.
    """
    if not alerts:
        return []

    # Sort by timestamp, then by alert_id for a completely stable ordering.
    sorted_alerts: List[Alert] = sorted(
        alerts, key=lambda a: (a.timestamp, a.id)
    )

    # active_groups: fingerprint -> list of open groups (there can be more than
    # one when the same fingerprint produces observations outside the window).
    active_groups: Dict[str, List[_Group]] = {}

    for alert in sorted_alerts:
        fp = build_fingerprint(alert)

        # Find an open group for this fingerprint whose window still covers us.
        matched: Optional[_Group] = None
        for grp in active_groups.get(fp, []):
            delta = (alert.timestamp - grp.first_seen).total_seconds()
            if 0 <= delta <= window_seconds:
                matched = grp
                break

        if matched is not None:
            matched.add(alert)
        else:
            # Open a new group.
            grp = _Group(fingerprint=fp, representative=alert)
            grp.add(alert)
            active_groups.setdefault(fp, []).append(grp)

    # Flatten all groups into ProcessedAlert instances.
    # Preserve deterministic order: sort by (first_seen, fingerprint, alert_id[0]).
    all_groups: List[_Group] = []
    for groups in active_groups.values():
        all_groups.extend(groups)

    all_groups.sort(
        key=lambda g: (
            g.first_seen or g.representative.timestamp,
            g.fingerprint,
            g.alert_ids[0] if g.alert_ids else "",
        )
    )
    return [g.to_processed() for g in all_groups]


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def process_alerts(
    alerts: Sequence[Alert],
    *,
    window_seconds: int = DEFAULT_DEDUP_WINDOW_SECONDS,
) -> Tuple[List[ProcessedAlert], List[ProcessorError]]:
    """Full pipeline: validate → normalise → deduplicate.

    Parameters
    ----------
    alerts:
        Raw :class:`~src.models.Alert` objects (e.g. from ``get_all_sample_alerts()``).
    window_seconds:
        Deduplication window width in seconds.

    Returns
    -------
    processed : List[ProcessedAlert]
        Deduplicated alerts, ready for the correlation engine.
    errors : List[ProcessorError]
        Validation / normalisation errors (one per rejected alert).  The
        pipeline does **not** raise on bad individual alerts — it collects
        errors and continues so a single malformed record cannot block the
        whole batch.
    """
    normalised: List[Alert] = []
    errors: List[ProcessorError] = []

    for alert in alerts:
        try:
            normalised.append(normalize_alert(alert))
        except ProcessorError as exc:
            errors.append(exc)

    processed = deduplicate_alerts(normalised, window_seconds=window_seconds)
    return processed, errors


__all__ = [
    "DEFAULT_DEDUP_WINDOW_SECONDS",
    "ProcessorError",
    "ProcessedAlert",
    "normalize_alert",
    "build_fingerprint",
    "deduplicate_alerts",
    "process_alerts",
]
