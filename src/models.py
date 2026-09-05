"""
Data models (schemas) for NetSentry-AI.

This module defines the vocabulary the rest of the system speaks: the shape of
a network node, a link, a raw alert, and a correlated incident.

Scope note (Step 3)
-------------------
These are *structural* models only. They describe and validate data — they do
not correlate, deduplicate, score, prioritise or explain anything. The
correlation engine, scorer, priority engine, runbook retrieval and the LLM
layer are implemented in later steps and will consume these models.

Two small pieces of behaviour do live here, because they are properties of the
data itself rather than triage logic:

* `Severity` knows how severities rank and how vendor-specific spellings
  (``P1``, ``sev2``, ``warning``, ``4``) normalise onto the canonical scale.
* `Alert.fingerprint` derives the stable identity of "the same thing happening
  on the same device". It is a pure, deterministic function of the alert
  fields. A future deduplication step will *use* fingerprints to collapse
  repeats, but choosing what to collapse is that step's decision, not this
  module's.

Scope note (Step 4)
-------------------
Step 4 (deterministic alert generator) adds vocabulary only — no logic:

* :class:`AlertStatus`, the lifecycle state of a single alert occurrence.
* three descriptive fields on :class:`Alert`: ``device_name``, ``device_type``
  and ``status``, so an alert carries the device context an operator expects
  to read next to an event instead of having to look it up.

They are annotations on the *observation*. Nothing here acknowledges,
suppresses, deduplicates or escalates an alert; those remain later steps.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Canonical alert/incident severity scale, ordered from worst to least."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank where a *lower* number is more severe (critical = 0)."""
        return _SEVERITY_ORDER.index(self)

    @property
    def weight(self) -> int:
        """Coarse 0-100 weight, useful for display and later scoring inputs."""
        return _SEVERITY_WEIGHT[self]

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        """Order severities so ``sorted()`` puts the most severe first."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def normalize(cls, value: Any) -> "Severity":
        """Map a vendor-specific severity onto the canonical scale.

        Accepts the canonical names, common synonyms (``warning``, ``major``),
        priority codes (``P1``, ``sev3``) and numeric levels (``1``-``5``).
        Anything unrecognised degrades to ``INFO`` rather than raising, so a
        single odd feed cannot stall ingestion.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return _NUMERIC_SEVERITY.get(value, cls.INFO)

        text = str(value).strip().lower()
        if not text:
            return cls.INFO
        if text.isdigit():
            return _NUMERIC_SEVERITY.get(int(text), cls.INFO)
        return _SEVERITY_ALIASES.get(text, cls.INFO)


_SEVERITY_ORDER: List[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_SEVERITY_WEIGHT: Dict[Severity, int] = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 75,
    Severity.MEDIUM: 50,
    Severity.LOW: 25,
    Severity.INFO: 10,
}

_NUMERIC_SEVERITY: Dict[int, Severity] = {
    1: Severity.CRITICAL,
    2: Severity.HIGH,
    3: Severity.MEDIUM,
    4: Severity.LOW,
    5: Severity.INFO,
}

_SEVERITY_ALIASES: Dict[str, Severity] = {
    "critical": Severity.CRITICAL, "crit": Severity.CRITICAL,
    "fatal": Severity.CRITICAL, "emergency": Severity.CRITICAL,
    "p1": Severity.CRITICAL, "sev1": Severity.CRITICAL,
    "high": Severity.HIGH, "major": Severity.HIGH, "error": Severity.HIGH,
    "p2": Severity.HIGH, "sev2": Severity.HIGH,
    "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM, "warn": Severity.MEDIUM, "minor": Severity.MEDIUM,
    "p3": Severity.MEDIUM, "sev3": Severity.MEDIUM,
    "low": Severity.LOW, "notice": Severity.LOW,
    "p4": Severity.LOW, "sev4": Severity.LOW,
    "info": Severity.INFO, "informational": Severity.INFO,
    "debug": Severity.INFO, "clear": Severity.INFO,
    "p5": Severity.INFO, "sev5": Severity.INFO,
}


class NodeType(str, Enum):
    """Physical/logical kind of a managed device."""

    ROUTER = "router"
    SWITCH = "switch"
    ACCESS = "access"
    FIREWALL = "firewall"
    CLOUD = "cloud"


class NetworkLayer(str, Enum):
    """Position of a node in the network hierarchy."""

    EXTERNAL = "external"
    CORE = "core"
    DISTRIBUTION = "distribution"
    ACCESS = "access"


class NodeStatus(str, Enum):
    """Observed operational state of a node or link."""

    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"


class AlertType(str, Enum):
    """Known alert event types emitted by the network."""

    LINK_DOWN = "LINK_DOWN"
    LINK_UP = "LINK_UP"
    DEVICE_UNREACHABLE = "DEVICE_UNREACHABLE"
    PACKET_LOSS = "PACKET_LOSS"
    HIGH_LATENCY = "HIGH_LATENCY"
    JITTER_THRESHOLD = "JITTER_THRESHOLD"
    CRC_ERRORS = "CRC_ERRORS"
    IF_FLAP = "IF_FLAP"
    BGP_SESSION_DROP = "BGP_SESSION_DROP"
    OPTICAL_RX_LOW = "OPTICAL_RX_LOW"
    AUTH_FAILURE = "AUTH_FAILURE"
    RADIUS_TIMEOUT = "RADIUS_TIMEOUT"
    CPU_HIGH = "CPU_HIGH"
    MEMORY_HIGH = "MEMORY_HIGH"
    POWER_SUPPLY_FAILURE = "POWER_SUPPLY_FAILURE"
    TEMPERATURE_HIGH = "TEMPERATURE_HIGH"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def _missing_(cls, value: object) -> "AlertType":
        """Fall back to ``UNKNOWN`` for event types we do not model yet."""
        return cls.UNKNOWN


class AlertStatus(str, Enum):
    """Lifecycle state of a single alert occurrence.

    Declared so alert feeds (and the deterministic sample data) can say whether
    an event is still fresh, has been seen by an operator, or has cleared.
    Transitions between these states belong to later steps — this enum is only
    the vocabulary.
    """

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLEARED = "cleared"

    @property
    def is_open(self) -> bool:
        """True while the alert still wants attention (not resolved/cleared)."""
        return self in (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.ESCALATED)

    @classmethod
    def _missing_(cls, value: object) -> "AlertStatus":
        """Map vendor spellings onto the canonical states, else ``NEW``."""
        return _ALERT_STATUS_ALIASES.get(str(value).strip().lower(), cls.NEW)


_ALERT_STATUS_ALIASES: Dict[str, AlertStatus] = {
    "new": AlertStatus.NEW, "open": AlertStatus.NEW,
    "active": AlertStatus.NEW, "firing": AlertStatus.NEW,
    "unacknowledged": AlertStatus.NEW, "unack": AlertStatus.NEW,
    "acknowledged": AlertStatus.ACKNOWLEDGED, "ack": AlertStatus.ACKNOWLEDGED,
    "acked": AlertStatus.ACKNOWLEDGED, "assigned": AlertStatus.ACKNOWLEDGED,
    "in_progress": AlertStatus.ACKNOWLEDGED, "triaging": AlertStatus.ACKNOWLEDGED,
    "escalated": AlertStatus.ESCALATED, "escalation": AlertStatus.ESCALATED,
    "paged": AlertStatus.ESCALATED,
    "resolved": AlertStatus.RESOLVED, "closed": AlertStatus.RESOLVED,
    "fixed": AlertStatus.RESOLVED,
    "cleared": AlertStatus.CLEARED, "clear": AlertStatus.CLEARED,
    "auto_cleared": AlertStatus.CLEARED, "recovered": AlertStatus.CLEARED,
}


class IncidentState(str, Enum):
    """Lifecycle state of a correlated incident."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    MONITORING = "monitoring"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class NetSentryModel(BaseModel):
    """Shared model configuration for every NetSentry schema."""

    model_config = ConfigDict(
        extra="ignore",          # tolerate unknown vendor fields
        use_enum_values=False,
        validate_assignment=True,
        str_strip_whitespace=True,
    )


def _utcnow() -> datetime:
    """Timezone-aware current UTC time (used as a default factory)."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Topology models
# ---------------------------------------------------------------------------


class Node(NetSentryModel):
    """A managed device in the network."""

    id: str = Field(..., description="Stable short identifier, e.g. 'R1'.")
    name: str = Field(..., description="Human-readable device name, e.g. 'CORE-R1'.")
    type: NodeType = NodeType.ROUTER
    layer: NetworkLayer = NetworkLayer.ACCESS
    site: str = Field("UNKNOWN", description="Physical site or POP code.")

    vendor: Optional[str] = None
    model: Optional[str] = None
    mgmt_ip: Optional[str] = None
    role: Optional[str] = Field(None, description="What this device does, in words.")

    criticality: Severity = Field(
        Severity.MEDIUM,
        description="Business criticality of the device, independent of current state.",
    )
    subscribers: int = Field(0, ge=0, description="Subscribers served directly by this node.")
    monitored: bool = True

    # Layout hints (0..1) so the UI can draw the graph without a layout engine.
    x: Optional[float] = Field(None, ge=0.0, le=1.0)
    y: Optional[float] = Field(None, ge=0.0, le=1.0)

    status: NodeStatus = Field(
        NodeStatus.UNKNOWN,
        description="Live state. Not stored in topology.json; set at runtime.",
    )

    @field_validator("criticality", mode="before")
    @classmethod
    def _norm_criticality(cls, v: Any) -> Any:
        return Severity.normalize(v) if v is not None else v

    @property
    def is_infrastructure(self) -> bool:
        """True for core/distribution devices, whose failure fans out widely."""
        return self.layer in (NetworkLayer.CORE, NetworkLayer.DISTRIBUTION)


class Link(NetSentryModel):
    """A connection between two nodes."""

    id: str
    source: str = Field(..., description="Node id at one end.")
    target: str = Field(..., description="Node id at the other end.")

    source_interface: Optional[str] = None
    target_interface: Optional[str] = None

    media: str = Field("fiber", description="fiber | copper | wireless")
    capacity_gbps: float = Field(0.0, ge=0.0)
    kind: str = Field("downlink", description="uplink | downlink | peer")
    redundant: bool = Field(
        False, description="True when an alternate path covers this link's failure."
    )

    status: NodeStatus = Field(NodeStatus.UNKNOWN, description="Live state, set at runtime.")

    def endpoints(self) -> tuple[str, str]:
        """The two node ids this link joins."""
        return (self.source, self.target)

    def other_end(self, node_id: str) -> Optional[str]:
        """Given one endpoint, return the node id at the far end."""
        if node_id == self.source:
            return self.target
        if node_id == self.target:
            return self.source
        return None


class Topology(NetSentryModel):
    """A complete network topology document (the parsed ``topology.json``)."""

    version: str = "1.0"
    name: str = "Unnamed network"
    region: Optional[str] = None
    description: Optional[str] = None
    nodes: List[Node] = Field(default_factory=list)
    links: List[Link] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Alert model
# ---------------------------------------------------------------------------


#: Vendor/role spellings for the kind of device an alert came from. Anything
#: unrecognised degrades to ``None`` rather than rejecting the whole alert.
_DEVICE_TYPE_ALIASES: Dict[str, NodeType] = {
    "router": NodeType.ROUTER, "core": NodeType.ROUTER, "core_router": NodeType.ROUTER,
    "edge_router": NodeType.ROUTER, "bng": NodeType.ROUTER, "gateway": NodeType.ROUTER,
    "pe": NodeType.ROUTER,
    "switch": NodeType.SWITCH, "distribution": NodeType.SWITCH,
    "distribution_switch": NodeType.SWITCH, "aggregation": NodeType.SWITCH,
    "dist": NodeType.SWITCH,
    "access": NodeType.ACCESS, "access_router": NodeType.ACCESS, "edge": NodeType.ACCESS,
    "olt": NodeType.ACCESS, "cpe": NodeType.ACCESS, "cell_site": NodeType.ACCESS,
    "firewall": NodeType.FIREWALL, "fw": NodeType.FIREWALL,
    "cloud": NodeType.CLOUD, "transit": NodeType.CLOUD, "internet": NodeType.CLOUD,
}


class Alert(NetSentryModel):
    """A single raw event received from the network.

    An alert is an *observation*, not a conclusion. It carries no notion of
    root cause, priority score or grouping — those are added downstream by the
    correlation and scoring engines.
    """

    id: str = Field(..., description="Unique id of this alert occurrence.")
    timestamp: datetime = Field(default_factory=_utcnow)

    node_id: str = Field(..., description="Id of the node that raised the alert.")
    interface: Optional[str] = Field(None, description="Interface involved, if any.")

    device_name: Optional[str] = Field(
        None, description="Human-readable device name as reported by the feed, e.g. 'CORE-R1'."
    )
    device_type: Optional[NodeType] = Field(
        None, description="Kind of device (router/switch/access/...), when the feed supplies it."
    )

    type: AlertType = AlertType.UNKNOWN
    severity: Severity = Severity.INFO
    message: str = ""

    source: str = Field("snmp", description="Feed that produced the alert, e.g. snmp/syslog.")
    status: AlertStatus = Field(
        AlertStatus.NEW,
        description="Lifecycle state of this occurrence. Transitions are a later step's job.",
    )
    metrics: Dict[str, float] = Field(
        default_factory=dict,
        description="Numeric context, e.g. {'loss_pct': 6.2, 'rtt_ms': 47}.",
    )
    labels: Dict[str, str] = Field(default_factory=dict)

    # Set by the correlation engine in a later step; None means "not yet grouped".
    incident_id: Optional[str] = None

    @field_validator("severity", mode="before")
    @classmethod
    def _norm_severity(cls, v: Any) -> Any:
        return Severity.normalize(v) if v is not None else v

    @field_validator("device_type", mode="before")
    @classmethod
    def _norm_device_type(cls, v: Any) -> Any:
        """Accept vendor spellings; unknown device kinds degrade to ``None``."""
        if v is None or isinstance(v, NodeType):
            return v
        return _DEVICE_TYPE_ALIASES.get(str(v).strip().lower())

    @field_validator("status", mode="before")
    @classmethod
    def _norm_status(cls, v: Any) -> Any:
        """Accept vendor status spellings via :class:`AlertStatus` aliases."""
        return AlertStatus(v) if v is not None else v

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_timestamp(cls, v: Any) -> Any:
        """Accept ISO-8601 strings, including a trailing ``Z``."""
        if isinstance(v, str) and v.endswith("Z"):
            return v[:-1] + "+00:00"
        return v

    @property
    def fingerprint(self) -> str:
        """Stable identity of *this kind of event on this device*.

        Two alerts sharing a fingerprint describe the same condition on the
        same node/interface. This is a pure data property; the decision to
        collapse such alerts belongs to the deduplication step.
        """
        return f"{self.node_id}:{self.interface or '-'}:{self.type.value}"

    @property
    def is_actionable(self) -> bool:
        """True when the alert is severe enough to warrant operator attention."""
        return self.severity.rank <= Severity.MEDIUM.rank


# ---------------------------------------------------------------------------
# Incident model
# ---------------------------------------------------------------------------


class Incident(NetSentryModel):
    """A group of related alerts presented to the operator as one problem.

    Step 3 defines the *container*. Its analytical fields (``priority_score``,
    ``root_cause``, ``confidence``, ``runbook_id``, ``recommendation``) are
    declared here so the shape is stable, but nothing in this module populates
    them — the scoring, priority, retrieval and LLM steps do that later.
    """

    id: str
    title: str
    severity: Severity = Severity.INFO
    state: IncidentState = IncidentState.OPEN

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    alert_ids: List[str] = Field(default_factory=list)
    node_ids: List[str] = Field(default_factory=list)
    site: Optional[str] = None
    owner: Optional[str] = None
    summary: str = ""

    # --- Populated by later steps; left empty by design in Step 3. ---
    priority_score: Optional[float] = Field(
        None, ge=0, le=100, description="Set by the priority engine (later step)."
    )
    root_cause: Optional[str] = Field(None, description="Set by the analysis layer (later step).")
    confidence: Optional[float] = Field(
        None, ge=0, le=100, description="Confidence in root_cause (later step)."
    )
    runbook_id: Optional[str] = Field(None, description="Set by runbook retrieval (later step).")
    recommendation: Optional[str] = Field(None, description="Set by the LLM layer (later step).")

    extra: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity", mode="before")
    @classmethod
    def _norm_severity(cls, v: Any) -> Any:
        return Severity.normalize(v) if v is not None else v

    @property
    def alert_count(self) -> int:
        """Number of alerts currently grouped into this incident."""
        return len(self.alert_ids)

    @property
    def device_count(self) -> int:
        """Number of distinct devices involved."""
        return len(set(self.node_ids))


__all__ = [
    "Severity",
    "NodeType",
    "NetworkLayer",
    "NodeStatus",
    "AlertType",
    "AlertStatus",
    "IncidentState",
    "NetSentryModel",
    "Node",
    "Link",
    "Topology",
    "Alert",
    "Incident",
]
