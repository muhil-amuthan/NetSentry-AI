"""
Deterministic telecom alert generator (Step 4).

This module produces the *input data* the rest of NetSentry-AI will triage:
realistic-looking network alerts for three hand-authored scenarios that exercise
the behaviours the later engines must handle (duplicate noise, a cascading
failure, and conditions with no runbook coverage).

Design rules
------------
1. **Deterministic.** Nothing here reads the clock, the network or a random
   number generator. Every scenario is a fixed table of events with fixed
   offsets from a fixed base timestamp, so two runs — or two judges on two
   different machines — see byte-identical data. ``rebase_to_now`` is the single
   opt-in exception, and it only shifts the whole timeline, never its shape.

2. **Offline.** No external APIs, no live traffic, no real devices. The device
   names/ids are the fictional ones from ``data/topology.json`` (``CORE-R1``,
   ``SW-S1``, ``ACC-R3`` …), which are the same nodes the dashboard draws.

3. **One alert model.** Records are converted into :class:`src.models.Alert`.
   This module owns the *feed vocabulary* (``alert_id``, ``device_id``,
   ``alert_type``, …) and the mapping onto the model; it does not define a
   second alert type.

4. **Data only.** No deduplication, correlation, scoring, prioritisation,
   retrieval, escalation or NLP lives here. Scenario definitions do carry a
   ``fixture_role``/``expected_handling`` annotation so tests (and later steps)
   can check what an engine *should* have done with each alert — that is
   fixture metadata, never logic.

Data flow
---------
``src/generator.py`` is the source of truth. ``data/sample_alerts.json`` is the
checked-in snapshot of what it generates, and is what the running application
loads::

    build_sample_document()  --write-->  data/sample_alerts.json
                                              |
    load_sample_records()  <-----------------+
            |
            v
    record_to_alert()  -->  List[Alert]   (load_sample_alerts / get_all_sample_alerts)

A test asserts the snapshot still matches the code, so the two cannot drift.

Typical use::

    from src.generator import get_all_sample_alerts, generate_scenario

    alerts = get_all_sample_alerts()              # everything, from the JSON snapshot
    cascade = generate_scenario("cascade_failure")  # one scenario, generated in code

Command line::

    python -m src.generator --summary                # what the fixture contains
    python -m src.generator --scenario cascade_failure
    python -m src.generator --write                  # regenerate data/sample_alerts.json
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from src.config import SAMPLE_ALERTS_FILE
from src.models import Alert, AlertStatus, AlertType, NodeType, Severity

__all__ = [
    "GeneratorError",
    "SCENARIOS",
    "SCENARIO_DUPLICATES",
    "SCENARIO_CASCADE",
    "SCENARIO_UNKNOWN",
    "BASE_TIMESTAMP",
    "SUPPORTED_ALERT_TYPES",
    "DEVICES",
    "DeviceSpec",
    "ScenarioSpec",
    "list_scenarios",
    "normalize_scenario_name",
    "get_scenario_spec",
    "scenario_devices",
    "generate_scenario",
    "generate_scenario_records",
    "generate_all_scenarios",
    "generate_all_records",
    "build_sample_document",
    "load_sample_records",
    "load_sample_alerts",
    "get_all_sample_alerts",
    "clear_cache",
    "record_to_alert",
    "alert_to_record",
    "write_sample_alerts",
    "scenario_summary",
    "main",
]


# ---------------------------------------------------------------------------
# Errors and constants
# ---------------------------------------------------------------------------


class GeneratorError(RuntimeError):
    """Raised when a scenario name, alert record or data file is unusable."""


#: Scenario identifiers. These are the names accepted by :func:`generate_scenario`.
SCENARIO_DUPLICATES = "duplicate_alerts"
SCENARIO_CASCADE = "cascade_failure"
SCENARIO_UNKNOWN = "unknown_escalation"

SCENARIOS: Tuple[str, ...] = (SCENARIO_DUPLICATES, SCENARIO_CASCADE, SCENARIO_UNKNOWN)

#: Friendly aliases so callers (and future API query strings) can be loose.
SCENARIO_ALIASES: Dict[str, str] = {
    "duplicate_alerts": SCENARIO_DUPLICATES,
    "duplicates": SCENARIO_DUPLICATES,
    "duplicate": SCENARIO_DUPLICATES,
    "dedup": SCENARIO_DUPLICATES,
    "scenario_1": SCENARIO_DUPLICATES,
    "scenario1": SCENARIO_DUPLICATES,
    "1": SCENARIO_DUPLICATES,
    "cascade_failure": SCENARIO_CASCADE,
    "cascading_failure": SCENARIO_CASCADE,
    "cascade": SCENARIO_CASCADE,
    "cascading": SCENARIO_CASCADE,
    "scenario_2": SCENARIO_CASCADE,
    "scenario2": SCENARIO_CASCADE,
    "2": SCENARIO_CASCADE,
    "unknown_escalation": SCENARIO_UNKNOWN,
    "unknown": SCENARIO_UNKNOWN,
    "escalation": SCENARIO_UNKNOWN,
    "uncovered": SCENARIO_UNKNOWN,
    "no_runbook": SCENARIO_UNKNOWN,
    "scenario_3": SCENARIO_UNKNOWN,
    "scenario3": SCENARIO_UNKNOWN,
    "3": SCENARIO_UNKNOWN,
}

#: The alert types this step's scenarios are built from. Later steps may widen
#: this; the generator keeps to the five the triage demo is written around.
SUPPORTED_ALERT_TYPES: Tuple[AlertType, ...] = (
    AlertType.LINK_DOWN,
    AlertType.DEVICE_UNREACHABLE,
    AlertType.HIGH_LATENCY,
    AlertType.PACKET_LOSS,
    AlertType.AUTH_FAILURE,
)

#: Fixture roles: what an alert is *for* in the sample data. Test metadata only.
ROLE_DUPLICATE = "duplicate"
ROLE_CASCADE = "cascade"
ROLE_UNCOVERED = "uncovered"
ROLE_NOISE = "noise"

#: Fixed anchor for the whole fixture — never the wall clock.
BASE_TIMESTAMP: datetime = datetime(2026, 9, 5, 9, 0, 0, tzinfo=timezone.utc)

#: Version stamp written into the snapshot document.
SAMPLE_DATA_VERSION = "1.0"

#: Where the generator writes/reads the snapshot by default.
DEFAULT_SAMPLE_ALERTS_FILE: Path = SAMPLE_ALERTS_FILE

_ALERT_ID_PREFIX = "AL-"


# ---------------------------------------------------------------------------
# Device catalogue
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceSpec:
    """The fictional devices alerts can be raised against.

    Mirrors ``data/topology.json`` (a test keeps the two in step) so generated
    alerts can be plotted on the dashboard graph without any translation.
    """

    device_id: str
    device_name: str
    device_type: NodeType
    site: str
    layer: str


DEVICES: Dict[str, DeviceSpec] = {
    spec.device_id: spec
    for spec in (
        DeviceSpec("R1", "CORE-R1", NodeType.ROUTER, "DC-CHENNAI-01", "core"),
        DeviceSpec("R2", "CORE-R2", NodeType.ROUTER, "DC-CHENNAI-01", "core"),
        DeviceSpec("S1", "SW-S1", NodeType.SWITCH, "AGG-CHENNAI-02", "distribution"),
        DeviceSpec("S2", "SW-S2", NodeType.SWITCH, "AGG-MADURAI-02", "distribution"),
        DeviceSpec("R3", "ACC-R3", NodeType.ACCESS, "EDGE-COIMBATORE", "access"),
        DeviceSpec("R4", "ACC-R4", NodeType.ACCESS, "EDGE-COIMBATORE", "access"),
        DeviceSpec("R5", "ACC-R5", NodeType.ACCESS, "EDGE-SALEM", "access"),
        DeviceSpec("R6", "ACC-R6", NodeType.ACCESS, "EDGE-SALEM", "access"),
    )
}


def require_device(device_id: str) -> DeviceSpec:
    """Return a :class:`DeviceSpec`, raising :class:`GeneratorError` if unknown."""
    try:
        return DEVICES[device_id]
    except KeyError:
        raise GeneratorError(f"unknown device in scenario table: {device_id!r}") from None


# ---------------------------------------------------------------------------
# Scenario tables
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _EventSpec:
    """One row of a scenario table = one alert the feed reports."""

    offset: int                       # seconds after the scenario base timestamp
    device_id: str
    alert_type: str                   # raw feed spelling; may be unmodelled
    severity: str
    message: str
    source: str = "snmp"
    interface: Optional[str] = None
    metrics: Mapping[str, float] = field(default_factory=dict)
    status: str = AlertStatus.NEW.value
    role: str = ROLE_CASCADE


@dataclass(frozen=True)
class ScenarioSpec:
    """A named, deterministic bundle of alerts."""

    name: str
    title: str
    description: str
    expected_handling: str            # fixture metadata for later steps' tests
    base_offset: timedelta            # from BASE_TIMESTAMP
    id_block: int                     # alert ids are AL-<id_block>, AL-<id_block+1>, ...
    events: Tuple[_EventSpec, ...]

    @property
    def base_timestamp(self) -> datetime:
        """Absolute start time of this scenario."""
        return BASE_TIMESTAMP + self.base_offset


# --- Scenario 1: the same few events reported over and over -----------------
#
# A single core-router uplink failure, seen through four different collectors.
# 10 alerts collapse onto 3 distinct fingerprints, which is exactly the shape a
# deduplication step will have to recognise later.

_DUPLICATE_EVENTS: Tuple[_EventSpec, ...] = (
    _EventSpec(0, "R1", "LINK_DOWN", "critical",
               "Uplink interface Te0/1 is down", "snmp_trap", "Te0/1",
               role=ROLE_DUPLICATE),
    _EventSpec(9, "R1", "DEVICE_UNREACHABLE", "critical",
               "No response received from device (ICMP probe timed out after 3 attempts)",
               "icmp_probe", role=ROLE_DUPLICATE),
    _EventSpec(17, "R1", "LINK_DOWN", "critical",
               "Uplink interface Te0/1 is down", "syslog", "Te0/1",
               role=ROLE_DUPLICATE),
    _EventSpec(26, "R1", "DEVICE_UNREACHABLE", "critical",
               "No response received from device", "nms_poll", role=ROLE_DUPLICATE),
    _EventSpec(34, "R1", "PACKET_LOSS", "high",
               "Packet loss exceeded 20% on interface Te0/2 (measured 27.4%)",
               "netflow", "Te0/2", {"loss_pct": 27.4}, role=ROLE_DUPLICATE),
    _EventSpec(43, "R1", "LINK_DOWN", "critical",
               "Uplink interface Te0/1 is down", "nms_poll", "Te0/1",
               role=ROLE_DUPLICATE),
    _EventSpec(51, "R1", "DEVICE_UNREACHABLE", "critical",
               "No response received from device", "icmp_probe", role=ROLE_DUPLICATE),
    _EventSpec(60, "R1", "PACKET_LOSS", "high",
               "Packet loss exceeded 20% on interface Te0/2 (measured 31.8%)",
               "netflow", "Te0/2", {"loss_pct": 31.8}, role=ROLE_DUPLICATE),
    _EventSpec(68, "R1", "LINK_DOWN", "critical",
               "Uplink interface Te0/1 is down", "snmp_trap", "Te0/1",
               role=ROLE_DUPLICATE),
    _EventSpec(77, "R1", "DEVICE_UNREACHABLE", "critical",
               "No response received from device (management plane silent for 90s)",
               "syslog", role=ROLE_DUPLICATE),
)


# --- Scenario 2: one major incident, rippling down the hierarchy ------------
#
# CORE-R1's transit uplink degrades and fails; the two distribution switches lose
# their uplink; the four access routers behind them go unreachable. 26 alerts
# across 7 devices inside ~3.5 minutes, so a correlation engine can recover the
# sequence from timestamps plus topology alone.

_CASCADE_EVENTS: Tuple[_EventSpec, ...] = (
    # Core: degradation, then hard failure.
    _EventSpec(0, "R1", "HIGH_LATENCY", "high",
               "Average latency exceeded threshold on transit uplink Te0/1 "
               "(212 ms against 80 ms baseline)", "netflow", "Te0/1", {"rtt_ms": 212.0}),
    _EventSpec(6, "R1", "PACKET_LOSS", "high",
               "Packet loss exceeded 20% on interface Te0/1 (measured 23.6%)",
               "snmp", "Te0/1", {"loss_pct": 23.6}),
    _EventSpec(14, "R1", "LINK_DOWN", "critical",
               "Uplink interface Te0/1 is down", "snmp_trap", "Te0/1"),
    _EventSpec(21, "R1", "PACKET_LOSS", "critical",
               "Packet loss exceeded 20% on interface Te0/2 towards SW-S1 (measured 41.2%)",
               "netflow", "Te0/2", {"loss_pct": 41.2}),
    _EventSpec(29, "R1", "LINK_DOWN", "critical",
               "Downlink interface Te0/3 towards SW-S2 is down", "syslog", "Te0/3"),
    _EventSpec(38, "R1", "DEVICE_UNREACHABLE", "critical",
               "No response received from device (ICMP probe timed out after 3 attempts)",
               "icmp_probe"),

    # Distribution north ring (SW-S1) loses its uplink, then its AAA path.
    _EventSpec(46, "S1", "LINK_DOWN", "critical",
               "Uplink interface et-0/0/1 towards CORE-R1 is down", "snmp_trap", "et-0/0/1"),
    _EventSpec(54, "S1", "HIGH_LATENCY", "high",
               "Average latency exceeded threshold on access ring "
               "(168 ms against 40 ms baseline)", "netflow", None, {"rtt_ms": 168.0}),
    _EventSpec(61, "S1", "PACKET_LOSS", "high",
               "Packet loss exceeded 20% on interface ge-0/0/10 towards ACC-R3 "
               "(measured 34.8%)", "snmp", "ge-0/0/10", {"loss_pct": 34.8}),
    _EventSpec(70, "S1", "DEVICE_UNREACHABLE", "critical",
               "No response received from device", "nms_poll"),
    _EventSpec(78, "S1", "AUTH_FAILURE", "high",
               "Repeated authentication failures detected: TACACS+ server 10.10.9.5 "
               "unreachable via CORE-R1", "syslog"),

    # Distribution south ring (SW-S2) follows ~40s later.
    _EventSpec(86, "S2", "LINK_DOWN", "critical",
               "Uplink interface et-0/0/1 towards CORE-R1 is down", "snmp_trap", "et-0/0/1"),
    _EventSpec(94, "S2", "PACKET_LOSS", "high",
               "Packet loss exceeded 20% on interface ge-0/0/23 towards ACC-R5 "
               "(measured 28.1%)", "snmp", "ge-0/0/23", {"loss_pct": 28.1}),
    _EventSpec(102, "S2", "DEVICE_UNREACHABLE", "critical",
               "No response received from device", "icmp_probe"),
    _EventSpec(110, "S2", "HIGH_LATENCY", "high",
               "Average latency exceeded threshold on access ring "
               "(191 ms against 40 ms baseline)", "netflow", None, {"rtt_ms": 191.0}),
    _EventSpec(118, "S2", "AUTH_FAILURE", "medium",
               "Repeated authentication failures detected: RADIUS server 10.10.9.6 "
               "timed out for 214 subscriber sessions", "syslog"),

    # Access layer: the routers hanging off both switches.
    _EventSpec(126, "R3", "DEVICE_UNREACHABLE", "critical",
               "No response received from device (management plane silent for 90s)",
               "icmp_probe"),
    _EventSpec(133, "R3", "LINK_DOWN", "critical",
               "Uplink interface 1/1/1 towards SW-S1 is down", "snmp_trap", "1/1/1"),
    _EventSpec(141, "R4", "PACKET_LOSS", "high",
               "Packet loss exceeded 20% on interface 1/1/1 towards SW-S1 (measured 46.5%)",
               "netflow", "1/1/1", {"loss_pct": 46.5}),
    _EventSpec(148, "R4", "DEVICE_UNREACHABLE", "critical",
               "No response received from device", "nms_poll"),
    _EventSpec(156, "R5", "HIGH_LATENCY", "high",
               "Average latency exceeded threshold for subscriber aggregate "
               "(233 ms against 60 ms baseline)", "netflow", None, {"rtt_ms": 233.0}),
    _EventSpec(163, "R5", "DEVICE_UNREACHABLE", "critical",
               "No response received from device", "icmp_probe"),
    _EventSpec(171, "R6", "LINK_DOWN", "critical",
               "Uplink interface 1/1/1 towards SW-S2 is down", "snmp_trap", "1/1/1"),
    _EventSpec(179, "R6", "PACKET_LOSS", "high",
               "Packet loss exceeded 20% on interface 1/1/1 towards SW-S2 (measured 38.9%)",
               "snmp", "1/1/1", {"loss_pct": 38.9}),
    _EventSpec(186, "R3", "AUTH_FAILURE", "high",
               "Repeated authentication failures detected: 612 PPPoE subscriber "
               "sessions rejected by RADIUS 10.10.9.6", "syslog"),
    _EventSpec(194, "R6", "DEVICE_UNREACHABLE", "critical",
               "No response received from device", "icmp_probe"),
)


# --- Scenario 3: no runbook coverage, plus unrelated background noise -------
#
# The first six use raw feed spellings that the model deliberately does *not*
# know (``AlertType`` degrades them to UNKNOWN and the original string survives
# in ``labels["raw_type"]``). Nothing here invents a runbook for them: a later
# step is expected to notice the gap and escalate to a human.
#
# The last four are ordinary, unrelated events that must NOT be swept into an
# incident just because they happened nearby in time.

_UNKNOWN_EVENTS: Tuple[_EventSpec, ...] = (
    _EventSpec(0, "R2", "OPTICAL_SYNC_ANOMALY", "high",
               "Optical synchronization anomaly: OTU4 framer on Te0/5 lost lock "
               "3 times in 60s with no fiber event reported", "syslog", "Te0/5",
               {"lock_loss_count": 3.0}, role=ROLE_UNCOVERED),
    _EventSpec(22, "S1", "PTP_CLOCK_DRIFT", "medium",
               "PTP clock drift exceeded 120 ns against grandmaster 10.10.9.20; "
               "optical sync state reported unstable", "syslog", None,
               {"drift_ns": 120.0}, role=ROLE_UNCOVERED),
    _EventSpec(47, "R2", "PROTOCOL_STATE_ANOMALY", "medium",
               "Unexpected protocol behaviour: OSPF neighbor 10.10.0.2 cycled "
               "EXSTART-DOWN-EXSTART 7 times without a configuration change",
               "snmp", None, {"state_changes": 7.0}, role=ROLE_UNCOVERED),
    _EventSpec(75, "S2", "MICROLOOP_DETECTED", "high",
               "Transient forwarding microloop between et-0/0/2 and ge-0/0/23; "
               "FIB entries oscillating for 4s", "netflow", None,
               {"duration_s": 4.0}, role=ROLE_UNCOVERED),
    _EventSpec(104, "R5", "ANOMALOUS_TRAFFIC_CONDITION", "medium",
               "Abnormal network condition: asymmetric byte ratio 9.4:1 on "
               "subscriber aggregate with no matching service event", "netflow",
               None, {"asym_ratio": 9.4}, role=ROLE_UNCOVERED),
    _EventSpec(131, "R6", "SNMP_TRAP_1.3.6.1.4.1.9999.42.1", "low",
               "Unrecognized SNMP trap OID 1.3.6.1.4.1.9999.42.1 received from "
               "device; no MIB entry available", "snmp_trap", role=ROLE_UNCOVERED),

    # Unrelated background noise.
    _EventSpec(158, "S1", "CONFIG_CHANGE", "info",
               "Configuration change committed by user 'netops' under planned "
               "maintenance window MW-4471", "syslog",
               status=AlertStatus.ACKNOWLEDGED.value, role=ROLE_NOISE),
    _EventSpec(176, "R6", "CPU_HIGH", "medium",
               "Control-plane CPU utilization at 88% (5 minute average) during "
               "routine BGP table refresh", "snmp", None, {"cpu_pct": 88.0},
               role=ROLE_NOISE),
    _EventSpec(197, "R2", "MEMORY_HIGH", "low",
               "Memory utilization at 81% on standby route processor", "snmp",
               None, {"mem_pct": 81.0}, role=ROLE_NOISE),
    _EventSpec(214, "S2", "AUTH_FAILURE", "low",
               "Repeated authentication failures detected: 2 failed SSH logins "
               "for user 'audit-bot' from 10.99.7.4", "syslog", role=ROLE_NOISE),
)


SCENARIO_SPECS: Dict[str, ScenarioSpec] = {
    SCENARIO_DUPLICATES: ScenarioSpec(
        name=SCENARIO_DUPLICATES,
        title="Duplicate alerts on CORE-R1",
        description=(
            "One core-router uplink failure reported repeatedly by four different "
            "collectors (SNMP traps, ICMP probes, NMS polling, syslog, netflow). "
            "10 alerts collapse onto 3 distinct device/interface/type fingerprints."
        ),
        expected_handling="deduplicate",
        base_offset=timedelta(0),
        id_block=1001,
        events=_DUPLICATE_EVENTS,
    ),
    SCENARIO_CASCADE: ScenarioSpec(
        name=SCENARIO_CASCADE,
        title="Cascading failure from CORE-R1 through distribution to access",
        description=(
            "A single major incident: CORE-R1's transit uplink degrades and fails, "
            "SW-S1 and SW-S2 lose their uplinks, and the access routers behind them "
            "(ACC-R3, ACC-R4, ACC-R5, ACC-R6) go unreachable. 26 alerts across "
            "7 devices inside roughly 3.5 minutes, ordered core -> distribution -> "
            "access so the sequence is recoverable from timestamps plus topology."
        ),
        expected_handling="correlate_into_one_incident",
        base_offset=timedelta(minutes=15),
        id_block=2001,
        events=_CASCADE_EVENTS,
    ),
    SCENARIO_UNKNOWN: ScenarioSpec(
        name=SCENARIO_UNKNOWN,
        title="Uncovered conditions and unrelated noise",
        description=(
            "Six alerts with no obvious runbook match (optical synchronization "
            "anomaly, PTP clock drift, unexpected protocol state changes, a "
            "microloop, an abnormal traffic condition and an unmapped trap OID). "
            "Their raw feed types are not modelled, so Alert.type degrades to "
            "UNKNOWN while labels['raw_type'] keeps the original string. Four "
            "further alerts are ordinary but unrelated and should stay noise."
        ),
        expected_handling="escalate_uncovered_and_ignore_noise",
        base_offset=timedelta(minutes=45),
        id_block=3001,
        events=_UNKNOWN_EVENTS,
    ),
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _iso(moment: datetime) -> str:
    """Format an aware datetime as a UTC ISO-8601 string with a ``Z`` suffix."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: Any) -> datetime:
    """Parse an ISO-8601 timestamp (``Z`` tolerated) into an aware datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise GeneratorError(f"invalid timestamp: {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _first(mapping: Mapping[str, Any], names: Sequence[str]) -> Any:
    """First present-and-non-empty value among ``names`` (feed tolerance)."""
    for name in names:
        if name in mapping and mapping[name] not in (None, ""):
            return mapping[name]
    return None


# ---------------------------------------------------------------------------
# Scenario accessors
# ---------------------------------------------------------------------------


def list_scenarios() -> List[str]:
    """Canonical scenario names, in the order they appear in the fixture."""
    return list(SCENARIOS)


def normalize_scenario_name(scenario_name: str) -> str:
    """Resolve a loose scenario name (alias, ``Scenario 2``, ...) to its canonical id."""
    key = str(scenario_name or "").strip().lower().replace("-", "_").replace(" ", "_")
    canonical = SCENARIO_ALIASES.get(key)
    if canonical is None:
        raise GeneratorError(
            f"unknown scenario: {scenario_name!r} (expected one of {', '.join(SCENARIOS)})"
        )
    return canonical


def get_scenario_spec(scenario_name: str) -> ScenarioSpec:
    """Return the :class:`ScenarioSpec` for a scenario name or alias."""
    return SCENARIO_SPECS[normalize_scenario_name(scenario_name)]


def scenario_devices(scenario_name: str) -> List[str]:
    """Device ids touched by a scenario, in order of first appearance."""
    spec = get_scenario_spec(scenario_name)
    ordered: List[str] = []
    for event in spec.events:
        if event.device_id not in ordered:
            ordered.append(event.device_id)
    return ordered


# ---------------------------------------------------------------------------
# Generation (code -> records -> Alert models)
# ---------------------------------------------------------------------------


def _build_records(spec: ScenarioSpec) -> List[Dict[str, Any]]:
    """Turn a scenario table into feed-format alert records (deterministic)."""
    records: List[Dict[str, Any]] = []
    for index, event in enumerate(spec.events):
        device = require_device(event.device_id)
        alert_id = f"{_ALERT_ID_PREFIX}{spec.id_block + index:04d}"
        moment = spec.base_timestamp + timedelta(seconds=event.offset)

        record: Dict[str, Any] = {
            "alert_id": alert_id,
            "timestamp": _iso(moment),
            "scenario": spec.name,
            "device_id": device.device_id,
            "device_name": device.device_name,
            "device_type": device.device_type.value,
            "site": device.site,
            "alert_type": event.alert_type,
            "severity": event.severity,
            "message": event.message,
            "source": event.source,
            "status": event.status,
            "fixture_role": event.role,
        }
        if event.interface:
            record["interface"] = event.interface
        if event.metrics:
            record["metrics"] = {k: float(v) for k, v in event.metrics.items()}
        records.append(record)
    return records


def generate_scenario_records(scenario_name: str) -> List[Dict[str, Any]]:
    """Feed-format records for one scenario (plain dicts, JSON-ready)."""
    return _build_records(get_scenario_spec(scenario_name))


def generate_scenario(scenario_name: str) -> List[Alert]:
    """Deterministically generate the alerts of one scenario as :class:`Alert` models."""
    return [record_to_alert(record) for record in generate_scenario_records(scenario_name)]


def generate_all_records() -> List[Dict[str, Any]]:
    """Feed-format records for every scenario, in fixture order."""
    records: List[Dict[str, Any]] = []
    for name in SCENARIOS:
        records.extend(_build_records(SCENARIO_SPECS[name]))
    return records


def generate_all_scenarios() -> List[Alert]:
    """Every scenario's alerts, generated in code, in fixture order."""
    return [record_to_alert(record) for record in generate_all_records()]


# ---------------------------------------------------------------------------
# Record <-> Alert mapping
# ---------------------------------------------------------------------------


def record_to_alert(record: Mapping[str, Any]) -> Alert:
    """Convert one feed-format record into an :class:`src.models.Alert`.

    Tolerates the usual spelling differences between collectors (``alert_id`` /
    ``id``, ``device_id`` / ``node_id``, ``alert_type`` / ``type``, ...) and
    keeps feed-only context in ``Alert.labels``:

    * ``scenario`` / ``fixture_role`` — which fixture bundle the alert came from,
    * ``site`` — where the device lives,
    * ``raw_type`` — the original type string when the model had to degrade it
      to ``AlertType.UNKNOWN``.
    """
    if not isinstance(record, Mapping):
        raise GeneratorError(f"alert record must be a mapping, got {type(record).__name__}")

    alert_id = _first(record, ("alert_id", "id", "event_id", "uuid"))
    device_id = _first(record, ("device_id", "node_id"))
    raw_type = _first(record, ("alert_type", "type", "event_type"))

    missing = [
        label
        for label, value in (("alert_id", alert_id), ("device_id", device_id))
        if value is None
    ]
    if missing:
        raise GeneratorError(f"alert record is missing required field(s): {', '.join(missing)}")

    timestamp = _first(record, ("timestamp", "time", "event_time", "received_at"))
    if timestamp is None:
        raise GeneratorError(f"alert record {alert_id} has no timestamp")

    device_name = _first(record, ("device_name", "node_name", "hostname"))
    device_type = _first(record, ("device_type", "node_type"))
    message = _first(record, ("message", "description", "summary", "text")) or ""
    source = _first(record, ("source", "feed", "collector")) or "snmp"
    status = _first(record, ("status", "state", "alarm_status")) or AlertStatus.NEW.value
    severity = _first(record, ("severity", "level", "priority")) or Severity.INFO.value
    interface = _first(record, ("interface", "if_name", "port"))

    metrics_raw = _first(record, ("metrics", "measurements", "values")) or {}
    labels_raw = _first(record, ("labels", "tags")) or {}
    if not isinstance(metrics_raw, Mapping) or not isinstance(labels_raw, Mapping):
        raise GeneratorError(f"alert record {alert_id} has non-object metrics/labels")

    metrics: Dict[str, float] = {}
    for key, value in metrics_raw.items():
        try:
            metrics[str(key)] = float(value)
        except (TypeError, ValueError):
            continue  # a bad number must not sink the whole alert

    labels: Dict[str, str] = {str(k): str(v) for k, v in labels_raw.items()}
    for key in ("scenario", "fixture_role", "site"):
        if key in record and record[key] is not None:
            labels.setdefault(key, str(record[key]))

    alert_type = AlertType(str(raw_type)) if raw_type is not None else AlertType.UNKNOWN
    if raw_type is not None and str(raw_type).strip() != alert_type.value:
        labels.setdefault("raw_type", str(raw_type).strip())

    try:
        return Alert(
            id=str(alert_id),
            timestamp=_parse_iso(timestamp),
            node_id=str(device_id),
            device_name=str(device_name) if device_name is not None else None,
            device_type=device_type,
            interface=str(interface) if interface is not None else None,
            type=alert_type,
            severity=severity,
            message=str(message),
            source=str(source),
            status=status,
            metrics=metrics,
            labels=labels,
        )
    except Exception as exc:  # pydantic ValidationError and friends
        raise GeneratorError(f"alert record {alert_id!r} is not a valid alert: {exc}") from exc


def alert_to_record(alert: Alert, *, scenario: Optional[str] = None) -> Dict[str, Any]:
    """Serialise an :class:`Alert` back into feed-format (the JSON snapshot shape)."""
    raw_type = alert.labels.get("raw_type", alert.type.value)
    record: Dict[str, Any] = {
        "alert_id": alert.id,
        "timestamp": _iso(alert.timestamp),
        "scenario": scenario or alert.labels.get("scenario"),
        "device_id": alert.node_id,
        "device_name": alert.device_name,
        "device_type": alert.device_type.value if alert.device_type else None,
        "site": alert.labels.get("site"),
        "alert_type": raw_type,
        "severity": alert.severity.value,
        "message": alert.message,
        "source": alert.source,
        "status": alert.status.value,
        "fixture_role": alert.labels.get("fixture_role"),
    }
    if alert.interface:
        record["interface"] = alert.interface
    if alert.metrics:
        record["metrics"] = dict(alert.metrics)
    return {k: v for k, v in record.items() if v is not None}


# ---------------------------------------------------------------------------
# Snapshot document (data/sample_alerts.json)
# ---------------------------------------------------------------------------


def build_sample_document() -> Dict[str, Any]:
    """Build the complete deterministic snapshot document (JSON-ready)."""
    scenarios: List[Dict[str, Any]] = []
    for name in SCENARIOS:
        spec = SCENARIO_SPECS[name]
        records = _build_records(spec)
        scenarios.append(
            {
                "name": spec.name,
                "title": spec.title,
                "description": spec.description,
                "expected_handling": spec.expected_handling,
                "base_timestamp": _iso(spec.base_timestamp),
                "alert_count": len(records),
                "alerts": records,
            }
        )

    return {
        "version": SAMPLE_DATA_VERSION,
        "name": "NetSentry-AI deterministic sample alerts",
        "description": (
            "Hand-authored, fully deterministic telecom alert fixture used for "
            "development and demos. Generated by src/generator.py; regenerate "
            "with `python -m src.generator --write`. No live network traffic, "
            "no external APIs, no random data."
        ),
        "generated_by": "src/generator.py",
        "deterministic": True,
        "base_timestamp": _iso(BASE_TIMESTAMP),
        "scenarios": scenarios,
    }


def write_sample_alerts(path: Optional[Path] = None) -> Path:
    """Write the snapshot document to disk (defaults to ``data/sample_alerts.json``)."""
    target = Path(path) if path else DEFAULT_SAMPLE_ALERTS_FILE
    document = build_sample_document()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


def _extract_records(payload: Any) -> List[Dict[str, Any]]:
    """Pull the flat list of alert records out of any accepted document shape."""
    if isinstance(payload, Mapping):
        groups = payload.get("scenarios")
        if isinstance(groups, Sequence) and not isinstance(groups, (str, bytes)):
            records: List[Dict[str, Any]] = []
            for group in groups:
                if not isinstance(group, Mapping):
                    raise GeneratorError("sample alerts document has a malformed scenario group")
                alerts = group.get("alerts", [])
                if not isinstance(alerts, Sequence):
                    raise GeneratorError("sample alerts document has a malformed 'alerts' list")
                for alert in alerts:
                    if not isinstance(alert, Mapping):
                        raise GeneratorError("sample alerts document has a malformed alert entry")
                    # The group name wins, so a record cannot disagree with its bundle.
                    merged = dict(alert)
                    merged.setdefault("scenario", group.get("name"))
                    records.append(merged)
            return records
        alerts = payload.get("alerts")
        if isinstance(alerts, Sequence):
            return [dict(a) for a in alerts if isinstance(a, Mapping)]
        return []

    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes)):
        return [dict(item) for item in payload if isinstance(item, Mapping)]

    raise GeneratorError("sample alerts document must be an object or a list of alerts")


def load_sample_records(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load feed-format alert records from the JSON snapshot.

    Falls back to generating them in code when the file is absent or holds no
    alerts, so a fresh checkout always has demo data available.
    """
    target = Path(path) if path else DEFAULT_SAMPLE_ALERTS_FILE
    if not target.exists():
        return generate_all_records()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GeneratorError(f"sample alerts file is not valid JSON: {target}: {exc}") from exc

    records = _extract_records(payload)
    return records or generate_all_records()


def load_sample_alerts(
    path: Optional[Path] = None, *, rebase_to_now: bool = False
) -> List[Alert]:
    """Load the deterministic sample alerts as :class:`Alert` models.

    ``rebase_to_now`` is off by default: the fixture keeps its fixed timestamps
    so every demo looks identical. When a live demo wants "3 minutes ago"
    instead of a fixed clock, pass ``rebase_to_now=True`` — the whole timeline is
    shifted as one block, so ordering and spacing (and therefore what the
    correlation engine sees) are unchanged.
    """
    alerts = [record_to_alert(record) for record in load_sample_records(path)]
    if rebase_to_now and alerts:
        alerts = _rebase(alerts, datetime.now(timezone.utc))
    return alerts


def _rebase(alerts: Sequence[Alert], now: datetime) -> List[Alert]:
    """Shift every alert so the earliest one keeps its relative distance to ``now``."""
    earliest = min(alert.timestamp for alert in alerts)
    shift = now - earliest
    shifted: List[Alert] = []
    for alert in alerts:
        copy = alert.model_copy(deep=True)
        copy.timestamp = alert.timestamp + shift
        shifted.append(copy)
    return shifted


_CACHE: Optional[List[Alert]] = None


def get_all_sample_alerts(*, refresh: bool = False) -> List[Alert]:
    """Every sample alert, loaded once and cached for the lifetime of the process.

    Returns a fresh list each call (the :class:`Alert` objects are shared, so
    treat them as read-only; call :func:`load_sample_alerts` for private copies).
    """
    global _CACHE
    if _CACHE is None or refresh:
        _CACHE = load_sample_alerts()
    return list(_CACHE)


def clear_cache() -> None:
    """Drop the cached sample alerts (used after rewriting the snapshot)."""
    global _CACHE
    _CACHE = None


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------


def scenario_summary() -> List[Dict[str, Any]]:
    """Per-scenario counts, handy for the CLI, tests and later debug endpoints."""
    summary: List[Dict[str, Any]] = []
    for name in SCENARIOS:
        spec = SCENARIO_SPECS[name]
        records = _build_records(spec)
        alerts = [record_to_alert(record) for record in records]
        offsets = [event.offset for event in spec.events]
        type_counts: Dict[str, int] = {}
        for alert in alerts:
            type_counts[alert.type.value] = type_counts.get(alert.type.value, 0) + 1
        summary.append(
            {
                "name": spec.name,
                "title": spec.title,
                "expected_handling": spec.expected_handling,
                "alert_count": len(alerts),
                "device_count": len({a.node_id for a in alerts}),
                "devices": scenario_devices(name),
                "alert_types": dict(sorted(type_counts.items())),
                "distinct_fingerprints": len({a.fingerprint for a in alerts}),
                "starts_at": _iso(spec.base_timestamp),
                "span_seconds": (max(offsets) - min(offsets)) if offsets else 0,
            }
        )
    return summary


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _format_table(alerts: Iterable[Alert]) -> List[str]:
    """Render alerts as fixed-width text rows for the terminal."""
    lines: List[str] = []
    for alert in alerts:
        device = f"{alert.node_id} ({alert.device_name or '?'})"
        raw_type = alert.labels.get("raw_type", alert.type.value)
        lines.append(
            f"{alert.id:<8} {alert.timestamp.strftime('%H:%M:%S')} {device:<18} "
            f"{raw_type:<30} {alert.severity.value:<8} {alert.message}"
        )
    return lines


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point (``python -m src.generator``)."""
    parser = argparse.ArgumentParser(
        prog="python -m src.generator",
        description="Deterministic telecom alert generator for NetSentry-AI.",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help=f"scenario to show ({', '.join(SCENARIOS)}); defaults to all",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    parser.add_argument(
        "--summary", action="store_true", help="print per-scenario counts and exit"
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="regenerate the JSON snapshot from the scenario tables",
    )
    parser.add_argument(
        "--path", type=Path, default=None, help="snapshot path (default: data/sample_alerts.json)"
    )
    args = parser.parse_args(argv)

    if args.write:
        target = write_sample_alerts(args.path)
        total = len(generate_all_records())
        print(f"wrote {total} deterministic sample alerts to {target}")
        return 0

    if args.summary:
        for row in scenario_summary():
            print(
                f"{row['name']:<20} {row['alert_count']:>3} alerts  "
                f"{row['device_count']} devices  {row['span_seconds']:>4}s  "
                f"{row['expected_handling']}"
            )
            print(f"{'':<20} {row['title']}")
            print(f"{'':<20} types: {row['alert_types']}")
        return 0

    if args.scenario:
        alerts = generate_scenario(args.scenario)
    else:
        alerts = generate_all_scenarios()

    if args.format == "json":
        print(
            json.dumps(
                [alert_to_record(alert) for alert in alerts], indent=2, ensure_ascii=False
            )
        )
    else:
        for line in _format_table(alerts):
            print(line)
        print(f"\n{len(alerts)} alerts")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI
    raise SystemExit(main())
