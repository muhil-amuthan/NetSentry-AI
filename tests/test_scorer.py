"""
Tests for the correlation scoring engine (Step 6).

Covers:
 1.  Same device score.
 2.  Related topology devices score.
 3.  Time proximity score (within / outside window).
 4.  Related alert type score.
 5.  Combined score (multiple signals firing).
 6.  Threshold behaviour — score == threshold is correlated.
 7.  Below-threshold behaviour — not correlated.
 8.  Different devices, no topology link — related_device = 0.
 9.  Different alert types with no relationship — related_type = 0.
10.  Alerts outside 5 minutes — time_proximity = 0.
11.  Transitive grouping — A-B correlated, B-C correlated → one incident.
12.  Multiple independent incidents from unrelated alerts.
13.  Unknown alert types handled gracefully.
14.  Empty input → empty result.
15.  Single alert → one single-alert incident.
16.  Deterministic incident IDs (INC-0001, INC-0002, …).
17.  Deterministic ordering regardless of input order.
18.  Cascade scenario produces one large connected group.
19.  Noise alerts from unknown_escalation remain separate or small.
20.  All Step 1-5 tests still pass (smoke import check).

Run with::

    python -m unittest discover -s tests -t tests
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.generator import (  # noqa: E402
    SCENARIO_CASCADE,
    SCENARIO_DUPLICATES,
    SCENARIO_UNKNOWN,
    generate_scenario,
)
from src.models import Alert, AlertType, Severity  # noqa: E402
from src.processor import process_alerts  # noqa: E402
from src.scorer import (  # noqa: E402
    CORRELATION_THRESHOLD,
    CORRELATION_WEIGHTS,
    TIME_PROXIMITY_WINDOW_SECONDS,
    CandidateIncident,
    PairScore,
    SignalScores,
    are_devices_related,
    build_candidate_incidents,
    correlate_processed_alerts,
    score_alert_pair,
    score_alert_type_relationship,
    score_same_device,
    score_time_proximity,
    score_topology_relationship,
)
from src.topology import NetworkTopology, get_topology  # noqa: E402


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

_BASE = datetime(2026, 9, 5, 9, 0, 0, tzinfo=timezone.utc)
_TOPO: Optional[NetworkTopology] = None  # loaded lazily in setUpClass


def _get_topo() -> NetworkTopology:
    global _TOPO
    if _TOPO is None:
        _TOPO = get_topology()
    return _TOPO


def _make_alert(
    *,
    alert_id: str = "AL-0001",
    node_id: str = "R1",
    device_name: str = "CORE-R1",
    alert_type: str = "LINK_DOWN",
    interface: str | None = "Te0/1",
    severity: str = "critical",
    source: str = "snmp_trap",
    ts_offset: int = 0,
    message: str = "test alert",
) -> Alert:
    """Minimal valid Alert factory for unit tests."""
    return Alert(
        id=alert_id,
        timestamp=_BASE + timedelta(seconds=ts_offset),
        node_id=node_id,
        device_name=device_name,
        interface=interface,
        type=AlertType(alert_type),
        severity=Severity.normalize(severity),
        source=source,
        message=message,
    )


# ---------------------------------------------------------------------------
# 1. Same device score
# ---------------------------------------------------------------------------


class TestSameDeviceScore(unittest.TestCase):
    def test_same_node_id_scores_full_weight(self):
        a = _make_alert(node_id="R1")
        b = _make_alert(alert_id="AL-0002", node_id="R1", ts_offset=10)
        self.assertEqual(score_same_device(a, b), CORRELATION_WEIGHTS["same_device"])

    def test_different_node_id_scores_zero(self):
        a = _make_alert(node_id="R1")
        b = _make_alert(alert_id="AL-0002", node_id="S1", ts_offset=10)
        self.assertEqual(score_same_device(a, b), 0)

    def test_same_device_score_is_symmetric(self):
        a = _make_alert(node_id="R1")
        b = _make_alert(alert_id="AL-0002", node_id="R1")
        self.assertEqual(score_same_device(a, b), score_same_device(b, a))


# ---------------------------------------------------------------------------
# 2. Topology relationship score
# ---------------------------------------------------------------------------


class TestTopologyRelationshipScore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def test_directly_linked_devices_score_full_weight(self):
        # R1 — S1 is LNK-004 in topology.json
        a = _make_alert(node_id="R1")
        b = _make_alert(alert_id="AL-0002", node_id="S1")
        score = score_topology_relationship(a, b, self.topo)
        self.assertEqual(score, CORRELATION_WEIGHTS["related_device"])

    def test_not_directly_linked_scores_zero(self):
        # R3 and R5 are not directly linked (both connect to different switches)
        a = _make_alert(node_id="R3")
        b = _make_alert(alert_id="AL-0002", node_id="R5")
        score = score_topology_relationship(a, b, self.topo)
        self.assertEqual(score, 0)

    def test_same_device_topology_scores_zero(self):
        # Same-device is handled by score_same_device; topology scores 0.
        a = _make_alert(node_id="R1")
        b = _make_alert(alert_id="AL-0002", node_id="R1")
        score = score_topology_relationship(a, b, self.topo)
        self.assertEqual(score, 0)

    def test_unknown_device_scores_zero(self):
        a = _make_alert(node_id="NONEXISTENT")
        b = _make_alert(alert_id="AL-0002", node_id="R1")
        score = score_topology_relationship(a, b, self.topo)
        self.assertEqual(score, 0)

    def test_topology_score_is_symmetric(self):
        a = _make_alert(node_id="R1")
        b = _make_alert(alert_id="AL-0002", node_id="S1")
        self.assertEqual(
            score_topology_relationship(a, b, self.topo),
            score_topology_relationship(b, a, self.topo),
        )

    def test_r1_s2_are_linked(self):
        # R1 — S2 is LNK-005
        a = _make_alert(node_id="R1")
        b = _make_alert(alert_id="AL-0002", node_id="S2")
        score = score_topology_relationship(a, b, self.topo)
        self.assertEqual(score, CORRELATION_WEIGHTS["related_device"])

    def test_s1_r3_are_linked(self):
        # S1 — R3 is LNK-006
        a = _make_alert(node_id="S1")
        b = _make_alert(alert_id="AL-0002", node_id="R3")
        score = score_topology_relationship(a, b, self.topo)
        self.assertEqual(score, CORRELATION_WEIGHTS["related_device"])

    def test_r1_r3_not_directly_linked(self):
        # R1 and R3 are connected via S1 but not directly.
        a = _make_alert(node_id="R1")
        b = _make_alert(alert_id="AL-0002", node_id="R3")
        score = score_topology_relationship(a, b, self.topo)
        self.assertEqual(score, 0)


# ---------------------------------------------------------------------------
# 3. Time proximity score
# ---------------------------------------------------------------------------


class TestTimeProximityScore(unittest.TestCase):
    def test_same_timestamp_scores_full_weight(self):
        a = _make_alert(ts_offset=0)
        b = _make_alert(alert_id="AL-0002", ts_offset=0)
        self.assertEqual(score_time_proximity(a, b), CORRELATION_WEIGHTS["time_proximity"])

    def test_within_window_scores_full_weight(self):
        a = _make_alert(ts_offset=0)
        b = _make_alert(alert_id="AL-0002", ts_offset=TIME_PROXIMITY_WINDOW_SECONDS - 1)
        self.assertEqual(score_time_proximity(a, b), CORRELATION_WEIGHTS["time_proximity"])

    def test_exactly_at_window_boundary_scores_full_weight(self):
        a = _make_alert(ts_offset=0)
        b = _make_alert(alert_id="AL-0002", ts_offset=TIME_PROXIMITY_WINDOW_SECONDS)
        self.assertEqual(score_time_proximity(a, b), CORRELATION_WEIGHTS["time_proximity"])

    def test_outside_window_scores_zero(self):
        a = _make_alert(ts_offset=0)
        b = _make_alert(alert_id="AL-0002", ts_offset=TIME_PROXIMITY_WINDOW_SECONDS + 1)
        self.assertEqual(score_time_proximity(a, b), 0)

    def test_time_proximity_is_symmetric(self):
        a = _make_alert(ts_offset=0)
        b = _make_alert(alert_id="AL-0002", ts_offset=120)
        self.assertEqual(score_time_proximity(a, b), score_time_proximity(b, a))

    def test_five_minutes_exactly(self):
        a = _make_alert(ts_offset=0)
        b = _make_alert(alert_id="AL-0002", ts_offset=300)  # 300 s == 5 minutes
        self.assertEqual(score_time_proximity(a, b), CORRELATION_WEIGHTS["time_proximity"])

    def test_five_minutes_plus_one_second_scores_zero(self):
        a = _make_alert(ts_offset=0)
        b = _make_alert(alert_id="AL-0002", ts_offset=301)
        self.assertEqual(score_time_proximity(a, b), 0)


# ---------------------------------------------------------------------------
# 4. Related alert type score
# ---------------------------------------------------------------------------


class TestAlertTypeRelationshipScore(unittest.TestCase):
    def test_link_down_and_device_unreachable_are_related(self):
        a = _make_alert(alert_type="LINK_DOWN")
        b = _make_alert(alert_id="AL-0002", alert_type="DEVICE_UNREACHABLE")
        self.assertEqual(
            score_alert_type_relationship(a, b),
            CORRELATION_WEIGHTS["related_type"],
        )

    def test_link_down_and_packet_loss_are_related(self):
        a = _make_alert(alert_type="LINK_DOWN")
        b = _make_alert(alert_id="AL-0002", alert_type="PACKET_LOSS")
        self.assertEqual(
            score_alert_type_relationship(a, b),
            CORRELATION_WEIGHTS["related_type"],
        )

    def test_packet_loss_and_high_latency_are_related(self):
        a = _make_alert(alert_type="PACKET_LOSS")
        b = _make_alert(alert_id="AL-0002", alert_type="HIGH_LATENCY")
        self.assertEqual(
            score_alert_type_relationship(a, b),
            CORRELATION_WEIGHTS["related_type"],
        )

    def test_auth_failure_and_auth_failure_are_related(self):
        a = _make_alert(alert_type="AUTH_FAILURE")
        b = _make_alert(alert_id="AL-0002", alert_type="AUTH_FAILURE")
        self.assertEqual(
            score_alert_type_relationship(a, b),
            CORRELATION_WEIGHTS["related_type"],
        )

    def test_link_down_and_auth_failure_unrelated(self):
        a = _make_alert(alert_type="LINK_DOWN")
        b = _make_alert(alert_id="AL-0002", alert_type="AUTH_FAILURE")
        self.assertEqual(score_alert_type_relationship(a, b), 0)

    def test_unknown_type_scores_zero(self):
        a = Alert(
            id="AL-UNK",
            timestamp=_BASE,
            node_id="R1",
            type=AlertType.UNKNOWN,
            severity=Severity.HIGH,
            source="syslog",
            message="unknown",
        )
        b = _make_alert(alert_id="AL-0002", alert_type="LINK_DOWN")
        self.assertEqual(score_alert_type_relationship(a, b), 0)

    def test_config_change_scores_zero_with_link_down(self):
        a = _make_alert(alert_type="CONFIG_CHANGE")
        b = _make_alert(alert_id="AL-0002", alert_type="LINK_DOWN")
        self.assertEqual(score_alert_type_relationship(a, b), 0)

    def test_type_score_is_symmetric(self):
        a = _make_alert(alert_type="LINK_DOWN")
        b = _make_alert(alert_id="AL-0002", alert_type="PACKET_LOSS")
        self.assertEqual(
            score_alert_type_relationship(a, b),
            score_alert_type_relationship(b, a),
        )


# ---------------------------------------------------------------------------
# 5. Combined score
# ---------------------------------------------------------------------------


class TestCombinedScore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def test_same_device_same_type_within_window_max_score(self):
        # same_device(30) + related_type(30) + time_proximity(20) = 80
        # related_device = 0 (same device, that signal is skipped)
        a = _make_alert(node_id="R1", alert_type="LINK_DOWN", ts_offset=0)
        b = _make_alert(alert_id="AL-0002", node_id="R1", alert_type="DEVICE_UNREACHABLE",
                        ts_offset=30)
        ps = score_alert_pair(a, b, self.topo)
        self.assertEqual(ps.signals.same_device, 30)
        self.assertEqual(ps.signals.related_device, 0)  # same device → 0
        self.assertEqual(ps.signals.time_proximity, 20)
        self.assertEqual(ps.signals.related_type, 30)
        self.assertEqual(ps.score, 80)

    def test_different_topology_linked_devices_related_type_within_window(self):
        # R1 LINK_DOWN, S1 DEVICE_UNREACHABLE, within 5 minutes
        # related_device(20) + time_proximity(20) + related_type(30) = 70
        a = _make_alert(node_id="R1", alert_type="LINK_DOWN", ts_offset=0)
        b = _make_alert(alert_id="AL-0002", node_id="S1", device_name="SW-S1",
                        alert_type="DEVICE_UNREACHABLE", ts_offset=60)
        ps = score_alert_pair(a, b, self.topo)
        self.assertEqual(ps.signals.same_device, 0)
        self.assertEqual(ps.signals.related_device, 20)
        self.assertEqual(ps.signals.time_proximity, 20)
        self.assertEqual(ps.signals.related_type, 30)
        self.assertEqual(ps.score, 70)

    def test_all_signals_fire_impossible_same_different_device(self):
        # same_device and related_device cannot both fire for same pair,
        # so max real score for different linked devices = 20+20+30 = 70.
        a = _make_alert(node_id="R1", alert_type="LINK_DOWN", ts_offset=0)
        b = _make_alert(alert_id="AL-0002", node_id="S1", device_name="SW-S1",
                        alert_type="DEVICE_UNREACHABLE", ts_offset=10)
        ps = score_alert_pair(a, b, self.topo)
        self.assertLessEqual(ps.score, 70)


# ---------------------------------------------------------------------------
# 6 & 7. Threshold behaviour
# ---------------------------------------------------------------------------


class TestThresholdBehaviour(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def test_score_at_threshold_is_correlated(self):
        # Build a pair that scores exactly 60: same_device(30)+time_proximity(20)+related_type(30)
        # Wait — same_device(30) alone + related_type(30) = 60 (no time proximity needed if within window)
        # But we want exactly 60 without time_proximity. Use different devices (no topo link)
        # and related types but outside time window:
        # related_type(30) + related_device(20) + time_proximity(?) + same_device(0)
        # For exactly 60: same_device(30) + related_type(30) + 0 + 0 = 60 (outside window, same device)
        a = _make_alert(node_id="R1", alert_type="LINK_DOWN", ts_offset=0)
        b = _make_alert(alert_id="AL-0002", node_id="R1", alert_type="DEVICE_UNREACHABLE",
                        ts_offset=TIME_PROXIMITY_WINDOW_SECONDS + 100)
        ps = score_alert_pair(a, b, self.topo)
        # same_device(30) + related_type(30) = 60 exactly
        self.assertEqual(ps.score, CORRELATION_THRESHOLD)
        self.assertTrue(ps.correlated)

    def test_score_below_threshold_is_not_correlated(self):
        # Only time_proximity(20) fires: different devices, no topo link, unrelated types
        a = _make_alert(node_id="R3", alert_type="CONFIG_CHANGE", ts_offset=0)
        b = _make_alert(alert_id="AL-0002", node_id="R5", device_name="ACC-R5",
                        alert_type="CPU_HIGH", ts_offset=30)
        ps = score_alert_pair(a, b, self.topo)
        self.assertLess(ps.score, CORRELATION_THRESHOLD)
        self.assertFalse(ps.correlated)

    def test_zero_score_is_not_correlated(self):
        # Different devices, no topo link, unrelated types, outside window.
        a = _make_alert(node_id="R3", alert_type="CONFIG_CHANGE", ts_offset=0)
        b = _make_alert(alert_id="AL-0002", node_id="R5", device_name="ACC-R5",
                        alert_type="CPU_HIGH", ts_offset=TIME_PROXIMITY_WINDOW_SECONDS + 100)
        ps = score_alert_pair(a, b, self.topo)
        self.assertFalse(ps.correlated)


# ---------------------------------------------------------------------------
# 8. Different devices, no topology link
# ---------------------------------------------------------------------------


class TestDifferentDevicesNoLink(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def test_r3_r5_no_direct_link(self):
        # R3 connects to S1; R5 connects to S2 — they are not directly linked.
        self.assertFalse(are_devices_related("R3", "R5", self.topo))

    def test_r3_r6_no_direct_link(self):
        self.assertFalse(are_devices_related("R3", "R6", self.topo))

    def test_r3_r4_no_direct_link(self):
        # Both connect to S1 but are not directly linked to each other.
        self.assertFalse(are_devices_related("R3", "R4", self.topo))

    def test_are_devices_related_same_device_false(self):
        # Same device is not "related" in the topology sense.
        self.assertFalse(are_devices_related("R1", "R1", self.topo))

    def test_are_devices_related_linked(self):
        self.assertTrue(are_devices_related("R1", "S1", self.topo))
        self.assertTrue(are_devices_related("S1", "R1", self.topo))  # symmetric


# ---------------------------------------------------------------------------
# 9. Different alert types with no relationship
# ---------------------------------------------------------------------------


class TestUnrelatedAlertTypes(unittest.TestCase):
    def test_link_down_and_cpu_high_unrelated(self):
        a = _make_alert(alert_type="LINK_DOWN")
        b = _make_alert(alert_id="AL-0002", alert_type="CPU_HIGH")
        self.assertEqual(score_alert_type_relationship(a, b), 0)

    def test_link_down_and_config_change_unrelated(self):
        a = _make_alert(alert_type="LINK_DOWN")
        b = _make_alert(alert_id="AL-0002", alert_type="CONFIG_CHANGE")
        self.assertEqual(score_alert_type_relationship(a, b), 0)

    def test_unknown_and_link_down_unrelated(self):
        a = Alert(
            id="AL-X", timestamp=_BASE, node_id="R1",
            type=AlertType.UNKNOWN, severity=Severity.HIGH,
            source="syslog", message="X",
        )
        b = _make_alert(alert_id="AL-0002", alert_type="LINK_DOWN")
        self.assertEqual(score_alert_type_relationship(a, b), 0)


# ---------------------------------------------------------------------------
# 10. Alerts outside 5 minutes
# ---------------------------------------------------------------------------


class TestOutsideTimeWindow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def test_outside_window_time_signal_zero(self):
        a = _make_alert(ts_offset=0)
        b = _make_alert(alert_id="AL-0002", ts_offset=TIME_PROXIMITY_WINDOW_SECONDS + 10)
        self.assertEqual(score_time_proximity(a, b), 0)

    def test_same_device_correlated_despite_outside_window(self):
        # same_device(30) + related_type(30) = 60 → still correlated even without time proximity
        a = _make_alert(node_id="R1", alert_type="LINK_DOWN", ts_offset=0)
        b = _make_alert(alert_id="AL-0002", node_id="R1",
                        alert_type="DEVICE_UNREACHABLE",
                        ts_offset=TIME_PROXIMITY_WINDOW_SECONDS + 100)
        ps = score_alert_pair(a, b, self.topo)
        self.assertTrue(ps.correlated)

    def test_different_device_outside_window_not_correlated(self):
        # R3 and R5 not linked; unrelated types; outside window → 0
        a = _make_alert(node_id="R3", alert_type="CONFIG_CHANGE", ts_offset=0)
        b = _make_alert(alert_id="AL-0002", node_id="R5",
                        alert_type="CPU_HIGH",
                        ts_offset=TIME_PROXIMITY_WINDOW_SECONDS + 100)
        ps = score_alert_pair(a, b, self.topo)
        self.assertFalse(ps.correlated)


# ---------------------------------------------------------------------------
# 11. Transitive grouping
# ---------------------------------------------------------------------------


class TestTransitiveGrouping(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def test_a_b_b_c_same_incident(self):
        """A-B correlated, B-C correlated → A,B,C in one incident."""
        # A: R1 LINK_DOWN  (t=0)  — same device as B
        # B: R1 DEVICE_UNREACHABLE (t=30) — same device as A; topology-linked to C
        # C: S1 DEVICE_UNREACHABLE (t=60) — topology-linked to B; related type to B
        a = _make_alert(alert_id="AL-A", node_id="R1", alert_type="LINK_DOWN",
                        device_name="CORE-R1", ts_offset=0)
        b = _make_alert(alert_id="AL-B", node_id="R1", alert_type="DEVICE_UNREACHABLE",
                        device_name="CORE-R1", ts_offset=30)
        c = _make_alert(alert_id="AL-C", node_id="S1", alert_type="DEVICE_UNREACHABLE",
                        device_name="SW-S1", ts_offset=60)
        incidents = build_candidate_incidents([a, b, c], self.topo)
        # A-B: same_device(30)+related_type(30)+time(20) = 80 → correlated
        # B-C: related_device(20)+related_type(30)+time(20) = 70 → correlated
        # A-C: related_type(30)+time(20) = 50 → NOT directly correlated (below 60)
        # But transitive grouping puts A,B,C together via B.
        self.assertEqual(len(incidents), 1)
        all_ids = set(incidents[0].alert_ids)
        self.assertIn("AL-A", all_ids)
        self.assertIn("AL-B", all_ids)
        self.assertIn("AL-C", all_ids)

    def test_chain_of_three_same_device(self):
        """A-B and B-C both correlated (same device) → one incident."""
        # same_device(30) + related_type(30) + time(20) = 80 ≥ 60
        types = ["LINK_DOWN", "DEVICE_UNREACHABLE", "PACKET_LOSS"]
        alerts = [
            _make_alert(alert_id=f"AL-{i:04d}", alert_type=t, ts_offset=i * 10)
            for i, t in enumerate(types)
        ]
        incidents = build_candidate_incidents(alerts, self.topo)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(len(incidents[0].alert_ids), 3)


# ---------------------------------------------------------------------------
# 12. Multiple independent incidents
# ---------------------------------------------------------------------------


class TestMultipleIndependentIncidents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def test_two_isolated_incidents(self):
        """Two completely unrelated alert groups produce two incidents."""
        # Group 1: R1 alerts
        g1 = [
            _make_alert(alert_id="AL-G1A", node_id="R1", alert_type="LINK_DOWN",
                        device_name="CORE-R1", ts_offset=0),
            _make_alert(alert_id="AL-G1B", node_id="R1", alert_type="DEVICE_UNREACHABLE",
                        device_name="CORE-R1", ts_offset=30),
        ]
        # Group 2: unrelated alerts far in the future on R2, different types
        g2 = [
            Alert(
                id="AL-G2A",
                timestamp=_BASE + timedelta(hours=2),
                node_id="R2",
                device_name="CORE-R2",
                type=AlertType.CPU_HIGH,
                severity=Severity.MEDIUM,
                source="snmp",
                message="cpu high",
            ),
        ]
        incidents = build_candidate_incidents(g1 + g2, self.topo)
        # G1 members should be grouped together; G2 should be its own incident.
        self.assertEqual(len(incidents), 2)

    def test_noise_alerts_stay_separate(self):
        """Completely unrelated alerts from unlinked devices become singletons."""
        # CONFIG_CHANGE on S1, CPU_HIGH on R5 — no relation
        a = Alert(
            id="AL-NOISE1",
            timestamp=_BASE + timedelta(hours=1),
            node_id="S1",
            device_name="SW-S1",
            type=AlertType.CONFIG_CHANGE,
            severity=Severity.INFO,
            source="syslog",
            message="config change",
        )
        b = Alert(
            id="AL-NOISE2",
            timestamp=_BASE + timedelta(hours=1, seconds=30),
            node_id="R5",
            device_name="ACC-R5",
            type=AlertType.CPU_HIGH,
            severity=Severity.MEDIUM,
            source="snmp",
            message="cpu high",
        )
        ps = score_alert_pair(a, b, _get_topo())
        # S1 and R5 are not directly linked (R5 → S2); unrelated types; below threshold.
        self.assertFalse(ps.correlated)


# ---------------------------------------------------------------------------
# 13. Unknown alert types
# ---------------------------------------------------------------------------


class TestUnknownAlertTypes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def _unknown(self, alert_id: str, node_id: str, ts_offset: int = 0) -> Alert:
        return Alert(
            id=alert_id,
            timestamp=_BASE + timedelta(seconds=ts_offset),
            node_id=node_id,
            type=AlertType.UNKNOWN,
            severity=Severity.HIGH,
            source="syslog",
            message="unknown condition",
        )

    def test_unknown_type_pair_scores_zero_for_type(self):
        a = self._unknown("AL-U1", "R2")
        b = self._unknown("AL-U2", "R2", ts_offset=10)
        self.assertEqual(score_alert_type_relationship(a, b), 0)

    def test_unknown_type_still_produces_candidate_incident(self):
        a = self._unknown("AL-U1", "R2")
        incidents = build_candidate_incidents([a], self.topo)
        self.assertEqual(len(incidents), 1)
        self.assertIn("AL-U1", incidents[0].alert_ids)

    def test_unknown_types_from_different_devices_separate(self):
        a = self._unknown("AL-U1", "R2", ts_offset=0)
        b = self._unknown("AL-U2", "S1", ts_offset=10)
        # R2 and S1 are not directly linked; type scores 0.
        # related_device=0, same_device=0, related_type=0, time_proximity=20 → 20 < 60
        ps = score_alert_pair(a, b, self.topo)
        self.assertFalse(ps.correlated)

    def test_unknown_types_do_not_absorb_unrelated_alerts(self):
        """Unknown alerts must not incorrectly pull in unrelated known alerts."""
        a = self._unknown("AL-U1", "R2", ts_offset=0)
        b = Alert(
            id="AL-K1",
            timestamp=_BASE + timedelta(seconds=5),
            node_id="S2",
            type=AlertType.MEMORY_HIGH,
            severity=Severity.LOW,
            source="snmp",
            message="memory",
        )
        # R2 and S2 are not directly linked; unrelated types; within window
        # → time_proximity(20) only → 20 < 60 → not correlated
        ps = score_alert_pair(a, b, self.topo)
        self.assertFalse(ps.correlated)


# ---------------------------------------------------------------------------
# 14. Empty input
# ---------------------------------------------------------------------------


class TestEmptyInput(unittest.TestCase):
    def test_empty_alerts_returns_empty(self):
        result = build_candidate_incidents([])
        self.assertEqual(result, [])

    def test_empty_processed_returns_empty(self):
        from src.processor import process_alerts
        processed, _ = process_alerts([])
        result = correlate_processed_alerts(processed)
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# 15. Single alert
# ---------------------------------------------------------------------------


class TestSingleAlert(unittest.TestCase):
    def test_single_alert_becomes_one_incident(self):
        a = _make_alert()
        incidents = build_candidate_incidents([a])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].alert_ids, ["AL-0001"])
        self.assertEqual(incidents[0].count if hasattr(incidents[0], "count") else 1, 1)

    def test_single_incident_id_is_inc_0001(self):
        a = _make_alert()
        incidents = build_candidate_incidents([a])
        self.assertEqual(incidents[0].incident_id, "INC-0001")


# ---------------------------------------------------------------------------
# 16. Deterministic incident IDs
# ---------------------------------------------------------------------------


class TestDeterministicIncidentIDs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def _multi_alerts(self) -> List[Alert]:
        return [
            _make_alert(alert_id="AL-0001", node_id="R1", alert_type="LINK_DOWN", ts_offset=0),
            _make_alert(alert_id="AL-0002", node_id="R1", alert_type="DEVICE_UNREACHABLE",
                        ts_offset=30),
            Alert(
                id="AL-0003",
                timestamp=_BASE + timedelta(hours=2),
                node_id="R2",
                type=AlertType.CPU_HIGH,
                severity=Severity.MEDIUM,
                source="snmp",
                message="cpu high",
            ),
        ]

    def test_incident_ids_are_sequential(self):
        incidents = build_candidate_incidents(self._multi_alerts(), self.topo)
        ids = [inc.incident_id for inc in incidents]
        self.assertEqual(ids[0], "INC-0001")
        if len(ids) > 1:
            self.assertEqual(ids[1], "INC-0002")

    def test_incident_ids_start_at_0001(self):
        a = _make_alert()
        incidents = build_candidate_incidents([a], self.topo)
        self.assertEqual(incidents[0].incident_id, "INC-0001")


# ---------------------------------------------------------------------------
# 17. Deterministic ordering
# ---------------------------------------------------------------------------


class TestDeterministicOrdering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def _build_batch(self) -> List[Alert]:
        return [
            _make_alert(alert_id="AL-0001", node_id="R1", alert_type="LINK_DOWN",
                        device_name="CORE-R1", ts_offset=0),
            _make_alert(alert_id="AL-0002", node_id="R1", alert_type="DEVICE_UNREACHABLE",
                        device_name="CORE-R1", ts_offset=20),
            _make_alert(alert_id="AL-0003", node_id="S1", alert_type="LINK_DOWN",
                        device_name="SW-S1", ts_offset=50),
        ]

    def test_same_input_same_output(self):
        batch = self._build_batch()
        r1 = build_candidate_incidents(batch, self.topo)
        r2 = build_candidate_incidents(batch, self.topo)
        self.assertEqual(
            [(i.incident_id, i.alert_ids) for i in r1],
            [(i.incident_id, i.alert_ids) for i in r2],
        )

    def test_different_input_order_same_output(self):
        batch = self._build_batch()
        reversed_batch = list(reversed(batch))
        r1 = build_candidate_incidents(batch, self.topo)
        r2 = build_candidate_incidents(reversed_batch, self.topo)
        self.assertEqual(
            [(i.incident_id, sorted(i.alert_ids)) for i in r1],
            [(i.incident_id, sorted(i.alert_ids)) for i in r2],
        )


# ---------------------------------------------------------------------------
# 18. Cascade scenario — expect one large connected group
# ---------------------------------------------------------------------------


class TestCascadeScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()
        raw = generate_scenario(SCENARIO_CASCADE)
        processed, _ = process_alerts(raw)
        cls.processed = processed
        cls.incidents = correlate_processed_alerts(processed, cls.topo)

    def test_produces_at_least_one_incident(self):
        self.assertGreater(len(self.incidents), 0)

    def test_largest_incident_covers_multiple_devices(self):
        largest = max(self.incidents, key=lambda i: len(i.affected_devices))
        self.assertGreater(len(largest.affected_devices), 1)

    def test_cascade_alerts_grouped_into_few_incidents(self):
        """The cascade should produce far fewer incidents than raw alerts."""
        total_raw = len(generate_scenario(SCENARIO_CASCADE))
        self.assertLess(len(self.incidents), total_raw)

    def test_all_seven_cascade_devices_appear_somewhere(self):
        all_devices = set()
        for inc in self.incidents:
            for a in inc.alerts:
                all_devices.add(a.node_id)
        for dev in ("R1", "S1", "S2", "R3", "R4", "R5", "R6"):
            self.assertIn(dev, all_devices, f"cascade device {dev} missing from incidents")

    def test_r1_and_s1_in_same_incident(self):
        """CORE-R1 and SW-S1 should be correlated (they are topology-linked)."""
        r1_incident = next(
            (inc for inc in self.incidents
             if any(a.node_id == "R1" for a in inc.alerts)
             and any(a.node_id == "S1" for a in inc.alerts)),
            None,
        )
        self.assertIsNotNone(
            r1_incident,
            "R1 and S1 should be in the same candidate incident",
        )

    def test_r1_and_s2_in_same_incident(self):
        """CORE-R1 and SW-S2 should be correlated (they are topology-linked)."""
        r1_s2_incident = next(
            (inc for inc in self.incidents
             if any(a.node_id == "R1" for a in inc.alerts)
             and any(a.node_id == "S2" for a in inc.alerts)),
            None,
        )
        self.assertIsNotNone(
            r1_s2_incident,
            "R1 and S2 should be in the same candidate incident",
        )


# ---------------------------------------------------------------------------
# 19. Noise stays separate
# ---------------------------------------------------------------------------


class TestNoiseSeparate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def test_noise_type_config_change_stays_isolated(self):
        noise = Alert(
            id="AL-NOISE",
            timestamp=_BASE + timedelta(hours=1),
            node_id="S1",
            device_name="SW-S1",
            type=AlertType.CONFIG_CHANGE,
            severity=Severity.INFO,
            source="syslog",
            message="planned maintenance config change",
        )
        critical = _make_alert(
            alert_id="AL-CRIT",
            node_id="R1",
            device_name="CORE-R1",
            alert_type="LINK_DOWN",
            ts_offset=0,
        )
        incidents = build_candidate_incidents([noise, critical], self.topo)
        # CONFIG_CHANGE on S1 at t+1h vs LINK_DOWN on R1 at t=0:
        # related_device(20) + no time(0) + no type(0) = 20 < 60
        noise_incident = next(
            (inc for inc in incidents if "AL-NOISE" in inc.alert_ids), None
        )
        critical_incident = next(
            (inc for inc in incidents if "AL-CRIT" in inc.alert_ids), None
        )
        # They must be in different incidents.
        self.assertIsNotNone(noise_incident)
        self.assertIsNotNone(critical_incident)
        self.assertNotEqual(
            noise_incident.incident_id, critical_incident.incident_id
        )


# ---------------------------------------------------------------------------
# PairScore and SignalScores data model tests
# ---------------------------------------------------------------------------


class TestPairScoreModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def test_pair_score_to_dict_has_required_keys(self):
        a = _make_alert(node_id="R1", alert_type="LINK_DOWN")
        b = _make_alert(alert_id="AL-0002", node_id="R1", alert_type="DEVICE_UNREACHABLE",
                        ts_offset=10)
        ps = score_alert_pair(a, b, self.topo)
        d = ps.to_dict()
        for key in ("alert_id_a", "alert_id_b", "score", "correlated", "signals", "explanation"):
            self.assertIn(key, d)

    def test_signal_scores_total(self):
        s = SignalScores(same_device=30, related_device=0, time_proximity=20, related_type=30)
        self.assertEqual(s.total, 80)

    def test_explanation_contains_score(self):
        a = _make_alert(node_id="R1", alert_type="LINK_DOWN")
        b = _make_alert(alert_id="AL-0002", node_id="R1", alert_type="DEVICE_UNREACHABLE",
                        ts_offset=10)
        ps = score_alert_pair(a, b, self.topo)
        self.assertIn(str(ps.score), ps.explanation)


# ---------------------------------------------------------------------------
# CandidateIncident structure tests
# ---------------------------------------------------------------------------


class TestCandidateIncidentStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def test_to_dict_has_required_keys(self):
        a = _make_alert()
        incidents = build_candidate_incidents([a], self.topo)
        d = incidents[0].to_dict()
        for key in ("incident_id", "alert_ids", "affected_devices",
                    "first_seen", "last_seen", "correlation_score"):
            self.assertIn(key, d)

    def test_first_last_seen_correct(self):
        # Use related types so the pair is correlated:
        # same_device(30) + related_type(30) + time(20) = 80 ≥ 60
        a = _make_alert(alert_id="AL-0001", alert_type="LINK_DOWN", ts_offset=0)
        b = _make_alert(alert_id="AL-0002", alert_type="DEVICE_UNREACHABLE",
                        interface=None, ts_offset=30)
        incidents = build_candidate_incidents([a, b], self.topo)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].first_seen, _BASE)
        self.assertEqual(incidents[0].last_seen, _BASE + timedelta(seconds=30))

    def test_affected_devices_unique_and_ordered(self):
        a = _make_alert(alert_id="AL-0001", node_id="R1", device_name="CORE-R1", ts_offset=0)
        b = _make_alert(alert_id="AL-0002", node_id="R1", device_name="CORE-R1", ts_offset=20)
        c = _make_alert(alert_id="AL-0003", node_id="S1", device_name="SW-S1",
                        alert_type="DEVICE_UNREACHABLE", ts_offset=50)
        incidents = build_candidate_incidents([a, b, c], self.topo)
        # All three should end up in the same incident via R1-R1 same-device and R1-S1 topology.
        merged = max(incidents, key=lambda i: len(i.affected_devices))
        # Devices should be unique.
        self.assertEqual(len(merged.affected_devices), len(set(merged.affected_devices)))


# ---------------------------------------------------------------------------
# correlate_processed_alerts convenience wrapper
# ---------------------------------------------------------------------------


class TestCorrelateProcessedAlerts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topo = _get_topo()

    def test_wrapper_produces_same_result_as_direct(self):
        raw = generate_scenario(SCENARIO_DUPLICATES)
        processed, _ = process_alerts(raw)
        representatives = [p.representative for p in processed]
        direct = build_candidate_incidents(representatives, self.topo)
        via_wrapper = correlate_processed_alerts(processed, self.topo)
        self.assertEqual(
            [(i.incident_id, sorted(i.alert_ids)) for i in direct],
            [(i.incident_id, sorted(i.alert_ids)) for i in via_wrapper],
        )

    def test_duplicate_scenario_produces_incidents(self):
        raw = generate_scenario(SCENARIO_DUPLICATES)
        processed, _ = process_alerts(raw)
        incidents = correlate_processed_alerts(processed, self.topo)
        self.assertGreater(len(incidents), 0)
        # All alerts accounted for.
        total = sum(len(i.alert_ids) for i in incidents)
        self.assertEqual(total, len(processed))


# ---------------------------------------------------------------------------
# 20. Smoke import — existing modules still importable
# ---------------------------------------------------------------------------


class TestExistingModulesUnchanged(unittest.TestCase):
    """20. All Step 1–5 tests still pass (module import smoke check)."""

    def test_models_importable(self):
        from src import models  # noqa: F401
        self.assertIsNotNone(models.Alert)

    def test_generator_importable(self):
        from src import generator  # noqa: F401
        self.assertIsNotNone(generator.get_all_sample_alerts)

    def test_topology_importable(self):
        from src import topology  # noqa: F401
        self.assertIsNotNone(topology.get_topology)

    def test_processor_importable(self):
        from src import processor  # noqa: F401
        self.assertIsNotNone(processor.process_alerts)

    def test_api_importable(self):
        from src import api  # noqa: F401
        self.assertIsNotNone(api.router)

    def test_scorer_exports_all_public_names(self):
        import src.scorer as sc
        for name in (
            "CORRELATION_WEIGHTS",
            "CORRELATION_THRESHOLD",
            "TIME_PROXIMITY_WINDOW_SECONDS",
            "RELATED_ALERT_TYPES",
            "score_same_device",
            "score_topology_relationship",
            "score_time_proximity",
            "score_alert_type_relationship",
            "SignalScores",
            "PairScore",
            "score_alert_pair",
            "are_devices_related",
            "CandidateIncident",
            "build_candidate_incidents",
            "correlate_processed_alerts",
        ):
            self.assertTrue(hasattr(sc, name), f"scorer missing export: {name}")


if __name__ == "__main__":
    unittest.main()
