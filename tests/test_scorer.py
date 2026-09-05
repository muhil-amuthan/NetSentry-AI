"""
Tests for the deterministic correlation scoring engine (``src.scorer``).

Covers the four signals in isolation, combined scoring, threshold behaviour,
grouping (including transitive grouping), determinism, edge cases and the
sample scenarios shipped in ``data/sample_alerts.json``.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from src.generator import generate_scenario
from src.models import Alert, AlertType, Severity
from src.processor import process_alerts
from src.scorer import (
    CORRELATION_THRESHOLD,
    CORRELATION_WEIGHTS,
    MAX_CORRELATION_SCORE,
    RELATED_ALERT_TYPES,
    ScorerError,
    are_devices_related,
    are_types_related,
    as_alert_view,
    build_alert_views,
    build_candidate_incidents,
    correlate,
    score_alert_pair,
    score_all_pairs,
)
from src.topology import get_topology

T0 = datetime(2026, 9, 5, 9, 0, 0, tzinfo=timezone.utc)


def make_alert(
    alert_id: str,
    node_id: str,
    alert_type: str,
    *,
    offset_seconds: int = 0,
    interface: str | None = None,
    timestamp: datetime | None = None,
) -> Alert:
    """Build a deterministic alert for tests."""
    return Alert(
        id=alert_id,
        node_id=node_id,
        type=AlertType(alert_type),
        severity=Severity.HIGH,
        interface=interface,
        timestamp=timestamp or (T0 + timedelta(seconds=offset_seconds)),
        message=f"{alert_type} on {node_id}",
    )


# ---------------------------------------------------------------------------
# Individual signals
# ---------------------------------------------------------------------------


class TestSignals(unittest.TestCase):
    def test_same_device_scores_30(self):
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "R1", "CPU_HIGH", offset_seconds=10_000)
        result = score_alert_pair(a, b)
        self.assertEqual(result.signals["same_device"], CORRELATION_WEIGHTS["same_device"])
        self.assertEqual(result.signals["same_device"], 30)

    def test_different_devices_score_zero_for_same_device(self):
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "R3", "CPU_HIGH", offset_seconds=10_000)
        self.assertEqual(score_alert_pair(a, b).signals["same_device"], 0)

    def test_related_topology_devices_score_20(self):
        a = make_alert("A1", "R1", "CONFIG_CHANGE")
        b = make_alert("A2", "S1", "CPU_HIGH", offset_seconds=10_000)
        result = score_alert_pair(a, b)
        self.assertEqual(result.signals["related_device"], 20)
        self.assertEqual(result.signals["same_device"], 0)

    def test_unrelated_topology_devices_score_zero(self):
        # R3 and R6 sit under different distribution switches: not directly linked.
        a = make_alert("A1", "R3", "CONFIG_CHANGE")
        b = make_alert("A2", "R6", "CPU_HIGH", offset_seconds=10_000)
        self.assertEqual(score_alert_pair(a, b).signals["related_device"], 0)

    def test_are_devices_related_uses_topology(self):
        topo = get_topology()
        self.assertTrue(are_devices_related("R1", "S1", topology=topo))
        self.assertTrue(are_devices_related("S1", "R1", topology=topo))
        self.assertFalse(are_devices_related("R1", "R6", topology=topo))
        self.assertFalse(are_devices_related("R1", "R1", topology=topo))
        self.assertFalse(are_devices_related("R1", "NOPE", topology=topo))
        self.assertFalse(are_devices_related("", "R1", topology=topo))

    def test_time_proximity_within_five_minutes(self):
        a = make_alert("A1", "R1", "CONFIG_CHANGE")
        b = make_alert("A2", "R6", "CPU_HIGH", offset_seconds=299)
        self.assertEqual(score_alert_pair(a, b).signals["time_proximity"], 20)

    def test_time_proximity_boundary_is_inclusive(self):
        a = make_alert("A1", "R1", "CONFIG_CHANGE")
        b = make_alert("A2", "R6", "CPU_HIGH", offset_seconds=300)
        self.assertEqual(score_alert_pair(a, b).signals["time_proximity"], 20)

    def test_outside_time_window_scores_zero(self):
        a = make_alert("A1", "R1", "CONFIG_CHANGE")
        b = make_alert("A2", "R6", "CPU_HIGH", offset_seconds=301)
        self.assertEqual(score_alert_pair(a, b).signals["time_proximity"], 0)

    def test_identical_timestamps_are_proximate(self):
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "R1", "PACKET_LOSS")
        self.assertEqual(a.timestamp, b.timestamp)
        self.assertEqual(score_alert_pair(a, b).signals["time_proximity"], 20)

    def test_related_alert_types_score_30(self):
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "R6", "PACKET_LOSS", offset_seconds=10_000)
        self.assertEqual(score_alert_pair(a, b).signals["related_type"], 30)

    def test_unrelated_alert_types_score_zero(self):
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "R6", "CPU_HIGH", offset_seconds=10_000)
        self.assertEqual(score_alert_pair(a, b).signals["related_type"], 0)

    def test_not_every_type_correlates_with_every_type(self):
        self.assertFalse(are_types_related("AUTH_FAILURE", "LINK_DOWN"))
        self.assertFalse(are_types_related("LINK_DOWN", "AUTH_FAILURE"))
        self.assertTrue(are_types_related("AUTH_FAILURE", "AUTH_FAILURE"))
        self.assertNotIn("UNKNOWN", RELATED_ALERT_TYPES)


# ---------------------------------------------------------------------------
# Combined score and threshold behaviour
# ---------------------------------------------------------------------------


class TestPairScoring(unittest.TestCase):
    def test_combined_score_same_device(self):
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "R1", "DEVICE_UNREACHABLE", offset_seconds=30)
        result = score_alert_pair(a, b)
        self.assertEqual(result.score, 80)
        self.assertEqual(
            result.signals,
            {
                "same_device": 30,
                "related_device": 0,
                "time_proximity": 20,
                "related_type": 30,
            },
        )
        self.assertTrue(result.correlated)

    def test_maximum_score_is_capped_at_100(self):
        self.assertEqual(MAX_CORRELATION_SCORE, 100)
        # same_device and related_device are mutually exclusive by construction.
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "S1", "PACKET_LOSS", offset_seconds=30)
        result = score_alert_pair(a, b)
        self.assertEqual(result.score, 70)
        self.assertLessEqual(result.score, MAX_CORRELATION_SCORE)

    def test_threshold_behaviour_at_boundary(self):
        # Related devices + related types + time proximity = 70 >= 60.
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "S1", "HIGH_LATENCY", offset_seconds=60)
        self.assertGreaterEqual(score_alert_pair(a, b).score, CORRELATION_THRESHOLD)
        self.assertTrue(score_alert_pair(a, b).correlated)

    def test_below_threshold_not_correlated(self):
        # Same device + time only = 50 < 60.
        a = make_alert("A1", "R1", "CPU_HIGH")
        b = make_alert("A2", "R1", "MEMORY_HIGH", offset_seconds=30)
        result = score_alert_pair(a, b)
        self.assertEqual(result.score, 50)
        self.assertFalse(result.correlated)

    def test_related_types_far_apart_in_time_not_correlated(self):
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "R1", "PACKET_LOSS", offset_seconds=7200)
        result = score_alert_pair(a, b)
        self.assertEqual(result.signals["time_proximity"], 0)
        self.assertFalse(result.correlated)

    def test_result_exposes_breakdown_and_explanation(self):
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "R1", "DEVICE_UNREACHABLE", offset_seconds=30)
        result = score_alert_pair(a, b)
        payload = result.to_dict()
        self.assertEqual(payload["score"], 80)
        self.assertEqual(set(payload["signals"]), set(CORRELATION_WEIGHTS))
        self.assertIn("Correlation score: 80", result.explanation)
        self.assertIn("Same device: +30", result.explanation)
        self.assertIn("Topology relationship: +0", result.explanation)

    def test_score_all_pairs_is_symmetric(self):
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "S1", "PACKET_LOSS", offset_seconds=30)
        self.assertEqual(score_alert_pair(a, b).score, score_alert_pair(b, a).score)
        self.assertEqual(len(score_all_pairs([a, b])), 1)


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------


class TestGrouping(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(build_candidate_incidents([]), [])

    def test_single_alert_becomes_one_incident(self):
        incidents = build_candidate_incidents([make_alert("A1", "R1", "LINK_DOWN")])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].incident_id, "INC-0001")
        self.assertEqual(incidents[0].alert_ids, ["A1"])
        self.assertEqual(incidents[0].correlation_score, 0)
        self.assertEqual(incidents[0].affected_devices, ["R1"])

    def test_transitive_grouping(self):
        # R1<->S1 correlate, S1<->R3 correlate, R1<->R3 do NOT (not linked).
        a = make_alert("A1", "R1", "LINK_DOWN")
        b = make_alert("A2", "S1", "PACKET_LOSS", offset_seconds=30)
        c = make_alert("A3", "R3", "DEVICE_UNREACHABLE", offset_seconds=60)
        self.assertFalse(score_alert_pair(a, c).correlated)
        self.assertTrue(score_alert_pair(a, b).correlated)
        self.assertTrue(score_alert_pair(b, c).correlated)

        incidents = build_candidate_incidents([a, b, c])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].alert_ids, ["A1", "A2", "A3"])
        self.assertEqual(incidents[0].affected_devices, ["R1", "R3", "S1"])

    def test_multiple_independent_incidents(self):
        group_one = [
            make_alert("A1", "R1", "LINK_DOWN"),
            make_alert("A2", "R1", "DEVICE_UNREACHABLE", offset_seconds=20),
        ]
        group_two = [
            make_alert("B1", "R6", "LINK_DOWN", offset_seconds=100_000),
            make_alert("B2", "R6", "PACKET_LOSS", offset_seconds=100_020),
        ]
        incidents = build_candidate_incidents(group_one + group_two)
        self.assertEqual(len(incidents), 2)
        self.assertEqual(incidents[0].alert_ids, ["A1", "A2"])
        self.assertEqual(incidents[1].alert_ids, ["B1", "B2"])
        self.assertEqual([i.incident_id for i in incidents], ["INC-0001", "INC-0002"])

    def test_unknown_alert_types_stay_separate(self):
        a = make_alert("A1", "R1", "TOTALLY_MADE_UP")
        b = make_alert("A2", "R1", "ALSO_MADE_UP", offset_seconds=30)
        self.assertEqual(a.type, AlertType.UNKNOWN)
        result = score_alert_pair(a, b)
        self.assertEqual(result.signals["related_type"], 0)
        self.assertFalse(result.correlated)
        self.assertEqual(len(build_candidate_incidents([a, b])), 2)

    def test_noise_alert_is_not_absorbed(self):
        cascade = [
            make_alert("A1", "R1", "LINK_DOWN"),
            make_alert("A2", "R1", "DEVICE_UNREACHABLE", offset_seconds=20),
            make_alert("A3", "S1", "PACKET_LOSS", offset_seconds=40),
        ]
        noise = make_alert("N1", "R6", "CONFIG_CHANGE", offset_seconds=45)
        incidents = build_candidate_incidents(cascade + [noise])
        self.assertEqual(len(incidents), 2)
        noise_incident = [i for i in incidents if "N1" in i.alert_ids][0]
        self.assertEqual(noise_incident.alert_ids, ["N1"])

    def test_incident_structure_fields(self):
        alerts = [
            make_alert("A1", "R1", "LINK_DOWN"),
            make_alert("A2", "S1", "PACKET_LOSS", offset_seconds=60),
        ]
        incident = build_candidate_incidents(alerts)[0]
        self.assertEqual(incident.first_seen, T0)
        self.assertEqual(incident.last_seen, T0 + timedelta(seconds=60))
        self.assertEqual(incident.affected_devices, ["R1", "S1"])
        self.assertGreaterEqual(incident.correlation_score, CORRELATION_THRESHOLD)
        self.assertTrue(incident.correlation_reasons)
        payload = incident.to_dict()
        for key in (
            "incident_id",
            "alert_ids",
            "affected_devices",
            "correlation_score",
            "correlation_reasons",
            "first_seen",
            "last_seen",
        ):
            self.assertIn(key, payload)
        self.assertEqual(payload["first_seen"], "2026-09-05T09:00:00Z")

    def test_duplicate_alert_objects_reaching_scorer(self):
        a = make_alert("A1", "R1", "LINK_DOWN")
        incidents = build_candidate_incidents([a, a, a])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].alert_ids, ["A1"])


# ---------------------------------------------------------------------------
# Edge cases / robustness
# ---------------------------------------------------------------------------


class TestEdgeCases(unittest.TestCase):
    def test_naive_timestamps_are_treated_as_utc(self):
        a = make_alert("A1", "R1", "LINK_DOWN", timestamp=datetime(2026, 9, 5, 9, 0, 0))
        b = make_alert("A2", "R1", "PACKET_LOSS", offset_seconds=30)
        self.assertTrue(score_alert_pair(a, b).correlated)

    def test_missing_optional_interface_is_fine(self):
        a = make_alert("A1", "R1", "LINK_DOWN", interface="Te0/1")
        b = make_alert("A2", "R1", "DEVICE_UNREACHABLE", offset_seconds=10)
        self.assertIsNone(b.interface)
        self.assertTrue(score_alert_pair(a, b).correlated)

    def test_malformed_alert_is_reported_not_crashing(self):
        class Broken:
            pass

        views, errors = build_alert_views([make_alert("A1", "R1", "LINK_DOWN"), Broken()])
        self.assertEqual(len(views), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ScorerError)

        incidents, errors = correlate([make_alert("A1", "R1", "LINK_DOWN"), Broken()])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(len(errors), 1)

    def test_unsupported_object_raises_scorer_error(self):
        with self.assertRaises(ScorerError):
            as_alert_view(object())
        # a valid alert still converts cleanly
        view = as_alert_view(make_alert("A1", "R1", "LINK_DOWN"))
        self.assertEqual(view.device_id, "R1")
        self.assertEqual(view.alert_type, "LINK_DOWN")
        self.assertEqual(view.timestamp, T0)

    def test_disconnected_device_not_related(self):
        self.assertFalse(are_devices_related("R3", "R5"))


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism(unittest.TestCase):
    def _alerts(self):
        return [
            make_alert("A1", "R1", "LINK_DOWN"),
            make_alert("A2", "S1", "PACKET_LOSS", offset_seconds=30),
            make_alert("B1", "R6", "CPU_HIGH", offset_seconds=100_000),
        ]

    def test_repeated_runs_are_identical(self):
        first = [i.to_dict() for i in build_candidate_incidents(self._alerts())]
        second = [i.to_dict() for i in build_candidate_incidents(self._alerts())]
        self.assertEqual(first, second)

    def test_input_order_does_not_change_output(self):
        alerts = self._alerts()
        forward = [i.to_dict() for i in build_candidate_incidents(alerts)]
        backward = [i.to_dict() for i in build_candidate_incidents(list(reversed(alerts)))]
        self.assertEqual(forward, backward)

    def test_incident_ids_are_sequential_and_padded(self):
        incidents = build_candidate_incidents(self._alerts())
        self.assertEqual(
            [i.incident_id for i in incidents],
            [f"INC-{n:04d}" for n in range(1, len(incidents) + 1)],
        )


# ---------------------------------------------------------------------------
# Sample scenarios
# ---------------------------------------------------------------------------


def processed_scenario(name: str):
    alerts = generate_scenario(name)
    processed, errors = process_alerts(alerts)
    assert not errors, errors
    return processed


class TestScenarios(unittest.TestCase):
    def test_duplicate_alerts_scenario_forms_one_incident(self):
        incidents = build_candidate_incidents(processed_scenario("duplicate_alerts"))
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].affected_devices, ["R1"])
        self.assertGreaterEqual(incidents[0].correlation_score, CORRELATION_THRESHOLD)

    def test_cascade_scenario_forms_a_strong_connected_group(self):
        incidents = build_candidate_incidents(processed_scenario("cascade_failure"))
        largest = max(incidents, key=lambda i: len(i.alert_ids))
        # The cascade must span core -> distribution -> access.
        self.assertTrue({"R1", "S1", "S2"}.issubset(set(largest.affected_devices)))
        self.assertTrue(
            {"R3", "R4", "R5", "R6"}.intersection(set(largest.affected_devices))
        )
        self.assertGreater(len(largest.alert_ids), 10)

    def test_unknown_escalation_stays_mostly_separate(self):
        processed = processed_scenario("unknown_escalation")
        incidents = build_candidate_incidents(processed)
        # Unknown types provide no type evidence, so nothing should collapse
        # into one big incident.
        self.assertGreaterEqual(len(incidents), len(processed) - 1)

    def test_full_fixture_is_deterministic_end_to_end(self):
        alerts = []
        for name in ("duplicate_alerts", "cascade_failure", "unknown_escalation"):
            alerts.extend(generate_scenario(name))
        processed, errors = process_alerts(alerts)
        self.assertEqual(errors, [])
        first = [i.to_dict() for i in build_candidate_incidents(processed)]
        second = [i.to_dict() for i in build_candidate_incidents(processed)]
        self.assertEqual(first, second)
        self.assertGreater(len(first), 1)


if __name__ == "__main__":
    unittest.main()
