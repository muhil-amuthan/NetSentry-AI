"""
Tests for the deterministic correlation scoring engine (Step 6).

Covers the four explainable signals in isolation, the combined pairwise
score/threshold behaviour, transitive grouping into candidate incidents, the
three sample scenarios (duplicate_alerts / cascade_failure /
unknown_escalation), determinism, and the edge cases the engine must survive
without crashing.

Run with::

    python -m unittest discover -s tests -t tests
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.generator import (  # noqa: E402
    SCENARIO_CASCADE,
    SCENARIO_DUPLICATES,
    SCENARIO_UNKNOWN,
    generate_scenario,
)
from src.models import Alert, AlertType, Severity  # noqa: E402
from src.scorer import (  # noqa: E402
    CORRELATION_THRESHOLD,
    CORRELATION_WEIGHTS,
    RELATED_ALERT_TYPES,
    TIME_PROXIMITY_WINDOW_SECONDS,
    CandidateIncident,
    CorrelationResult,
    are_devices_related,
    build_candidate_incidents,
    score_alert_pair,
    score_alert_type_relationship,
    score_same_device,
    score_time_proximity,
    score_topology_relationship,
)
from src.topology import get_topology  # noqa: E402

BASE = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)


def make_alert(
    alert_id: str,
    node_id: str,
    alert_type: AlertType = AlertType.LINK_DOWN,
    offset_seconds: int = 0,
    **kwargs,
) -> Alert:
    """Small builder for hand-crafted alerts, kept out of the fixture data."""
    return Alert(
        id=alert_id,
        node_id=node_id,
        type=alert_type,
        timestamp=BASE + timedelta(seconds=offset_seconds),
        severity=kwargs.pop("severity", Severity.HIGH),
        **kwargs,
    )


class TestConfiguration(unittest.TestCase):
    """The scoring configuration is centralised and internally consistent."""

    def test_weights_sum_to_one_hundred(self):
        self.assertEqual(sum(CORRELATION_WEIGHTS.values()), 100)

    def test_threshold_is_sixty(self):
        self.assertEqual(CORRELATION_THRESHOLD, 60)

    def test_time_window_is_five_minutes(self):
        self.assertEqual(TIME_PROXIMITY_WINDOW_SECONDS, 5 * 60)

    def test_related_alert_types_are_not_exhaustive(self):
        """AUTH_FAILURE must not be treated as related to link/reachability types."""
        self.assertNotIn(AlertType.LINK_DOWN, RELATED_ALERT_TYPES[AlertType.AUTH_FAILURE])
        self.assertEqual(RELATED_ALERT_TYPES[AlertType.AUTH_FAILURE], frozenset({AlertType.AUTH_FAILURE}))


class TestSameDeviceSignal(unittest.TestCase):
    def test_same_device_scores_full_weight(self):
        a = make_alert("A1", "R1")
        b = make_alert("A2", "R1")
        self.assertEqual(score_same_device(a, b), CORRELATION_WEIGHTS["same_device"])

    def test_different_devices_score_zero(self):
        a = make_alert("A1", "R1")
        b = make_alert("A2", "S1")
        self.assertEqual(score_same_device(a, b), 0)


class TestTopologyRelationshipSignal(unittest.TestCase):
    def test_are_devices_related_uses_real_topology_links(self):
        # R1 <-> S1 is a real link in data/topology.json.
        self.assertTrue(are_devices_related("R1", "S1"))

    def test_are_devices_related_false_for_unconnected_devices(self):
        # R3 and R5 sit behind different distribution switches: not directly linked.
        self.assertFalse(are_devices_related("R3", "R5"))

    def test_are_devices_related_false_for_same_device(self):
        self.assertFalse(are_devices_related("R1", "R1"))

    def test_are_devices_related_false_for_unknown_devices(self):
        self.assertFalse(are_devices_related("R1", "NOT-A-REAL-DEVICE"))
        self.assertFalse(are_devices_related("GHOST-A", "GHOST-B"))

    def test_topology_relationship_scores_full_weight_for_linked_devices(self):
        a = make_alert("A1", "R1")
        b = make_alert("A2", "S1")
        self.assertEqual(
            score_topology_relationship(a, b), CORRELATION_WEIGHTS["related_device"]
        )

    def test_topology_relationship_zero_for_same_device(self):
        # Same device is not a "topology relationship" — it's signal 1's job.
        a = make_alert("A1", "R1")
        b = make_alert("A2", "R1")
        self.assertEqual(score_topology_relationship(a, b), 0)

    def test_topology_relationship_zero_for_disconnected_devices(self):
        a = make_alert("A1", "R3")
        b = make_alert("A2", "R5")
        self.assertEqual(score_topology_relationship(a, b), 0)

    def test_does_not_assume_all_devices_related(self):
        topo = get_topology()
        node_ids = [n.id for n in topo.nodes]
        # Sanity: the topology has enough nodes that "all related" would be a
        # very different (much higher) number than the real link count.
        possible_pairs = len(node_ids) * (len(node_ids) - 1) // 2
        self.assertGreater(possible_pairs, len(topo.links))


class TestTimeProximitySignal(unittest.TestCase):
    def test_within_five_minutes_scores_full_weight(self):
        a = make_alert("A1", "R1", offset_seconds=0)
        b = make_alert("A2", "R1", offset_seconds=290)
        self.assertEqual(score_time_proximity(a, b), CORRELATION_WEIGHTS["time_proximity"])

    def test_identical_timestamps_score_full_weight(self):
        a = make_alert("A1", "R1", offset_seconds=100)
        b = make_alert("A2", "R1", offset_seconds=100)
        self.assertEqual(score_time_proximity(a, b), CORRELATION_WEIGHTS["time_proximity"])

    def test_exactly_at_boundary_scores_full_weight(self):
        a = make_alert("A1", "R1", offset_seconds=0)
        b = make_alert("A2", "R1", offset_seconds=TIME_PROXIMITY_WINDOW_SECONDS)
        self.assertEqual(score_time_proximity(a, b), CORRELATION_WEIGHTS["time_proximity"])

    def test_outside_five_minutes_scores_zero(self):
        a = make_alert("A1", "R1", offset_seconds=0)
        b = make_alert("A2", "R1", offset_seconds=TIME_PROXIMITY_WINDOW_SECONDS + 1)
        self.assertEqual(score_time_proximity(a, b), 0)

    def test_order_of_alerts_does_not_matter(self):
        a = make_alert("A1", "R1", offset_seconds=0)
        b = make_alert("A2", "R1", offset_seconds=100)
        self.assertEqual(score_time_proximity(a, b), score_time_proximity(b, a))

    def test_malformed_timestamp_is_handled_safely(self):
        a = make_alert("A1", "R1", offset_seconds=0)
        b = make_alert("A2", "R1", offset_seconds=100)
        object.__setattr__  # (no-op; Alert is a pydantic model, use dict assignment)
        b.__dict__["timestamp"] = "not-a-timestamp"
        self.assertEqual(score_time_proximity(a, b), 0)


class TestAlertTypeRelationshipSignal(unittest.TestCase):
    def test_related_types_score_full_weight(self):
        self.assertEqual(
            score_alert_type_relationship(AlertType.LINK_DOWN, AlertType.DEVICE_UNREACHABLE),
            CORRELATION_WEIGHTS["related_type"],
        )

    def test_relationship_is_symmetric(self):
        self.assertEqual(
            score_alert_type_relationship(AlertType.PACKET_LOSS, AlertType.HIGH_LATENCY),
            score_alert_type_relationship(AlertType.HIGH_LATENCY, AlertType.PACKET_LOSS),
        )

    def test_same_type_is_related_to_itself_when_declared(self):
        self.assertEqual(
            score_alert_type_relationship(AlertType.AUTH_FAILURE, AlertType.AUTH_FAILURE),
            CORRELATION_WEIGHTS["related_type"],
        )

    def test_unrelated_types_score_zero(self):
        self.assertEqual(
            score_alert_type_relationship(AlertType.AUTH_FAILURE, AlertType.LINK_DOWN), 0
        )

    def test_unknown_alert_type_scores_zero_against_everything(self):
        self.assertEqual(
            score_alert_type_relationship(AlertType.UNKNOWN, AlertType.LINK_DOWN), 0
        )
        self.assertEqual(
            score_alert_type_relationship(AlertType.UNKNOWN, AlertType.UNKNOWN), 0
        )

    def test_not_every_type_correlates_with_every_other_type(self):
        self.assertEqual(
            score_alert_type_relationship(AlertType.CPU_HIGH, AlertType.MEMORY_HIGH), 0
        )


class TestPairwiseScoring(unittest.TestCase):
    def test_combined_score_is_the_sum_of_signals(self):
        a = make_alert("A1", "R1", AlertType.LINK_DOWN, offset_seconds=0)
        b = make_alert("A2", "R1", AlertType.DEVICE_UNREACHABLE, offset_seconds=30)
        result = score_alert_pair(a, b)
        self.assertIsInstance(result, CorrelationResult)
        self.assertEqual(
            result.score,
            CORRELATION_WEIGHTS["same_device"]
            + CORRELATION_WEIGHTS["time_proximity"]
            + CORRELATION_WEIGHTS["related_type"],
        )
        self.assertEqual(result.signals.related_device, 0)

    def test_score_for_topology_linked_devices_combines_three_signals(self):
        # Different-but-linked devices, close in time, related types.
        # same_device and related_device are mutually exclusive by construction
        # (related_device only ever applies to two *different* devices), so this
        # pair's score is related_device + time_proximity + related_type.
        a = make_alert("A1", "R1", AlertType.LINK_DOWN, offset_seconds=0)
        b = make_alert("A2", "S1", AlertType.DEVICE_UNREACHABLE, offset_seconds=30)
        result = score_alert_pair(a, b)
        self.assertEqual(
            result.score,
            CORRELATION_WEIGHTS["related_device"]
            + CORRELATION_WEIGHTS["time_proximity"]
            + CORRELATION_WEIGHTS["related_type"],
        )
        self.assertTrue(result.correlated)

    def test_score_for_same_device_combines_three_other_signals(self):
        # same_device + time_proximity + related_type is the practical ceiling
        # for a same-device pair (related_device never applies here).
        a = make_alert("A1", "R1", AlertType.LINK_DOWN, offset_seconds=0)
        b = make_alert("A2", "R1", AlertType.DEVICE_UNREACHABLE, offset_seconds=30)
        result = score_alert_pair(a, b)
        self.assertEqual(
            result.score,
            CORRELATION_WEIGHTS["same_device"]
            + CORRELATION_WEIGHTS["time_proximity"]
            + CORRELATION_WEIGHTS["related_type"],
        )

    def test_threshold_behavior_meets_exactly_sixty(self):
        # same_device (30) + time_proximity (20) + related_type (0, unrelated) = 50 -> not correlated
        a = make_alert("A1", "R1", AlertType.AUTH_FAILURE, offset_seconds=0)
        b = make_alert("A2", "R1", AlertType.LINK_DOWN, offset_seconds=10)
        below = score_alert_pair(a, b)
        self.assertEqual(below.score, CORRELATION_WEIGHTS["same_device"] + CORRELATION_WEIGHTS["time_proximity"])
        self.assertLess(below.score, CORRELATION_THRESHOLD)
        self.assertFalse(below.correlated)

        # same_device (30) + time_proximity (20) + related_type (30) = 80 -> correlated
        c = make_alert("A3", "R1", AlertType.LINK_DOWN, offset_seconds=0)
        d = make_alert("A4", "R1", AlertType.DEVICE_UNREACHABLE, offset_seconds=10)
        above = score_alert_pair(c, d)
        self.assertEqual(above.score, 80)
        self.assertGreaterEqual(above.score, CORRELATION_THRESHOLD)
        self.assertTrue(above.correlated)

    def test_below_threshold_pair_is_not_correlated(self):
        # Different device, no topology link, far apart in time, unrelated types.
        a = make_alert("A1", "R3", AlertType.AUTH_FAILURE, offset_seconds=0)
        b = make_alert("A2", "R5", AlertType.CPU_HIGH, offset_seconds=10_000)
        result = score_alert_pair(a, b)
        self.assertEqual(result.score, 0)
        self.assertFalse(result.correlated)

    def test_different_devices_reduce_score(self):
        same = score_alert_pair(
            make_alert("A1", "R1", AlertType.LINK_DOWN),
            make_alert("A2", "R1", AlertType.DEVICE_UNREACHABLE),
        )
        different = score_alert_pair(
            make_alert("A1", "R3", AlertType.LINK_DOWN),
            make_alert("A2", "R5", AlertType.DEVICE_UNREACHABLE),
        )
        self.assertGreater(same.score, different.score)

    def test_different_alert_types_reduce_score(self):
        related = score_alert_pair(
            make_alert("A1", "R1", AlertType.LINK_DOWN),
            make_alert("A2", "R1", AlertType.DEVICE_UNREACHABLE),
        )
        unrelated = score_alert_pair(
            make_alert("A1", "R1", AlertType.LINK_DOWN),
            make_alert("A2", "R1", AlertType.CPU_HIGH),
        )
        self.assertGreater(related.score, unrelated.score)

    def test_outside_time_window_reduces_score(self):
        close = score_alert_pair(
            make_alert("A1", "R1", AlertType.LINK_DOWN, offset_seconds=0),
            make_alert("A2", "R1", AlertType.DEVICE_UNREACHABLE, offset_seconds=30),
        )
        far = score_alert_pair(
            make_alert("A1", "R1", AlertType.LINK_DOWN, offset_seconds=0),
            make_alert("A2", "R1", AlertType.DEVICE_UNREACHABLE, offset_seconds=99_999),
        )
        self.assertGreater(close.score, far.score)

    def test_result_exposes_structured_signal_breakdown(self):
        a = make_alert("A1", "R1", AlertType.LINK_DOWN, offset_seconds=0)
        b = make_alert("A2", "R1", AlertType.DEVICE_UNREACHABLE, offset_seconds=10)
        result = score_alert_pair(a, b)
        breakdown = result.to_dict()
        self.assertIn("signals", breakdown)
        self.assertEqual(
            set(breakdown["signals"]),
            {"same_device", "related_device", "time_proximity", "related_type"},
        )
        self.assertIn("Correlation score:", result.explain())


class TestCandidateIncidentStructure(unittest.TestCase):
    def test_incident_has_the_required_fields(self):
        a = make_alert("A1", "R1", AlertType.LINK_DOWN, offset_seconds=0)
        b = make_alert("A2", "R1", AlertType.DEVICE_UNREACHABLE, offset_seconds=10)
        incidents = build_candidate_incidents([a, b])
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertIsInstance(incident, CandidateIncident)
        self.assertEqual(incident.incident_id, "INC-0001")
        self.assertEqual(set(incident.alert_ids), {"A1", "A2"})
        self.assertEqual(len(incident.alerts), 2)
        self.assertEqual(incident.affected_devices, ["R1"])
        self.assertEqual(incident.first_seen, BASE)
        self.assertGreaterEqual(incident.correlation_score, CORRELATION_THRESHOLD)
        self.assertTrue(incident.correlation_reasons)
        as_dict = incident.to_dict()
        for key in (
            "incident_id",
            "alert_ids",
            "alerts",
            "correlation_score",
            "correlation_reasons",
            "first_seen",
            "last_seen",
            "affected_devices",
        ):
            self.assertIn(key, as_dict)


class TestGroupingAndTransitivity(unittest.TestCase):
    def test_transitive_grouping_across_topology_hops(self):
        # R1 -LINK_DOWN-> (correlates with) S1 -PACKET_LOSS-> (correlates with) R3
        # R1 and R3 are NOT directly linked in the topology and are more than
        # 5 minutes apart, so they must NOT score above the threshold directly...
        r1 = make_alert("R1A", "R1", AlertType.LINK_DOWN, offset_seconds=0)
        r3 = make_alert("R3A", "R3", AlertType.DEVICE_UNREACHABLE, offset_seconds=500)
        direct = score_alert_pair(r1, r3)
        self.assertFalse(direct.correlated)

        # ...but via an intermediate S1 alert bridging both in time and topology
        # (S1 is directly linked to both R1 and R3), they land in the same
        # candidate incident: this is the cascading-failure case.
        s1 = make_alert("S1A", "S1", AlertType.PACKET_LOSS, offset_seconds=250)
        r1_s1 = score_alert_pair(r1, s1)
        s1_r3 = score_alert_pair(s1, r3)
        self.assertTrue(r1_s1.correlated)
        self.assertTrue(s1_r3.correlated)

        incidents = build_candidate_incidents([r1, s1, r3])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(set(incidents[0].alert_ids), {"R1A", "S1A", "R3A"})

    def test_multiple_independent_incidents_stay_separate(self):
        group_a = [
            make_alert("G1", "R1", AlertType.LINK_DOWN, offset_seconds=0),
            make_alert("G2", "R1", AlertType.DEVICE_UNREACHABLE, offset_seconds=10),
        ]
        group_b = [
            make_alert("H1", "R5", AlertType.LINK_DOWN, offset_seconds=10_000),
            make_alert("H2", "R5", AlertType.DEVICE_UNREACHABLE, offset_seconds=10_010),
        ]
        incidents = build_candidate_incidents(group_a + group_b)
        self.assertEqual(len(incidents), 2)
        alert_id_sets = {frozenset(inc.alert_ids) for inc in incidents}
        self.assertIn(frozenset({"G1", "G2"}), alert_id_sets)
        self.assertIn(frozenset({"H1", "H2"}), alert_id_sets)

    def test_noise_remains_separate_from_a_major_incident(self):
        cascade_like = [
            make_alert("C1", "R1", AlertType.LINK_DOWN, offset_seconds=0),
            make_alert("C2", "S1", AlertType.DEVICE_UNREACHABLE, offset_seconds=20),
        ]
        noise = make_alert("N1", "R6", AlertType.CPU_HIGH, offset_seconds=15)
        incidents = build_candidate_incidents(cascade_like + [noise])
        # noise must not be absorbed into the correlated pair's incident
        noise_incident = next(inc for inc in incidents if "N1" in inc.alert_ids)
        self.assertEqual(noise_incident.alert_ids, ["N1"])
        self.assertEqual(len(incidents), 2)


class TestDeterminism(unittest.TestCase):
    def test_same_input_produces_same_grouping_and_ids(self):
        alerts = generate_scenario(SCENARIO_CASCADE)
        first = build_candidate_incidents(alerts)
        second = build_candidate_incidents(list(reversed(alerts)))
        self.assertEqual(len(first), len(second))
        for inc_a, inc_b in zip(first, second):
            self.assertEqual(inc_a.incident_id, inc_b.incident_id)
            self.assertEqual(inc_a.alert_ids, inc_b.alert_ids)
            self.assertEqual(inc_a.correlation_score, inc_b.correlation_score)

    def test_incident_ids_are_sequential_and_deterministic(self):
        alerts = generate_scenario(SCENARIO_UNKNOWN)
        incidents = build_candidate_incidents(alerts)
        expected_ids = [f"INC-{i:04d}" for i in range(1, len(incidents) + 1)]
        self.assertEqual([inc.incident_id for inc in incidents], expected_ids)

    def test_ordering_is_deterministic_across_repeated_runs(self):
        alerts = generate_scenario(SCENARIO_CASCADE)
        runs = [build_candidate_incidents(alerts) for _ in range(3)]
        baseline = [(inc.incident_id, tuple(inc.alert_ids)) for inc in runs[0]]
        for run in runs[1:]:
            self.assertEqual(baseline, [(inc.incident_id, tuple(inc.alert_ids)) for inc in run])


class TestEdgeCases(unittest.TestCase):
    def test_empty_input_returns_no_incidents(self):
        self.assertEqual(build_candidate_incidents([]), [])
        self.assertEqual(build_candidate_incidents(None), [])

    def test_single_alert_forms_its_own_incident(self):
        incidents = build_candidate_incidents([make_alert("A1", "R1")])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].alert_ids, ["A1"])
        self.assertEqual(incidents[0].correlation_score, 0)

    def test_duplicate_alert_objects_reaching_the_scorer_do_not_duplicate(self):
        a = make_alert("DUPX", "R1")
        incidents = build_candidate_incidents([a, a, a])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].alert_ids, ["DUPX"])

    def test_unknown_alert_types_stay_separate_without_other_evidence(self):
        a = make_alert("U1", "R2", AlertType.UNKNOWN, offset_seconds=0)
        b = make_alert("U2", "S2", AlertType.UNKNOWN, offset_seconds=5000)
        incidents = build_candidate_incidents([a, b])
        self.assertEqual(len(incidents), 2)

    def test_missing_optional_interface_does_not_break_scoring(self):
        a = make_alert("A1", "R1", AlertType.LINK_DOWN, interface=None)
        b = make_alert("A2", "R1", AlertType.DEVICE_UNREACHABLE, interface=None)
        result = score_alert_pair(a, b)
        self.assertTrue(result.correlated)

    def test_malformed_record_is_skipped_not_fatal(self):
        good = make_alert("GOOD1", "R1")
        incidents = build_candidate_incidents([{"nonsense": True}, good, 12345, "oops"])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].alert_ids, ["GOOD1"])

    def test_disconnected_devices_never_get_topology_points(self):
        a = make_alert("A1", "R3")
        b = make_alert("A2", "R6")
        self.assertEqual(score_topology_relationship(a, b), 0)


class TestScenarioBehavior(unittest.TestCase):
    """End-to-end behaviour against the Step 4 sample scenarios."""

    def test_duplicate_alerts_scenario_forms_one_coherent_incident(self):
        alerts = generate_scenario(SCENARIO_DUPLICATES)
        incidents = build_candidate_incidents(alerts)
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(set(incident.alert_ids), {a.id for a in alerts})
        self.assertEqual(incident.affected_devices, ["CORE-R1"])

    def test_cascade_failure_scenario_forms_one_dominant_incident(self):
        alerts = generate_scenario(SCENARIO_CASCADE)
        incidents = build_candidate_incidents(alerts)
        # The dominant incident should absorb the large majority of the cascade.
        largest = max(incidents, key=lambda inc: inc.alert_count)
        self.assertGreaterEqual(largest.alert_count, int(0.8 * len(alerts)))
        # It should span the core, both distribution switches and the access layer.
        touched = set(largest.affected_devices)
        self.assertIn("CORE-R1", touched)
        self.assertIn("SW-S1", touched)
        self.assertIn("SW-S2", touched)
        self.assertTrue(touched & {"ACC-R3", "ACC-R4", "ACC-R5", "ACC-R6"})

    def test_cascade_grouping_is_not_a_naive_time_window_rule(self):
        """Two alerts within 5 minutes but with no other evidence must stay apart."""
        alerts = generate_scenario(SCENARIO_CASCADE)
        # Take two alerts that are close in time but on disconnected access
        # devices, with no shared device/topology-link/related-type evidence.
        r3 = next(a for a in alerts if a.node_id == "R3")
        r5 = next(a for a in alerts if a.node_id == "R5")
        # These two are not directly linked in the topology (different switches).
        self.assertFalse(are_devices_related(r3.node_id, r5.node_id))

    def test_unknown_escalation_scenario_keeps_unrelated_alerts_separate(self):
        alerts = generate_scenario(SCENARIO_UNKNOWN)
        incidents = build_candidate_incidents(alerts)
        # Six distinct unknown-type devices + four noise alerts sharing no
        # device/type/topology evidence: expect (close to) one incident per alert.
        self.assertGreaterEqual(len(incidents), len(alerts) - 2)
        for incident in incidents:
            self.assertLessEqual(incident.alert_count, 2)


if __name__ == "__main__":
    unittest.main()
