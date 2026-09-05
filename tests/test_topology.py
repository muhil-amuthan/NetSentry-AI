"""
Tests for the topology loader and graph queries (Step 3).

These cover structure only — loading, validation and connectivity. No
correlation, scoring or AI behaviour is exercised, because none exists yet.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models import Alert, AlertType, Incident, NetworkLayer, Severity  # noqa: E402
from src.topology import NetworkTopology, TopologyError, get_topology  # noqa: E402


class TestTopologyLoading(unittest.TestCase):
    def setUp(self):
        self.topo = get_topology()

    def test_loads_reference_network(self):
        self.assertEqual(len(self.topo), 9)
        self.assertEqual(len(self.topo.links), 9)
        self.assertIn("R1", self.topo)
        self.assertNotIn("R99", self.topo)

    def test_nodes_have_layout_hints(self):
        for node in self.topo.nodes:
            self.assertIsNotNone(node.x, f"{node.id} missing x")
            self.assertIsNotNone(node.y, f"{node.id} missing y")

    def test_layers_populated(self):
        self.assertEqual(len(self.topo.nodes_by_layer(NetworkLayer.CORE)), 2)
        self.assertEqual(len(self.topo.nodes_by_layer(NetworkLayer.ACCESS)), 4)

    def test_summary(self):
        summary = self.topo.summary()
        self.assertEqual(summary["node_count"], 9)
        self.assertEqual(summary["total_subscribers"], 6220)

    def test_rejects_dangling_link(self):
        with self.assertRaises(TopologyError):
            NetworkTopology.from_dict(
                {"nodes": [{"id": "A", "name": "A"}],
                 "links": [{"id": "L1", "source": "A", "target": "GHOST"}]}
            )

    def test_rejects_duplicate_nodes(self):
        with self.assertRaises(TopologyError):
            NetworkTopology.from_dict(
                {"nodes": [{"id": "A", "name": "A"}, {"id": "A", "name": "A2"}], "links": []}
            )

    def test_require_node_raises(self):
        with self.assertRaises(TopologyError):
            self.topo.require_node("NOPE")


class TestGraphQueries(unittest.TestCase):
    def setUp(self):
        self.topo = get_topology()

    def test_neighbors(self):
        self.assertEqual(self.topo.neighbors("R1"), ["INTERNET", "R2", "S1", "S2"])
        self.assertEqual(self.topo.neighbors("R3"), ["S1"])

    def test_downstream_and_upstream(self):
        self.assertEqual(self.topo.downstream("S2"), ["R5", "R6"])
        self.assertEqual(self.topo.downstream("R6"), [])
        self.assertEqual(self.topo.upstream("R3"), ["S1"])

    def test_shortest_path(self):
        self.assertEqual(self.topo.shortest_path("R3", "R6"), ["R3", "S1", "R1", "S2", "R6"])
        self.assertEqual(self.topo.shortest_path("R1", "R1"), ["R1"])

    def test_impact_of_failure(self):
        self.assertEqual(self.topo.impact_of_failure("S2"), ["R5", "R6"])
        # A leaf access router isolates nobody but itself.
        self.assertEqual(self.topo.impact_of_failure("R6"), [])

    def test_affected_subscribers(self):
        self.assertEqual(self.topo.affected_subscribers(["R5", "R6"]), 2760)
        # Duplicates are only counted once.
        self.assertEqual(self.topo.affected_subscribers(["R5", "R5"]), 1470)

    def test_link_lookup(self):
        link = self.topo.get_link("S2", "R6")
        self.assertIsNotNone(link)
        self.assertEqual(link.other_end("S2"), "R6")
        self.assertIsNone(self.topo.get_link("R3", "R6"))


class TestModels(unittest.TestCase):
    def test_severity_normalization(self):
        self.assertEqual(Severity.normalize("P1"), Severity.CRITICAL)
        self.assertEqual(Severity.normalize("sev2"), Severity.HIGH)
        self.assertEqual(Severity.normalize("warning"), Severity.MEDIUM)
        self.assertEqual(Severity.normalize(4), Severity.LOW)
        self.assertEqual(Severity.normalize("nonsense"), Severity.INFO)

    def test_severity_ordering(self):
        ordered = sorted([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM])
        self.assertEqual(ordered[0], Severity.CRITICAL)

    def test_alert_fingerprint_and_parsing(self):
        alert = Alert(
            id="A1", node_id="R1", interface="Te0/1", type="LINK_DOWN",
            severity="P1", timestamp="2026-09-05T12:41:08Z",
        )
        self.assertEqual(alert.fingerprint, "R1:Te0/1:LINK_DOWN")
        self.assertEqual(alert.severity, Severity.CRITICAL)
        self.assertTrue(alert.is_actionable)
        self.assertIsNotNone(alert.timestamp.tzinfo)

    def test_unknown_alert_type_degrades(self):
        self.assertEqual(Alert(id="A2", node_id="R1", type="NOT_A_TYPE").type, AlertType.UNKNOWN)

    def test_incident_counts_and_empty_analysis(self):
        inc = Incident(id="INC-1", title="t", alert_ids=["a", "b"], node_ids=["R1", "R1", "S1"])
        self.assertEqual(inc.alert_count, 2)
        self.assertEqual(inc.device_count, 2)
        # Analytical fields belong to later steps and must start empty.
        self.assertIsNone(inc.priority_score)
        self.assertIsNone(inc.root_cause)
        self.assertIsNone(inc.runbook_id)


if __name__ == "__main__":
    unittest.main()
