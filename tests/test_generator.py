"""
Tests for the deterministic alert generator and sample data (Step 4).

These cover the *fixture* only: the JSON snapshot loads, every alert is complete
and validly typed, and the three scenarios have the shape the later
deduplication / correlation / escalation steps will need. No triage behaviour is
asserted, because none exists yet.

Run with::

    python -m unittest discover -s tests -t tests
"""

import json
import sys
import unittest
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import SAMPLE_ALERTS_FILE  # noqa: E402
from src.generator import (  # noqa: E402
    BASE_TIMESTAMP,
    DEVICES,
    ROLE_CASCADE,
    ROLE_DUPLICATE,
    ROLE_NOISE,
    ROLE_UNCOVERED,
    SCENARIOS,
    SCENARIO_CASCADE,
    SCENARIO_DUPLICATES,
    SCENARIO_UNKNOWN,
    SUPPORTED_ALERT_TYPES,
    GeneratorError,
    alert_to_record,
    build_sample_document,
    generate_all_records,
    generate_all_scenarios,
    generate_scenario,
    generate_scenario_records,
    get_all_sample_alerts,
    list_scenarios,
    load_sample_alerts,
    load_sample_records,
    normalize_scenario_name,
    record_to_alert,
    require_device,
    scenario_devices,
    scenario_summary,
)
from src.models import Alert, AlertStatus, AlertType, NodeType, Severity  # noqa: E402
from src.topology import get_topology  # noqa: E402


#: Fields every feed-format record must carry (Step 4 alert contract).
REQUIRED_RECORD_FIELDS = (
    "alert_id",
    "timestamp",
    "device_id",
    "device_name",
    "device_type",
    "alert_type",
    "severity",
    "message",
    "source",
    "status",
)

SUPPORTED_TYPE_VALUES = {t.value for t in SUPPORTED_ALERT_TYPES}


def _by_scenario(alerts):
    """Group alerts by their ``scenario`` label."""
    grouped = {}
    for alert in alerts:
        grouped.setdefault(alert.labels.get("scenario"), []).append(alert)
    return grouped


class TestSampleAlertsFile(unittest.TestCase):
    """1. The JSON snapshot exists, parses and has the documented shape."""

    @classmethod
    def setUpClass(cls):
        cls.path = Path(SAMPLE_ALERTS_FILE)
        cls.document = json.loads(cls.path.read_text(encoding="utf-8"))
        cls.records = load_sample_records()

    def test_file_exists_and_is_valid_json(self):
        self.assertTrue(self.path.exists(), f"missing sample data file: {self.path}")
        self.assertIsInstance(self.document, dict)

    def test_document_shape(self):
        self.assertTrue(self.document["deterministic"])
        self.assertEqual(self.document["base_timestamp"], "2026-09-05T09:00:00Z")
        self.assertEqual(
            [s["name"] for s in self.document["scenarios"]], list(SCENARIOS)
        )

    def test_all_three_scenarios_present_with_alerts(self):
        counts = {s["name"]: len(s["alerts"]) for s in self.document["scenarios"]}
        self.assertEqual(counts[SCENARIO_DUPLICATES], 10)
        self.assertEqual(counts[SCENARIO_CASCADE], 26)
        self.assertEqual(counts[SCENARIO_UNKNOWN], 10)
        for scenario in self.document["scenarios"]:
            self.assertEqual(scenario["alert_count"], len(scenario["alerts"]))

    def test_records_have_required_fields(self):
        self.assertTrue(self.records)
        for record in self.records:
            for field_name in REQUIRED_RECORD_FIELDS:
                self.assertIn(field_name, record, f"{record.get('alert_id')} lacks {field_name}")
                self.assertNotIn(
                    record[field_name], (None, ""), f"{record['alert_id']}: empty {field_name}"
                )

    def test_snapshot_matches_generator(self):
        """The committed JSON must be exactly what the code generates (no drift)."""
        self.assertEqual(self.document, build_sample_document())

    def test_no_flat_list_shape_regression(self):
        """Sanity: the old empty-list placeholder has been replaced."""
        self.assertNotIsInstance(self.document, list)
        self.assertGreaterEqual(len(self.records), 40)


class TestAlertModelConversion(unittest.TestCase):
    """2. Records convert into the existing Alert model, fully populated."""

    @classmethod
    def setUpClass(cls):
        cls.alerts = load_sample_alerts()

    def test_returns_alert_models(self):
        self.assertTrue(all(isinstance(a, Alert) for a in self.alerts))
        self.assertEqual(len(self.alerts), len(load_sample_records()))

    def test_required_model_fields_populated(self):
        for alert in self.alerts:
            self.assertTrue(alert.id)
            self.assertTrue(alert.node_id)
            self.assertTrue(alert.message, f"{alert.id} has no message")
            self.assertTrue(alert.source)
            self.assertTrue(alert.device_name, f"{alert.id} has no device_name")
            self.assertIsInstance(alert.timestamp, datetime)
            self.assertIsNotNone(alert.timestamp.tzinfo)
            self.assertIsInstance(alert.type, AlertType)
            self.assertIsInstance(alert.severity, Severity)
            self.assertIsInstance(alert.status, AlertStatus)
            self.assertIsInstance(alert.device_type, NodeType)

    def test_alert_ids_unique(self):
        ids = [a.id for a in self.alerts]
        self.assertEqual(len(ids), len(set(ids)))

    def test_device_context_matches_catalogue(self):
        for alert in self.alerts:
            device = DEVICES[alert.node_id]
            self.assertEqual(alert.device_name, device.device_name)
            self.assertEqual(alert.device_type, device.device_type)
            self.assertEqual(alert.labels.get("site"), device.site)

    def test_fingerprints_available_for_later_dedup(self):
        for alert in self.alerts:
            self.assertEqual(
                alert.fingerprint,
                f"{alert.node_id}:{alert.interface or '-'}:{alert.type.value}",
            )

    def test_no_alert_is_pregrouped(self):
        """Correlation happens in a later step: nothing may arrive pre-grouped."""
        self.assertTrue(all(a.incident_id is None for a in self.alerts))

    def test_get_all_sample_alerts_is_cached_and_equal(self):
        first = get_all_sample_alerts()
        second = get_all_sample_alerts()
        self.assertEqual([a.model_dump(mode="json") for a in first],
                         [a.model_dump(mode="json") for a in second])
        self.assertIsNot(first, second)  # a fresh list each call
        self.assertEqual(len(first), len(self.alerts))


class TestAlertTypes(unittest.TestCase):
    """3. Alert types are valid, and the scenarios use the intended vocabulary."""

    @classmethod
    def setUpClass(cls):
        cls.alerts = load_sample_alerts()
        cls.grouped = _by_scenario(cls.alerts)

    def test_all_types_are_known_enum_members(self):
        for alert in self.alerts:
            self.assertIsInstance(alert.type, AlertType)
            self.assertIn(alert.type, set(AlertType))

    def test_duplicate_and_cascade_use_supported_types(self):
        for scenario in (SCENARIO_DUPLICATES, SCENARIO_CASCADE):
            used = {a.type for a in self.grouped[scenario]}
            self.assertTrue(used.issubset(set(SUPPORTED_ALERT_TYPES)), f"{scenario}: {used}")

    def test_supported_types_are_the_five_from_the_brief(self):
        self.assertEqual(
            SUPPORTED_TYPE_VALUES,
            {"LINK_DOWN", "DEVICE_UNREACHABLE", "HIGH_LATENCY", "PACKET_LOSS", "AUTH_FAILURE"},
        )

    def test_cascade_uses_every_supported_type(self):
        used = {a.type.value for a in self.grouped[SCENARIO_CASCADE]}
        self.assertEqual(used, SUPPORTED_TYPE_VALUES)

    def test_realistic_messages(self):
        expectations = {
            "LINK_DOWN": "is down",
            "DEVICE_UNREACHABLE": "No response received from device",
            "HIGH_LATENCY": "Average latency exceeded threshold",
            "PACKET_LOSS": "Packet loss exceeded 20%",
            "AUTH_FAILURE": "Repeated authentication failures detected",
        }
        seen = set()
        for alert in self.alerts:
            fragment = expectations.get(alert.type.value)
            if fragment:
                self.assertIn(fragment, alert.message, f"{alert.id}: {alert.message}")
                seen.add(alert.type.value)
        self.assertEqual(seen, set(expectations))


class TestScenario1Duplicates(unittest.TestCase):
    """4. Scenario 1 repeats the same events on one device (dedup fixture)."""

    @classmethod
    def setUpClass(cls):
        cls.alerts = generate_scenario(SCENARIO_DUPLICATES)

    def test_about_ten_alerts_on_one_device(self):
        self.assertEqual(len(self.alerts), 10)
        self.assertEqual({a.node_id for a in self.alerts}, {"R1"})
        self.assertEqual({a.device_name for a in self.alerts}, {"CORE-R1"})

    def test_contains_repeated_alert_types(self):
        counts = Counter(a.type for a in self.alerts)
        self.assertEqual(counts[AlertType.LINK_DOWN], 4)
        self.assertEqual(counts[AlertType.DEVICE_UNREACHABLE], 4)
        self.assertEqual(counts[AlertType.PACKET_LOSS], 2)

    def test_duplicates_share_fingerprints(self):
        fingerprints = Counter(a.fingerprint for a in self.alerts)
        self.assertLess(len(fingerprints), len(self.alerts), "no duplicates to collapse")
        self.assertEqual(len(fingerprints), 3)
        self.assertEqual(fingerprints.most_common(1)[0][1], 4)

    def test_duplicates_arrive_from_different_sources(self):
        """Realistic: the same event is reported by several collectors."""
        self.assertGreaterEqual(len({a.source for a in self.alerts}), 4)

    def test_duplicate_window_is_short(self):
        span = (max(a.timestamp for a in self.alerts) - min(a.timestamp for a in self.alerts))
        self.assertLessEqual(span.total_seconds(), 120)

    def test_fixture_role_annotation(self):
        self.assertEqual({a.labels.get("fixture_role") for a in self.alerts}, {ROLE_DUPLICATE})


class TestScenario2Cascade(unittest.TestCase):
    """5. Scenario 2 is one incident cascading across devices and layers."""

    @classmethod
    def setUpClass(cls):
        cls.alerts = generate_scenario(SCENARIO_CASCADE)
        cls.topo = get_topology()

    def test_about_twenty_five_alerts(self):
        self.assertEqual(len(self.alerts), 26)

    def test_multiple_devices_across_layers(self):
        devices = {a.node_id for a in self.alerts}
        self.assertGreaterEqual(len(devices), 5)
        self.assertIn("R1", devices)          # core
        self.assertIn("S1", devices)          # distribution
        self.assertIn("S2", devices)
        self.assertTrue({"R3", "R4", "R5", "R6"} & devices)  # access
        layers = {self.topo.require_node(d).layer.value for d in devices}
        self.assertEqual(layers, {"core", "distribution", "access"})

    def test_devices_exist_in_topology(self):
        for alert in self.alerts:
            self.assertIn(alert.node_id, self.topo)

    def test_timestamps_are_ordered_and_dense(self):
        stamps = [a.timestamp for a in self.alerts]
        self.assertEqual(stamps, sorted(stamps))
        span = (max(stamps) - min(stamps)).total_seconds()
        self.assertLessEqual(span, 300, "cascade should stay inside a correlation window")
        gaps = [(b - a).total_seconds() for a, b in zip(stamps, stamps[1:])]
        self.assertLessEqual(max(gaps), 60, "a gap this wide would split the incident")
        self.assertTrue(all(gap > 0 for gap in gaps))

    def test_failure_travels_core_then_distribution_then_access(self):
        first_seen = {}
        for alert in self.alerts:
            layer = self.topo.require_node(alert.node_id).layer.value
            first_seen.setdefault(layer, alert.timestamp)
        self.assertLess(first_seen["core"], first_seen["distribution"])
        self.assertLess(first_seen["distribution"], first_seen["access"])

    def test_core_failure_is_the_earliest_alert(self):
        self.assertEqual(self.alerts[0].node_id, "R1")
        self.assertEqual(self.alerts[0].type, AlertType.HIGH_LATENCY)  # degradation first

    def test_ends_with_devices_unreachable(self):
        self.assertIn(AlertType.DEVICE_UNREACHABLE, {a.type for a in self.alerts[-6:]})

    def test_messages_name_the_upstream_device(self):
        """The cascade is recoverable from message text plus topology."""
        mentions = [a for a in self.alerts if "CORE-R1" in a.message and a.node_id != "R1"]
        self.assertTrue(mentions)

    def test_fixture_role_annotation(self):
        self.assertEqual({a.labels.get("fixture_role") for a in self.alerts}, {ROLE_CASCADE})


class TestScenario3UnknownAndNoise(unittest.TestCase):
    """6. Scenario 3 has no runbook match, plus unrelated noise."""

    @classmethod
    def setUpClass(cls):
        cls.alerts = generate_scenario(SCENARIO_UNKNOWN)
        cls.uncovered = [a for a in cls.alerts if a.labels.get("fixture_role") == ROLE_UNCOVERED]
        cls.noise = [a for a in cls.alerts if a.labels.get("fixture_role") == ROLE_NOISE]

    def test_uncovered_alerts_degrade_to_unknown_type(self):
        self.assertGreaterEqual(len(self.uncovered), 5)
        for alert in self.uncovered:
            self.assertEqual(alert.type, AlertType.UNKNOWN)

    def test_raw_feed_type_is_preserved(self):
        for alert in self.uncovered:
            raw = alert.labels.get("raw_type")
            self.assertTrue(raw, f"{alert.id} lost its raw type")
            self.assertNotIn(raw, SUPPORTED_TYPE_VALUES)
            self.assertNotIn(raw, {t.value for t in AlertType})

    def test_expected_anomalies_are_present(self):
        raw_types = {a.labels.get("raw_type") for a in self.uncovered}
        self.assertIn("OPTICAL_SYNC_ANOMALY", raw_types)       # optical synchronization anomaly
        self.assertIn("PROTOCOL_STATE_ANOMALY", raw_types)     # unexpected protocol behaviour
        self.assertIn("ANOMALOUS_TRAFFIC_CONDITION", raw_types)  # abnormal network condition

    def test_no_runbook_is_invented_here(self):
        """Step 4 must not pre-answer coverage: alerts stay ungrouped/unresolved."""
        for alert in self.uncovered:
            self.assertIsNone(alert.incident_id)
            self.assertEqual(alert.status, AlertStatus.NEW)

    def test_unrelated_noise_uses_known_types(self):
        self.assertGreaterEqual(len(self.noise), 3)
        for alert in self.noise:
            self.assertNotEqual(alert.type, AlertType.UNKNOWN)
        self.assertIn(AlertType.AUTH_FAILURE, {a.type for a in self.noise})

    def test_noise_is_separate_from_uncovered(self):
        self.assertEqual(len(self.uncovered) + len(self.noise), len(self.alerts))
        self.assertFalse({a.id for a in self.uncovered} & {a.id for a in self.noise})


class TestDeterminism(unittest.TestCase):
    """The fixture never varies between runs, processes or machines."""

    def test_two_generations_are_identical(self):
        first = generate_all_scenarios()
        second = generate_all_scenarios()
        self.assertEqual(
            [a.model_dump(mode="json") for a in first],
            [a.model_dump(mode="json") for a in second],
        )

    def test_records_are_identical(self):
        self.assertEqual(generate_all_records(), generate_all_records())

    def test_fixed_base_timestamp(self):
        self.assertEqual(BASE_TIMESTAMP, datetime(2026, 9, 5, 9, 0, 0, tzinfo=timezone.utc))

    def test_timestamps_do_not_drift_with_wall_clock(self):
        alerts = load_sample_alerts()
        self.assertEqual(alerts[0].timestamp, BASE_TIMESTAMP)
        self.assertTrue(all(a.timestamp.year == 2026 for a in alerts))

    def test_json_snapshot_equals_generated_alerts(self):
        loaded = [a.model_dump(mode="json") for a in load_sample_alerts()]
        generated = [a.model_dump(mode="json") for a in generate_all_scenarios()]
        self.assertEqual(loaded, generated)

    def test_rebase_keeps_order_and_spacing(self):
        original = load_sample_alerts()
        rebased = load_sample_alerts(rebase_to_now=True)
        self.assertEqual([a.id for a in original], [a.id for a in rebased])
        gaps_before = [b.timestamp - a.timestamp for a, b in zip(original, original[1:])]
        gaps_after = [b.timestamp - a.timestamp for a, b in zip(rebased, rebased[1:])]
        self.assertEqual(gaps_before, gaps_after)
        self.assertLessEqual(
            abs((datetime.now(timezone.utc) - rebased[0].timestamp).total_seconds()), 60
        )


class TestGeneratorApi(unittest.TestCase):
    """The public API behaves, and bad input fails loudly instead of silently."""

    def test_list_scenarios(self):
        self.assertEqual(
            list_scenarios(), [SCENARIO_DUPLICATES, SCENARIO_CASCADE, SCENARIO_UNKNOWN]
        )

    def test_scenario_aliases(self):
        self.assertEqual(normalize_scenario_name("Scenario 2"), SCENARIO_CASCADE)
        self.assertEqual(normalize_scenario_name("cascade"), SCENARIO_CASCADE)
        self.assertEqual(normalize_scenario_name("cascading-failure"), SCENARIO_CASCADE)
        self.assertEqual(normalize_scenario_name("3"), SCENARIO_UNKNOWN)
        self.assertEqual(normalize_scenario_name("duplicates"), SCENARIO_DUPLICATES)

    def test_unknown_scenario_raises(self):
        with self.assertRaises(GeneratorError):
            generate_scenario("not_a_scenario")
        with self.assertRaises(GeneratorError):
            normalize_scenario_name("")

    def test_generate_scenario_matches_records(self):
        for name in SCENARIOS:
            alerts = generate_scenario(name)
            records = generate_scenario_records(name)
            self.assertEqual(len(alerts), len(records))
            self.assertEqual([a.id for a in alerts], [r["alert_id"] for r in records])

    def test_scenario_devices(self):
        self.assertEqual(scenario_devices(SCENARIO_DUPLICATES), ["R1"])
        self.assertEqual(scenario_devices(SCENARIO_CASCADE)[0], "R1")
        self.assertEqual(len(scenario_devices(SCENARIO_CASCADE)), 7)

    def test_unknown_device_raises(self):
        with self.assertRaises(GeneratorError):
            require_device("R99")

    def test_scenario_summary(self):
        rows = {row["name"]: row for row in scenario_summary()}
        self.assertEqual(set(rows), set(SCENARIOS))
        self.assertEqual(rows[SCENARIO_DUPLICATES]["alert_count"], 10)
        self.assertEqual(rows[SCENARIO_DUPLICATES]["distinct_fingerprints"], 3)
        self.assertEqual(rows[SCENARIO_CASCADE]["device_count"], 7)
        self.assertEqual(rows[SCENARIO_UNKNOWN]["alert_types"]["UNKNOWN"], 6)

    def test_record_to_alert_accepts_vendor_spellings(self):
        alert = record_to_alert(
            {
                "id": "X-1",
                "node_id": "S2",
                "type": "PACKET_LOSS",
                "level": "P2",
                "time": "2026-09-05T10:00:00Z",
                "hostname": "SW-S2",
                "port": "ge-0/0/23",
                "state": "ack",
                "measurements": {"loss_pct": "12.5", "bogus": "n/a"},
            }
        )
        self.assertEqual(alert.id, "X-1")
        self.assertEqual(alert.node_id, "S2")
        self.assertEqual(alert.device_name, "SW-S2")
        self.assertEqual(alert.type, AlertType.PACKET_LOSS)
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertEqual(alert.interface, "ge-0/0/23")
        self.assertEqual(alert.status, AlertStatus.ACKNOWLEDGED)
        self.assertEqual(alert.metrics, {"loss_pct": 12.5})
        self.assertIsNone(alert.device_type)  # not supplied by this feed

    def test_record_to_alert_rejects_incomplete_records(self):
        with self.assertRaises(GeneratorError):
            record_to_alert({"timestamp": "2026-09-05T10:00:00Z", "device_id": "R1"})
        with self.assertRaises(GeneratorError):
            record_to_alert({"alert_id": "A-1", "device_id": "R1"})
        with self.assertRaises(GeneratorError):
            record_to_alert({"alert_id": "A-1", "device_id": "R1", "timestamp": "not-a-time"})
        with self.assertRaises(GeneratorError):
            record_to_alert(["not", "a", "record"])

    def test_alert_to_record_round_trip(self):
        for record in load_sample_records():
            self.assertEqual(alert_to_record(record_to_alert(record)), record)

    def test_load_from_missing_file_falls_back_to_generator(self):
        alerts = load_sample_alerts(Path("data/does-not-exist.json"))
        self.assertEqual(len(alerts), len(generate_all_scenarios()))

    def test_load_from_malformed_file_raises(self):
        broken = Path("data") / "_broken_sample_alerts.json"
        broken.write_text("{not json", encoding="utf-8")
        try:
            with self.assertRaises(GeneratorError):
                load_sample_alerts(broken)
        finally:
            broken.unlink(missing_ok=True)

    def test_device_catalogue_matches_topology(self):
        topo = get_topology()
        for device_id, spec in DEVICES.items():
            node = topo.require_node(device_id)
            self.assertEqual(spec.device_name, node.name)
            self.assertEqual(spec.device_type, node.type)
            self.assertEqual(spec.site, node.site)
            self.assertEqual(spec.layer, node.layer.value)


class TestStep4ScopeBoundaries(unittest.TestCase):
    """Guard rails: Step 4 ships data, not triage logic."""

    def test_generator_does_not_import_engine_modules(self):
        source = Path("src/generator.py").read_text(encoding="utf-8")
        for forbidden in ("src.scorer", "src.priority", "src.processor",
                          "src.runbook_engine", "src.escalation", "src.nlp_handler",
                          "google.generativeai", "faiss", "openai", "requests", "httpx"):
            self.assertNotIn(forbidden, source)

    def test_no_randomness_in_generator(self):
        source = Path("src/generator.py").read_text(encoding="utf-8")
        for forbidden in ("import random", "random.", "uuid4", "time.time", "datetime.today"):
            self.assertNotIn(forbidden, source)
        # The single clock read in the module is the opt-in demo rebase.
        self.assertEqual(source.count("datetime.now"), 1)

    def test_engine_modules_are_still_stubs(self):
        # processor.py is implemented in Step 5 and is no longer a stub.
        # scorer.py is implemented in Step 6 and is no longer a stub.
        for module in ("priority", "runbook_engine",
                       "escalation", "nlp_handler", "database"):
            text = Path(f"src/{module}.py").read_text(encoding="utf-8")
            self.assertNotIn("def ", text, f"src/{module}.py should stay a stub in Step 4")


if __name__ == "__main__":
    unittest.main()
