"""Behavioral checks for dependency, proof, routing and native-link admission."""

import copy
import json
import unittest

from issue_pipeline.graph import Graph, GraphError, Task


def graph_record():
    return {
        "version": 1, "source": "a" * 40, "master_issue": 35,
        "final_issue": 86, "lock_policy": "Claim scopes and concrete files.",
        "legacy_umbrella": {"issue": 13, "depends_on": [36]},
        "tasks": [
            {"key": "ENC-01", "issue": 36, "depends_on": [],
             "locks": ["normative"], "external_gate": False, "level": 0},
            {"key": "OPS-02", "issue": 41, "depends_on": [],
             "locks": ["ci"], "external_gate": False, "level": 0},
            {"key": "REL-13", "issue": 86, "depends_on": [36, 41],
             "locks": ["signing"], "external_gate": True, "level": 1},
        ],
    }


def master(record):
    return "Introduction\n\n```json\n" + json.dumps(record) + "\n```\n"


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.record = graph_record()
        self.graph = Graph.from_master(master(self.record))

    def test_valid_graph_keeps_legacy_separate_and_maps_tasks(self):
        self.assertEqual(len(self.graph.tasks), 3)
        self.assertNotIn(13, self.graph.by_issue)
        self.assertEqual(self.graph.by_key["ENC-01"].issue, 36)
        self.assertEqual(self.graph.legacy_umbrella["depends_on"], (36,))

    def test_closed_dependency_without_accepted_proof_is_not_ready(self):
        snapshots = {36: {"state": "closed"}, 41: {"state": "CLOSED"}, 86: {"state": "OPEN"}}
        self.assertEqual(self.graph.ready(snapshots, {36}), [])
        self.assertEqual([task.issue for task in self.graph.ready(snapshots, {36, 41})], [86])
        self.assertEqual([task.issue for task in self.graph.ready(snapshots, lambda n: n in {36, 41})], [86])

    def test_proof_cannot_replace_open_dependency_or_missing_snapshot(self):
        snapshots = {36: {"state": "open"}, 86: {"state": "open"}}
        self.assertEqual([task.issue for task in self.graph.ready(snapshots, {36, 41})], [36])

    def test_occupied_scope_excludes_ready_task(self):
        snapshots = {task.issue: {"state": "OPEN"} for task in self.graph.tasks}
        self.assertEqual([task.issue for task in self.graph.ready(snapshots, set(), {"normative"})], [41])

    def test_unknown_and_self_dependency_refused(self):
        for dependency in (900, 36):
            with self.subTest(dependency=dependency):
                record = copy.deepcopy(self.record)
                record["tasks"][0]["depends_on"] = [dependency]
                with self.assertRaises(GraphError):
                    Graph.from_master(master(record))

    def test_cycle_refused(self):
        self.record["tasks"][0]["depends_on"] = [41]
        self.record["tasks"][1]["depends_on"] = [36]
        with self.assertRaisesRegex(GraphError, "cycle"):
            Graph.from_master(master(self.record))

    def test_orphan_refused(self):
        self.record["tasks"][-1]["depends_on"] = [36]
        with self.assertRaisesRegex(GraphError, "every task"):
            Graph.from_master(master(self.record))

    def test_stale_levels_refused(self):
        self.record["tasks"][-1]["level"] = 2
        with self.assertRaisesRegex(GraphError, "levels"):
            Graph.from_master(master(self.record))

    def test_boolean_integer_fields_refused(self):
        for field in ("version", "master_issue", "final_issue"):
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                record[field] = True
                with self.assertRaises(GraphError):
                    Graph.from_master(master(record))
        for field in ("issue", "level", "depends_on"):
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                record["tasks"][0][field] = [True] if field == "depends_on" else True
                with self.assertRaises(GraphError):
                    Graph.from_master(master(record))

    def test_closed_schema_duplicate_keys_and_locks_refused(self):
        invalid = []
        for field, value in (("key", "OPS-02"), ("issue", 41),
                             ("locks", ["normative", "normative"]), ("external_gate", 0)):
            record = copy.deepcopy(self.record)
            record["tasks"][0][field] = value
            invalid.append(record)
        record = copy.deepcopy(self.record)
        record["extra"] = "ignored policy would be unsafe"
        invalid.append(record)
        record = copy.deepcopy(self.record)
        record["tasks"][-1]["depends_on"] = [36, 36, 41]
        invalid.append(record)
        for record in invalid:
            with self.subTest(record=record):
                with self.assertRaises(GraphError):
                    Graph.from_master(master(record))

    def test_duplicate_json_field_and_multiple_graphs_refused(self):
        body = master(self.record)
        with self.assertRaisesRegex(GraphError, "duplicate JSON"):
            Graph.from_master(body.replace('"version": 1', '"version": 1, "version": 1'))
        with self.assertRaises(GraphError):
            Graph.from_master(body + body)
        with self.assertRaises(GraphError):
            Graph.from_master("no graph")

    def test_native_edges_must_match_including_legacy(self):
        children = [36, 41, 86, 13]
        blockers = {36: [], 41: [], 86: [41, 36], 13: [36]}
        self.graph.validate_native_links(children, blockers)
        for observed in ({36: [], 41: [], 86: [36], 13: [36]},
                         {36: [], 41: [], 86: [36, 41]},
                         {36: [], 41: [], 86: [36, 41], 13: []}):
            with self.subTest(observed=observed):
                with self.assertRaises(GraphError):
                    self.graph.validate_native_links(children, observed)
        with self.assertRaises(GraphError):
            self.graph.validate_native_links([36, 41, 86], blockers)

    def test_specialized_routing_is_not_inferred_from_external_flag_alone(self):
        expected = {
            "STO-01": "upstream", "STO-02": "upstream", "ENC-11": "external",
            "REL-01": "host", "REL-02": "repository", "REL-03": "repository",
            "REL-04": "native", "REL-12": "native", "REL-13": "external",
            "OPS-02": "repository", "ENC-12": "repository",
        }
        for key, route in expected.items():
            with self.subTest(key=key):
                self.assertEqual(Task(key, 1, (), (), False, 0).route, route)
        self.assertEqual(Task("NEW-01", 1, (), (), True, 0).route, "external")


if __name__ == "__main__":
    unittest.main()
