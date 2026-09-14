"""Aggregate publication races use real local Git, SQLite and immutable proofs."""
from __future__ import annotations

import copy
import json
import unittest
from unittest import mock

from issue_pipeline.controller import Controller, PipelineBlocked
from issue_pipeline.graph import GraphError
from issue_pipeline.github import GithubError, GithubIdentityError
from issue_pipeline_tests import test_controller as fixture


class AggregateClosureTests(unittest.TestCase):
    setUp = fixture.ControllerTests.setUp
    graph_record = fixture.ControllerTests.graph_record
    replace_graph = fixture.ControllerTests.replace_graph
    accepted_fixture = fixture.ControllerTests.accepted_fixture
    execute = fixture.ControllerTests.execute

    def ready(self, *, all_tasks=True):
        self.accepted_fixture(36)
        if all_tasks:
            self.accepted_fixture(41)
            self.accepted_fixture(86)

    def update(self):
        self.controller.update_master(self.github.graph, {}, set())

    def entry(self, number):
        return self.controller.state.get_task(number)["data"]["aggregate_closure"]

    def restart(self):
        self.controller = Controller(self.config, repo=self.repo, github=self.github,
                                     runner=self.runner, gate=self.gate)
        self.addCleanup(self.controller.state.close)
        self.controller.log = mock.Mock()

    def invalidate(self, kind):
        if kind == "body":
            self.github.issues[36]["body"] += " Additional acceptance."
        elif kind == "reopen":
            self.github.issues[36]["state"] = "open"
        elif kind == "proof":
            old = self.controller.state.receipts(36, "completion")[-1]
            value = {k: v for k, v in old["data"].items() if k != "artifacts"}
            self.controller.record(36, "completion", self.base, self.base, value, accepted=False)
        elif kind == "master":
            self.github.issues[35]["body"] += "\nChanged aggregate requirements.\n"
        elif kind == "legacy":
            self.github.issues[13]["body"] += " Changed legacy requirements."
        elif kind == "graph":
            graph = self.graph_record()
            graph["tasks"][0]["locks"].append("new-scope")
            self.replace_graph(graph)

    def assert_blocked_open(self, *numbers):
        for number in numbers:
            self.assertEqual(self.github.issue(number)["state"], "open")
            self.assertEqual(self.controller.state.get_task(number)["status"], "blocked")
            self.assertNotEqual(self.entry(number)["stage"], "complete")

    def test_valid_aggregates_bind_legacy_terminal_and_repeat_without_writes(self):
        self.ready()
        self.update()
        self.assertEqual(self.github.close_calls, [13, 35])
        self.assertEqual(self.entry(35)["legacy_terminal"], self.entry(13)["terminal"])
        original = {n: copy.deepcopy(self.entry(n)) for n in (13, 35)}
        comments = copy.deepcopy(self.github.comment_rows)
        self.restart()
        self.controller.reconcile_aggregates()
        self.update()
        self.assertEqual({n: self.entry(n) for n in (13, 35)}, original)
        self.assertEqual(self.github.close_calls, [13, 35])
        self.assertEqual(self.github.comment_rows, comments)

    def assert_comment_mutation(self, boundary, change):
        self.ready()
        original = self.github.comment

        def publish(number, body):
            value = original(number, body)
            matches = ((boundary == "status" and "agenc-pipeline-live-status" in body)
                       or (boundary == "legacy" and number == 13 and "agenc-pipeline-aggregate:" in body)
                       or (boundary == "master" and number == 35 and "agenc-pipeline-aggregate:" in body))
            if matches:
                self.invalidate(change)
            return value

        with mock.patch.object(self.github, "comment", side_effect=publish):
            with self.assertRaises(PipelineBlocked):
                self.update()
        self.assert_blocked_open(13, 35)
        self.assertEqual(self.github.close_calls, [13] if boundary == "master" else [])
        preparations = {n: self.entry(n)["preparation"] for n in (13, 35)}
        self.restart()
        with self.assertRaises(PipelineBlocked):
            self.controller.reconcile_aggregates()
        self.assertEqual({n: self.entry(n)["preparation"] for n in (13, 35)}, preparations)
        self.assert_blocked_open(13, 35)

    def test_initial_status_comment_child_edit_cannot_rebind_either_aggregate(self):
        self.assert_comment_mutation("status", "body")

    def test_initial_status_comment_master_edit_cannot_rebind_either_aggregate(self):
        self.assert_comment_mutation("status", "master")

    def test_initial_status_comment_graph_edit_cannot_rebind_either_aggregate(self):
        self.assert_comment_mutation("status", "graph")

    def test_legacy_comment_reopened_prerequisite_blocks_both_aggregates(self):
        self.assert_comment_mutation("legacy", "reopen")

    def test_master_comment_revoked_proof_reopens_previously_completed_legacy(self):
        self.assert_comment_mutation("master", "proof")

    def test_master_comment_legacy_body_edit_reopens_owned_legacy(self):
        self.assert_comment_mutation("master", "legacy")

    def assert_close_mutation(self, target, change):
        self.ready()
        close = self.github.close_issue

        def publish(number):
            result = close(number)
            if number == target:
                self.invalidate(change)
            return result

        with mock.patch.object(self.github, "close_issue", side_effect=publish):
            with self.assertRaises(PipelineBlocked):
                self.update()
        self.assert_blocked_open(13, 35)
        self.assertEqual(self.github.close_calls, [13] if target == 13 else [13, 35])

    def test_legacy_close_child_edit_reopens_legacy_and_prevents_master_close(self):
        self.assert_close_mutation(13, "body")

    def test_legacy_close_master_body_edit_is_not_recaptured_for_master_intent(self):
        self.assert_close_mutation(13, "master")

    def test_master_close_child_edit_reopens_both_owned_aggregates(self):
        self.assert_close_mutation(35, "body")

    def test_lost_close_response_recovers_exact_intent_without_duplicate_comment_or_close(self):
        self.ready()
        self.github.lose_close_response = True
        with self.assertRaises(PipelineBlocked):
            self.update()
        original = self.entry(13)["intent"]
        comments = copy.deepcopy(self.github.comments(13))
        self.assertTrue(self.entry(13)["close_attempted"])
        self.restart()
        self.controller.reconcile_aggregates()
        self.assertEqual(self.entry(13)["intent"], original)
        self.assertEqual(self.github.comments(13), comments)
        self.assertEqual(self.github.close_calls, [13, 35])
        self.assertEqual(self.entry(35)["legacy_terminal"], self.entry(13)["terminal"])

    def test_lost_comment_response_uses_same_marker_on_fresh_controller(self):
        self.ready()
        comment = self.github.comment

        def disconnected(number, body):
            result = comment(number, body)
            if number == 13:
                raise OSError("comment response lost after publication")
            return result

        with mock.patch.object(self.github, "comment", side_effect=disconnected):
            with self.assertRaises(PipelineBlocked):
                self.update()
        intent = self.entry(13)["intent"]
        self.restart()
        self.controller.reconcile_aggregates()
        self.assertEqual(self.entry(13)["intent"], intent)
        self.assertEqual(len(self.github.comments(13)), 1)
        self.assertEqual(self.github.close_calls, [13, 35])

    def test_recovery_finishes_approved_backlog_journal_before_aggregate_validation(self):
        graph = self.graph_record()
        changed = copy.deepcopy(graph)
        changed["legacy_umbrella"]["depends_on"] = [41]
        self.github.issues[35]["body"] = self.github.issues[35]["body"].replace(json.dumps(graph), json.dumps(changed))
        self.github.graph = fixture.Graph.from_master(self.github.issues[35]["body"])
        self.github.dependencies[13] = {41}
        self.accepted_fixture(41)
        self.update()
        terminal = self.entry(13)["terminal"]
        fixture.ControllerTests.interrupt_discovery_registration(self, "during-register")
        # The interrupted, approved operation made one more native write before
        # crashing: its child is attached while the old JSON graph remains.
        self.github.child_links[35].add(100)
        with self.assertRaises((GraphError, GithubIdentityError)):
            self.controller.snapshot()
        with mock.patch("issue_pipeline.controller.halt_children"):
            self.controller.recover()
        self.assertIn(100, self.github.graph.by_issue[36].depends_on)
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertEqual(self.entry(13)["stage"], "complete")
        self.assertEqual(self.github.close_calls, [13])
        self.assertEqual(self.github.next_issue, 101)

    def test_native_graph_mismatch_reopens_both_owned_aggregates(self):
        self.ready()
        self.update()
        self.github.dependencies[13].add(41)
        with self.assertRaisesRegex(PipelineBlocked, "native dependencies"):
            self.controller.reconcile_aggregates()
        self.assert_blocked_open(13, 35)

    def test_confirmed_native_identity_mismatch_reopens_both_owned_aggregates(self):
        self.ready()
        self.update()
        children = self.github.children

        def foreign(number):
            rows = children(number)
            rows[0]["node_id"] = "I_foreign_identity"
            return rows

        with mock.patch.object(self.github, "children", side_effect=foreign):
            with self.assertRaisesRegex(PipelineBlocked, "native dependencies"):
                self.controller.reconcile_aggregates()
        self.assert_blocked_open(13, 35)

    def test_transport_uncertainty_preserves_terminal_for_automatic_reconciliation(self):
        self.ready()
        self.update()
        terminals = {n: self.entry(n)["terminal"] for n in (13, 35)}
        with mock.patch.object(self.github, "children", side_effect=GithubError("transport unavailable")):
            with self.assertRaises(PipelineBlocked):
                self.controller.reconcile_aggregates()
        for number in (13, 35):
            self.assertEqual(self.github.issue(number)["state"], "closed")
            self.assertEqual(self.entry(number)["stage"], "complete")
            self.assertEqual(self.controller.state.get_task(number)["status"], "blocked")
        self.restart()
        self.controller.reconcile_aggregates()
        self.assertEqual({n: self.entry(n)["terminal"] for n in (13, 35)}, terminals)
        self.assertEqual(self.github.close_calls, [13, 35])

    def test_legacy_final_target_read_follows_master_read_before_terminal_receipt(self):
        self.ready(all_tasks=False)
        context, issue = self.controller.aggregate_context, self.github.issue
        final_read = False
        mutated = False

        def checked_context():
            nonlocal final_read
            result = context()
            final_read = 13 in self.github.close_calls
            return result

        def read(number):
            nonlocal mutated
            if number == 35 and final_read and not mutated:
                mutated = True
                self.invalidate("legacy")
            return issue(number)

        with mock.patch.object(self.controller, "aggregate_context", side_effect=checked_context), \
                mock.patch.object(self.github, "issue", side_effect=read):
            with self.assertRaises(PipelineBlocked):
                self.update()
        self.assertTrue(mutated)
        self.assert_blocked_open(13)
        self.assertEqual(self.controller.state.receipts(13, "aggregate-completion"), [])

    def test_unrelated_main_advance_preserves_existing_legacy_terminal(self):
        self.ready(all_tasks=False)
        self.update()
        terminal = self.entry(13)["terminal"]
        fixture.git(self.config.clone, "commit", "--allow-empty", "-m", "Unrelated subsequent source")
        fixture.git(self.config.clone, "push", "origin", "main")
        self.update()
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertEqual(self.github.close_calls, [13])

    def test_revocation_drains_both_owned_aggregates_despite_uncertain_legacy_reopen(self):
        self.ready()
        self.update()
        self.invalidate("proof")
        api = self.github.api

        def unavailable(endpoint, method="GET", payload=None):
            if endpoint == "issues/13" and payload == {"state": "open"}:
                raise OSError("legacy reopen was not acknowledged")
            return api(endpoint, method, payload)

        with mock.patch.object(self.github, "api", side_effect=unavailable):
            with self.assertRaises(PipelineBlocked):
                self.controller.reconcile_aggregates()
        self.assertEqual(self.github.issue(35)["state"], "open")
        self.assertEqual(self.entry(13)["stage"], "reopening")
        self.assertEqual(self.entry(35)["stage"], "invalidated")
        self.restart()
        with self.assertRaises(PipelineBlocked):
            self.controller.reconcile_aggregates()
        self.assert_blocked_open(13, 35)

    def test_lost_reopen_response_is_settled_by_open_readback(self):
        self.ready()
        self.update()
        self.invalidate("reopen")
        api = self.github.api
        requests = []

        def disconnected(endpoint, method="GET", payload=None):
            result = api(endpoint, method, payload)
            if payload == {"state": "open"}:
                requests.append(endpoint)
                raise OSError("reopen response lost after mutation")
            return result

        with mock.patch.object(self.github, "api", side_effect=disconnected):
            with self.assertRaises(PipelineBlocked):
                self.controller.reconcile_aggregates()
        self.assertEqual(requests, ["issues/13", "issues/35"])
        self.assert_blocked_open(13, 35)

    def test_delayed_owned_close_after_invalidation_is_reopened_on_restart(self):
        self.ready()
        self.update()
        self.invalidate("body")
        with self.assertRaises(PipelineBlocked):
            self.controller.reconcile_aggregates()
        self.assert_blocked_open(13, 35)
        intents = {n: self.entry(n)["intent"] for n in (13, 35)}
        # A close whose response was uncertain arrives after compensation's
        # last successful open readback. The retained intent remains owned.
        self.github.issues[13]["state"] = "closed"
        self.github.issues[35]["state"] = "closed"
        self.restart()
        with self.assertRaises(PipelineBlocked):
            self.controller.reconcile_aggregates()
        self.assert_blocked_open(13, 35)
        self.assertEqual({n: self.entry(n)["intent"] for n in (13, 35)}, intents)

    def test_explicit_retry_after_restoring_original_evidence_reuses_both_intents(self):
        self.ready()
        self.update()
        original_body = self.github.issues[36]["body"]
        original = {n: copy.deepcopy(self.entry(n)) for n in (13, 35)}
        comments = copy.deepcopy(self.github.comment_rows)
        self.invalidate("body")
        with self.assertRaises(PipelineBlocked):
            self.controller.reconcile_aggregates()
        self.github.issues[36]["body"] = original_body
        # The existing CLI retry operation preserves data and changes only the
        # blocked row to pending; no new acceptance or intent is manufactured.
        for number in (13, 35):
            row = self.controller.state.get_task(number)
            self.controller.state.set_task(number, "pending", row["data"])
        self.restart()
        self.controller.reconcile_aggregates()
        self.assertEqual({n: self.entry(n) for n in (13, 35)}, original)
        self.assertEqual(self.github.comment_rows, comments)
        self.assertEqual(self.github.close_calls, [13, 35, 13, 35])

    def test_unowned_preexisting_closed_aggregate_is_never_adopted_or_reopened(self):
        self.ready()
        self.github.issues[13]["state"] = "closed"
        with mock.patch.object(self.github, "api", wraps=self.github.api) as api:
            with self.assertRaises(PipelineBlocked):
                self.update()
        self.assertEqual(self.github.issue(13)["state"], "closed")
        self.assertEqual(self.github.issue(35)["state"], "open")
        self.assertFalse(self.entry(13)["close_attempted"])
        self.assertFalse(self.github.close_calls)
        self.assertFalse(any(call.args[0] == "issues/13" for call in api.call_args_list))

    def test_unrelated_graph_extension_preserves_terminal_legacy_and_delays_master(self):
        self.ready(all_tasks=False)
        self.update()
        terminal = self.entry(13)["terminal"]
        graph = self.graph_record()
        graph["tasks"].insert(2, {"key": "FIX-01", "issue": 100, "depends_on": [], "locks": ["new"],
                                  "external_gate": False, "level": 0})
        graph["tasks"][-1]["depends_on"].append(100)
        self.replace_graph(graph)
        self.github.issues[35]["body"] += "\nVerified unrelated discovery extends this backlog.\n"
        self.update()
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertEqual(self.github.close_calls, [13])
        self.assertEqual(self.github.issue(35)["state"], "open")
        for number in (41, 100, 86):
            self.accepted_fixture(number)
        self.update()
        self.assertEqual(self.entry(35)["legacy_terminal"], terminal)
        self.assertEqual(self.github.close_calls, [13, 35])

    def test_stale_complete_rows_display_invalid_evidence_without_rescheduling(self):
        self.ready()
        self.invalidate("body")
        self.update()
        body = self.github.comments(35)[0]["body"]
        self.assertIn("- [ ] #36 ENC-12: completion evidence invalid", body)
        self.assertIn("- [ ] #86 REL-13: completion evidence invalid", body)
        self.assertEqual(self.controller.state.get_task(36)["status"], "complete")
        self.assertFalse(self.github.close_calls)

    def test_compensation_refreshes_existing_live_status_before_reporting_block(self):
        self.ready()
        self.update()
        self.assertIn("- [x] #36", self.github.comments(35)[0]["body"])
        self.invalidate("body")
        with self.assertRaises(PipelineBlocked):
            self.update()
        body = self.github.comments(35)[0]["body"]
        self.assertIn("Aggregate completion is blocked", body)
        self.assertIn("- [ ] #36 ENC-12: completion evidence invalid", body)
        self.assertIn("- [ ] #86 REL-13: completion evidence invalid", body)
        self.assert_blocked_open(13, 35)

    def test_blocked_status_mutation_reopens_uncertain_owned_close_without_retrying_publication(self):
        self.ready()
        self.github.lose_close_response = True
        api = self.github.api
        intent = None

        def publish(endpoint, method="GET", payload=None):
            nonlocal intent
            result = api(endpoint, method, payload)
            if endpoint.startswith("issues/comments/") and "Aggregate completion is blocked" in payload.get("body", ""):
                self.assertEqual(self.entry(13)["stage"], "closing")
                intent = self.entry(13)["intent"]
                self.invalidate("body")
            return result

        with mock.patch.object(self.github, "api", side_effect=publish):
            with self.assertRaises(PipelineBlocked):
                self.update()
        self.assertIsNotNone(intent)
        self.assertEqual(self.entry(13)["intent"], intent)
        self.assertEqual(self.github.close_calls, [13])
        self.assertEqual(len(self.github.comments(13)), 1)
        self.assert_blocked_open(13, 35)
