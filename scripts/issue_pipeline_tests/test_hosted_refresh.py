"""Late hosted transitions exercise actual local Git promotion and real classification."""
from contextlib import contextmanager
import copy
from dataclasses import replace
import unittest
from unittest import mock

from issue_pipeline.controller import Controller, PipelineBlocked
from issue_pipeline.github import Github
from issue_pipeline_tests import test_controller as fixture


class HostedRefreshTests(unittest.TestCase):
    execute = fixture.ControllerTests.execute

    def setUp(self):
        fixture.ControllerTests.setUp(self)
        self.config = replace(self.config, max_attempts=1)
        self.controller.config = self.config

    @contextmanager
    def late_hosted(self, initial, final, boundary):
        evidence = {"current": initial, "changed": False, "reads": [], "events": []}
        provider = Github(self.config.repository)

        def classify(source):
            state = evidence["current"]
            checks, workflows = [], []
            if state in {"passed", "failed", "pending", "incomplete"}:
                checks = [{"name": "external/ci", "head_sha": source,
                           "status": "in_progress" if state == "pending" else "completed",
                           "conclusion": {"passed": "success", "failed": "failure", "pending": None,
                                          "incomplete": "skipped"}[state]}]
            elif state == "startup_failure":
                workflows = [{"id": 123, "head_sha": source, "status": "completed", "conclusion": "startup_failure"}]

            def pages(path, member=None):
                if "/check-runs" in path:
                    return copy.deepcopy(checks)
                if "/statuses" in path:
                    return []
                if path.startswith("actions/runs?"):
                    return copy.deepcopy(workflows)
                if path == "actions/runs/123/jobs":
                    return []
                self.fail("unexpected hosted endpoint: " + path)

            with mock.patch.object(provider, "_pages", side_effect=pages):
                result = provider.hosted_checks(source)
            evidence["reads"].append(copy.deepcopy(result))
            evidence["events"].append("hosted:" + result["state"])
            return result

        method = "live_preconditions" if boundary == "preconditions" else "require_candidate_receipts"
        original = getattr(self.controller, method)

        def slow_verification(*args, **kwargs):
            result = original(*args, **kwargs)
            if len(evidence["reads"]) == 1 and not evidence["changed"]:
                evidence.update(current=final, changed=True)
                evidence["events"].append("changed_during:" + boundary)
            return result

        with mock.patch.object(self.github, "hosted_checks", side_effect=classify), \
                mock.patch.object(self.controller, method, side_effect=slow_verification), \
                mock.patch.object(self.controller.stop, "wait", return_value=True):
            yield evidence

    def assert_late_block(self, initial, final, boundary):
        with self.late_hosted(initial, final, boundary) as evidence, \
                mock.patch.object(self.repo, "atomic_promote", wraps=self.repo.atomic_promote) as promote:
            self.execute()
            promote.assert_not_called()
        self.assertTrue(evidence["changed"])
        self.assertEqual([read["state"] for read in evidence["reads"]], [initial, final])
        row = self.controller.state.get_task(36)
        self.assertEqual(row["status"], "blocked")
        self.assertEqual(self.repo.fetch(), self.base)
        self.assertFalse(self.github.close_calls)
        self.assertEqual(self.github.statuses, [])
        receipts = self.controller.state.receipts(36, "hosted-checks")
        self.assertEqual([r["status"] for r in receipts], ["accepted", "rejected"])
        self.assertEqual(receipts[-1]["data"]["state"], final)
        self.assertEqual(receipts[-1]["source"], row["data"]["candidate"])
        self.assertEqual(receipts[-1]["base"], self.base)
        self.assertTrue(self.controller.receipt_valid(receipts[-1]))
        return row, receipts

    def test_empty_to_failure_during_live_preconditions_never_pushes_main(self):
        self.assert_late_block("empty", "failed", "preconditions")

    def test_passed_to_pending_during_live_preconditions_never_pushes_main(self):
        self.assert_late_block("passed", "pending", "preconditions")

    def test_passed_to_failure_during_receipt_hashing_never_pushes_main(self):
        self.assert_late_block("passed", "failed", "receipts")

    def test_empty_to_pending_during_receipt_hashing_never_pushes_main(self):
        self.assert_late_block("empty", "pending", "receipts")

    def test_late_incomplete_check_blocks_main_and_archives_rejection(self):
        self.assert_late_block("passed", "incomplete", "receipts")

    def test_retained_initial_pass_does_not_authorize_restart_after_latest_rejection(self):
        row, receipts = self.assert_late_block("passed", "failed", "receipts")
        restarted = Controller(self.config, repo=self.repo, github=self.github, runner=self.runner, gate=self.gate)
        self.addCleanup(restarted.state.close)
        restarted.log = mock.Mock()
        rejected = copy.deepcopy(receipts[-1]["data"])
        rejected.pop("artifacts", None)
        with mock.patch.object(self.github, "hosted_checks", return_value=rejected), \
                mock.patch.object(self.repo, "atomic_promote", wraps=self.repo.atomic_promote) as promote:
            with self.assertRaises(PipelineBlocked):
                restarted.publish_and_promote(self.task, row["data"], fixture.PHASE)
            promote.assert_not_called()
        self.assertEqual(self.repo.fetch(), self.base)
        self.assertEqual(restarted.state.receipts(36, "hosted-checks")[-1]["status"], "rejected")
        self.assertEqual(self.github.statuses, [])

    def assert_fresh_allowed(self, state):
        promote = self.repo.atomic_promote
        with self.late_hosted("empty", state, "receipts") as evidence:
            def checked_promote(source, base):
                self.assertEqual(evidence["events"][-1], "hosted:" + state)
                self.assertEqual(evidence["reads"][-1]["sha"], source)
                self.assertFalse(evidence["reads"][-1]["blocking"])
                evidence["events"].append("atomic_promote")
                return promote(source, base)
            with mock.patch.object(self.repo, "atomic_promote", side_effect=checked_promote) as promotion:
                self.execute()
                promotion.assert_called_once()
        self.assertEqual(self.controller.state.get_task(36)["status"], "complete")
        self.assertNotEqual(self.repo.fetch(), self.base)
        self.assertEqual([read["state"] for read in evidence["reads"]], ["empty", state])
        self.assertEqual(self.github.statuses, [])
        self.assertEqual(self.controller.state.receipts(36, "hosted-checks")[-1]["data"]["state"], state)

    def test_fresh_passing_checks_allow_actual_promotion(self):
        self.assert_fresh_allowed("passed")

    def test_fresh_empty_hosted_evidence_preserves_existing_local_gate_policy(self):
        self.assert_fresh_allowed("empty")

    def test_fresh_known_zero_job_startup_failure_preserves_existing_policy(self):
        self.assert_fresh_allowed("startup_failure")
