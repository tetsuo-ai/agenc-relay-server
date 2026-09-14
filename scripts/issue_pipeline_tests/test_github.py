"""Mock-network tests for exact GitHub requests and fail-closed hosted evidence."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from issue_pipeline.github import Github, GithubError, issue_identity, native_issue_numbers

SHA = "a" * 40
OTHER = "b" * 40


def issue_row(number, repository="example/private", **fields):
    """REST issue identity fields present on actual issue and relationship rows."""
    return {"number": number, "id": number + 1000, "node_id": f"I_fixture_{number}",
            "repository_url": f"https://api.github.com/repos/{repository}",
            "url": f"https://api.github.com/repos/{repository}/issues/{number}",
            "html_url": f"https://github.com/{repository}/issues/{number}",
            "state": "open", "body": "", **fields}


class GithubTests(unittest.TestCase):
    def setUp(self) -> None:
        self.github = Github("example/private", cwd=Path("/tmp"))

    def test_exact_json_body_uses_stdin_without_shell_or_interpolation(self) -> None:
        body = "first line\n`literal` $(touch nope)\nUnicode: é"
        with patch("issue_pipeline.github._process", return_value=(0, '{"id":1}')) as process:
            self.github.comment(35, body)
        args = process.call_args.args
        self.assertEqual(args[0][0:3], ["gh", "api", "repos/example/private/issues/35/comments"])
        self.assertIn("--input", args[0])
        self.assertEqual(args[0][-1], "-")
        self.assertEqual(json.loads(args[3]), {"body": body})
        self.assertNotIn(body, args[0])

    def test_mutation_failure_is_not_retried_or_echoed(self) -> None:
        with patch("issue_pipeline.github._process", return_value=(1, "SECRET_CREDENTIAL")) as process:
            with self.assertRaises(GithubError) as captured:
                self.github.comment(35, "receipt")
        self.assertEqual(process.call_count, 1)
        self.assertNotIn("SECRET_CREDENTIAL", str(captured.exception))

    def test_cross_repository_nonfinite_or_oversized_api_inputs_are_refused(self) -> None:
        with patch("issue_pipeline.github._process") as process:
            with self.assertRaises(GithubError):
                self.github.api("repos/other/private/issues/35")
            with self.assertRaises(GithubError):
                self.github.api("issues/../35")
            with self.assertRaises(GithubError):
                self.github.api("issues/35", "POST", {"number": float("nan")})
            with self.assertRaises(GithubError):
                self.github.comment(35, "x" * (1024 * 1024 + 1))
        process.assert_not_called()

    def test_master_graph_requires_one_matching_json_graph(self) -> None:
        graph = {"version": 1, "master_issue": 35, "tasks": []}
        issue = issue_row(35, body="text\n```json\n" + json.dumps(graph) + "\n```\n")
        with patch.object(self.github, "api", return_value=issue):
            self.assertEqual(self.github.master_graph(35), graph)
            issue["body"] *= 2
            with self.assertRaises(GithubError):
                self.github.master_graph(35)
            issue["body"] = "```json\n{\"master_issue\":36,\"tasks\":[]}\n```"
            with self.assertRaises(GithubError):
                self.github.master_graph(35)
            issue["body"] = "```json\n{broken\n```"
            with self.assertRaises(GithubError):
                self.github.master_graph(35)
            issue["body"] = '```json\n{"master_issue":35,"tasks":[],"tasks":[1]}\n```'
            with self.assertRaises(GithubError):
                self.github.master_graph(35)

    def test_issue_refuses_pr_bool_number_and_wrong_identity(self) -> None:
        with self.assertRaises(GithubError):
            self.github.issue(True)
        with patch.object(self.github, "api", return_value={"number": 36, "state": "open", "body": ""}):
            with self.assertRaises(GithubError):
                self.github.issue(35)
        with patch.object(self.github, "api", return_value={"number": 35, "pull_request": {}}):
            with self.assertRaises(GithubError):
                self.github.issue(35)

    def test_native_child_dependency_and_comment_pagination(self) -> None:
        page = [issue_row(number) for number in range(1, 101)]
        with patch.object(self.github, "api", side_effect=[page, [issue_row(101)]]) as api:
            self.assertEqual(len(self.github.children(35)), 101)
        self.assertEqual(api.call_args_list[0].args[0], "issues/35/sub_issues?per_page=100&page=1")
        self.assertEqual(api.call_args_list[1].args[0], "issues/35/sub_issues?per_page=100&page=2")
        with patch.object(self.github, "api", return_value=[]) as api:
            self.assertEqual(self.github.blockers(40), [])
            self.assertIn("dependencies/blocked_by", api.call_args.args[0])
            self.assertEqual(self.github.comments(40), [])
            self.assertIn("/comments", api.call_args.args[0])

    def test_issue_and_native_endpoints_reject_foreign_or_malformed_identities(self):
        invalid = [issue_row(36, "foreign/private")]
        for field, value in (("repository_url", "https://api.github.com/repos/foreign/private"),
                             ("url", "https://api.github.com/repos/example/private/issues/37"),
                             ("html_url", "https://github.com/example/private/pull/36"),
                             ("id", True), ("id", 0), ("node_id", ""),
                             ("node_id", None), ("pull_request", {})):
            invalid.append(issue_row(36, **{field: value}))
        for field in ("repository_url", "url", "html_url", "id", "node_id"):
            value = issue_row(36)
            del value[field]
            invalid.append(value)
        for value in invalid:
            for method in ("issue", "children", "blockers"):
                with self.subTest(value=value, method=method), patch.object(
                        self.github, "api", return_value=value if method == "issue" else [value]):
                    with self.assertRaises(GithubError):
                        getattr(self.github, method)(36)

    def test_native_rows_must_match_local_numeric_and_node_ids_before_projection(self):
        local = {36: issue_row(36)}
        self.assertEqual(native_issue_numbers([issue_row(36)], self.github.repo, local), (36,))
        self.assertEqual(issue_identity(issue_row(36, "EXAMPLE/Private"), self.github.repo),
                         (36, 1036, "I_fixture_36"))
        for row in (issue_row(36, "foreign/private"), issue_row(36, id=9000),
                    issue_row(36, node_id="I_another_issue"), issue_row(37)):
            with self.subTest(row=row), self.assertRaises(GithubError):
                native_issue_numbers([row], self.github.repo, local)
        with self.assertRaises(GithubError):
            native_issue_numbers([issue_row(36), issue_row(36)], self.github.repo, local)
        with patch.object(self.github, "issue") as resolve:
            with self.assertRaises(GithubError):
                native_issue_numbers([issue_row(36, "foreign/private")], self.github.repo, resolve)
            resolve.assert_not_called()

    def test_pagination_refuses_exhaustion_or_malformed_page(self) -> None:
        with patch("issue_pipeline.github.MAX_PAGES", 2), \
                patch.object(self.github, "api", return_value=[{}] * 100):
            with self.assertRaises(GithubError):
                self.github.children(35)
        with patch.object(self.github, "api", return_value={"items": []}):
            with self.assertRaises(GithubError):
                self.github.comments(35)
        with patch("issue_pipeline.github.MAX_OUTPUT", 10), \
                patch.object(self.github, "api", return_value=[{"body": "long response"}]):
            with self.assertRaises(GithubError):
                self.github.comments(35)

    def test_create_pr_uses_exact_structured_payload(self) -> None:
        with patch.object(self.github, "api", return_value={"number": 90}) as api:
            self.github.create_pr("pipeline/issue-40", "Resolve #40", "first\nsecond")
            self.assertEqual(api.call_args.args,
                             ("pulls", "POST", {"head": "pipeline/issue-40", "base": "main", "title": "Resolve #40",
                                                "body": "first\nsecond", "draft": False}))

    def test_merged_pr_readback_refuses_closed_unmerged_or_changed_head(self) -> None:
        value = {"number": 90, "state": "closed", "merged": False, "head": {"sha": SHA},
                 "base": {"sha": OTHER}, "merge_commit_sha": SHA}
        with patch.object(self.github, "api", return_value=value):
            with self.assertRaises(GithubError):
                self.github.merged_pr(90, SHA)
            value["merged"] = True
            with self.assertRaises(GithubError):
                self.github.merged_pr(90, OTHER)
            self.assertTrue(self.github.merged_pr(90, SHA)["merged"])
            value["merge_commit_sha"] = None
            with self.assertRaises(GithubError):
                self.github.merged_pr(90, SHA)

    def test_close_and_add_labels_never_replace_unrelated_labels(self) -> None:
        with patch.object(self.github, "api", return_value={"state": "closed"}) as api:
            self.github.close_issue(35)
            self.assertEqual(api.call_args.args, ("issues/35", "PATCH", {"state": "closed", "state_reason": "completed"}))
            self.github.add_labels(35, ["pipeline:blocked"])
            self.assertEqual(api.call_args.args, ("issues/35/labels", "POST", {"labels": ["pipeline:blocked"]}))

    @staticmethod
    def status(context="agenc/pipeline", state="success", identity=17, creator=23):
        return {"id": identity, "creator": {"id": creator}, "context": context, "state": state,
                "description": "Reviewed exact commit", "target_url": "https://example.invalid/receipt"}

    def checks(self, *, checks=None, statuses=None, workflows=None, jobs=None):
        def response(path, member=None):
            if "/check-runs" in path:
                return checks or []
            if "/statuses" in path:
                return statuses or []
            if "/jobs" in path:
                return jobs or []
            if path.startswith("actions/runs?"):
                return workflows or []
            self.fail(f"unexpected path {path}")
        with patch.object(self.github, "_pages", side_effect=response):
            return self.github.hosted_checks(SHA)

    def test_empty_hosted_state_is_never_passing(self) -> None:
        summary = self.checks()
        self.assertEqual(summary["state"], "empty")
        self.assertFalse(summary["blocking"])

    def test_zero_job_startup_failure_is_retained_and_never_passing(self) -> None:
        workflow = {"id": 123, "head_sha": SHA, "status": "completed", "conclusion": "startup_failure"}
        summary = self.checks(workflows=[workflow])
        self.assertEqual(summary["state"], "startup_failure")
        self.assertFalse(summary["blocking"])
        self.assertEqual(summary["startup_failures"], [workflow])
        self.assertEqual(self.checks(workflows=[workflow], jobs=[{"id": 1}])["state"], "failed")

    def test_actual_failed_checks_block_even_with_startup_failure(self) -> None:
        workflow = {"id": 123, "head_sha": SHA, "status": "completed", "conclusion": "startup_failure"}
        check = {"name": "test", "head_sha": SHA, "status": "completed", "conclusion": "failure"}
        summary = self.checks(checks=[check], workflows=[workflow])
        self.assertEqual(summary["state"], "failed")
        self.assertTrue(summary["blocking"])
        self.assertEqual(len(summary["startup_failures"]), 1)

    def test_successful_workflow_without_actual_jobs_is_not_passing(self) -> None:
        workflow = {"id": 123, "head_sha": SHA, "status": "completed", "conclusion": "success"}
        self.assertEqual(self.checks(workflows=[workflow])["state"], "incomplete")
        job = {"id": 1, "status": "completed", "conclusion": "success"}
        self.assertEqual(self.checks(workflows=[workflow], jobs=[job])["state"], "passed")
        job["conclusion"] = "failure"
        self.assertEqual(self.checks(workflows=[workflow], jobs=[job])["state"], "failed")

    def test_pending_skipped_and_successful_checks_are_distinct(self) -> None:
        check = {"name": "test", "head_sha": SHA, "status": "in_progress", "conclusion": None}
        self.assertEqual(self.checks(checks=[check])["state"], "pending")
        check.update(status="completed", conclusion="skipped")
        self.assertEqual(self.checks(checks=[check])["state"], "incomplete")
        check["conclusion"] = "success"
        self.assertEqual(self.checks(checks=[check])["state"], "passed")

    def test_latest_external_status_wins_for_both_orderings_without_name_exemptions(self) -> None:
        for name in ("ci", "agenc-pipeline/recorded-gate", "agenc-pipeline/independent-review"):
            for adverse, expected in (("failure", "failed"), ("pending", "pending"), ("error", "failed")):
                success = self.status(context=name, state="success", identity=18, creator=24)
                failure = self.status(context=name, state=adverse, identity=17, creator=23)
                for rows, state in (([failure, success], expected), ([success, failure], "passed")):
                    with self.subTest(name=name, ordering=[row["state"] for row in rows]):
                        summary = self.checks(statuses=rows)
                        self.assertEqual(summary["state"], state)
                        self.assertEqual(summary["blocking"], state != "passed")
                        self.assertEqual(summary["statuses"], rows[:1])

    def test_status_from_another_context_is_never_superseded(self) -> None:
        for adverse, expected in (("failure", "failed"), ("pending", "pending")):
            for rows in ([self.status(), self.status(context="external/ci", state=adverse)],
                         [self.status(context="external/ci", state=adverse), self.status()]):
                with self.subTest(ordering=[row["context"] for row in rows], state=adverse):
                    summary = self.checks(statuses=rows)
                    self.assertEqual(summary["state"], expected)
                    self.assertTrue(summary["blocking"])
                    self.assertEqual(len(summary["statuses"]), 2)

    def test_same_named_check_runs_are_always_classified_and_source_checked(self) -> None:
        for name in ("agenc-pipeline/recorded-gate", "agenc-pipeline/independent-review"):
            success = self.status(context=name)
            for status, conclusion, expected in (("completed", "failure", "failed"),
                                                   ("in_progress", None, "pending"),
                                                   ("completed", "skipped", "incomplete"),
                                                   ("completed", "success", "passed")):
                with self.subTest(name=name, status=status, conclusion=conclusion):
                    check = {"name": name, "head_sha": SHA, "status": status, "conclusion": conclusion}
                    summary = self.checks(checks=[check], statuses=[success])
                    self.assertEqual(summary["state"], expected)
                    self.assertEqual(summary["blocking"], expected != "passed")
                    self.assertEqual(summary["checks"], [check])
            with self.subTest(name=name, source="foreign"), self.assertRaises(GithubError):
                self.checks(checks=[{"name": name, "head_sha": OTHER}])

    def test_commit_status_reader_has_no_local_publication_or_exemption_api(self) -> None:
        self.assertFalse(hasattr(self.github, "set_status"))
        with patch.object(self.github, "_pages") as pages:
            with self.assertRaises(TypeError):
                self.github.hosted_checks(SHA, published_statuses=[])
            pages.assert_not_called()

    def test_mismatched_check_or_workflow_sha_fails_closed(self) -> None:
        with self.assertRaises(GithubError):
            self.checks(checks=[{"name": "test", "head_sha": OTHER}])
        with self.assertRaises(GithubError):
            self.checks(workflows=[{"id": 1, "head_sha": OTHER}])


if __name__ == "__main__":
    unittest.main()
