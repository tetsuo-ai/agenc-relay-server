"""Aggregate acceptance retries retain independent comment dispatch authority."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from issue_pipeline import controller as controller_module
from issue_pipeline.controller import PipelineBlocked
from issue_pipeline.github import GithubError
from issue_pipeline_tests import test_aggregate_closure as aggregates
from issue_pipeline_tests import test_cli as operator
from issue_pipeline_tests import test_controller as fixture


class Crash(BaseException):
    pass


class AggregateCommentRetryTests(unittest.TestCase):
    setUp = fixture.ControllerTests.setUp
    accepted_fixture = fixture.ControllerTests.accepted_fixture
    ready = aggregates.AggregateClosureTests.ready
    update = aggregates.AggregateClosureTests.update
    entry = aggregates.AggregateClosureTests.entry
    restart = aggregates.AggregateClosureTests.restart

    def retry_invalidated(self):
        config = self.config.state.parent / "operator.toml"
        config.write_text("version = 1\nstate_dir = " + json.dumps(str(self.config.state)) + "\n")
        for number in (13, 35):
            row = self.controller.state.get_task(number)
            if row and row["status"] == "blocked" and row["data"]["aggregate_closure"]["stage"] == "invalidated":
                original = copy.deepcopy(row["data"]["aggregate_closure"])
                with mock.patch.object(sys, "argv", [str(operator.CLI_PATH), "--config", str(config), "retry", str(number)]), \
                        redirect_stdout(io.StringIO()):
                    self.assertEqual(operator.cli.main(), 0)
                current = self.controller.state.get_task(number)
                self.assertEqual(current["status"], "pending")
                self.assertEqual(current["data"]["aggregate_closure"], original)

    def recover(self):
        with mock.patch("issue_pipeline.controller.halt_children"):
            self.controller.recover()

    def start_delay(self, number):
        self.ready()
        comment, queued = self.github.comment, []

        def delayed(target, body):
            if target == number and "<!-- agenc-pipeline-aggregate:" in body:
                queued.append((target, body))
                raise OSError("POST accepted for delayed publication; response lost")
            return comment(target, body)

        with mock.patch.object(self.github, "comment", side_effect=delayed), self.assertRaises(PipelineBlocked):
            self.update()
        self.assertEqual(self.entry(number)["stage"], "commenting")
        self.assertEqual(len(queued), 1)
        return comment, queued, delayed

    def invalidate_restore_retry(self, number):
        original = self.github.issues[number]["body"]
        self.github.issues[number]["body"] += "\nChanged aggregate acceptance."
        self.restart()
        with self.assertRaises(PipelineBlocked):
            self.recover()
        self.assertEqual(self.entry(number)["stage"], "invalidated")
        self.github.issues[number]["body"] = original
        self.retry_invalidated()
        self.restart()

    def comment_journal(self, number):
        marker = "<!-- agenc-pipeline-aggregate:" + self.entry(number)["intent"] + " -->"
        found = [p.parent for p in (self.config.state / "comment-publications").glob("*/intent.json")
                 if json.loads(p.read_text())["marker"] == marker]
        self.assertEqual(len(found), 1)
        return found[0]

    def delayed_retry(self, number):
        comment, queued, delayed = self.start_delay(number)
        intent = self.entry(number)["intent"]
        original = {name: self.controller.state.receipts(number, name)
                    for name in ("aggregate-preparation", "aggregate-intent")}
        directory = self.comment_journal(number)
        journals = {p: p.read_bytes() for p in directory.iterdir()}
        self.invalidate_restore_retry(number)
        for _ in range(2):
            with mock.patch.object(self.github, "comment", side_effect=delayed), self.assertRaises(PipelineBlocked):
                self.recover()
            self.restart()
        self.assertEqual(len(queued), 1, "CLI retry repeated a delayed aggregate POST")
        self.assertEqual({p: p.read_bytes() for p in journals}, journals)
        self.assertEqual(self.entry(number)["intent"], intent)
        self.assertFalse(self.entry(number)["close_attempted"])
        self.assertEqual({name: self.controller.state.receipts(number, name) for name in original}, original)
        # Only the original delayed request becomes visible. Its fixed ID is
        # adopted after another real operator retry/restart, never reposted.
        visible = comment(*queued[0])
        self.retry_invalidated()
        self.restart()
        with mock.patch.object(self.github, "comment", wraps=comment) as post:
            self.recover()
        self.assertFalse(any(c.args[0] == number and "agenc-pipeline-aggregate:" in c.args[1]
                             for c in post.call_args_list))
        self.assertEqual(self.entry(number)["intent"], intent)
        self.assertEqual(self.entry(number)["stage"], "complete")
        self.assertEqual(self.controller.state.get_task(number)["status"], "complete")
        accepted = json.loads((directory / "accepted.json").read_text())
        self.assertEqual(accepted["comment_id"], visible["id"])
        self.assertEqual(len([r for r in self.github.comments(number) if intent in r["body"]]), 1)
        self.assertEqual(self.github.close_calls, [13, 35])

    def test_legacy_delayed_comment_survives_invalidation_cli_retry_and_restart(self):
        self.delayed_retry(13)

    def test_master_delayed_comment_survives_invalidation_cli_retry_and_restart(self):
        self.delayed_retry(35)

    def missing_journal(self, number):
        comment, queued, delayed = self.start_delay(number)
        intent = self.entry(number)["intent"]
        directory = self.comment_journal(number)
        for p in directory.iterdir():
            p.unlink()
        directory.rmdir()
        self.invalidate_restore_retry(number)
        for visible in (False, True):
            if visible:
                comment(*queued[0])
            with mock.patch.object(self.github, "comment", side_effect=delayed), \
                    self.assertRaisesRegex(PipelineBlocked, "lacks its required original intent"):
                self.recover()
            self.assertEqual(len(queued), 1)
            self.assertFalse(directory.exists(), "missing retained authority must not be silently recreated")
            self.assertEqual(self.entry(number)["intent"], intent)
            self.assertFalse(self.entry(number)["close_attempted"])
            self.assertEqual(self.controller.state.get_task(number)["status"], "blocked")
            self.restart()

    def test_legacy_retained_intent_without_comment_journal_never_authorizes_new_post(self):
        self.missing_journal(13)

    def test_master_retained_intent_without_comment_journal_never_authorizes_new_post(self):
        self.missing_journal(35)

    def preparation_crash(self, after_prepare):
        self.ready()
        ensure = controller_module.ensure_comment

        def interrupted(*args, **kwargs):
            if kwargs.get("prepare_only") and args[2] == 13:
                if after_prepare:
                    ensure(*args, **kwargs)
                raise Crash("between aggregate receipt and parent intent checkpoint")
            return ensure(*args, **kwargs)

        with mock.patch.object(controller_module, "ensure_comment", side_effect=interrupted), \
                self.assertRaises(Crash):
            self.update()
        self.assertIsNone(self.entry(13)["intent"])
        receipts = self.controller.state.receipts(13, "aggregate-intent")
        self.assertEqual(len(receipts), 1)
        self.assertEqual(self.github.comments(13), [])
        original = receipts[0]["digest"]
        self.restart()
        with mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
            self.recover()
        self.assertEqual(sum(c.args[0] == 13 for c in post.call_args_list), 1)
        self.assertEqual(self.entry(13)["intent"], original)
        self.assertEqual(self.controller.state.receipts(13, "aggregate-intent"), receipts)
        self.assertEqual(self.github.close_calls, [13, 35])

    def test_crash_after_aggregate_receipt_before_comment_preparation_reuses_exact_intent(self):
        self.preparation_crash(after_prepare=False)

    def test_crash_after_comment_preparation_before_parent_checkpoint_sends_once(self):
        self.preparation_crash(after_prepare=True)

    def test_comment_transport_uncertainty_after_retry_retains_dispatch_and_closure_proofs(self):
        comment, queued, _ = self.start_delay(13)
        self.invalidate_restore_retry(13)
        directory = self.comment_journal(13)
        journals = {p: p.read_bytes() for p in directory.iterdir()}
        intent = self.entry(13)["intent"]
        comments = self.github.comments

        def unavailable(number):
            if number == 13:
                raise GithubError("comment collection transport unavailable")
            return comments(number)

        with mock.patch.object(self.github, "comments", side_effect=unavailable), \
                mock.patch.object(self.github, "comment", wraps=comment) as post, \
                self.assertRaisesRegex(PipelineBlocked, "transport unavailable"):
            self.recover()
        post.assert_not_called()
        self.assertEqual(self.entry(13)["intent"], intent)
        self.assertEqual(self.entry(13)["stage"], "commenting")
        self.assertFalse(self.entry(13)["close_attempted"])
        self.assertEqual({p: p.read_bytes() for p in journals}, journals)
        comment(*queued[0])
        self.retry_invalidated()
        self.restart()
        self.recover()
        self.assertEqual(self.github.close_calls, [13, 35])

    def lost_close(self, number):
        self.ready()
        close = self.github.close_issue

        def lost(target):
            close(target)
            if target == number:
                raise OSError("owned close applied but response was lost")

        with mock.patch.object(self.github, "close_issue", side_effect=lost), self.assertRaises(PipelineBlocked):
            self.update()
        self.assertTrue(self.entry(number)["close_attempted"])
        self.assertEqual(self.entry(number)["stage"], "closing")
        self.assertEqual(self.github.issues[number]["state"], "closed")
        self.assertIsNone(self.entry(number)["terminal"])
        return self.entry(number)["intent"]

    def confirmed_comment_change(self, number, *, duplicate):
        intent = self.lost_close(number)
        row = next(r for r in self.github.comment_rows[number] if intent in r["body"])
        if duplicate:
            self.github.comment(number, row["body"])
        else:
            row["body"] += "\nAltered published acceptance evidence."
        self.restart()
        with mock.patch.object(self.github, "comment", wraps=self.github.comment) as post, \
                self.assertRaises(PipelineBlocked):
            self.recover()
        post.assert_not_called()
        self.assertEqual(self.entry(number)["intent"], intent)
        self.assertEqual(self.entry(number)["stage"], "invalidated")
        self.assertEqual(self.github.issues[number]["state"], "open")
        self.assertIsNone(self.entry(number)["terminal"])
        self.assertEqual(self.controller.state.get_task(number)["status"], "blocked")

    def test_altered_legacy_comment_reopens_owned_uncertain_close_without_new_terminal(self):
        self.confirmed_comment_change(13, duplicate=False)

    def test_duplicate_master_comment_reopens_owned_uncertain_close_without_new_terminal(self):
        self.confirmed_comment_change(35, duplicate=True)

    def test_comment_transport_during_uncertain_close_blocks_without_reopening_or_accepting(self):
        intent = self.lost_close(13)
        comments = self.github.comments

        def unavailable(number):
            if number == 13:
                raise GithubError("comment read transport unavailable")
            return comments(number)

        self.restart()
        with mock.patch.object(self.github, "comments", side_effect=unavailable), \
                self.assertRaisesRegex(PipelineBlocked, "transport unavailable"):
            self.recover()
        self.assertEqual(self.entry(13)["intent"], intent)
        self.assertEqual(self.entry(13)["stage"], "commenting")
        self.assertEqual(self.github.issues[13]["state"], "closed")
        self.assertIsNone(self.entry(13)["terminal"])
        self.assertEqual(self.controller.state.get_task(13)["status"], "blocked")
        self.restart()
        with mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
            self.recover()
        self.assertFalse(any(c.args[0] == 13 for c in post.call_args_list))
        self.assertEqual(self.github.close_calls, [13, 35])
        self.assertEqual(self.entry(13)["stage"], "complete")


if __name__ == "__main__":
    unittest.main()
