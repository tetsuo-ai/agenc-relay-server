"""Comment publication recovery uses real local Git/SQLite and delayed provider writes."""
from __future__ import annotations

import json
import threading
import unittest
from unittest import mock

from issue_pipeline.controller import Controller, PipelineBlocked
from issue_pipeline_tests import test_controller as fixture


class Crash(BaseException):
    pass


class CommentPublicationTests(unittest.TestCase):
    setUp = fixture.ControllerTests.setUp

    def restart(self):
        self.controller = Controller(self.config, repo=self.repo, github=self.github,
                                     runner=self.runner, gate=self.gate)
        self.addCleanup(self.controller.state.close)
        self.controller.log = mock.Mock()

    def delayed_publication(self, master):
        queued = []
        comment = self.github.comment
        marker = "<!-- agenc-pipeline-completion:fixture-proof -->"

        def publish(number, body):
            queued.append((number, body))
            raise OSError("request outcome unknown; publication is delayed")

        def invoke():
            if master:
                self.controller.write_master_status(self.github.graph, set())
            else:
                self.controller.comment_once(36, marker, "Accepted original evidence.")

        with mock.patch.object(self.github, "comment", side_effect=publish):
            with self.assertRaises(Exception):
                invoke()
            self.restart()
            with self.assertRaises(Exception):
                invoke()
        self.assertEqual(len(queued), 1, "restart repeated an uncertain comment POST")
        number, original_body = queued[0]
        comment(number, original_body)
        with mock.patch.object(self.github, "comment", wraps=comment) as post:
            invoke()
            post.assert_not_called()
        self.assertEqual(len(self.github.comments(number)), 1)

    def test_delayed_master_status_is_not_posted_again_after_restart(self):
        self.delayed_publication(master=True)

    def test_delayed_completion_comment_is_not_posted_again_after_restart(self):
        self.delayed_publication(master=False)

    def once(self, *, external=False, body="Accepted original evidence."):
        marker = "<!-- agenc-pipeline-" + ("external:" if external else "completion:") + "fixture-proof -->"
        self.controller.comment_once(36, marker, body)

    def journal(self):
        paths = list((self.config.state / "comment-publications").glob("*/intent.json"))
        self.assertEqual(len(paths), 1)
        return paths[0].parent, json.loads(paths[0].read_text())

    def test_successful_external_comment_binds_source_body_marker_and_fixed_identity(self):
        self.once(external=True)
        directory, intent = self.journal()
        self.assertEqual(intent["source"], self.base)
        self.assertEqual(intent["repository"], self.config.repository)
        self.assertEqual(intent["issue"], 36)
        self.assertIn("agenc-pipeline-external:", intent["marker"])
        self.assertEqual(intent["body"], self.github.comments(36)[0]["body"])
        self.assertEqual(json.loads((directory / "accepted.json").read_text())["comment_id"], 1)
        for path in directory.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.restart()
        with mock.patch.object(self.controller, "fetch", side_effect=AssertionError("unneeded source fetch")), \
                mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
            self.once(external=True)
            post.assert_not_called()

    def test_changed_status_waits_for_original_creation_then_patches_fixed_id(self):
        queued = []
        comment = self.github.comment

        def delayed(number, body):
            queued.append((number, body))
            raise OSError("uncertain status creation")

        with mock.patch.object(self.github, "comment", side_effect=delayed):
            with self.assertRaises(OSError):
                self.controller.write_master_status(self.github.graph, set(), source=self.base)
        directory, intent = self.journal()
        self.restart()
        with self.assertRaisesRegex(PipelineBlocked, "uncertain"):
            self.controller.write_master_status(self.github.graph, {36}, source="f" * 40)
        self.assertEqual(json.loads((directory / "intent.json").read_text()), intent)
        comment(*queued[0])
        with mock.patch.object(self.github, "comment", wraps=comment) as post:
            self.controller.write_master_status(self.github.graph, {36}, source="f" * 40)
            post.assert_not_called()
        self.assertIn("- [x] #36", self.github.comments(35)[0]["body"])
        self.assertEqual(self.github.comments(35)[0]["id"], 1)
        self.assertEqual(json.loads((directory / "intent.json").read_text()), intent)

    def crash_during_write(self, name):
        from issue_pipeline import comments
        write = comments._write

        def crash(path, value):
            write(path, value)
            if path.name == name:
                raise Crash()

        with mock.patch.object(comments, "_write", side_effect=crash), \
                mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
            with self.assertRaises(Crash):
                self.once()
            posts = post.call_count
        self.restart()
        return posts

    def test_crash_after_preparation_before_dispatch_can_send_once(self):
        self.assertEqual(self.crash_during_write("intent.json"), 0)
        with mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
            self.once()
            self.assertEqual(post.call_count, 1)

    def test_crash_after_dispatch_before_send_never_assumes_post_did_not_happen(self):
        self.assertEqual(self.crash_during_write("dispatch.json"), 0)
        with mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
            with self.assertRaisesRegex(PipelineBlocked, "uncertain"):
                self.once()
            post.assert_not_called()

    def test_durability_failure_prevents_post(self):
        with mock.patch("issue_pipeline.comments.os.fsync", side_effect=OSError("durability unavailable")), \
                mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
            with self.assertRaisesRegex(OSError, "durability unavailable"):
                self.once()
            post.assert_not_called()

    def test_crash_after_accepted_readback_reuses_receipt_without_post(self):
        self.assertEqual(self.crash_during_write("accepted.json"), 1)
        with mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
            self.once()
            post.assert_not_called()

    def test_crash_after_actual_send_reconciles_original_marker(self):
        comment = self.github.comment

        def crash(number, body):
            comment(number, body)
            raise Crash()

        with mock.patch.object(self.github, "comment", side_effect=crash):
            with self.assertRaises(Crash):
                self.once()
        self.restart()
        with mock.patch.object(self.github, "comment", wraps=comment) as post:
            self.once()
            post.assert_not_called()
        self.assertEqual(len(self.github.comments(36)), 1)

    def test_post_reply_alone_cannot_accept_without_exact_collection_readback(self):
        with mock.patch.object(self.github, "comment", return_value={"id": 1, "body": "not yet visible"}) as post:
            with self.assertRaisesRegex(PipelineBlocked, "readback"):
                self.once()
            self.restart()
            with self.assertRaisesRegex(PipelineBlocked, "uncertain"):
                self.once()
            self.assertEqual(post.call_count, 1)

    def test_existing_exact_comment_is_recorded_without_reposting(self):
        body = "Accepted original evidence.\n\n<!-- agenc-pipeline-completion:fixture-proof -->"
        self.github.comment(36, body)
        with mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
            self.once()
            post.assert_not_called()
        directory, intent = self.journal()
        self.assertEqual(intent["body"], body)
        self.assertFalse((directory / "dispatch.json").exists())
        self.assertTrue((directory / "accepted.json").exists())

    def test_existing_mutable_status_is_bound_before_patch_without_post(self):
        original = "<!-- agenc-pipeline-live-status -->\nOlder execution status.\n"
        self.github.comment(35, original)
        with mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
            self.controller.write_master_status(self.github.graph, set(), source=self.base)
            post.assert_not_called()
        _, intent = self.journal()
        self.assertEqual(intent["body"], original)
        self.assertIn("Automated execution status", self.github.comments(35)[0]["body"])

    def test_unrelated_marker_does_not_satisfy_publication(self):
        unrelated = self.github.comment(36, "Other evidence.\n\n<!-- agenc-pipeline-completion:other-proof -->")
        self.once()
        self.assertEqual(self.github.comments(36)[0], unrelated)
        self.assertEqual(len(self.github.comments(36)), 2)

    def test_existing_same_marker_wrong_body_or_duplicate_refuses_post(self):
        marker = "<!-- agenc-pipeline-completion:fixture-proof -->"
        self.github.comment(36, "Unaccepted replacement.\n\n" + marker)
        with mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
            with self.assertRaisesRegex(PipelineBlocked, "exact intended body"):
                self.once()
            post.assert_not_called()
        self.github.comment(36, "Accepted original evidence.\n\n" + marker)
        with self.assertRaisesRegex(PipelineBlocked, "duplicate"):
            self.once()

    def test_accepted_comment_cannot_be_deleted_or_replaced_to_authorize_new_post(self):
        self.once()
        original = self.github.comments(36)[0]
        for changed in ([], [{**original, "id": 99}], [{**original, "body": "Changed\n" + original["body"]}]):
            self.github.comment_rows[36] = changed
            with self.subTest(changed=changed), mock.patch.object(self.github, "comment", wraps=self.github.comment) as post:
                with self.assertRaisesRegex(PipelineBlocked, "absent or changed"):
                    self.once()
                post.assert_not_called()

    def test_changed_request_or_boolean_dispatch_version_cannot_rebind_intent(self):
        self.crash_during_write("dispatch.json")
        directory, intent = self.journal()
        with self.assertRaisesRegex(PipelineBlocked, "original source/marker/body"):
            self.once(body="New acceptance.")
        path = directory / "dispatch.json"
        record = json.loads(path.read_text())
        record["version"] = True
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(PipelineBlocked, "dispatch differs"):
            self.once()
        self.assertEqual(json.loads((directory / "intent.json").read_text()), intent)

    def test_concurrent_comment_call_waits_for_original_creation(self):
        entered, release = threading.Event(), threading.Event()
        comment = self.github.comment
        outcomes = []

        def delayed(number, body):
            entered.set()
            if not release.wait(3):
                raise AssertionError("test did not release original publication")
            return comment(number, body)

        def call():
            try:
                self.once()
            except BaseException as error:
                outcomes.append(error)

        with mock.patch.object(self.github, "comment", side_effect=delayed) as post:
            first = threading.Thread(target=call)
            second = threading.Thread(target=call)
            first.start()
            self.assertTrue(entered.wait(3))
            second.start()
            release.set()
            first.join(3)
            second.join(3)
            self.assertFalse(first.is_alive() or second.is_alive())
            self.assertEqual(outcomes, [])
            self.assertEqual(post.call_count, 1)
