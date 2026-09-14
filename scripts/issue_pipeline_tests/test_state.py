"""Crash, concurrency and exact-source tests for the durable scheduler store."""

import json
import multiprocessing
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from issue_pipeline.state import ClaimConflict, State, StateError, SupervisorLock


def crash_after_commit(path):
    state = State(path)
    state.set_task(36, "merging", {"worktree": "/owned/issue-36", "pr": 90, "pid": 123})
    state.claim(36, ("normative",), ("docs/spec.md",), "run-1")
    state.add_receipt(36, "gate", "a" * 40, "b" * 40, "c" * 40,
                      {"log": "d" * 64}, "passed")
    os._exit(17)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "state.sqlite3"
        self.state = State(self.path)
        for issue in (36, 41):
            self.state.set_task(issue, "pending", {"issue": issue})

    def tearDown(self):
        self.state.close()
        self.temporary.cleanup()

    def test_task_metadata_survives_phase_change_and_reopen(self):
        self.state.set_task(36, "working", {"worktree": "owned", "checklist": [True, False]})
        self.state.set_task(36, "reviewing")
        with State(self.path) as other:
            record = other.get_task(36)
            self.assertEqual(record["status"], "reviewing")
            self.assertEqual(record["data"]["checklist"], [True, False])
            self.assertEqual(len(other.list_tasks("reviewing")), 1)
            self.assertEqual(other.connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(other.connection.execute("PRAGMA synchronous").fetchone()[0], 2)

    def test_invalid_status_numbers_and_nonfinite_metadata_refused(self):
        with self.assertRaises(StateError):
            self.state.set_task(True, "pending")
        with self.assertRaises(StateError):
            self.state.set_task(36, "almost complete")
        with self.assertRaises(StateError):
            self.state.set_task(36, "working", {"bad": float("nan")})
        self.assertEqual(self.state.get_task(36)["status"], "pending")

    def test_claims_augment_without_releasing_original_scope(self):
        self.state.claim(36, ("normative",), owner="worker-a")
        self.state.claim(36, ("normative", "catalog"), ("docs/spec.md",), "worker-a")
        self.state.claim(36, ("normative",), ("docs/spec.md",), "worker-a")
        self.assertEqual(len(self.state.claims()), 4)
        with self.assertRaises(ClaimConflict):
            self.state.claim(41, ("normative",), owner="worker-b")
        with self.assertRaises(ClaimConflict):
            self.state.claim(36, ("unused",), owner="worker-b")

    def test_failed_multi_claim_does_not_partially_acquire(self):
        self.state.claim(36, ("owned",), ("crates/runtime",))
        with self.assertRaises(ClaimConflict):
            self.state.claim(41, ("available",), ("crates/runtime/src/lib.rs",))
        self.assertFalse(any(claim["issue"] == 41 for claim in self.state.claims()))
        self.state.claim(41, ("available",), ("crates/runtime-other/src/lib.rs",))

    def test_ancestor_and_descendant_file_claims_both_conflict(self):
        self.state.claim(36, files=("crates/runtime/src/lib.rs",))
        with self.assertRaises(ClaimConflict):
            self.state.claim(41, files=("crates/runtime",))
        with self.assertRaises(ClaimConflict):
            self.state.claim(41, files=("crates/runtime/src/lib.rs",))

    def test_path_escape_and_aliases_refused(self):
        for path in ("../secret", "/absolute", "./src/lib.rs", "src//lib.rs", "src/../lib.rs",
                     "src\\lib.rs", ".", "src/", "bad\x00path"):
            with self.subTest(path=path):
                with self.assertRaises(StateError):
                    self.state.claim(36, files=(path,))

    def test_empty_claim_still_prevents_duplicate_issue_owners(self):
        self.state.claim(36, owner="first")
        with self.assertRaises(ClaimConflict):
            self.state.claim(36, owner="second")

    def test_concurrent_claims_have_exactly_one_winner(self):
        barrier = threading.Barrier(2)

        def attempt(issue):
            with State(self.path) as connection:
                barrier.wait(timeout=5)
                try:
                    connection.claim(issue, ("shared",), ("docs/spec.md",))
                    return "won"
                except ClaimConflict:
                    return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(attempt, 36)
            second = pool.submit(attempt, 41)
            self.assertEqual(sorted([first.result(timeout=10), second.result(timeout=10)]),
                             ["conflict", "won"])
        self.assertEqual(len({claim["issue"] for claim in self.state.claims()}), 1)

    def test_release_requires_matching_explicit_owner(self):
        self.state.claim(36, ("scope",), owner="first")
        with self.assertRaises(ClaimConflict):
            self.state.release(36, "second")
        self.state.release(36, "first")
        self.state.claim(41, ("scope",))

    def test_crash_recovery_preserves_claims_worktree_and_source_receipts(self):
        process = multiprocessing.get_context("spawn").Process(target=crash_after_commit,
                                                                args=(str(self.path),))
        process.start()
        process.join(timeout=15)
        self.assertEqual(process.exitcode, 17)
        recovered = self.state.recover_interrupted()
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["status"], "pending")
        self.assertEqual(recovered[0]["interrupted_from"], "merging")
        self.assertEqual(recovered[0]["data"]["worktree"], "/owned/issue-36")
        self.assertEqual(self.state.receipts(36)[0]["source"], "a" * 40)
        self.assertTrue(self.state.claims())
        self.assertEqual(self.state.recover_interrupted()[0]["interrupted_from"], "merging")
        self.state.set_task(36, "reviewing")
        self.assertIsNone(self.state.get_task(36)["interrupted_from"])

    def test_complete_and_blocked_tasks_are_not_restarted(self):
        self.state.set_task(36, "complete")
        self.state.set_task(41, "blocked", {"reason": "external evidence"})
        self.assertEqual(self.state.recover_interrupted(), [])

    def test_receipts_are_source_bound_immutable_and_idempotent(self):
        args = (36, "review", "a" * 40, "b" * 40, "c" * 40, {"review": "d" * 64}, "passed")
        first = self.state.add_receipt(*args, data={"findings": []})
        self.assertEqual(first, self.state.add_receipt(*args, data={"findings": []}))
        second = self.state.add_receipt(36, "review", "e" * 40, "b" * 40, "c" * 40,
                                        {"review": "d" * 64}, "passed", {"findings": []})
        self.assertNotEqual(first["digest"], second["digest"])
        self.assertEqual(len(self.state.receipts(36, "review")), 2)
        with self.assertRaises(sqlite3.IntegrityError):
            self.state.connection.execute("UPDATE receipts SET source=?", ("f" * 40,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.state.connection.execute("DELETE FROM receipts")

    def test_unbound_receipts_refused(self):
        for source, artifacts, status in (("short", {"log": "d" * 64}, "passed"),
                                           ("a" * 40, {}, "passed"),
                                           ("a" * 40, {"log": "short"}, "passed"),
                                           ("a" * 40, {"log": "d" * 64}, "claimed")):
            with self.subTest(source=source, artifacts=artifacts, status=status):
                with self.assertRaises(StateError):
                    self.state.add_receipt(36, "gate", source, "b" * 40, "c" * 40,
                                           artifacts, status)
        self.assertEqual(self.state.receipts(36), [])

    def test_supervisor_lock_excludes_second_owner_and_releases_on_close(self):
        path = Path(self.temporary.name) / "supervisor.lock"
        with SupervisorLock(path):
            record = json.loads(path.read_text())
            self.assertEqual(record["pid"], os.getpid())
            with self.assertRaises(ClaimConflict):
                with SupervisorLock(path):
                    self.fail("second owner admitted")
        with SupervisorLock(path):
            pass


if __name__ == "__main__":
    unittest.main()
