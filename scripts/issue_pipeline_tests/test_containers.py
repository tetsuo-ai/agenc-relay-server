"""Offline Docker recovery: all daemon calls are mocked, all records temporary."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from issue_pipeline import containers
from issue_pipeline.containers import ContainerError, container_cleanup_complete, load_container_record
from issue_pipeline.containers import record_created_container, stop_owned_container
from issue_pipeline.gitops import GitError

SOURCE = "a" * 40
IMAGE = "sha256:" + "b" * 64
IDENTITY = "c" * 64
FOREIGN = "d" * 64
UNIT_NAME = "agenc-ircd-pipeline-gate-" + "e" * 32


class DockerFixture:
    """A stateful mocked daemon that never invokes an actual Docker executable."""
    def __init__(self, record):
        self.record = record
        self.present = True
        self.running = True
        self.paused = False
        self.restarting = False
        self.stop_effect = True
        self.kill_effect = True
        self.rm_effect = True
        self.stop_error = False
        self.kill_error = False
        self.rm_error = False
        self.daemon_error = False
        self.inspect_error = False
        self.autoremove_on_inspect = False
        self.replacement = False
        self.inspect_changes = {}
        self.calls = []

    def inspect(self):
        return {"id": IDENTITY, "name": "/" + self.record["name"], "image": IMAGE,
                "labels": dict(self.record["labels"]), "running": self.running,
                "paused": self.paused, "restarting": self.restarting,
                "status": "running" if self.running else "exited", **self.inspect_changes}

    def run(self, argv, cwd, timeout, *, environment):
        self.calls.append((argv, cwd, timeout, environment))
        assert argv[:3] == [containers.DOCKER, "--host", containers.DOCKER_HOST]
        assert timeout > 0 and timeout <= 12
        args = argv[3:]
        if args[:2] == ["container", "ls"]:
            if self.daemon_error:
                return 1, "DO_NOT_ECHO_DAEMON_SECRET"
            query = args[args.index("--filter") + 1]
            identity = IDENTITY if self.present else FOREIGN if self.replacement and query.startswith("name=") else None
            return 0, json.dumps(identity) + "\n" if identity else ""
        if args[:2] == ["container", "inspect"]:
            assert args[-1] == IDENTITY
            if self.autoremove_on_inspect:
                self.present = False
            if not self.present or self.inspect_error:
                return 1, "DO_NOT_ECHO_INSPECT_SECRET"
            return 0, json.dumps(self.inspect())
        if args[:2] == ["container", "stop"]:
            assert args[-1] == IDENTITY
            if self.stop_effect:
                self.running = self.paused = self.restarting = False
            return (1 if self.stop_error else 0), ""
        if args[:2] == ["container", "kill"]:
            assert args[-1] == IDENTITY
            if self.kill_effect:
                self.running = self.paused = self.restarting = False
            return (1 if self.kill_error else 0), ""
        if args[:2] == ["container", "rm"]:
            assert args[-1] == IDENTITY
            if self.rm_effect:
                self.present = False
            return (1 if self.rm_error else 0), ""
        raise AssertionError("unexpected Docker command")

    @property
    def mutations(self):
        return [call[0][4] for call in self.calls if call[0][4] in {"stop", "kill", "rm"}]


class ContainerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agenc-container-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "state"
        self.attempt = self.state / "gates" / ("f" * 32)
        for path in (self.state, self.state / "gates", self.attempt):
            path.mkdir(mode=0o700)
        self.path = self.attempt / "container.json"
        self.record = {"version": 1, "backend": "docker", "name": UNIT_NAME, "image": IMAGE,
                       "source": SOURCE, "unit": UNIT_NAME + ".service", "state_dir": str(self.state),
                       "repository": "tetsuo-ai/agenc-ircd",
                       "private_home": str(self.state / "gate-cache" / "homes" / ("1" * 32)),
                       "labels": {"agenc-ircd.pipeline.state": str(self.state),
                                  "agenc-ircd.pipeline.source": SOURCE,
                                  "agenc-ircd.pipeline.unit": UNIT_NAME + ".service",
                                  "agenc-ircd.pipeline.purpose": "full-gate",
                                  "agenc-ircd.pipeline.repository": "tetsuo-ai/agenc-ircd"}}
        self.write()
        self.id_path = self.path.with_name("container-id.json")
        self.terminal = self.path.with_name("container-cleanup.json")
        self.id_path.write_text(json.dumps({"version": 1, "container_id": IDENTITY,
                                            "record_sha256": containers._record_digest(self.record)}))
        self.id_path.chmod(0o600)
        self.daemon = DockerFixture(self.record)
        self.process = mock.patch.object(containers, "_process", side_effect=self.daemon.run).start()
        self.addCleanup(mock.patch.stopall)

    def write(self, value=None):
        self.path.write_text(json.dumps(self.record if value is None else value))
        self.path.chmod(0o600)

    def cleanup(self):
        stop_owned_container(self.path, self.state)

    def test_valid_record_and_successful_stop_use_verified_immutable_id_only(self):
        self.assertEqual(load_container_record(self.path, self.state), self.record)
        self.cleanup()
        self.assertFalse(self.daemon.present)
        self.assertEqual(self.daemon.mutations, ["stop", "rm"])
        self.assertTrue(self.path.exists())
        for argv, cwd, timeout, environment in self.daemon.calls:
            self.assertEqual(cwd, self.state)
            self.assertEqual(environment["DOCKER_HOST"], "unix:///var/run/docker.sock")
            self.assertNotIn("DOCKER_CONTEXT", environment)
            self.assertNotIn("GH_TOKEN", environment)
            self.assertNotIn("OPENAI_API_KEY", environment)
            if argv[4] in {"stop", "kill", "rm"}:
                self.assertEqual(argv[-1], IDENTITY)
                self.assertNotIn(UNIT_NAME, argv)
                self.assertNotIn("--force", argv)

    def test_create_applied_without_cidfile_and_already_auto_removed_are_recoverable(self):
        self.assertFalse((self.attempt / "container.cid").exists())
        self.id_path.unlink()
        self.daemon.running = False
        self.daemon.inspect_changes = {"status": "created"}
        self.cleanup()
        self.daemon.calls.clear()
        self.cleanup()
        self.assertEqual(len(self.daemon.calls), 0)
        self.assertEqual(self.daemon.mutations, [])

    def test_authoritative_absence_is_not_inferred_from_daemon_error(self):
        self.daemon.present = False
        self.daemon.daemon_error = True
        with self.assertRaisesRegex(ContainerError, "absence is unproven") as error:
            self.cleanup()
        self.assertNotIn("SECRET", str(error.exception))
        self.assertEqual(self.daemon.mutations, [])

    def test_inspect_autoremove_race_requires_successful_id_absence_query(self):
        self.daemon.autoremove_on_inspect = True
        self.cleanup()
        self.assertEqual(self.daemon.mutations, [])
        self.assertTrue(any("id=" + IDENTITY in call[0] for call in self.daemon.calls))
        self.terminal.unlink()
        self.daemon.present = True
        self.daemon.autoremove_on_inspect = False
        self.daemon.inspect_error = True
        with self.assertRaisesRegex(ContainerError, "could not inspect"):
            self.cleanup()
        self.assertEqual(self.daemon.mutations, [])

    def test_failed_stop_escalates_to_kill_then_requires_removal_readback(self):
        self.daemon.stop_effect = False
        self.daemon.stop_error = True
        self.cleanup()
        self.assertEqual(self.daemon.mutations, ["stop", "kill", "rm"])
        self.assertFalse(self.daemon.present)

    def test_failed_stop_and_kill_cannot_claim_quiescence_or_remove_running_container(self):
        self.daemon.stop_effect = self.daemon.kill_effect = False
        self.daemon.stop_error = self.daemon.kill_error = True
        with self.assertRaisesRegex(ContainerError, "remains present or active"):
            self.cleanup()
        self.assertEqual(self.daemon.mutations, ["stop", "kill"] * 3)
        self.assertTrue(self.daemon.present)

    def test_applied_mutation_with_error_response_is_resolved_by_daemon_readback(self):
        self.daemon.stop_error = self.daemon.rm_error = True
        self.cleanup()
        self.assertFalse(self.daemon.present)
        self.assertEqual(self.daemon.mutations, ["stop", "rm"])

    def test_cli_timeout_after_applied_stop_is_read_back_without_echoing_credentials(self):
        original = self.daemon.run
        def timeout(argv, cwd, bound, *, environment):
            result = original(argv, cwd, bound, environment=environment)
            if argv[4] == "stop":
                raise GitError("SECRET_AUTH_DATA")
            return result
        self.process.side_effect = timeout
        self.cleanup()
        self.assertFalse(self.daemon.present)
        self.assertEqual(self.daemon.mutations, ["stop", "rm"])

    def test_removal_failure_preserves_uncertainty_and_does_not_claim_success(self):
        self.daemon.running = False
        self.daemon.rm_effect = False
        self.daemon.rm_error = True
        with self.assertRaisesRegex(ContainerError, "remains present or active"):
            self.cleanup()
        self.assertEqual(self.daemon.mutations, ["rm"] * 3)

    def test_reused_name_never_grants_authority_to_mutate_replacement(self):
        self.daemon.replacement = True
        self.cleanup()
        self.assertTrue(container_cleanup_complete(self.path, self.state))
        for argv, *_ in self.daemon.calls:
            if argv[4] in {"stop", "kill", "rm"}:
                self.assertEqual(argv[-1], IDENTITY)
                self.assertNotIn(FOREIGN, argv)

    def test_foreign_name_image_source_unit_and_state_labels_refuse_before_mutation(self):
        changes = [{"name": "/another-container"}, {"id": FOREIGN}, {"image": "sha256:" + "2" * 64}]
        changes += [{"labels": {**self.record["labels"], key: "foreign"}} for key in self.record["labels"]]
        for change in changes:
            with self.subTest(change=change):
                self.daemon.inspect_changes = change
                with self.assertRaisesRegex(ContainerError, "ownership record"):
                    self.cleanup()
        self.assertEqual(self.daemon.mutations, [])

    def test_paused_and_restarting_containers_are_active_even_without_running_flag(self):
        for field in ("paused", "restarting"):
            self.terminal.unlink(missing_ok=True)
            self.daemon.present = True
            self.daemon.running = False
            setattr(self.daemon, field, True)
            self.daemon.calls.clear()
            self.cleanup()
            self.assertEqual(self.daemon.mutations, ["stop", "rm"])

    def test_wrong_closed_schema_types_labels_and_private_home_refuse_before_daemon(self):
        variants = [{**self.record, "extra": "unsupported"}, {**self.record, "version": True},
                    {**self.record, "backend": "podman"}, {**self.record, "source": True},
                    {**self.record, "image": "ubuntu:latest"}, {**self.record, "name": "foreign"},
                    {**self.record, "unit": "foreign.service"}, {**self.record, "state_dir": str(self.root)},
                    {**self.record, "private_home": str(self.root / ("1" * 32))},
                    {**self.record, "labels": {**self.record["labels"], "extra": "unsupported"}}]
        for value in variants:
            with self.subTest(value=value):
                self.write(value)
                with self.assertRaises(ContainerError):
                    self.cleanup()
        self.process.assert_not_called()

    def test_duplicate_nonfinite_oversized_and_nonobject_record_refuse_before_daemon(self):
        for raw in ('{"version":1,"version":1}', '{"version":NaN}', '[]', '[' * 2000,
                    ' ' * (containers.RECORD_LIMIT + 1)):
            self.path.write_text(raw)
            with self.assertRaises(ContainerError):
                self.cleanup()
        self.process.assert_not_called()

    def test_symlink_public_record_and_foreign_directory_are_rejected(self):
        self.path.chmod(0o644)
        with self.assertRaises(ContainerError):
            self.cleanup()
        self.path.chmod(0o600)
        self.attempt.chmod(0o755)
        with self.assertRaises(ContainerError):
            self.cleanup()
        self.attempt.chmod(0o700)
        target = self.root / "record-copy.json"
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(ContainerError):
            self.cleanup()
        self.path.unlink()
        target.rename(self.path)
        alias = self.root / "alias"
        alias.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(ContainerError):
            stop_owned_container(alias / "gates" / self.attempt.name / "container.json", alias)
        with self.assertRaises(ContainerError):
            stop_owned_container(self.path, self.root)
        self.process.assert_not_called()

    def test_fifo_hardlinked_record_and_wrong_owner_refuse_before_daemon(self):
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(ContainerError):
            self.cleanup()
        self.path.unlink()
        self.write()
        alias = self.root / "hardlink.json"
        os.link(self.path, alias)
        with self.assertRaises(ContainerError):
            self.cleanup()
        alias.unlink()
        with mock.patch.object(containers.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(ContainerError):
                self.cleanup()
        self.process.assert_not_called()

    def test_cidfile_is_not_mutation_authority_and_private_home_symlink_is_rejected(self):
        (self.attempt / "container.cid").write_text(FOREIGN)
        self.cleanup()
        self.assertTrue(all(call[0][-1] == IDENTITY for call in self.daemon.calls
                            if call[0][4] in {"stop", "kill", "rm"}))
        self.daemon.calls.clear()
        cache = self.state / "gate-cache"
        cache.mkdir(mode=0o700)
        (cache / "homes").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ContainerError):
            self.cleanup()
        self.assertEqual(self.daemon.calls, [])

    def test_missing_record_does_not_query_or_infer_an_absent_container(self):
        self.path.unlink()
        with self.assertRaises(ContainerError):
            self.cleanup()
        self.process.assert_not_called()

    def test_malformed_or_ambiguous_daemon_json_never_creates_deletion_authority(self):
        for output in ("not JSON", '"short-id"', json.dumps(IDENTITY) + "\n" + json.dumps(FOREIGN), "null"):
            self.process.return_value = (0, output)
            self.process.side_effect = None
            with self.assertRaises(ContainerError):
                self.cleanup()
        self.assertEqual(self.daemon.mutations, [])

    def test_inspection_boolean_impostors_and_unhashable_status_refused(self):
        for change in ({"running": 1}, {"paused": "false"}, {"status": []}, {"labels": []}):
            self.daemon.inspect_changes = change
            with self.assertRaises(ContainerError):
                self.cleanup()
        self.assertEqual(self.daemon.mutations, [])

    def test_create_identity_is_durable_before_start_authority_is_returned(self):
        self.id_path.unlink()
        self.daemon.running = False
        self.daemon.inspect_changes = {"status": "created"}
        self.assertEqual(record_created_container(self.path, self.state, IDENTITY + "\n"), IDENTITY)
        self.assertEqual(json.loads(self.id_path.read_text()),
                         {"version": 1, "container_id": IDENTITY,
                          "record_sha256": containers._record_digest(self.record)})
        self.assertEqual(self.id_path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(container_cleanup_complete(self.path, self.state))
        self.assertEqual(self.daemon.mutations, [])
        self.assertTrue(all(call[0][4] == "inspect" for call in self.daemon.calls))

    def test_running_exited_foreign_or_malformed_create_results_never_get_start_authority(self):
        self.id_path.unlink()
        for returned in ("short", IDENTITY + "\n" + FOREIGN, None, True):
            with self.subTest(returned=returned), self.assertRaises(ContainerError):
                record_created_container(self.path, self.state, returned)
        with self.assertRaisesRegex(ContainerError, "verified inert"):
            record_created_container(self.path, self.state, IDENTITY)
        self.daemon.running = False
        with self.assertRaisesRegex(ContainerError, "verified inert"):
            record_created_container(self.path, self.state, IDENTITY)
        self.daemon.inspect_changes = {"status": "created", "image": "sha256:" + FOREIGN}
        with self.assertRaises(ContainerError):
            record_created_container(self.path, self.state, IDENTITY)
        self.assertFalse(self.id_path.exists())
        self.assertEqual(self.daemon.mutations, [])

    def test_id_publication_fault_cannot_return_start_authority_and_retry_resyncs_existing_id(self):
        self.id_path.unlink()
        self.daemon.running = False
        self.daemon.inspect_changes = {"status": "created"}
        with mock.patch.object(containers.os, "fsync", side_effect=OSError("sync failed")):
            with self.assertRaises(ContainerError):
                record_created_container(self.path, self.state, IDENTITY)
        self.assertFalse(self.id_path.exists())
        original = os.fsync
        calls = 0
        def fail_parent(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("directory sync failed")
            original(descriptor)
        with mock.patch.object(containers.os, "fsync", side_effect=fail_parent), self.assertRaises(ContainerError):
            record_created_container(self.path, self.state, IDENTITY)
        self.assertTrue(self.id_path.exists())
        with mock.patch.object(containers.os, "fsync", wraps=original) as sync:
            self.assertEqual(record_created_container(self.path, self.state, IDENTITY), IDENTITY)
            self.assertGreaterEqual(sync.call_count, 2)
        self.assertEqual(self.daemon.mutations, [])

    def test_unbound_absence_stays_unresolved_until_delayed_inert_create_can_be_captured(self):
        self.id_path.unlink()
        self.daemon.present = False
        with self.assertRaisesRegex(ContainerError, "inert create outcome remains unresolved"):
            self.cleanup()
        self.assertFalse(self.id_path.exists())
        self.assertFalse(self.terminal.exists())
        self.daemon.present = True
        self.daemon.running = False
        self.daemon.inspect_changes = {"status": "created"}
        self.cleanup()
        self.assertTrue(self.id_path.exists())
        self.assertTrue(container_cleanup_complete(self.path, self.state))
        self.assertEqual(self.daemon.mutations, ["rm"])

    def test_bound_absence_confirms_late_start_cannot_recreate_the_immutable_id(self):
        self.daemon.present = False
        self.daemon.replacement = True
        self.cleanup()
        self.assertTrue(container_cleanup_complete(self.path, self.state))
        self.assertTrue(all("id=" + IDENTITY in call[0] for call in self.daemon.calls))
        self.assertEqual(self.daemon.mutations, [])

    def test_start_racing_initial_remove_is_stopped_on_next_bounded_sweep(self):
        self.daemon.running = False
        original = self.daemon.run
        raced = False
        def delayed_start(argv, cwd, timeout, *, environment):
            nonlocal raced
            if argv[4] == "rm" and not raced:
                raced = True
                self.daemon.rm_effect = False
                value = original(argv, cwd, timeout, environment=environment)
                self.daemon.rm_effect = True
                self.daemon.running = True
                return 1, value[1]
            return original(argv, cwd, timeout, environment=environment)
        self.process.side_effect = delayed_start
        self.cleanup()
        self.assertEqual(self.daemon.mutations, ["rm", "stop", "rm"])
        self.assertTrue(container_cleanup_complete(self.path, self.state))

    def test_terminal_receipt_skips_historical_daemon_queries_and_prevents_relaunch(self):
        self.cleanup()
        self.process.reset_mock()
        self.daemon.daemon_error = True
        self.assertTrue(container_cleanup_complete(self.path, self.state))
        self.cleanup()
        self.process.assert_not_called()
        with self.assertRaisesRegex(ContainerError, "cannot authorize another"):
            record_created_container(self.path, self.state, IDENTITY)
        self.process.assert_not_called()

    def test_forged_stale_public_or_mismatched_id_and_terminal_journals_are_refused(self):
        self.cleanup()
        self.process.reset_mock()
        original = self.terminal.read_text()
        value = json.loads(original)
        for changed in ({**value, "version": True}, {**value, "container_id": FOREIGN},
                        {**value, "record_sha256": "0" * 64}, {**value, "result": "pending"},
                        {**value, "extra": "unsupported"}):
            self.terminal.write_text(json.dumps(changed))
            with self.assertRaises(ContainerError):
                container_cleanup_complete(self.path, self.state)
            with self.assertRaises(ContainerError):
                self.cleanup()
        self.terminal.write_text(original)
        self.terminal.chmod(0o644)
        with self.assertRaises(ContainerError):
            container_cleanup_complete(self.path, self.state)
        self.terminal.chmod(0o600)
        self.id_path.unlink()
        with self.assertRaises(ContainerError):
            container_cleanup_complete(self.path, self.state)
        self.process.assert_not_called()

    def test_total_cleanup_deadline_is_bounded_and_fails_closed(self):
        with mock.patch.object(containers.time, "monotonic", side_effect=[0, containers.CLEANUP_TIMEOUT + 1]):
            with self.assertRaisesRegex(ContainerError, "total time bound"):
                self.cleanup()
        self.process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
