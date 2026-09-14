"""Recovery only stops exact units backed by this controller's durable records."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from issue_pipeline.controller import PipelineBlocked, halt_children
from issue_pipeline.containers import ContainerError


class ProcessRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="agenc-unit-ownership-test-")
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / "state"
        self.foreign_state = Path(self.temporary.name) / "foreign"
        self.state.mkdir(mode=0o700)
        self.foreign_state.mkdir(mode=0o700)
        self.owned_gate = "agenc-ircd-pipeline-gate-" + "a" * 32 + ".service"
        self.foreign_gate = "agenc-ircd-pipeline-gate-" + "b" * 32 + ".service"
        self.owned_agent = "agenc-ircd-agent-" + "c" * 32 + ".service"
        self.active = [self.owned_gate, self.foreign_gate, self.owned_agent, "unrelated.service"]
        self.stopped = []
        self.observed_state = "inactive\n"
        self.main_pid = "0"
        self.control_group = ""
        completed = mock.patch("issue_pipeline.controller.container_cleanup_complete", return_value=False)
        self.completed = completed.start()
        self.addCleanup(completed.stop)
        lifecycle = mock.patch("issue_pipeline.controller.session_lifecycle", return_value={
            "unit": self.owned_agent, "state": "registered", "request_sha256": "a" * 64})
        self.lifecycle = lifecycle.start()
        self.addCleanup(lifecycle.stop)
        receipt = mock.patch("issue_pipeline.controller.record_session_quiescent")
        self.quiet_receipt = receipt.start()
        self.addCleanup(receipt.stop)

    def record_gate(self, root, unit, *, claimed_state=None, attempt="attempt"):
        path = root / "gates" / attempt / "unit.json"
        path.parent.parent.mkdir(mode=0o700, exist_ok=True)
        path.parent.mkdir(mode=0o700)
        path.write_text(json.dumps({"unit": unit, "source": "a" * 40,
                                    "state_dir": str(claimed_state or root),
                                    "repository": "tetsuo-ai/agenc-ircd"}))
        return path

    def process(self, argv, **kwargs):
        if "list-units" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout="\n".join(
                unit + " loaded active running fixture" for unit in self.active))
        if "stop" in argv:
            self.stopped.append(argv[-1])
            return subprocess.CompletedProcess(argv, 0, stdout="")
        if "show" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout="LoadState=not-found\nActiveState="
                + self.observed_state.strip() + "\nMainPID=" + self.main_pid
                + "\nControlPID=0\nControlGroup=" + self.control_group + "\n")
        raise AssertionError(argv)

    def halt(self):
        with mock.patch("issue_pipeline.controller.subprocess.run", side_effect=self.process):
            halt_children(self.state)

    def test_only_exact_owned_gate_and_agent_units_are_stopped(self):
        self.record_gate(self.state, self.owned_gate)
        self.record_gate(self.foreign_state, self.foreign_gate)
        request = self.state / "sessions" / "session" / "request.json"
        request.parent.mkdir(parents=True)
        request.write_text(json.dumps({"systemd_unit": self.owned_agent, "role": "reviewer", "argv": []}))
        self.halt()
        self.assertEqual(set(self.stopped), {self.owned_gate, self.owned_agent})

    def test_unrecorded_matching_prefix_grants_no_stop_authority(self):
        self.halt()
        self.assertEqual(self.stopped, [])

    def test_record_claiming_another_state_directory_is_rejected_before_stop(self):
        self.record_gate(self.state, self.foreign_gate, claimed_state=self.foreign_state)
        with self.assertRaises(PipelineBlocked):
            self.halt()
        self.assertEqual(self.stopped, [])

    def test_symlinked_record_parent_cannot_import_foreign_process_ownership(self):
        target = self.record_gate(self.foreign_state, self.foreign_gate)
        (self.state / "gates").mkdir()
        (self.state / "gates" / "foreign").symlink_to(target.parent, target_is_directory=True)
        with self.assertRaises(PipelineBlocked):
            self.halt()
        self.assertEqual(self.stopped, [])

    def test_symlinked_record_file_is_rejected(self):
        target = self.record_gate(self.foreign_state, self.foreign_gate)
        path = self.state / "gates" / "attempt" / "unit.json"
        path.parent.mkdir(parents=True)
        path.symlink_to(target)
        with self.assertRaises(PipelineBlocked):
            self.halt()
        self.assertEqual(self.stopped, [])

    def test_absent_unit_record_does_not_authorize_other_running_units(self):
        self.record_gate(self.state, self.owned_gate)
        self.active.remove(self.owned_gate)
        self.halt()
        self.assertEqual(self.stopped, [])

    def test_empty_or_active_quiescence_report_is_not_success(self):
        self.record_gate(self.state, self.owned_gate)
        for status in ("", "active\n", "deactivating\n"):
            with self.subTest(status=status):
                self.observed_state = status
                with self.assertRaises(PipelineBlocked):
                    self.halt()

    def container_fixture(self, *, unit=None, attempt="attempt"):
        unit = unit or self.owned_gate
        unit_path = self.record_gate(self.state, unit, attempt=attempt)
        path = unit_path.with_name("container.json")
        record = {**json.loads(unit_path.read_text()), "version": 1, "backend": "docker",
                  "name": unit.removesuffix(".service"), "image": "sha256:" + "b" * 64,
                  "private_home": str(self.state / "gate-cache" / "homes" / ("1" * 32)),
                  "labels": {"agenc-ircd.pipeline.state": str(self.state),
                             "agenc-ircd.pipeline.source": "a" * 40,
                             "agenc-ircd.pipeline.unit": unit,
                             "agenc-ircd.pipeline.purpose": "full-gate",
                             "agenc-ircd.pipeline.repository": "tetsuo-ai/agenc-ircd"}}
        path.write_text(json.dumps(record))
        path.chmod(0o600)
        return path, record

    def record_agent(self):
        request = self.state / "sessions" / "session" / "request.json"
        request.parent.mkdir(parents=True)
        request.write_text(json.dumps({"systemd_unit": self.owned_agent}))
        return request

    def assert_damaged_record_drains(self, kind):
        healthy_container, _ = self.container_fixture()
        self.record_agent()
        expected_units = {self.owned_gate, self.owned_agent}
        if kind == "request":
            damaged = self.state / "sessions" / "damaged" / "request.json"
            damaged.parent.mkdir()
            raw = ('{"systemd_unit":"' + self.foreign_gate + '","argv":[').encode()
        else:
            other_container, _ = self.container_fixture(unit=self.foreign_gate, attempt="damaged")
            if kind == "unit":
                damaged = other_container.with_name("unit.json")
                raw = ('{"unit":"' + self.foreign_gate + '","state_dir":').encode()
            else:
                damaged = other_container
                raw = b'{"version":1,"backend":"docker","name":'
                # The intact launcher record still grants authority to stop
                # that launcher, even when its container cannot be adopted.
                expected_units.add(self.foreign_gate)
        damaged.write_bytes(raw)
        with mock.patch("issue_pipeline.controller.stop_owned_container") as stop:
            with self.assertRaisesRegex(PipelineBlocked, "requires reconciliation") as error:
                self.halt()
        self.assertEqual(set(self.stopped), expected_units)
        stop.assert_called_once_with(healthy_container, self.state)
        self.quiet_receipt.assert_called_once()
        self.assertIn(str(damaged), str(error.exception))
        self.assertEqual(damaged.read_bytes(), raw)

    def test_truncated_request_preserved_after_other_units_and_container_stop(self):
        self.assert_damaged_record_drains("request")

    def test_truncated_launcher_preserved_without_adopting_its_container(self):
        self.assert_damaged_record_drains("unit")

    def test_truncated_container_preserved_after_independently_owned_children_stop(self):
        self.assert_damaged_record_drains("container")

    def test_malformed_process_record_types_and_duplicate_fields_grant_no_authority(self):
        healthy_container, _ = self.container_fixture()
        damaged = self.state / "sessions" / "damaged" / "request.json"
        damaged.parent.mkdir(parents=True)
        records = [b"null", b"[]", b"{}", b'{"systemd_unit":true}',
                   ('{"systemd_unit":null,"systemd_unit":"' + self.foreign_gate + '"}').encode(),
                   ('{"systemd_unit":"' + self.foreign_gate + '","extra":NaN}').encode(),
                   b'[' * 2000]
        for raw in records:
            with self.subTest(raw=raw[:100]):
                damaged.write_bytes(raw)
                self.stopped.clear()
                with mock.patch("issue_pipeline.controller.stop_owned_container") as stop:
                    with self.assertRaises(PipelineBlocked):
                        self.halt()
                self.assertEqual(self.stopped, [self.owned_gate])
                stop.assert_called_once_with(healthy_container, self.state)
                self.assertEqual(damaged.read_bytes(), raw)

    def test_all_invalid_records_reported_after_valid_container_cleanup(self):
        healthy_container, _ = self.container_fixture()
        request = self.state / "sessions" / "damaged" / "request.json"
        request.parent.mkdir(parents=True)
        unit = self.record_gate(self.state, self.foreign_gate, attempt="damaged")
        container = unit.with_name("container.json")
        for path in (request, unit, container):
            path.write_bytes(b'{"truncated":')
            path.chmod(0o600)
        with mock.patch("issue_pipeline.controller.stop_owned_container") as stop:
            with self.assertRaises(PipelineBlocked) as error:
                self.halt()
        stop.assert_called_once_with(healthy_container, self.state)
        self.assertEqual(self.stopped, [self.owned_gate])
        for path in (request, unit, container):
            self.assertIn(str(path), str(error.exception))
            self.assertEqual(path.read_bytes(), b'{"truncated":')

    def test_inactive_recovery_unit_with_live_pid_or_descendants_is_rejected(self):
        self.record_gate(self.state, self.owned_gate)
        self.main_pid = "42"
        with self.assertRaises(PipelineBlocked):
            self.halt()
        self.main_pid = "0"
        self.control_group = "/owned-cgroup"
        events = Path("/sys/fs/cgroup/owned-cgroup/cgroup.events")
        original_exists, original_read = Path.exists, Path.read_text
        with mock.patch.object(Path, "exists", autospec=True,
                               side_effect=lambda path: True if path == events else original_exists(path)), \
             mock.patch.object(Path, "read_text", autospec=True,
                               side_effect=lambda path: "populated 1\n" if path == events else original_read(path)):
            with self.assertRaisesRegex(PipelineBlocked, "still populated"):
                self.halt()

    def test_container_cleanup_follows_launcher_stop(self):
        path, record = self.container_fixture()
        def cleanup(observed_path, state):
            self.assertEqual((observed_path, state), (path, self.state))
            self.assertIn(self.owned_gate, self.stopped)
        with mock.patch("issue_pipeline.controller.load_container_record", return_value=record), \
             mock.patch("issue_pipeline.controller.stop_owned_container", side_effect=cleanup) as stop:
            self.halt()
        stop.assert_called_once()

    def test_container_cleanup_runs_even_after_launcher_unit_was_collected(self):
        path, record = self.container_fixture()
        self.active.remove(self.owned_gate)
        with mock.patch("issue_pipeline.controller.load_container_record", return_value=record), \
             mock.patch("issue_pipeline.controller.stop_owned_container") as stop:
            self.halt()
        stop.assert_called_once_with(path, self.state)
        self.assertEqual(self.stopped, [])

    def test_container_cleanup_does_not_run_before_launcher_quiescence(self):
        _, record = self.container_fixture()
        self.active.remove(self.owned_gate)
        self.observed_state = "active\n"
        with mock.patch("issue_pipeline.controller.load_container_record", return_value=record), \
             mock.patch("issue_pipeline.controller.stop_owned_container") as stop:
            with self.assertRaises(PipelineBlocked):
                self.halt()
        stop.assert_not_called()

    def test_container_without_matching_launcher_record_is_preserved(self):
        _, record = self.container_fixture()
        record["source"] = "b" * 40
        with mock.patch("issue_pipeline.controller.load_container_record", return_value=record), \
             mock.patch("issue_pipeline.controller.stop_owned_container") as stop:
            with self.assertRaises(PipelineBlocked):
                self.halt()
        stop.assert_not_called()
        self.assertEqual(self.stopped, [self.owned_gate])

    def test_failed_launcher_stop_does_not_prevent_independent_container_cleanup(self):
        healthy_container, _ = self.container_fixture()
        self.container_fixture(unit=self.foreign_gate, attempt="failed")
        self.record_agent()
        original = self.process
        def process(argv, **kwargs):
            if "stop" in argv and argv[-1] == self.foreign_gate:
                raise subprocess.CalledProcessError(1, argv, stderr="DO_NOT_ECHO_SECRET")
            return original(argv, **kwargs)
        self.process = process
        with mock.patch("issue_pipeline.controller.stop_owned_container") as stop:
            with self.assertRaisesRegex(PipelineBlocked, "launcher cleanup could not be verified") as error:
                self.halt()
        stop.assert_called_once_with(healthy_container, self.state)
        self.assertEqual(set(self.stopped), {self.owned_gate, self.owned_agent})
        self.quiet_receipt.assert_called_once()
        self.assertNotIn("SECRET", str(error.exception))

    def test_failed_launcher_quiescence_does_not_prevent_independent_container_cleanup(self):
        failed_container, _ = self.container_fixture()
        healthy_container, _ = self.container_fixture(unit=self.foreign_gate, attempt="healthy")
        original = self.process
        def process(argv, **kwargs):
            result = original(argv, **kwargs)
            if "show" in argv and self.owned_gate in argv:
                result.stdout = result.stdout.replace("MainPID=0", "MainPID=42")
            return result
        self.process = process
        with mock.patch("issue_pipeline.controller.stop_owned_container") as stop:
            with self.assertRaisesRegex(PipelineBlocked, "not quiescent"):
                self.halt()
        stop.assert_called_once_with(healthy_container, self.state)
        self.assertNotEqual(healthy_container, failed_container)
        self.assertEqual(set(self.stopped), {self.owned_gate, self.foreign_gate})

    def test_failed_container_cleanup_does_not_prevent_next_owned_container_cleanup(self):
        failed_container, _ = self.container_fixture(attempt="failed")
        healthy_container, _ = self.container_fixture(unit=self.foreign_gate, attempt="healthy")
        attempted = []
        def cleanup(path, state):
            attempted.append(path)
            self.assertEqual(state, self.state)
            self.assertEqual(set(self.stopped), {self.owned_gate, self.foreign_gate})
            if path == failed_container:
                raise ContainerError("daemon unavailable")
        with mock.patch("issue_pipeline.controller.stop_owned_container", side_effect=cleanup):
            with self.assertRaisesRegex(PipelineBlocked, "cleanup could not be verified"):
                self.halt()
        self.assertEqual(set(attempted), {failed_container, healthy_container})

    def test_unverified_container_cleanup_blocks_recovery(self):
        _, record = self.container_fixture()
        with mock.patch("issue_pipeline.controller.load_container_record", return_value=record), \
             mock.patch("issue_pipeline.controller.stop_owned_container", side_effect=ContainerError("daemon unavailable")):
            with self.assertRaisesRegex(PipelineBlocked, "cleanup could not be verified"):
                self.halt()

    def test_completed_immutable_id_does_not_require_another_service_or_daemon_query(self):
        path, record = self.container_fixture()
        self.active.remove(self.owned_gate)
        self.completed.return_value = True
        self.observed_state = "active\n"
        with mock.patch("issue_pipeline.controller.load_container_record", return_value=record), \
             mock.patch("issue_pipeline.controller.stop_owned_container") as stop:
            self.halt()
        self.completed.assert_called_once_with(path, self.state)
        stop.assert_not_called()
        self.assertEqual(self.stopped, [])

    def test_ambiguous_agent_registration_survives_restart_after_other_children_stop(self):
        self.record_gate(self.state, self.owned_gate)
        session = self.state / "sessions" / "session"
        session.mkdir(parents=True)
        (session / "request.json").write_text(json.dumps({"systemd_unit": self.owned_agent}))
        marker = session / "cleanup-uncertain.json"
        marker.write_text(json.dumps({"version": 1, "unit": self.owned_agent,
                                    "reason": "launcher registration was not confirmed before cancellation"}))
        marker.chmod(0o600)
        self.active.remove(self.owned_agent)
        self.lifecycle.return_value["state"] = "unresolved"
        with self.assertRaisesRegex(PipelineBlocked, "registration remains uncertain"):
            self.halt()
        self.assertIn(self.owned_gate, self.stopped)
        self.assertTrue(marker.exists())

    def test_unresolved_intent_without_exception_marker_still_blocks_restart(self):
        session = self.state / "sessions" / "abrupt-death"
        session.mkdir(parents=True)
        (session / "request.json").write_text(json.dumps({"systemd_unit": self.owned_agent}))
        self.active.remove(self.owned_agent)
        self.lifecycle.return_value["state"] = "unresolved"
        with self.assertRaisesRegex(PipelineBlocked, "requires reconciliation"):
            self.halt()
        self.quiet_receipt.assert_not_called()

    def test_observed_registered_unit_can_complete_its_interrupted_cleanup(self):
        session = self.state / "sessions" / "abrupt-death"
        session.mkdir(parents=True)
        (session / "request.json").write_text(json.dumps({"systemd_unit": self.owned_agent}))
        self.lifecycle.return_value["state"] = "unresolved"
        self.halt()
        self.quiet_receipt.assert_called_once_with(session, observed_registered=True)

    def test_collected_registered_unit_still_gets_quiescence_receipt(self):
        session = self.state / "sessions" / "registered"
        session.mkdir(parents=True)
        (session / "request.json").write_text(json.dumps({"systemd_unit": self.owned_agent}))
        self.active.remove(self.owned_agent)
        self.halt()
        self.quiet_receipt.assert_called_once_with(session, observed_registered=False)


if __name__ == "__main__":
    unittest.main()
