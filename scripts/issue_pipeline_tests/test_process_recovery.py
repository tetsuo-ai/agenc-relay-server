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
        self.state.mkdir()
        self.foreign_state.mkdir()
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

    def record_gate(self, root, unit, *, claimed_state=None):
        path = root / "gates" / "attempt" / "unit.json"
        path.parent.mkdir(parents=True)
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

    def container_fixture(self):
        unit_path = self.record_gate(self.state, self.owned_gate)
        path = unit_path.with_name("container.json")
        path.write_text("{}")
        return path, json.loads(unit_path.read_text())

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
        self.assertEqual(self.stopped, [])

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
        with self.assertRaisesRegex(PipelineBlocked, "registration remains uncertain"):
            self.halt()
        self.assertIn(self.owned_gate, self.stopped)
        self.assertTrue(marker.exists())


if __name__ == "__main__":
    unittest.main()
