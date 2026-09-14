"""Recovery only stops exact units backed by this controller's durable records."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from issue_pipeline.controller import PipelineBlocked, halt_children


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
            return subprocess.CompletedProcess(argv, 0, stdout=self.observed_state)
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


if __name__ == "__main__":
    unittest.main()
