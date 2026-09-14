"""Reject weakened policy, forged evidence and unsafe gate restart conditions."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock

from issue_pipeline.config import Config, digest_file, private_directory
from issue_pipeline.gate import GATE, ARTIFACT_PREFIX, GateFailure, GateRunner
from issue_pipeline.gate import check_policy, commands, validate_artifact

ROOT = Path(__file__).resolve().parents[2]
SOURCE, TREE, BASE = "a" * 40, "b" * 40, "c" * 40
MANIFEST = '''schema_version = 1
[gate.stage-nine-implementation]
[[gate.stage-nine-implementation.command]]
argv = ["python3", "scripts/check-first.py"]
[[gate.stage-nine-implementation.command]]
argv = ["cargo", "test", "--locked"]
'''
FLOORS = '''schema_version = 1
minimum_overall_branch_percent = 90.0
minimum_overall_line_percent = 90.0
critical_region_percent = 100.0
'''


class ConfigTests(unittest.TestCase):
    def test_valid_defaults_and_explicit_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            path.write_text("version = 1\nmax_issues = 1\nmax_sessions = 2\n")
            config = Config.load(path)
            self.assertEqual(config.max_sessions, 2)
            self.assertEqual(config.master_issue, 35)

    def test_boolean_version_wrong_types_unknown_keys_and_unbounded_concurrency_refused(self):
        values = ["version = true", "version = 1\nmax_sessions = true",
                  "version = 1\nunknown = 3", "version = 1\nmax_sessions = 9",
                  "version = 1\nmax_issues = 4\nmax_sessions = 2",
                  "version = 1\ngate_timeout_seconds = 0", "version = 1\nmodel = ' '",
                  "version = 1\nstate_dir = ''", "version = 1\nstate_dir = 'relative'",
                  "version = 1\nstate_dir = '/'", "version = 1\nbase_branch = 'main/'",
                  "version = 1\nbase_branch = 'main.lock'", "version = 1\nbase_branch = 'main//a'"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            for value in values:
                with self.subTest(value=value):
                    path.write_text(value)
                    with self.assertRaises(ValueError):
                        Config.load(path)

    def test_private_directory_rejects_symlink_without_changing_target_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            target.mkdir(mode=0o755)
            link = Path(temporary) / "link"
            link.symlink_to(target)
            before = target.stat().st_mode
            with self.assertRaises(ValueError):
                private_directory(link)
            self.assertEqual(target.stat().st_mode, before)


class PolicyRepo:
    def __init__(self, manifest=MANIFEST, floors=FLOORS, changed=()):
        self.manifest, self.floors, self.changed = manifest, floors, changed

    def run(self, argv):
        if argv[0] == "diff":
            return "\0".join(self.changed)
        revision, path = argv[1].split(":", 1)
        if path == "conformance/gates.toml":
            return MANIFEST if revision == BASE else self.manifest
        return FLOORS if revision == BASE else self.floors


class PolicyTests(unittest.TestCase):
    def test_existing_gate_and_added_check_pass(self):
        self.assertEqual(len(check_policy(PolicyRepo(), BASE, SOURCE)), 2)
        added = MANIFEST + '\n[[gate.stage-nine-implementation.command]]\nargv = ["cargo", "fmt", "--check"]\n'
        self.assertEqual(len(check_policy(PolicyRepo(manifest=added), BASE, SOURCE)), 3)

    def test_missing_or_changed_required_command_refused(self):
        for manifest in (MANIFEST.replace('"--locked"', '"--offline"'),
                         MANIFEST[:MANIFEST.rfind("[[gate.")]):
            with self.assertRaises(GateFailure):
                check_policy(PolicyRepo(manifest=manifest), BASE, SOURCE)

    def test_required_order_preserved(self):
        before, first, second = MANIFEST.split("[[gate.stage-nine-implementation.command]]")
        changed = before + "[[gate.stage-nine-implementation.command]]" + second
        changed += "[[gate.stage-nine-implementation.command]]" + first
        with self.assertRaises(GateFailure):
            check_policy(PolicyRepo(manifest=changed), BASE, SOURCE)

    def test_minimum_and_critical_floors_cannot_be_lowered_deleted_or_nonfinite(self):
        for key, original in (("minimum_overall_branch_percent", "90.0"),
                              ("minimum_overall_line_percent", "90.0"),
                              ("critical_region_percent", "100.0")):
            for replacement in ("0.0", "nan", "+inf", "-inf", "true", "101.0"):
                with self.subTest(key=key, replacement=replacement):
                    floors = FLOORS.replace(f"{key} = {original}", f"{key} = {replacement}")
                    with self.assertRaises(GateFailure):
                        check_policy(PolicyRepo(floors=floors), BASE, SOURCE)
            with self.assertRaises(GateFailure):
                check_policy(PolicyRepo(floors=FLOORS.replace(f"{key} = {original}\n", "")), BASE, SOURCE)

    def test_runner_checker_toolchain_and_controller_rewrites_refused(self):
        for path in ("scripts/run-gate.py", "scripts/check-first.py", "scripts/check-evidence.py",
                     "scripts/check-stage-nine.sh", "scripts/issue_pipeline/gate.py",
                     "scripts/issue_pipeline_tests/test_gate.py", "rust-toolchain.toml"):
            with self.subTest(path=path):
                with self.assertRaises(GateFailure):
                    check_policy(PolicyRepo(changed=[path]), BASE, SOURCE)

    def test_environment_and_manifest_types_are_closed(self):
        manifest = tomllib.loads(MANIFEST)
        for value in (True, 1.0):
            with self.assertRaises(GateFailure):
                commands({**manifest, "schema_version": value})
        for environment in ({"LD_PRELOAD": "injection"}, {"RUSTC_BOOTSTRAP": "1"}):
            changed = copy.deepcopy(manifest)
            changed["gate"][GATE]["command"][0]["environment"] = environment
            with self.assertRaises(GateFailure):
                commands(changed)


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="agenc-gate-artifact-test-")
        cls.root = Path(cls.temporary.name) / "source"
        subprocess.run(["git", "clone", "--shared", "--quiet", str(ROOT), str(cls.root)],
                       check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=cls.root, text=True).strip()
        cls.tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=cls.root, text=True).strip()
        cls.policy = runpy.run_path(str(cls.root / "scripts/check-evidence.py"), run_name="artifact_test_policy")
        cls.expected = commands(tomllib.loads((cls.root / "conformance/gates.toml").read_text()))
        tool_hash, tools, limitations = cls.policy["load_toolchain_policy"](cls.root, 9)
        cls.required = cls.policy["required_stage_evidence_ids"](cls.root, 9, cls.source)
        cls.source_hash = cls.policy["canonical_source_sha256"](cls.root, cls.source)
        time = "2026-09-13T01:00:00.000000Z"
        cls.value = {
            "schema_version": 2, "gate": GATE, "source_commit": cls.source,
            "source_sha256": cls.source_hash, "lock_sha256": digest_file(cls.root / "Cargo.lock"),
            "gate_manifest_sha256": digest_file(cls.root / "conformance/gates.toml"),
            "argv": ["python3", "scripts/run-gate.py", GATE],
            "tool": {"name": "agenc-ircd-gate-runner", "version": digest_file(cls.root / "scripts/run-gate.py")},
            "toolchain_policy_sha256": tool_hash, "toolchain": tools, "limitations": limitations,
            "target": "x86_64-unknown-linux-gnu", "features": ["all-features"],
            "started_at": time, "ended_at": time, "result": "passed", "exit_code": 0,
            "evidence": cls.policy["closure_evidence_inventory"](cls.required),
            "command_results": [{**command, "started_at": time, "ended_at": time, "exit_code": 0}
                                for command in cls.expected],
        }

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def validate(self, value):
        return validate_artifact(value, self.source, self.tree, self.root, self.expected)

    def test_complete_exact_source_record_is_validated_by_real_isolated_checker(self):
        self.assertEqual(self.validate(self.value)["source"], self.source)

    def test_wrong_sha_schema_and_boolean_exit_refused(self):
        for field, value in (("source_commit", "f" * 40), ("schema_version", 2.0),
                             ("schema_version", True), ("exit_code", False),
                             ("lock_sha256", "f" * 64), ("gate_manifest_sha256", "f" * 64)):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(self.value)
                changed[field] = value
                with self.assertRaises(GateFailure):
                    self.validate(changed)

    def test_missing_commands_boolean_command_exit_and_invalid_timing_refused(self):
        for mutation in (lambda v: v["command_results"].pop(),
                         lambda v: v["command_results"][0].update(exit_code=False),
                         lambda v: v["command_results"][0].update(started_at=True),
                         lambda v: v["command_results"][0].update(ended_at="2026-09-12T01:00:00.000000Z")):
            changed = copy.deepcopy(self.value)
            mutation(changed)
            with self.assertRaises(GateFailure):
                self.validate(changed)

    def test_forged_source_hash_toolchain_evidence_and_unknown_fields_refused(self):
        for field, value in (("source_sha256", "f" * 64), ("toolchain_policy_sha256", "f" * 64),
                             ("toolchain", []), ("evidence", []), ("unreviewed_field", "ignored")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.value)
                changed[field] = value
                with self.assertRaises(GateFailure):
                    self.validate(changed)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="agenc-gate-process-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "worktree"
        self.root.mkdir()
        self.output = Path(self.temporary.name) / "receipt"
        self.artifact = self.root / ARTIFACT_PREFIX / f"{GATE}-{SOURCE}.json"
        self.artifact.parent.mkdir(parents=True)
        self.repo = mock.Mock()
        self.repo.head.return_value = SOURCE
        self.repo.tree.return_value = TREE
        self.repo.run.return_value = ""
        self.runner = GateRunner(Config(minimum_free_gib=1, gate_timeout_seconds=1))
        self.calls = []
        self.exit_code = 0
        self.timeout = False
        self.payload = b'{"invalid": "diagnostic"}'
        self.active = False
        self.stop_timeout = False

    def process(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == "systemd-run":
            recorded = json.loads((self.output / "unit.json").read_text())
            self.assertEqual(recorded["unit"], next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--unit=")))
            self.assertEqual(recorded["source"], SOURCE)
            self.assertEqual(recorded["state_dir"], str(self.runner.config.state))
            self.assertIn("--expand-environment=no", argv)
            if self.payload is not None:
                self.artifact.write_bytes(self.payload)
            if self.timeout:
                raise subprocess.TimeoutExpired(argv, 1)
            return subprocess.CompletedProcess(argv, self.exit_code)
        if "stop" in argv and self.stop_timeout:
            raise subprocess.TimeoutExpired(argv, 1)
        if "show" in argv:
            state, pid = ("active", "42") if self.active else ("inactive", "0")
            return subprocess.CompletedProcess(argv, 0, stdout=(f"LoadState=loaded\nActiveState={state}\n"
                                                f"MainPID={pid}\nControlPID=0\nControlGroup=\n"))
        return subprocess.CompletedProcess(argv, 0)

    def invoke(self):
        with mock.patch("issue_pipeline.gate.check_policy", return_value=[]), \
                mock.patch("issue_pipeline.gate.filesystem_command", return_value=["/bin/true"]), \
                mock.patch("issue_pipeline.gate.subprocess.run", side_effect=self.process), \
                mock.patch("issue_pipeline.gate.validate_artifact", side_effect=GateFailure("bad evidence")), \
                mock.patch("issue_pipeline.gate.shutil.disk_usage", return_value=shutil._ntuple_diskusage(2**40, 0, 2**40)):
            return self.runner.run(self.repo, self.root, SOURCE, BASE, self.output)

    def test_nonzero_gate_preserves_failed_artifact_outside_worktree(self):
        self.exit_code = 1
        with self.assertRaises(GateFailure):
            self.invoke()
        self.assertFalse(self.artifact.exists())
        self.assertEqual((self.output / "gate-artifact-failed.json").read_bytes(), self.payload)
        self.assertFalse(self.runner._active)

    def test_invalid_evidence_is_retained_as_failure_and_does_not_poison_retry_worktree(self):
        with self.assertRaises(GateFailure):
            self.invoke()
        self.assertFalse(self.artifact.exists())
        self.assertTrue((self.output / "gate-artifact-failed.json").exists())
        self.assertFalse((self.output / "gate-artifact.json").exists())

    def test_timeout_forces_descendant_stop_and_verifies_quiescence(self):
        self.timeout = True
        self.stop_timeout = True
        with self.assertRaises(GateFailure):
            self.invoke()
        self.assertTrue(any("--kill-whom=all" in argv for argv in self.calls))
        self.assertTrue(any("show" in argv for argv in self.calls))
        self.assertFalse(self.runner._active)

    def test_unconfirmed_cleanup_permanently_blocks_runner_and_preserves_work(self):
        self.active = True
        with self.assertRaisesRegex(GateFailure, "cleanup is uncertain"):
            self.invoke()
        self.assertTrue(self.artifact.exists())
        self.assertTrue(self.runner._active)
        self.assertTrue(self.runner._cancelled.is_set())
        self.calls.clear()
        with self.assertRaises(GateFailure):
            self.invoke()
        self.assertFalse(any(argv[0] == "systemd-run" for argv in self.calls))

    def test_missing_evidence_cannot_become_success(self):
        self.payload = None
        with self.assertRaisesRegex(GateFailure, "did not produce"):
            self.invoke()

    def test_preexisting_artifact_is_never_overwritten_or_deleted(self):
        self.artifact.write_bytes(b"previous receipt")
        with self.assertRaisesRegex(GateFailure, "preexisting"):
            self.invoke()
        self.assertEqual(self.artifact.read_bytes(), b"previous receipt")
        self.assertFalse(self.calls)

    def test_cancellation_during_policy_validation_prevents_launch(self):
        def policy(*args):
            self.runner.cancel()
            return []
        with mock.patch("issue_pipeline.gate.check_policy", side_effect=policy), \
                mock.patch("issue_pipeline.gate.filesystem_command", return_value=["/bin/true"]), \
                mock.patch("issue_pipeline.gate.subprocess.run", side_effect=self.process), \
                mock.patch("issue_pipeline.gate.shutil.disk_usage", return_value=shutil._ntuple_diskusage(2**40, 0, 2**40)):
            with self.assertRaises(GateFailure):
                self.runner.run(self.repo, self.root, SOURCE, BASE, self.output)
        self.assertFalse(any(argv[0] == "systemd-run" for argv in self.calls))


if __name__ == "__main__":
    unittest.main()
