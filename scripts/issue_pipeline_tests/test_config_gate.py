"""Reject weakened policy, forged evidence and unsafe gate restart conditions."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

from issue_pipeline.config import Config, digest_file, private_directory
from issue_pipeline.containers import ContainerError
from issue_pipeline.gate import GATE, ARTIFACT_PREFIX, GateCleanupUncertain, GateFailure, GateRunner, GateStopped
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
                  "version = 1\nmax_issues = 3\nmax_sessions = 4",
                  "version = 1\nmax_issues = 4\nmax_sessions = 4",
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
    @staticmethod
    def coverage(source, first=2, last=4):
        import hashlib
        return {"required_categories": ["authorization-decisions"], "deferred": [], "region": [{
            "id": "fixture-critical", "category": "authorization-decisions",
            "file": "crates/example/src/lib.rs", "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "start_line": first, "end_line": last, "metric": "branches", "reason": "Preserve the authorization paths."}]}

    @staticmethod
    def coverage_text(value):
        lines = [FLOORS]
        for key, item in value.items():
            if key == "region":
                continue
            if key == "deferred":
                text = "[" + ", ".join("{" + ", ".join(field + " = " + json.dumps(data)
                                                         for field, data in row.items()) + "}" for row in item) + "]"
            else:
                text = json.dumps(item)
            lines.append(key + " = " + text)
        for row in value.get("region", []):
            lines.append("\n[[region]]")
            lines.extend(key + " = " + json.dumps(item) for key, item in row.items())
        return "\n".join(lines) + "\n"

    def coverage_repo(self, old_source, new_source, before=None, after=None, diff=None):
        import difflib
        before = self.coverage_text(self.coverage(old_source) if before is None else before)
        after = self.coverage_text(self.coverage(new_source) if after is None else after)
        patch = "".join(difflib.unified_diff(old_source.splitlines(keepends=True),
                                            new_source.splitlines(keepends=True), n=0)) if diff is None else diff
        class SourceRepo:
            def __init__(self):
                self.calls = []
            def run(self, argv):
                self.calls.append(argv)
                if argv[0] == "diff":
                    return "" if "--name-only" in argv else patch
                revision, path = argv[1].split(":", 1)
                if path == "conformance/gates.toml":
                    return MANIFEST
                if path == "crates/example/src/lib.rs":
                    return old_source if revision == BASE else new_source
                return before if revision == BASE else after
        return SourceRepo()

    def test_critical_region_deletion_renaming_or_reclassification_cannot_keep_numeric_floors(self):
        source = "header\na\nb\nc\nfooter\n"
        baseline = self.coverage(source)
        variants = [{**baseline, "region": []}]
        for field, value in (("id", "replacement-id"), ("category", "parser-error-discriminants"),
                             ("file", "crates/example/src/other.rs"), ("metric", "regions")):
            changed = copy.deepcopy(baseline)
            changed["region"][0][field] = value
            variants.append(changed)
        for after in variants:
            with self.subTest(after=after), self.assertRaises(GateFailure):
                check_policy(self.coverage_repo(source, source, baseline, after), BASE, SOURCE)

    def test_unchanged_source_must_keep_entire_span_but_can_expand_it(self):
        source = "header\na\nb\nc\nfooter\n"
        for first, last in ((3, 4), (2, 3)):
            with self.subTest(first=first, last=last), self.assertRaisesRegex(GateFailure, "narrows"):
                check_policy(self.coverage_repo(source, source, after=self.coverage(source, first, last)), BASE, SOURCE)
        self.assertEqual(len(check_policy(self.coverage_repo(source, source, after=self.coverage(source, 1, 5)), BASE, SOURCE)), 2)

    def test_required_categories_and_deferrals_cannot_reduce_critical_obligations(self):
        source = "header\na\nb\nc\nfooter\n"
        baseline = self.coverage(source)
        missing = copy.deepcopy(baseline)
        missing.pop("required_categories")
        deferred = copy.deepcopy(baseline)
        deferred["deferred"] = [{"category": "authorization-decisions", "until_task": "REL-13", "reason": "Later"}]
        for after in (missing, {**baseline, "required_categories": []}, deferred):
            with self.assertRaises(GateFailure):
                check_policy(self.coverage_repo(source, source, baseline, after), BASE, SOURCE)
        delayed = copy.deepcopy(deferred)
        delayed["deferred"][0]["until_task"] = "REL-99"
        with self.assertRaisesRegex(GateFailure, "deferral"):
            check_policy(self.coverage_repo(source, source, deferred, delayed), BASE, SOURCE)
        self.assertEqual(len(check_policy(self.coverage_repo(source, source, deferred, baseline), BASE, SOURCE)), 2)

    def test_shifted_spans_and_hash_refreshes_preserve_covered_lines_with_cached_mapping(self):
        old = "header\na\nb\nc\nfooter\n"
        new = "preface\n" + old
        after = self.coverage(new, 3, 5)
        after.update(reviewed_source_files=999, reviewed_source_sha256="f" * 64)
        repo = self.coverage_repo(old, new, after=after)
        self.assertEqual(len(check_policy(repo, BASE, SOURCE)), 2)
        self.assertEqual(sum("--unified=0" in argv for argv in repo.calls), 1)
        self.assertEqual(sum(argv[0] == "show" and argv[1].endswith(":crates/example/src/lib.rs") for argv in repo.calls), 2)
        with self.assertRaisesRegex(GateFailure, "narrows"):
            check_policy(self.coverage_repo(old, new, after=self.coverage(new, 2, 4)), BASE, SOURCE)
        outside = old.replace("header", "updated preamble")
        self.assertEqual(len(check_policy(self.coverage_repo(old, outside), BASE, SOURCE)), 2)

    def test_replacement_hunks_must_keep_every_replacement_and_retained_line(self):
        old = "header\na\nb\nc\nfooter\n"
        new = "header\na\nnew_one\nnew_two\nc\nfooter\n"
        self.assertEqual(len(check_policy(self.coverage_repo(old, new, after=self.coverage(new, 2, 5)), BASE, SOURCE)), 2)
        for first, last in ((2, 4), (3, 5)):
            with self.subTest(first=first, last=last), self.assertRaisesRegex(GateFailure, "narrows"):
                check_policy(self.coverage_repo(old, new, after=self.coverage(new, first, last)), BASE, SOURCE)
        before = self.coverage(old, 3, 3)
        with self.assertRaisesRegex(GateFailure, "narrows"):
            check_policy(self.coverage_repo(old, new, before, self.coverage(new, 3, 3)), BASE, SOURCE)
        self.assertEqual(len(check_policy(self.coverage_repo(old, new, before, self.coverage(new, 3, 4)), BASE, SOURCE)), 2)

    def test_shorter_rewrites_and_partial_deletion_can_refresh_coverage(self):
        old = "header\na\nb\nc\nfooter\n"
        rewritten = "header\nfixed_authorization\nfooter\n"
        self.assertEqual(len(check_policy(self.coverage_repo(old, rewritten, after=self.coverage(rewritten, 2, 2)), BASE, SOURCE)), 2)
        partial = "header\na\nc\nfooter\n"
        self.assertEqual(len(check_policy(self.coverage_repo(old, partial, after=self.coverage(partial, 2, 3)), BASE, SOURCE)), 2)
        removed = "header\nfooter\n"
        with self.assertRaisesRegex(GateFailure, "entirely deleted"):
            check_policy(self.coverage_repo(old, removed, after=self.coverage(removed, 1, 2)), BASE, SOURCE)

    def test_forged_source_hash_duplicate_id_and_unprovable_diff_are_refused(self):
        source = "header\na\nb\nc\nfooter\n"
        wrong = self.coverage(source)
        wrong["region"][0]["source_sha256"] = "f" * 64
        with self.assertRaisesRegex(GateFailure, "stale source"):
            check_policy(self.coverage_repo(source, source, after=wrong), BASE, SOURCE)
        duplicate = self.coverage(source)
        duplicate["region"] *= 2
        with self.assertRaisesRegex(GateFailure, "duplicate"):
            check_policy(self.coverage_repo(source, source, after=duplicate), BASE, SOURCE)
        shifted = "preface\n" + source
        with self.assertRaisesRegex(GateFailure, "mapping is unproven"):
            check_policy(self.coverage_repo(source, shifted, after=self.coverage(shifted, 3, 5), diff=""), BASE, SOURCE)

    def test_real_git_line_mapping_keeps_critical_replacements_and_rejects_omitted_tail(self):
        from issue_pipeline.gitops import GitRepo
        with tempfile.TemporaryDirectory(prefix="agenc-policy-git-") as temporary:
            root = Path(temporary)
            def git(*argv):
                return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", *argv], cwd=root,
                                               text=True, stderr=subprocess.DEVNULL).strip()
            git("init", "--initial-branch=main")
            git("config", "user.name", "Policy Test")
            git("config", "user.email", "policy@example.invalid")
            (root / "conformance").mkdir()
            file = root / "crates/example/src/lib.rs"
            file.parent.mkdir(parents=True)
            old = "header\na\nb\nc\nfooter\n"
            file.write_text(old)
            (root / "conformance/gates.toml").write_text(MANIFEST)
            policies = [root / "conformance" / name for name in ("critical-coverage.toml", "release-critical-coverage.toml")]
            for path in policies:
                path.write_text(self.coverage_text(self.coverage(old)))
            git("add", ".")
            git("commit", "-m", "Initial critical inventory")
            base = git("rev-parse", "HEAD")
            new = "preface\nheader\na\nnew_one\nnew_two\nc\nfooter\n"
            file.write_text(new)
            for path in policies:
                path.write_text(self.coverage_text(self.coverage(new, 3, 6)))
            git("add", ".")
            git("commit", "-m", "Preserve complete replacement coverage")
            repo = GitRepo(root, worktree_root=root / "worktrees")
            self.assertEqual(len(check_policy(repo, base, git("rev-parse", "HEAD"))), 2)
            policies[0].write_text(self.coverage_text(self.coverage(new, 3, 5)))
            git("add", "conformance/critical-coverage.toml")
            git("commit", "-m", "Attempt to omit the retained critical tail")
            with self.assertRaisesRegex(GateFailure, "narrows"):
                check_policy(repo, base, git("rev-parse", "HEAD"))

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

    def test_candidate_modules_cannot_shadow_host_validator_standard_library(self):
        marker = Path(self.temporary.name) / "candidate-imported-on-host"
        payload = "from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\nraise RuntimeError('candidate import executed')\n"
        shadows = [self.root / "scripts" / name for name in ("copy.py", "tomllib.py")]
        try:
            for shadow in shadows:
                self.assertFalse(shadow.exists())
                shadow.write_text(payload)
            self.assertEqual(self.validate(self.value)["source"], self.source)
            self.assertFalse(marker.exists())
        finally:
            for shadow in shadows:
                shadow.unlink(missing_ok=True)

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
        if argv[0] == "/usr/bin/prlimit":
            self.assertEqual(argv[1], "--fsize=67108864:67108864")
            argv = argv[3:]
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
                mock.patch("issue_pipeline.gate.subprocess.Popen", side_effect=self.popen), \
                mock.patch.object(self.runner, "_wait_for_gate", side_effect=lambda launcher, root: launcher.wait(timeout=1)), \
                mock.patch("issue_pipeline.gate.validate_artifact", side_effect=GateFailure("bad evidence")), \
                mock.patch("issue_pipeline.gate.shutil.disk_usage", return_value=shutil._ntuple_diskusage(2**40, 0, 2**40)):
            return self.runner.run(self.repo, self.root, SOURCE, BASE, self.output)

    def test_disk_reserve_failure_still_quiesces_the_gate(self):
        def wait(launcher, root):
            with mock.patch("issue_pipeline.gate.shutil.disk_usage", return_value=shutil._ntuple_diskusage(2**40, 2**40, 0)):
                return GateRunner._wait_for_gate(self.runner, launcher, root)
        # This fixture exercises the production monitor and its run() finally
        # cleanup; only Docker/systemd are mocked at their external boundaries.
        with mock.patch("issue_pipeline.gate.check_policy", return_value=[]), \
             mock.patch("issue_pipeline.gate.filesystem_command", return_value=["/bin/true"]), \
             mock.patch("issue_pipeline.gate.subprocess.run", side_effect=self.process), \
             mock.patch("issue_pipeline.gate.subprocess.Popen", side_effect=self.popen), \
             mock.patch.object(self.runner, "_wait_for_gate", side_effect=wait):
            with self.assertRaisesRegex(GateFailure, "free-disk reserve"):
                self.runner.run(self.repo, self.root, SOURCE, BASE, self.output)
        self.assertTrue(any("show" in argv for argv in self.calls))
        self.assertFalse(self.runner._active)
        self.assertFalse(self.runner._launchers)

    @unittest.skipUnless(Path("/usr/bin/prlimit").exists(), "native Linux file-size control")
    def test_native_file_size_control_bounds_noisy_launcher_output(self):
        path = self.root / "bounded-log"
        limit = 64 * 1024
        with path.open("xb") as log:
            result = subprocess.run(["/usr/bin/prlimit", f"--fsize={limit}:{limit}", "--", sys.executable,
                                     "-I", "-B", "-c", "import os; [os.write(1, b'x'*8192) for _ in range(100)]"],
                                    stdout=log, stderr=subprocess.DEVNULL, timeout=10, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertLessEqual(path.stat().st_size, limit)

    def popen(self, argv, **kwargs):
        self.assertTrue(self.runner._active_lock.locked(), "spawn must share the cancellation barrier")
        try:
            result = self.process(argv, **kwargs)
        except subprocess.TimeoutExpired:
            result = subprocess.CompletedProcess(argv, 0)
        launcher = mock.Mock()
        launcher.pid = 987654321
        launcher.poll.return_value = result.returncode
        if self.timeout:
            launcher.wait.side_effect = subprocess.TimeoutExpired(argv, 1)
        else:
            launcher.wait.return_value = result.returncode
        return launcher

    def test_cancellation_after_registration_before_spawn_never_launches(self):
        original_open = Path.open

        def opening(path, *args, **kwargs):
            result = original_open(path, *args, **kwargs)
            if path == self.output / "full-gate.log":
                self.assertTrue(self.runner._active)
                self.runner.cancel()
            return result

        with mock.patch.object(Path, "open", opening):
            with self.assertRaisesRegex(GateFailure, "stopped before gate launch"):
                self.invoke()
        self.assertFalse(any(argv[0] == "systemd-run" for argv in self.calls))
        self.assertFalse(self.runner._active)
        self.assertFalse(self.runner._launchers)

    def test_timeout_quiesces_local_launcher_before_unit_reconciliation(self):
        launcher = mock.Mock()
        launcher.pid = 987654321
        launcher.poll.return_value = None
        launcher.wait.side_effect = [subprocess.TimeoutExpired("systemd-run", 1), -9]

        def spawn(argv, **kwargs):
            self.process(argv, **kwargs)
            self.assertTrue(self.runner._active_lock.locked())
            return launcher

        def kill(pid, sig):
            self.assertEqual(pid, launcher.pid)
            self.assertFalse(any("show" in argv for argv in self.calls))

        with mock.patch.object(self, "popen", side_effect=spawn), \
                mock.patch("issue_pipeline.gate.os.killpg", side_effect=kill) as killed:
            with self.assertRaisesRegex(GateFailure, "timed out"):
                self.invoke()
        killed.assert_called_once()
        self.assertEqual(launcher.wait.call_count, 2)
        self.assertFalse(self.runner._active)
        self.assertFalse(self.runner._launchers)
        self.assertTrue((self.output / "gate-artifact-failed.json").exists())

    def test_error_or_partial_systemd_output_cannot_prove_quiescence(self):
        complete = "LoadState=loaded\nActiveState=inactive\nMainPID=0\nControlPID=0\nControlGroup=\n"
        for code, output in ((1, complete), (0, complete.replace("ControlGroup=\n", "")),
                             (0, complete + "MainPID=0\n"),
                             (0, complete.replace("LoadState=loaded", "LoadState=error"))):
            with self.subTest(code=code, output=output):
                runner = GateRunner(self.runner.config)
                with mock.patch("issue_pipeline.gate.subprocess.run", return_value=
                                subprocess.CompletedProcess([], code, stdout=output)):
                    with self.assertRaisesRegex(GateCleanupUncertain, "cleanup is uncertain"):
                        runner._stop_unit("agenc-ircd-pipeline-gate-" + "a" * 32 + ".service")
                self.assertTrue(runner._cancelled.is_set())

    def test_nonzero_gate_preserves_failed_artifact_outside_worktree(self):
        self.exit_code = 1
        with self.assertRaises(GateFailure):
            self.invoke()
        self.assertFalse(self.artifact.exists())
        self.assertEqual((self.output / "gate-artifact-failed.json").read_bytes(), self.payload)
        self.assertFalse(self.runner._active)
        self.runner.assert_available()

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
        with self.assertRaisesRegex(GateCleanupUncertain, "cleanup is uncertain"):
            self.invoke()
        self.assertTrue(self.artifact.exists())
        self.assertTrue(self.runner._active)
        self.assertTrue(self.runner._cancelled.is_set())
        self.calls.clear()
        with self.assertRaises(GateCleanupUncertain):
            self.invoke()
        self.assertFalse(any(argv[0] == "systemd-run" for argv in self.calls))
        with self.assertRaises(GateCleanupUncertain):
            self.runner.assert_available()

    def test_successful_later_cleanup_does_not_silently_resume_stopped_controller(self):
        self.active = True
        with self.assertRaises(GateCleanupUncertain):
            self.invoke()
        self.active = False
        with mock.patch("issue_pipeline.gate.subprocess.run", side_effect=self.process):
            self.runner.cancel()
        with self.assertRaises(GateCleanupUncertain):
            self.runner.assert_available()
        self.assertTrue(self.artifact.exists())

    def test_unresolved_container_creation_is_a_typed_nonrepairable_stop(self):
        def unresolved(config, repo, worktree, output):
            (output / "container.json").write_text("unresolved inert create intent")
            raise GateFailure("Docker create response was lost")

        with mock.patch("issue_pipeline.gate.check_policy", return_value=[]), \
                mock.patch("issue_pipeline.gate.filesystem_command", side_effect=unresolved), \
                mock.patch("issue_pipeline.gate.subprocess.Popen") as launch, \
                mock.patch("issue_pipeline.gate.shutil.disk_usage", return_value=shutil._ntuple_diskusage(2**40, 0, 2**40)):
            with self.assertRaisesRegex(GateCleanupUncertain, "preparation is unresolved"):
                self.runner.run(self.repo, self.root, SOURCE, BASE, self.output)
        launch.assert_not_called()
        self.assertTrue((self.output / "container.json").exists())
        with self.assertRaises(GateCleanupUncertain):
            self.runner.assert_available()

    def test_cancelled_runner_is_distinct_from_cleanup_uncertainty(self):
        self.runner.cancel()
        with self.assertRaises(GateStopped) as raised:
            self.runner.assert_available()
        self.assertNotIsInstance(raised.exception, GateCleanupUncertain)

    def test_container_cleanup_follows_launcher_quiescence_and_removes_active_authority(self):
        self.output.mkdir()
        container = self.output / "container.json"
        container.write_text("benign mocked ownership record")
        (self.output / "filesystem-policy.json").write_text(json.dumps({
            "bootstrap": {"home_scratch": str(self.root / "absent-private-home-canary")}}))

        def cleanup(path, state):
            self.assertEqual(path, container)
            self.assertEqual(state, self.runner.config.state)
            self.assertTrue(any("show" in argv for argv in self.calls))

        with mock.patch("issue_pipeline.gate.stop_owned_container", side_effect=cleanup) as stop:
            with self.assertRaises(GateFailure):
                self.invoke()
        stop.assert_called_once()
        self.assertFalse(self.runner._containers)
        self.assertFalse(self.runner._active)
        self.assertTrue((self.output / "gate-artifact-failed.json").exists())

    def test_daemon_failure_blocks_retry_and_preserves_artifact_after_launcher_stops(self):
        self.output.mkdir()
        (self.output / "container.json").write_text("benign mocked ownership record")
        with mock.patch("issue_pipeline.gate.stop_owned_container", side_effect=ContainerError("daemon unavailable")):
            with self.assertRaisesRegex(GateCleanupUncertain, "cleanup is uncertain"):
                self.invoke()
        self.assertTrue(self.artifact.exists())
        self.assertTrue(self.runner._containers)
        self.assertTrue(self.runner._active)
        self.assertTrue(self.runner._cancelled.is_set())
        self.assertFalse((self.output / "gate-artifact-failed.json").exists())

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
