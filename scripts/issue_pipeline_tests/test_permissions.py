"""Closed command sandbox policies isolate source edits, archives and dependency inputs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from issue_pipeline.permissions import CREDENTIAL_VARIABLES, prepare_permissions


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.state = self.home / "state"
        self.worktree = self.state / "worktrees" / "worker"
        self.output = self.state / "sessions" / "attempt"
        self.common = self.state / "repository" / ".git"
        self.cache = self.state / "gate-cache" / "cargo"
        self.tool = self.root / "trusted-tool"
        self.runtime = self.root / "sandbox-runtime"
        for path in (self.worktree, self.output, self.common / "worktrees", self.tool, self.runtime,
                     self.cache / "registry" / "src", self.cache / "registry" / "cache",
                     self.cache / "registry" / "index"):
            path.mkdir(parents=True)
        (self.worktree / ".git").write_text("gitdir: fixture\n")
        (self.worktree / "Cargo.toml").write_text('[workspace]\n')
        (self.common / "HEAD").write_text("ref: refs/heads/main\n")
        for name in ("src", "cache"):
            (self.cache / "registry" / name / ".gate-readonly-canary").write_text("benign cache canary\n")
        (self.cache / "registry/index/config.json").write_text('{}\n')
        self.launcher = self.runtime / "srt"
        self.launcher.write_text("#!/bin/sh\nexit 0\n")
        self.launcher.chmod(0o700)
        self.calls = []

    def process(self, argv, *args, **kwargs):
        self.calls.append(argv)
        if argv[0] == "git":
            return 0, str(self.common)
        if argv[0] == "cp":
            shutil.copytree(argv[-2], argv[-1])
            return 0, ""
        self.fail("unexpected external preparation command")

    def prepare(self, role="worker", evidence_paths=()):
        with mock.patch("issue_pipeline.permissions._process", side_effect=self.process), \
                mock.patch("issue_pipeline.permissions._tool_roots", return_value=[self.tool]), \
                mock.patch("issue_pipeline.permissions.Path.home", return_value=self.home):
            return prepare_permissions(self.worktree, self.output, role, str(self.launcher),
                                       evidence_paths=evidence_paths)

    def test_worker_policy_hides_home_and_preserves_exact_write_scope(self):
        before_home = os.environ.get("HOME")
        profile = self.prepare()
        settings = json.loads(profile.settings)
        sandbox = settings["sandbox"]
        fs = sandbox["filesystem"]
        self.assertTrue(sandbox["enabled"])
        self.assertTrue(sandbox["failIfUnavailable"])
        self.assertFalse(sandbox["allowUnsandboxedCommands"])
        self.assertEqual(sandbox["excludedCommands"], [])
        self.assertEqual(sandbox["network"]["allowedDomains"], [])
        self.assertTrue(sandbox["network"]["strictAllowlist"])
        self.assertIn(str(self.home) + "/", fs["denyRead"])
        self.assertIn("/run/docker.sock", fs["denyRead"])
        self.assertIn("/run/user/" + str(os.getuid()), fs["denyRead"])
        runtime = Path(profile.environment["TMPDIR"])
        self.assertEqual(runtime.parent, self.state / "runtime")
        self.assertTrue(runtime.is_dir())
        self.assertEqual(runtime.stat().st_mode & 0o777, 0o700)
        self.assertLess(len(str(runtime)), 80)
        self.assertEqual(set(fs["allowWrite"]), {str(self.worktree), str(self.output / "tmp"), str(runtime)})
        for path in (self.worktree, self.common, self.cache, self.tool, self.output / "tmp"):
            self.assertIn(str(path), fs["allowRead"])
        for path in (self.worktree / ".git", self.common, self.cache):
            self.assertIn(str(path), fs["denyWrite"])
        self.assertNotIn(str(self.state), fs["allowRead"])
        self.assertNotIn(str(self.output), fs["allowRead"])
        self.assertEqual({entry["name"] for entry in sandbox["credentials"]["envVars"]}, set(CREDENTIAL_VARIABLES))
        self.assertTrue(all(entry["mode"] == "deny" for entry in sandbox["credentials"]["envVars"]))
        self.assertEqual(settings["permissions"]["defaultMode"], "dontAsk")
        self.assertIn("Read(//" + str(self.home / ".claude").lstrip("/") + "/**)", settings["permissions"]["deny"])
        self.assertIn("WebFetch", settings["permissions"]["deny"])
        self.assertEqual(profile.tools, ("Bash", "Read", "Edit", "Write", "Glob", "Grep"))
        self.assertEqual(profile.add_dirs, (str(self.worktree),))
        self.assertEqual(set(profile.environment), {"TMPDIR", "CARGO_HOME", "RUSTUP_HOME"})
        self.assertEqual(os.environ.get("HOME"), before_home)
        self.assertEqual((self.output / "permissions.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.output / "sandbox-probe.json").stat().st_mode & 0o777, 0o600)

    def test_probe_runs_the_same_filesystem_policy_through_the_sandbox_runtime(self):
        profile = self.prepare()
        self.assertEqual(profile.probe_argv[0], str(self.launcher.resolve()))
        self.assertEqual(profile.probe_argv[1:3], ("-s", str(self.output / "sandbox-probe.json")))
        self.assertEqual(profile.probe_argv[3:6], ("--", "/usr/bin/python3", "-I"))
        probe = json.loads((self.output / "sandbox-probe.json").read_text())
        self.assertEqual(probe["filesystem"], json.loads(profile.settings)["sandbox"]["filesystem"])
        self.assertEqual(probe["network"], {"allowedDomains": [], "deniedDomains": []})
        request = json.loads(profile.probe_argv[-1])
        self.assertIn(str(self.output / "permission-hidden-canary"), request["denied"])
        self.assertIn(str(self.home / ".claude" / ".credentials.json"), request["denied"])
        self.assertIn("/var/run/docker.sock", request["sockets"])
        self.assertIn(str(self.worktree / ".git"), request["readonly"])
        self.assertIn(str(self.common / "HEAD"), request["readonly"])
        self.assertTrue(any(path.startswith(str(self.worktree / ".permission-write-control-")) for path in request["writable"]))
        self.assertTrue(any(path.startswith(str(self.output / "tmp" / "write-control-")) for path in request["writable"]))
        self.assertEqual(request["visible"], str(self.output / "permission-readonly-canary"))
        self.assertIn(request["visible"], json.loads(profile.settings)["sandbox"]["filesystem"]["allowRead"])

    def test_readonly_role_cannot_write_source_but_can_use_its_exact_temporary_directory(self):
        profile = self.prepare("reviewer")
        fs = json.loads(profile.settings)["sandbox"]["filesystem"]
        self.assertEqual(fs["allowWrite"], [str(self.output / "tmp"), profile.environment["TMPDIR"]])
        self.assertIn(str(self.worktree), fs["denyWrite"])
        self.assertEqual(profile.tools, ("Bash", "Read", "Glob", "Grep"))
        probe = json.loads(profile.probe_argv[-1])
        self.assertIn(str(self.worktree / "Cargo.toml"), probe["readonly"])
        self.assertTrue(all(Path(path).is_relative_to(self.output / "tmp")
                            or Path(path).is_relative_to(profile.environment["TMPDIR"]) for path in probe["writable"]))

    def test_private_cargo_owns_mutable_metadata_and_package_aliases_stay_readonly(self):
        profile = self.prepare()
        cargo = Path(profile.environment["CARGO_HOME"])
        self.assertTrue(cargo.is_relative_to(self.output / "tmp"))
        for name in ("src", "cache"):
            alias = cargo / "registry" / name
            self.assertTrue(alias.is_symlink())
            self.assertEqual(alias.resolve(), self.cache / "registry" / name)
            self.assertIn(str(alias / ".gate-readonly-canary"), json.loads(profile.probe_argv[-1])["readonly"])
        index = cargo / "registry" / "index"
        self.assertFalse(index.is_symlink())
        (index / "config.json").write_text('local session mutation\n')
        self.assertEqual((self.cache / "registry/index/config.json").read_text(), '{}\n')

    def test_exact_archive_files_are_copied_into_one_private_readable_directory(self):
        archive = self.state / "gates" / "completed" / "receipt.json"
        archive.parent.mkdir(parents=True)
        archive.write_text('{"benign": true}\n')
        profile = self.prepare("reviewer", (archive,))
        copy = self.output / "evidence" / "receipt.json"
        self.assertEqual(profile.evidence, (str(copy),))
        self.assertEqual(profile.add_dirs, (str(self.worktree), str(copy.parent)))
        self.assertEqual(copy.read_bytes(), archive.read_bytes())
        self.assertEqual(copy.stat().st_mode & 0o777, 0o400)
        fs = json.loads(profile.settings)["sandbox"]["filesystem"]
        self.assertIn(str(copy.parent), fs["allowRead"])
        self.assertIn(str(copy.parent), fs["denyWrite"])
        self.assertNotIn(str(archive), fs["allowRead"])
        self.assertNotIn(str(archive.parent), fs["allowRead"])
        self.assertNotIn(str(self.state), fs["allowRead"])
        self.assertIn(str(copy), json.loads(profile.probe_argv[-1])["readonly"])
        record = json.loads((self.output / "permissions.json").read_text())
        self.assertEqual(record["evidence_paths"], [str(archive)])
        self.assertEqual(record["evidence_copies"], [str(copy)])

    def test_archive_directory_symlink_outside_file_and_duplicate_names_are_rejected(self):
        outside = self.root / "outside.json"
        outside.write_text('{}\n')
        link = self.state / "archive-link.json"
        link.symlink_to(outside)
        first = self.state / "gates" / "one" / "receipt.json"
        second = self.state / "gates" / "two" / "receipt.json"
        for path in (first, second):
            path.parent.mkdir(parents=True)
            path.write_text('{}\n')
        for paths in ((self.state,), (link,), (outside,), (first, second)):
            with self.subTest(paths=paths):
                # Each refused preparation receives a fresh private attempt.
                self.output = self.output.parent / ("attempt-" + str(len(self.calls)))
                self.output.mkdir()
                with self.assertRaises(ValueError):
                    self.prepare("reviewer", evidence_paths=paths)

    def test_invalid_role_and_unbounded_evidence_are_rejected_before_preparation(self):
        for role, paths in (("operator", ()), ("worker", []), ("worker", tuple([self.root] * 33))):
            with self.subTest(role=role, paths=type(paths).__name__):
                with self.assertRaises(ValueError):
                    self.prepare(role, paths)
        self.assertFalse(self.calls)

    def test_state_outside_home_and_tool_roots_inside_state_are_rejected(self):
        with mock.patch("issue_pipeline.permissions._process", side_effect=self.process), \
                mock.patch("issue_pipeline.permissions._tool_roots", return_value=[self.state / "gate-cache"]), \
                mock.patch("issue_pipeline.permissions.Path.home", return_value=self.home):
            with self.assertRaises(ValueError):
                prepare_permissions(self.worktree, self.output, "worker", str(self.launcher))
        self.output = self.output.parent / "attempt-outside"
        self.output.mkdir()
        with mock.patch("issue_pipeline.permissions._process", side_effect=self.process), \
                mock.patch("issue_pipeline.permissions._tool_roots", return_value=[self.tool]), \
                mock.patch("issue_pipeline.permissions.Path.home", return_value=self.root / "elsewhere"):
            (self.root / "elsewhere").mkdir()
            with self.assertRaises(ValueError):
                prepare_permissions(self.worktree, self.output, "worker", str(self.launcher))


if __name__ == "__main__":
    unittest.main()
