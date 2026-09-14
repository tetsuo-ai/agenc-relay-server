"""Closed command profiles isolate source edits, archives and dependency inputs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import tomllib
import unittest
from unittest import mock

from issue_pipeline.permissions import prepare_permissions


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.worktree = self.state / "worktrees" / "worker"
        self.output = self.state / "sessions" / "attempt"
        self.common = self.state / "repository" / ".git"
        self.cache = self.state / "gate-cache" / "cargo"
        self.tool = self.root / "trusted-tool"
        for path in (self.worktree, self.output, self.common / "worktrees", self.tool,
                     self.cache / "registry" / "src", self.cache / "registry" / "cache",
                     self.cache / "registry" / "index"):
            path.mkdir(parents=True)
        (self.worktree / ".git").write_text("gitdir: fixture\n")
        (self.worktree / "Cargo.toml").write_text('[workspace]\n')
        (self.common / "HEAD").write_text("ref: refs/heads/main\n")
        for name in ("src", "cache"):
            (self.cache / "registry" / name / ".gate-readonly-canary").write_text("benign cache canary\n")
        (self.cache / "registry/index/config.json").write_text('{}\n')
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
                mock.patch("issue_pipeline.permissions._tool_roots", return_value=[self.tool]):
            return prepare_permissions(self.worktree, self.output, role, "codex", evidence_paths=evidence_paths)

    def configuration(self, profile):
        self.assertEqual(len(profile.argv) % 2, 0)
        for flag, value in zip(profile.argv[::2], profile.argv[1::2]):
            self.assertEqual(flag, "-c")
        return tomllib.loads("\n".join(profile.argv[1::2]))

    def test_worker_profile_is_closed_and_preserves_exact_write_scope(self):
        before_home, before_codex = os.environ.get("HOME"), os.environ.get("CODEX_HOME")
        profile = self.prepare()
        config = self.configuration(profile)
        fs = config["permissions"][profile.profile]["filesystem"]
        self.assertEqual(fs[":root"], "deny")
        self.assertEqual(fs[":minimal"], "read")
        self.assertEqual(fs[":slash_tmp"], "deny")
        self.assertEqual({key for key, value in fs.items() if value == "write"},
                         {str(self.worktree), str(self.output / "tmp")})
        self.assertEqual(fs[str(self.common)], "read")
        self.assertEqual(fs[str(self.worktree / ".git")], "read")
        self.assertEqual(fs[str(self.worktree / ".codex")], "read")
        self.assertEqual(fs[str(self.cache)], "read")
        self.assertFalse(config["permissions"][profile.profile]["network"]["enabled"])
        self.assertNotIn("--sandbox", profile.argv)
        self.assertNotIn("sandbox_mode", config)
        self.assertEqual(config["projects"][str(self.worktree)]["trust_level"], "untrusted")
        self.assertEqual(config["projects"][str(self.common.parent)]["trust_level"], "untrusted")
        self.assertEqual(config["shell_environment_policy"]["inherit"], "none")
        self.assertEqual(set(profile.environment), {"TMPDIR", "CARGO_HOME", "RUSTUP_HOME"})
        self.assertEqual(os.environ.get("HOME"), before_home)
        self.assertEqual(os.environ.get("CODEX_HOME"), before_codex)
        self.assertEqual((self.output / "permissions.json").stat().st_mode & 0o777, 0o600)

    def test_readonly_role_cannot_write_source_but_can_use_its_exact_temporary_directory(self):
        profile = self.prepare("reviewer")
        config = self.configuration(profile)
        fs = config["permissions"][profile.profile]["filesystem"]
        self.assertEqual(fs[str(self.worktree)], "read")
        self.assertEqual({key for key, value in fs.items() if value == "write"}, {str(self.output / "tmp")})
        probe = json.loads(profile.probe_argv[-1])
        self.assertIn(str(self.worktree / "Cargo.toml"), probe["readonly"])
        self.assertTrue(all(Path(path).is_relative_to(self.output / "tmp") for path in probe["writable"]))

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

    def test_exact_archive_files_are_readable_without_exposing_parent_state(self):
        archive = self.state / "gates" / "completed" / "receipt.json"
        archive.parent.mkdir(parents=True)
        archive.write_text('{}\n')
        profile = self.prepare("reviewer", (archive,))
        fs = self.configuration(profile)["permissions"][profile.profile]["filesystem"]
        self.assertEqual(fs[str(archive)], "read")
        self.assertNotIn(str(archive.parent), fs)
        self.assertNotIn(str(self.state), fs)

    def test_archive_directory_symlink_and_outside_file_are_rejected(self):
        outside = self.root / "outside.json"
        outside.write_text('{}\n')
        link = self.state / "archive-link.json"
        link.symlink_to(outside)
        for path in (self.state, link, outside):
            with self.subTest(path=path):
                # Each refused preparation receives a fresh private attempt.
                self.output = self.output.parent / ("attempt-" + str(len(self.calls)))
                self.output.mkdir()
                with self.assertRaises(ValueError):
                    self.prepare(evidence_paths=(path,))

    def test_invalid_role_and_unbounded_evidence_are_rejected_before_preparation(self):
        for role, paths in (("operator", ()), ("worker", []), ("worker", tuple([self.root] * 33))):
            with self.subTest(role=role, paths=type(paths).__name__):
                with self.assertRaises(ValueError):
                    self.prepare(role, paths)
        self.assertFalse(self.calls)


if __name__ == "__main__":
    unittest.main()
