"""Real Git tracked inputs must never reach a writable container build-root bind."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from issue_pipeline.config import Config
from issue_pipeline.gitops import GitError, GitRepo
from issue_pipeline.sandbox import ARTIFACT_PREFIX, SandboxFailure
from issue_pipeline_tests import test_sandbox as fixture
from issue_pipeline_tests.test_gitops import git


class BuildRootProtectionTests(unittest.TestCase):
    command = fixture.SandboxPlanTests.command

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agenc-build-root-test-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.config = Config(state_dir=str(self.home / "state"))
        self.worktree = self.config.worktrees / "validation"
        self.output = self.config.state / "gates" / "attempt"
        self.cargo = self.config.state / "gate-cache" / "cargo"
        self.rustup = self.home / ".rustup"
        self.cargo_bin = self.home / ".cargo" / "bin"
        for path in (self.config.clone, self.output, self.rustup, self.cargo_bin):
            path.mkdir(parents=True)
        git(self.config.clone, "init", "--initial-branch=main")
        git(self.config.clone, "config", "user.name", "Sandbox Fixture")
        git(self.config.clone, "config", "user.email", "sandbox@example.invalid")
        for relative in ("scripts/check-stage-nine.sh", "crates/agenc-ircd-storage/.keep", "fuzz/.keep",
                         "target-source.rs", "fuzz/target-source.rs", "other/target/tracked.rs"):
            path = self.config.clone / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("benign tracked fixture\n")
        (self.config.clone / ".gitignore").write_text(
            "/target/\n/fuzz/target/\n/conformance/evidence/artifacts/\n"
            "/crates/agenc-ircd-storage/target/\n/fuzz/artifacts/\n")
        git(self.config.clone, "add", ".")
        git(self.config.clone, "commit", "-m", "Initial containment fixture")
        self.repo = GitRepo(self.config.clone, worktree_root=self.config.worktrees)
        self.source = self.repo.head(self.config.clone)
        self.repo.add_worktree(self.worktree, None, self.source)
        self.common = self.repo.common_dir
        self.admin = Path(self.repo.run(["rev-parse", "--absolute-git-dir"], cwd=self.worktree).strip())
        self.identity = "d" * 64
        self.create_result = 0
        self.created = None
        self.unit = "agenc-ircd-pipeline-gate-" + "b" * 32 + ".service"
        self.record_source()

    def record_source(self):
        self.unit_record = {"unit": self.unit, "source": self.source,
                            "state_dir": str(self.config.state), "repository": self.config.repository}
        (self.output / "unit.json").write_text(json.dumps(self.unit_record))

    def tracked(self, relative, *, kind="file"):
        path = self.worktree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if kind == "gitlink":
            path.mkdir()
            self.repo.run(["update-index", "--add", "--cacheinfo", f"160000,{self.source},{relative}"], cwd=self.worktree)
        else:
            if kind == "symlink":
                path.symlink_to("unowned-destination")
            else:
                path.write_text("reviewed committed source must remain immutable\n")
            self.repo.run(["add", "--force", "--", relative], cwd=self.worktree)
        self.repo.run(["commit", "-m", "Track adversarial build-root input"], cwd=self.worktree)
        self.source = self.repo.head(self.worktree)
        self.record_source()
        # This is committed source, not a dirty cache or merely staged addition.
        self.assertEqual(self.repo.run(["status", "--porcelain"], cwd=self.worktree), "")
        self.assertEqual(self.repo.run(["diff", "HEAD", "--exit-code"], cwd=self.worktree), "")
        return path

    def assert_refused(self, relative, *, kind="file", message="build roots contain tracked source"):
        path = self.tracked(relative, kind=kind)
        before = path.read_bytes() if kind == "file" else os.readlink(path) if kind == "symlink" else None
        with self.assertRaisesRegex(SandboxFailure, message):
            self.command()
        self.assertIsNone(self.created)
        for name in ("container.json", "container-id.json", "filesystem-policy.json", "readonly-canary"):
            self.assertFalse((self.output / name).exists(), name)
        self.assertFalse(self.cargo.exists())  # Refusal precedes cache preparation too.
        self.assertEqual(self.repo.run(["status", "--porcelain"], cwd=self.worktree), "")
        if kind == "file":
            self.assertEqual(path.read_bytes(), before)
        elif kind == "symlink":
            self.assertEqual(os.readlink(path), before)

    def test_clean_tracked_target_descendant_is_refused_before_container_create(self):
        self.assert_refused("target/committed-source.rs")

    def test_clean_tracked_fuzz_target_descendant_is_refused_before_container_create(self):
        self.assert_refused("fuzz/target/committed-source.rs")

    def test_tracked_target_root_file_is_refused_before_mkdir(self):
        self.assert_refused("target")

    def test_tracked_fuzz_target_root_file_is_refused_before_mkdir(self):
        self.assert_refused("fuzz/target")

    def test_tracked_target_root_symlink_is_refused_by_inventory(self):
        self.assert_refused("target", kind="symlink")

    def test_tracked_fuzz_target_root_symlink_is_refused_by_inventory(self):
        self.assert_refused("fuzz/target", kind="symlink")

    def test_tracked_target_root_gitlink_is_refused_by_inventory(self):
        self.assert_refused("target", kind="gitlink")

    def test_tracked_fuzz_target_root_gitlink_is_refused_by_inventory(self):
        self.assert_refused("fuzz/target", kind="gitlink")

    def test_nul_inventory_refuses_tracked_literal_whitespace_and_glob_names(self):
        self.assert_refused("fuzz/target/ \n[committed]*.rs")

    def test_ordinary_untracked_caches_and_neighboring_tracked_paths_remain_supported(self):
        cache_files = []
        for relative in ("target/debug/normal-cache", "fuzz/target/release/normal-cache"):
            path = self.worktree / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("untracked reusable compiler output\n")
            cache_files.append(path)
        self.assertEqual(self.repo.run(["status", "--porcelain"], cwd=self.worktree), "")
        command = self.command()
        self.assertEqual(command[-3:], ["start", "--attach", self.identity])
        self.assertIn("create", self.created)
        policy = json.loads((self.output / "filesystem-policy.json").read_text())
        mounts = {row["target"]: row for row in policy["mounts"]}
        for relative in ("target", "fuzz/target"):
            path = str(self.worktree / relative)
            self.assertEqual(mounts[path], {"source": path, "target": path, "readonly": False})
        self.assertTrue(mounts[str(self.worktree)]["readonly"])
        self.assertTrue(all(path.read_text() == "untracked reusable compiler output\n" for path in cache_files))
        self.assertEqual(self.repo.run(["status", "--porcelain"], cwd=self.worktree), "")

    def test_nested_tracked_artifact_cannot_have_a_writable_renameable_parent(self):
        self.assert_refused(ARTIFACT_PREFIX + "nested/history.json", message="tracked artifacts must be direct regular")

    def test_tracked_artifact_root_file_is_refused_before_mkdir(self):
        self.assert_refused(ARTIFACT_PREFIX.rstrip("/"), message="tracked artifacts must be direct regular")

    def test_tracked_artifact_root_gitlink_is_refused_before_mount_inventory(self):
        self.assert_refused(ARTIFACT_PREFIX.rstrip("/"), kind="gitlink", message="tracked artifacts must be direct regular")

    def test_unpopulated_tracked_artifact_gitlink_is_refused(self):
        self.assert_refused(ARTIFACT_PREFIX + "vendor", kind="gitlink", message="tracked artifacts must be direct regular")

    def test_tracked_artifact_symlink_is_refused(self):
        self.assert_refused(ARTIFACT_PREFIX + "history.json", kind="symlink", message="tracked artifacts must be direct regular")

    def test_existing_untracked_artifact_directory_is_refused_before_create(self):
        path = self.worktree / ARTIFACT_PREFIX / "nested"
        path.mkdir(parents=True)
        (path / "history.json").write_text("preserve original untracked evidence\n")
        with self.assertRaisesRegex(SandboxFailure, "existing artifacts must be direct regular"):
            self.command()
        self.assertIsNone(self.created)
        self.assertFalse((self.output / "container.json").exists())
        self.assertEqual((path / "history.json").read_text(), "preserve original untracked evidence\n")

    def test_existing_untracked_artifact_symlink_is_refused_before_create(self):
        root = self.worktree / ARTIFACT_PREFIX
        root.mkdir(parents=True)
        (root / "history.json").symlink_to(self.worktree / "target-source.rs")
        with self.assertRaisesRegex(SandboxFailure, "existing artifacts must be direct regular"):
            self.command()
        self.assertIsNone(self.created)
        self.assertFalse((self.output / "container.json").exists())
        self.assertTrue((root / "history.json").is_symlink())

    def test_existing_nonregular_artifact_is_refused_without_opening_it(self):
        root = self.worktree / ARTIFACT_PREFIX
        root.mkdir(parents=True)
        os.mkfifo(root / "unexpected-pipe")
        with self.assertRaisesRegex(SandboxFailure, "existing artifacts must be direct regular"):
            self.command()
        self.assertIsNone(self.created)
        self.assertFalse((self.output / "container.json").exists())

    def test_tracked_artifact_parent_symlink_cannot_alias_another_source_directory(self):
        (self.worktree / "conformance").mkdir()
        (self.worktree / "elsewhere").mkdir()
        path = self.worktree / "conformance/evidence"
        path.symlink_to("../elsewhere", target_is_directory=True)
        self.repo.run(["add", "--", "conformance/evidence"], cwd=self.worktree)
        self.repo.run(["commit", "-m", "Track adversarial artifact parent"], cwd=self.worktree)
        self.source = self.repo.head(self.worktree)
        self.record_source()
        self.assertEqual(self.repo.run(["status", "--porcelain"], cwd=self.worktree), "")
        with self.assertRaisesRegex(SandboxFailure, "generated directory traverses a symlink"):
            self.command()
        self.assertIsNone(self.created)
        self.assertFalse(self.cargo.exists())
        self.assertFalse((self.worktree / "elsewhere/artifacts").exists())

    def test_twenty_direct_tracked_receipts_and_new_artifact_creation_remain_supported(self):
        root = self.worktree / ARTIFACT_PREFIX
        root.mkdir(parents=True)
        for index in range(20):
            (root / f"history-{index}.json").write_text("{\"result\": \"historical fixture\"}\n")
        self.repo.run(["add", "--force", "--", ARTIFACT_PREFIX], cwd=self.worktree)
        self.repo.run(["commit", "-m", "Retain twenty direct receipt fixtures"], cwd=self.worktree)
        self.source = self.repo.head(self.worktree)
        self.record_source()
        (root / "untracked-existing.json").write_text("existing untracked receipt\n")
        self.assertEqual(self.repo.run(["status", "--porcelain"], cwd=self.worktree), "")
        self.command()
        mounts = {row["target"]: row for row in json.loads((self.output / "filesystem-policy.json").read_text())["mounts"]}
        self.assertFalse(mounts[str(root)]["readonly"])
        for path in root.iterdir():
            self.assertTrue(mounts[str(path)]["readonly"], path.name)
        self.assertEqual(len(list(root.iterdir())), 21)
        self.assertTrue(mounts[str(self.worktree)]["readonly"])
        self.assertIn("create", self.created)
        self.assertEqual(self.repo.run(["status", "--porcelain"], cwd=self.worktree), "")

    def test_git_inventory_failure_never_reaches_container_creation(self):
        run = self.repo.run
        def unreadable(argv, **kwargs):
            if argv[0] == "ls-files":
                raise GitError("bounded inventory unavailable")
            return run(argv, **kwargs)
        with mock.patch.object(self.repo, "run", side_effect=unreadable), self.assertRaises(GitError):
            self.command()
        self.assertIsNone(self.created)
        self.assertFalse((self.output / "container.json").exists())
        self.assertFalse(self.cargo.exists())


if __name__ == "__main__":
    unittest.main()
