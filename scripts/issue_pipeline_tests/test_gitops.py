"""Real local-Git proofs for pipeline ref leases, worktree ownership and cleanup."""

from __future__ import annotations

import fcntl
import json
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from issue_pipeline.gitops import GitError, GitRepo, _process


def git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=path,
                            text=True, capture_output=True, timeout=30, check=True)
    return result.stdout.strip()


class GitRepoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="agenc-pipeline-git-")
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.remote = self.parent / "remote.git"
        self.seed = self.parent / "seed"
        self.root = self.parent / "controller"
        self.owned = self.parent / "worktrees"
        git(self.parent, "init", "--bare", "--initial-branch=main", str(self.remote))
        git(self.parent, "init", "--initial-branch=main", str(self.seed))
        self.identity(self.seed)
        (self.seed / "tracked.txt").write_text("base\n")
        (self.seed / ".gitignore").write_text("*.generated\ntarget/\n")
        git(self.seed, "add", ".")
        git(self.seed, "commit", "-m", "base")
        git(self.seed, "remote", "add", "origin", str(self.remote))
        git(self.seed, "push", "origin", "main")
        git(self.parent, "clone", str(self.remote), str(self.root))
        self.identity(self.root)
        self.repo = GitRepo(self.root, worktree_root=self.owned)
        self.base = self.repo.fetch()

    @staticmethod
    def identity(path: Path) -> None:
        git(path, "config", "user.name", "Pipeline Test")
        git(path, "config", "user.email", "pipeline-test@example.invalid")

    def worker(self, name: str = "worker", branch: str | None = "pipeline/worker") -> Path:
        path = self.owned / name
        self.repo.add_worktree(path, branch, self.base)
        return path

    def commit(self, path: Path, text: str = "worker\n", name: str = "tracked.txt") -> str:
        (path / name).write_text(text)
        return self.repo.commit(path, "Complete fixture change\n\nLiteral `code` and $(text).")

    def advance_remote(self, name: str = "concurrent.txt") -> str:
        (self.seed / name).write_text("another controller\n")
        git(self.seed, "add", name)
        git(self.seed, "commit", "-m", "concurrent main change")
        git(self.seed, "push", "origin", "main")
        return git(self.seed, "rev-parse", "HEAD")

    def test_fetch_head_tree_and_exact_sha_validation(self) -> None:
        self.assertEqual(self.repo.head(self.root), self.base)
        self.assertEqual(self.repo.tree(self.base), git(self.root, "rev-parse", "HEAD^{tree}"))
        with self.assertRaises(GitError):
            self.repo.tree("HEAD")
        with self.assertRaises(GitError):
            self.repo.atomic_promote(self.base, "--help")

    def test_controller_commits_literal_filenames_and_message_without_shell(self) -> None:
        path = self.worker()
        filename = "literal $(touch escaped); `echo x`\nrecord.txt"
        sha = self.commit(path, "literal\n", filename)
        self.assertEqual(self.repo.changed_paths(path, self.base), [filename])
        self.assertEqual(self.repo.changed_paths(path), [])
        self.assertIn("$(text)", git(path, "log", "-1", "--format=%B"))
        self.assertNotEqual(sha, self.base)
        self.assertFalse((path / "escaped").exists())

    def test_commit_refuses_symlink_and_staged_gitlink(self) -> None:
        path = self.worker()
        (path / "unsafe").symlink_to(self.parent / "outside")
        with self.assertRaises(GitError):
            self.repo.commit(path, "reject symlink")
        self.assertEqual(self.repo.head(path), self.base)
        (path / "unsafe").unlink()
        git(path, "update-index", "--add", "--cacheinfo", f"160000,{self.base},vendor")
        with self.assertRaises(GitError):
            self.repo.commit(path, "reject gitlink")
        self.assertEqual(self.repo.head(path), self.base)

    def test_atomic_promotion_proves_fast_forward_and_preserves_worker_ref(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.push_branch("pipeline/worker", candidate)
        self.assertEqual(self.repo.atomic_promote(candidate, self.base), candidate)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/main"), candidate)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/pipeline/worker"), candidate)

    def test_atomic_promotion_rejects_concurrent_base_without_overwriting_it(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        concurrent = self.advance_remote()
        with self.assertRaises(GitError):
            self.repo.atomic_promote(candidate, self.base)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/main"), concurrent)

    def test_atomic_promotion_rejects_non_descendant_even_with_correct_lease(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.atomic_promote(candidate, self.base)
        with self.assertRaises(GitError):
            self.repo.atomic_promote(self.base, candidate)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/main"), candidate)

    def test_ancestry_proof_ignores_local_grafts_and_replacement_refs(self) -> None:
        path = self.worker()
        git(path, "checkout", "--orphan", "unrelated")
        git(path, "commit", "-m", "unrelated root")
        unrelated = git(path, "rev-parse", "HEAD")
        grafts = self.repo.common_dir / "info" / "grafts"
        grafts.write_text(f"{unrelated} {self.base}\n")
        self.assertFalse(self.repo.is_ancestor(self.base, unrelated))
        grafts.unlink()
        git(path, "replace", "--graft", unrelated, self.base)
        self.assertFalse(self.repo.is_ancestor(self.base, unrelated))
        with self.assertRaises(GitError):
            self.repo.atomic_promote(unrelated, self.base)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/main"), self.base)

    def test_push_branch_rejects_foreign_remote_ref_and_base_branch(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        git(self.seed, "push", "origin", f"{self.base}:refs/heads/pipeline/worker")
        with self.assertRaises(GitError):
            self.repo.push_branch("pipeline/worker", candidate)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/pipeline/worker"), self.base)
        with self.assertRaises(GitError):
            self.repo.push_branch("main", candidate)

    def test_push_reconciles_applied_response_loss_without_repeating_push(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        original = self.repo.run
        def response_lost(argv, cwd=None):
            value = original(argv, cwd=cwd)
            if argv[0] == "push":
                raise RuntimeError("push response lost")
            return value
        with mock.patch.object(self.repo, "run", side_effect=response_lost), self.assertRaises(RuntimeError):
            self.repo.push_branch("pipeline/worker", candidate)
        item = json.loads(self.repo.ownership.read_text())["worktrees"][str(path)]
        self.assertEqual(item["pending_push"], {"old": None, "wanted": candidate})
        self.assertIsNone(item["remote_head"])
        recovered = GitRepo(self.root, worktree_root=self.owned)
        with mock.patch.object(recovered, "run", wraps=recovered.run) as calls:
            self.assertEqual(recovered.push_branch("pipeline/worker", candidate), candidate)
        self.assertFalse(any(call.args[0][0] == "push" for call in calls.call_args_list))
        item = json.loads(self.repo.ownership.read_text())["worktrees"][str(path)]
        self.assertEqual(item["remote_head"], candidate)
        self.assertNotIn("pending_push", item)

    def test_push_reconciles_final_ledger_write_loss_but_not_arbitrary_matching_ref(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        # A matching SHA alone grants no ownership of an externally created ref.
        git(self.root, "push", "origin", candidate + ":refs/heads/pipeline/worker")
        with self.assertRaisesRegex(GitError, "outside controller ownership"):
            self.repo.push_branch("pipeline/worker", candidate)
        git(self.root, "push", "origin", ":refs/heads/pipeline/worker")
        original = self.repo._write_records
        writes = 0
        def crash(records):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise OSError("final journal flush lost")
            original(records)
        with mock.patch.object(self.repo, "_write_records", side_effect=crash), self.assertRaises(OSError):
            self.repo.push_branch("pipeline/worker", candidate)
        recovered = GitRepo(self.root, worktree_root=self.owned)
        self.assertEqual(recovered.push_branch("pipeline/worker", candidate), candidate)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/pipeline/worker"), candidate)

    def test_pending_push_refuses_a_changed_wanted_commit_or_remote_ref(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        original = self.repo.run
        def before_push(argv, cwd=None):
            if argv[0] == "push":
                raise RuntimeError("push not sent")
            return original(argv, cwd=cwd)
        with mock.patch.object(self.repo, "run", side_effect=before_push), self.assertRaises(RuntimeError):
            self.repo.push_branch("pipeline/worker", candidate)
        git(self.seed, "push", "origin", self.base + ":refs/heads/pipeline/worker")
        with self.assertRaisesRegex(GitError, "outside controller ownership"):
            self.repo.push_branch("pipeline/worker", candidate)
        git(self.seed, "push", "origin", ":refs/heads/pipeline/worker")
        changed = self.commit(path, "newer unreviewed phase\n")
        with self.assertRaisesRegex(GitError, "pending intent"):
            self.repo.push_branch("pipeline/worker", changed)
        self.assertEqual(git(self.remote, "ls-remote", "--refs", str(self.remote), "refs/heads/pipeline/worker"), "")

    def test_push_branch_uses_recorded_lease_after_rebase(self) -> None:
        path = self.worker()
        first = self.commit(path)
        self.repo.push_branch("pipeline/worker", first)
        newbase = self.advance_remote()
        self.repo.fetch()
        self.assertTrue(self.repo.rebase(path, newbase))
        rebased = self.repo.head(path)
        self.assertNotEqual(first, rebased)
        self.repo.push_branch("pipeline/worker", rebased)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/pipeline/worker"), rebased)

    def test_rebase_conflict_restores_clean_original_head(self) -> None:
        path = self.worker()
        old = self.commit(path, "worker conflicting text\n")
        newbase = self.advance_remote("tracked.txt")
        self.repo.fetch()
        self.assertFalse(self.repo.rebase(path, newbase))
        self.assertEqual(self.repo.head(path), old)
        self.assertEqual(self.repo.changed_paths(path), [])
        self.assertFalse(Path(git(path, "rev-parse", "--git-path", "rebase-merge")).exists())

    def test_rebase_refuses_dirty_or_foreign_worktree(self) -> None:
        path = self.worker()
        (path / "tracked.txt").write_text("uncommitted\n")
        with self.assertRaises(GitError):
            self.repo.rebase(path, self.base)
        with self.assertRaises(GitError):
            self.repo.rebase(self.root, self.base)
        self.assertEqual((path / "tracked.txt").read_text(), "uncommitted\n")

    def test_owned_merge_retains_conflicts_until_controller_commits_resolution(self) -> None:
        path = self.worker()
        old = self.commit(path, "worker conflicting text\n")
        newbase = self.advance_remote("tracked.txt")
        self.repo.fetch()
        self.assertEqual(self.repo.begin_merge_owned(path, newbase), ["tracked.txt"])
        self.assertEqual(self.repo.head(path), old)
        with self.assertRaises(GitError):
            self.repo.commit(path, "unresolved conflict")
        with self.assertRaises(GitError):
            self.repo.cleanup_owned(path, "pipeline/worker", old)
        (path / "tracked.txt").write_text("both intended changes resolved\n")
        merged = self.repo.commit(path, "Resolve current main and worker change")
        self.assertTrue(self.repo.is_ancestor(old, merged))
        self.assertTrue(self.repo.is_ancestor(newbase, merged))
        self.assertEqual(self.repo.changed_paths(path), [])

    def test_worker_cannot_invent_unrecorded_merge_state(self) -> None:
        path = self.worker()
        self.commit(path)
        newbase = self.advance_remote()
        self.repo.fetch()
        git(path, "merge", "--no-commit", "--no-ff", newbase)
        with self.assertRaises(GitError):
            self.repo.commit(path, "unowned merge")

    def test_cleanup_requires_merge_and_preserves_uncommitted_work(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.push_branch("pipeline/worker", candidate)
        with self.assertRaises(GitError):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        self.repo.atomic_promote(candidate, self.base)
        (path / "tracked.txt").write_text("uncommitted valuable work\n")
        with self.assertRaises(GitError):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate, ["tracked.txt"])
        self.assertTrue(path.exists())
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/pipeline/worker"), candidate)

    def test_cleanup_exact_merged_refs_and_generated_file(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.push_branch("pipeline/worker", candidate)
        self.repo.atomic_promote(candidate, self.base)
        generated = path / "gate.generated"
        generated.write_text("controller output\n")
        with self.assertRaises(GitError):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        self.assertTrue(self.repo.cleanup_owned(path, "pipeline/worker", candidate, ["gate.generated"]))
        self.assertFalse(path.exists())
        self.assertEqual(git(self.remote, "ls-remote", "--refs", str(self.remote), "refs/heads/pipeline/worker"), "")
        self.assertNotEqual(subprocess.run(["git", "show-ref", "--verify", "refs/heads/pipeline/worker"],
                                          cwd=self.root, capture_output=True).returncode, 0)

    def test_cleanup_refuses_foreign_path_symlink_and_unregistered_worktree(self) -> None:
        path = self.worker()
        outside = self.parent / "outside"
        git(self.root, "worktree", "add", "--detach", str(outside), self.base)
        foreign = self.owned / "foreign"
        git(self.root, "worktree", "add", "--detach", str(foreign), self.base)
        alias = self.owned / "alias"
        alias.symlink_to(path, target_is_directory=True)
        for target in (outside, foreign, alias):
            with self.subTest(target=target), self.assertRaises(GitError):
                self.repo.cleanup_owned(target, None, self.base)
        self.assertTrue(path.exists())
        self.assertTrue(outside.exists())
        self.assertTrue(foreign.exists())

    def test_cleanup_rejects_moved_head_and_moved_remote_ref(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.push_branch("pipeline/worker", candidate)
        self.repo.atomic_promote(candidate, self.base)
        git(path, "reset", "--hard", self.base)
        with self.assertRaises(GitError):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        git(path, "reset", "--hard", candidate)
        git(self.seed, "push", "--force", "origin", f"{self.base}:refs/heads/pipeline/worker")
        with self.assertRaises(GitError):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        self.assertTrue(path.exists())
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/pipeline/worker"), self.base)

    def test_cleanup_recovers_after_each_destructive_git_boundary(self) -> None:
        for boundary in ("push", "worktree", "update-ref"):
            with self.subTest(boundary=boundary):
                branch = "pipeline/crash-" + boundary
                path = self.worker("crash-" + boundary, branch)
                # Each fixture starts from the current accepted main.
                current = self.repo.fetch()
                self.repo.rebase(path, current)
                candidate = self.commit(path, boundary + "\n", boundary + ".txt")
                self.repo.push_branch(branch, candidate)
                self.repo.atomic_promote(candidate, current)
                original = self.repo.run
                def crash(argv, cwd=None):
                    value = original(argv, cwd=cwd)
                    deletion = ((boundary == "push" and argv[0] == "push" and argv[-1].startswith(":"))
                                or (boundary == "worktree" and argv[:2] == ["worktree", "remove"])
                                or (boundary == "update-ref" and argv[:2] == ["update-ref", "-d"]))
                    if deletion:
                        raise RuntimeError("simulated crash after " + boundary)
                    return value
                with mock.patch.object(self.repo, "run", side_effect=crash):
                    with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                        self.repo.cleanup_owned(path, branch, candidate)
                envelope = json.loads(self.repo.ownership.read_text())
                self.assertFalse(envelope["worktrees"][str(path)]["cleanup"]["complete"])
                recovered = GitRepo(self.root, worktree_root=self.owned)
                self.assertTrue(recovered.cleanup_owned(path, branch, candidate))
                self.assertFalse(path.exists())
                self.assertEqual(git(self.remote, "ls-remote", "--refs", str(self.remote), "refs/heads/" + branch), "")
                # A lost caller checkpoint can repeat a fully completed cleanup.
                self.assertTrue(recovered.cleanup_owned(path, branch, candidate))

    def test_missing_worktree_without_cleanup_intent_is_never_assumed_owned(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.push_branch("pipeline/worker", candidate)
        self.repo.atomic_promote(candidate, self.base)
        git(self.root, "worktree", "remove", str(path))
        with self.assertRaisesRegex(GitError, "no durable cleanup intent"):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        self.assertEqual(git(self.root, "rev-parse", "refs/heads/pipeline/worker"), candidate)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/pipeline/worker"), candidate)

    def test_cleanup_recovers_exact_registration_when_worktree_files_were_removed(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.push_branch("pipeline/worker", candidate)
        self.repo.atomic_promote(candidate, self.base)
        original = self.repo.run
        def crash(argv, cwd=None):
            if argv[:2] == ["worktree", "remove"]:
                shutil.rmtree(path)
                raise RuntimeError("crash before registration cleanup")
            return original(argv, cwd=cwd)
        with mock.patch.object(self.repo, "run", side_effect=crash):
            with self.assertRaisesRegex(RuntimeError, "registration cleanup"):
                self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        self.assertIn(str(path), git(self.root, "worktree", "list", "--porcelain"))
        self.assertTrue(self.repo.cleanup_owned(path, "pipeline/worker", candidate))
        self.assertNotIn(str(path), git(self.root, "worktree", "list", "--porcelain"))

    def test_cleanup_recovery_refuses_moved_local_remote_or_foreign_checkout(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.push_branch("pipeline/worker", candidate)
        self.repo.atomic_promote(candidate, self.base)
        original = self.repo.run
        def crash(argv, cwd=None):
            value = original(argv, cwd=cwd)
            if argv[:2] == ["worktree", "remove"]:
                raise RuntimeError("crash after removal")
            return value
        with mock.patch.object(self.repo, "run", side_effect=crash), self.assertRaises(RuntimeError):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        git(self.root, "update-ref", "refs/heads/pipeline/worker", self.base, candidate)
        with self.assertRaisesRegex(GitError, "local worker ref"):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        git(self.root, "update-ref", "refs/heads/pipeline/worker", candidate, self.base)
        git(self.seed, "push", "origin", self.base + ":refs/heads/pipeline/worker")
        with self.assertRaisesRegex(GitError, "remote worker ref"):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        git(self.seed, "push", "origin", ":refs/heads/pipeline/worker")
        foreign = self.parent / "foreign-checkout"
        git(self.root, "worktree", "add", str(foreign), "pipeline/worker")
        with self.assertRaisesRegex(GitError, "foreign worktree"):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        self.assertTrue(foreign.exists())
        self.assertEqual(git(self.root, "rev-parse", "refs/heads/pipeline/worker"), candidate)

    def test_completed_cleanup_never_deletes_a_recreated_matching_ref(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.push_branch("pipeline/worker", candidate)
        self.repo.atomic_promote(candidate, self.base)
        self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        git(self.root, "update-ref", "refs/heads/pipeline/worker", candidate)
        with self.assertRaisesRegex(GitError, "local ref has been recreated"):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        self.assertEqual(git(self.root, "rev-parse", "refs/heads/pipeline/worker"), candidate)
        git(self.root, "update-ref", "-d", "refs/heads/pipeline/worker", candidate)
        git(self.root, "push", "origin", candidate + ":refs/heads/pipeline/worker")
        with self.assertRaisesRegex(GitError, "remote ref has been recreated"):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/pipeline/worker"), candidate)

    def test_completed_cleanup_refuses_recreated_path_and_different_policy(self) -> None:
        path = self.worker(branch=None)
        self.repo.cleanup_owned(path, None, self.base)
        with self.assertRaisesRegex(GitError, "policy differs"):
            self.repo.cleanup_owned(path, None, self.base, generated_roots=("target",))
        path.mkdir()
        (path / "valuable.txt").write_text("foreign replacement")
        with self.assertRaisesRegex(GitError, "recreated"):
            self.repo.cleanup_owned(path, None, self.base)
        self.assertEqual((path / "valuable.txt").read_text(), "foreign replacement")

    def test_detached_review_cleanup_never_deletes_a_branch(self) -> None:
        path = self.worker(branch=None)
        self.assertTrue(self.repo.cleanup_owned(path, None, self.base))
        self.assertEqual(git(self.remote, "rev-parse", "refs/heads/main"), self.base)

    def test_cleanup_accepts_github_autodeleted_branch_only_after_merge(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.push_branch("pipeline/worker", candidate)
        git(self.root, "push", "origin", ":refs/heads/pipeline/worker")
        with self.assertRaises(GitError):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate)
        self.repo.atomic_promote(candidate, self.base)
        self.assertTrue(self.repo.cleanup_owned(path, "pipeline/worker", candidate))

    def test_persistent_validation_keeps_cache_and_refuses_dirty_or_foreign_path(self) -> None:
        worker = self.worker()
        candidate = self.commit(worker)
        validation = self.owned / "validation"
        self.repo.prepare_validation_worktree(validation, self.base)
        target = validation / "target"
        target.mkdir()
        (target / "cache").write_text("expensive cache\n")
        self.repo.prepare_validation_worktree(validation, candidate)
        self.assertEqual(self.repo.head(validation), candidate)
        self.assertEqual((target / "cache").read_text(), "expensive cache\n")
        (validation / "tracked.txt").write_text("unexpected source edit\n")
        with self.assertRaises(GitError):
            self.repo.prepare_validation_worktree(validation, self.base)
        self.assertEqual((validation / "tracked.txt").read_text(), "unexpected source edit\n")
        with self.assertRaises(GitError):
            self.repo.prepare_validation_worktree(worker, self.base)

    def test_generated_tree_cleanup_removes_nested_symlink_without_following_it(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.atomic_promote(candidate, self.base)
        external = self.parent / "external-cache"
        external.mkdir()
        (external / "valuable.txt").write_text("do not delete\n")
        target = path / "target"
        target.mkdir()
        (target / "object").write_text("generated\n")
        (target / "external-link").symlink_to(external, target_is_directory=True)
        fuzz = path / "fuzz" / "target"
        fuzz.mkdir(parents=True)
        (fuzz / "object").write_text("generated fuzz output\n")
        self.assertTrue(self.repo.cleanup_owned(path, "pipeline/worker", candidate,
                                                generated_roots=("target", "fuzz/target")))
        self.assertEqual((external / "valuable.txt").read_text(), "do not delete\n")

    def test_generated_root_symlinks_unknown_work_and_tracked_content_are_refused(self) -> None:
        path = self.worker()
        candidate = self.commit(path)
        self.repo.atomic_promote(candidate, self.base)
        external = self.parent / "external"
        external.mkdir()
        (path / "target").symlink_to(external, target_is_directory=True)
        with self.assertRaises(GitError):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate, generated_roots=("target",))
        (path / "target").unlink()
        (path / "target").mkdir()
        (path / "target" / "object").write_text("generated")
        (path / "unknown.txt").write_text("uncommitted source")
        with self.assertRaises(GitError):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate, generated_roots=("target",))
        self.assertTrue((path / "unknown.txt").exists())
        self.assertTrue((path / "target" / "object").exists())
        (path / "unknown.txt").unlink()
        git(path, "add", "--force", "target/object")
        with self.assertRaises(GitError):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate, generated_roots=("target",))
        with self.assertRaises(GitError):
            self.repo.cleanup_owned(path, "pipeline/worker", candidate, generated_roots=("src",))

    def test_existing_directory_cannot_be_adopted(self) -> None:
        path = self.owned / "existing"
        path.mkdir()
        with self.assertRaises(GitError):
            self.repo.add_worktree(path, "pipeline/existing", self.base)
        self.assertTrue(path.exists())

    def test_command_timeout_is_bounded(self) -> None:
        with self.assertRaisesRegex(GitError, "timed out"):
            _process(["python3", "-c", "import time; time.sleep(10)"], self.root, 0.05)

    def test_ownership_lock_wait_is_bounded_without_creating_a_worktree(self) -> None:
        path = self.owned / "locked"
        with self.repo.ownership_lock.open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            self.repo.timeout = 0.1
            with self.assertRaisesRegex(GitError, "ownership lock timed out"):
                self.repo.add_worktree(path, "pipeline/locked", self.base)
        self.assertFalse(path.exists())

    def test_failure_does_not_echo_stderr_credentials(self) -> None:
        with self.assertRaises(GitError) as captured:
            self.repo.run(["-c", "credential.helper=SECRET_SENTINEL", "not-a-real-command"])
        self.assertNotIn("SECRET_SENTINEL", str(captured.exception))


if __name__ == "__main__":
    unittest.main()
