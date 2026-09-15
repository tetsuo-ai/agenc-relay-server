"""Controller-owned Git operations with explicit ref leases and worktree ownership."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator, Sequence

SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
MAX_OUTPUT = 8 * 1024 * 1024


class GitError(RuntimeError):
    """A bounded Git operation or controller ownership check failed."""


def _process(argv: Sequence[str], cwd: Path, timeout: float, data: bytes | None = None,
             environment: dict[str, str] | None = None) -> tuple[int, str]:
    """Run argv without a shell, bound time/output, and suppress stderr on failure."""
    if timeout <= 0 or (data is not None and len(data) > MAX_OUTPUT):
        raise GitError("invalid command bound")
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as out, \
            tempfile.TemporaryFile() as err:
        if data:
            source.write(data)
        source.seek(0)
        try:
            child = subprocess.Popen(list(argv), cwd=cwd, stdin=source, stdout=out, stderr=err,
                                     env=environment, start_new_session=True)
        except OSError as error:
            raise GitError("Git executable could not be started") from error
        deadline = time.monotonic() + timeout
        try:
            while child.poll() is None:
                if time.monotonic() >= deadline:
                    raise GitError("Git command timed out")
                if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > MAX_OUTPUT:
                    raise GitError("Git command exceeded its output bound")
                time.sleep(0.02)
            if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > MAX_OUTPUT:
                raise GitError("Git command exceeded its output bound")
            out.seek(0)
            return child.returncode, out.read(MAX_OUTPUT + 1).decode("utf-8", errors="strict")
        except BaseException:
            if child.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            raise


class GitRepo:
    """A controller clone and its explicitly registered, directly contained worktrees.

    ``worktree_root`` must be dedicated to this controller. Existing worktrees are
    never adopted. Ownership records live in this clone's common Git directory;
    another clone or an unrecorded path has no cleanup authority.
    """

    def __init__(self, root: Path, remote: str = "origin", base_branch: str = "main", *,
                 worktree_root: Path | None = None, timeout: float = 120):
        self.root = Path(root).resolve(strict=True)
        self.remote = remote
        self.base_branch = base_branch
        self.timeout = timeout
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", remote):
            raise GitError("invalid remote name")
        self._check_branch(base_branch)
        selected = Path(worktree_root) if worktree_root is not None else self.root.parent / "worktrees"
        selected.mkdir(parents=True, exist_ok=True)
        if selected.is_symlink():
            raise GitError("worktree root must not be a symlink")
        self.worktree_root = selected.resolve(strict=True)
        common = self.run(["rev-parse", "--git-common-dir"]).strip()
        self.common_dir = (self.root / common).resolve(strict=True)
        self.ownership = self.common_dir / "issue-pipeline-worktrees.json"
        self.ownership_lock = self.common_dir / "issue-pipeline-worktrees.lock"

    def _environment(self) -> dict[str, str]:
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_EDITOR": "true", "GIT_SEQUENCE_EDITOR": "true",
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": os.devnull})
        return env

    def _invoke(self, args: Sequence[str], cwd: Path | None = None, *,
                data: bytes | None = None) -> tuple[int, str]:
        return _process(["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                         "-c", "core.fsmonitor=false", "-c", "submodule.recurse=false", *args],
                        self.root if cwd is None else Path(cwd), self.timeout, data, self._environment())

    def run(self, args: Sequence[str], cwd: Path | None = None) -> str:
        """Run a bounded Git argv command; errors never echo URLs or credential output."""
        if isinstance(args, (str, bytes)) or not all(isinstance(arg, str) for arg in args):
            raise GitError("Git arguments must be a sequence of strings")
        code, output = self._invoke(args, cwd)
        if code:
            raise GitError(f"Git command failed with exit status {code}")
        return output

    def _check_branch(self, branch: str) -> None:
        if not isinstance(branch, str) or branch.startswith("-") or not branch:
            raise GitError("invalid branch name")
        code, _ = self._invoke(["check-ref-format", "--branch", branch])
        if code:
            raise GitError("invalid branch name")

    def _commit_sha(self, sha: str) -> str:
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise GitError("an exact commit SHA is required")
        actual = self.run(["rev-parse", "--verify", f"{sha}^{{commit}}" ]).strip()
        if actual != sha:
            raise GitError("commit identity does not match")
        return actual

    def head(self, worktree: Path) -> str:
        """Return the exact HEAD commit of an existing worktree."""
        return self.run(["rev-parse", "--verify", "HEAD^{commit}"], cwd=worktree).strip()

    def tree(self, sha: str) -> str:
        """Return the immutable tree identity of an exact commit."""
        return self.run(["rev-parse", f"{self._commit_sha(sha)}^{{tree}}" ]).strip()

    def fetch(self) -> str:
        """Fetch only base history, without force, and return its exact remote tip."""
        self.run(["fetch", "--no-tags", self.remote,
                  f"refs/heads/{self.base_branch}:refs/remotes/{self.remote}/{self.base_branch}"])
        return self.run(["rev-parse", "--verify",
                         f"refs/remotes/{self.remote}/{self.base_branch}^{{commit}}" ]).strip()

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        """Prove local commit ancestry without treating Git errors as a negative proof."""
        ancestor, descendant = self._commit_sha(ancestor), self._commit_sha(descendant)
        code, _ = self._invoke(["merge-base", "--is-ancestor", ancestor, descendant])
        if code not in (0, 1):
            raise GitError("commit ancestry could not be established")
        return code == 0

    def atomic_promote(self, candidate_sha: str, expected_base: str) -> str:
        """Compare-and-swap only base_branch after proving this update is fast-forward.

        The explicit lease is safe here because the candidate is first proven a
        descendant of exactly the leased old value. A concurrently moved base is
        rejected by the remote, even if a REST merge API would accept a stale PR.
        """
        candidate_sha, expected_base = self._commit_sha(candidate_sha), self._commit_sha(expected_base)
        if not self.is_ancestor(expected_base, candidate_sha):
            raise GitError("candidate is not a descendant of the expected base")
        ref = f"refs/heads/{self.base_branch}"
        self.run(["push", "--porcelain", f"--force-with-lease={ref}:{expected_base}",
                  self.remote, f"{candidate_sha}:{ref}"])
        return candidate_sha

    def _remote_head(self, branch: str) -> str | None:
        self._check_branch(branch)
        output = self.run(["ls-remote", "--refs", self.remote, f"refs/heads/{branch}"])
        rows = output.splitlines()
        if not rows:
            return None
        if len(rows) != 1:
            raise GitError("remote branch identity is ambiguous")
        fields = rows[0].split("\t")
        if len(fields) != 2 or fields[1] != f"refs/heads/{branch}" or not SHA.fullmatch(fields[0]):
            raise GitError("remote branch identity is malformed")
        return fields[0]

    def push_branch(self, branch: str, sha: str) -> str:
        """Publish with an exact lease and a fsynced, recoverable push intent.

        An applied-but-lost response is accepted only when the remote equals the
        exact wanted SHA in this controller's already durable pending intent.
        """
        self._check_branch(branch)
        if branch == self.base_branch:
            raise GitError("use atomic_promote for the base branch")
        sha = self._commit_sha(sha)
        with self._records() as records:
            matches = [item for item in records.values() if item["branch"] == branch]
            if len(matches) != 1 or matches[0]["head"] != sha:
                raise GitError("branch is not owned at the requested commit")
            item = matches[0]
            path = Path(item["path"])
            self._verify_owned(path, branch, sha, records)
            expected = item.get("remote_head")
            pending = item.get("pending_push")
            if pending is not None and pending != {"old": expected, "wanted": sha}:
                raise GitError("branch push differs from its durable pending intent")
            actual = self._remote_head(branch)
            if pending is not None and actual == sha:
                item["remote_head"] = sha
                item.pop("pending_push")
                return sha
            if actual != expected:
                raise GitError("remote branch moved outside controller ownership")
            if actual == sha:
                return sha
            item["pending_push"] = {"old": expected, "wanted": sha}
            self._write_records(records)
            ref = f"refs/heads/{branch}"
            self.run(["push", "--porcelain", f"--force-with-lease={ref}:{expected or ''}",
                      self.remote, f"{sha}:{ref}"])
            if self._remote_head(branch) != sha:
                raise GitError("published worker ref did not retain the requested source")
            item["remote_head"] = sha
            item.pop("pending_push")
        return sha

    def _path(self, path: Path) -> Path:
        path = Path(path).absolute()
        if path.name in ("", ".", "..") or path.parent.resolve(strict=True) != self.worktree_root:
            raise GitError("worktree is outside the dedicated owned parent")
        if path.is_symlink() or path.resolve(strict=False) != path:
            raise GitError("worktree path must not traverse a symlink or dot component")
        return path

    @contextlib.contextmanager
    def _records(self) -> Iterator[dict[str, Any]]:
        with self.ownership_lock.open("a+b") as lock:
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise GitError("controller worktree ownership lock timed out")
                    time.sleep(0.02)
            records: dict[str, Any] = {}
            if self.ownership.exists():
                if self.ownership.is_symlink() or self.ownership.stat().st_size > MAX_OUTPUT:
                    raise GitError("invalid ownership record")
                try:
                    envelope = json.loads(self.ownership.read_text())
                except (ValueError, OSError) as error:
                    raise GitError("ownership record is unreadable") from error
                if (not isinstance(envelope, dict) or type(envelope.get("version")) is not int or envelope.get("version") != 1
                        or envelope.get("root") != str(self.root)
                        or envelope.get("worktree_root") != str(self.worktree_root)
                        or not isinstance(envelope.get("worktrees"), dict)):
                    raise GitError("ownership record belongs to a different controller")
                records = envelope["worktrees"]
            yield records
            self._write_records(records)

    def _write_records(self, records: dict[str, Any]) -> None:
        """Flush records while the caller holds the ownership lock."""
        envelope = {"version": 1, "root": str(self.root), "worktree_root": str(self.worktree_root),
                    "worktrees": records}
        encoded = (json.dumps(envelope, sort_keys=True) + "\n").encode()
        if len(encoded) > MAX_OUTPUT:
            raise GitError("ownership record exceeds its bound")
        descriptor, name = tempfile.mkstemp(prefix=".issue-pipeline-", dir=self.common_dir)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, self.ownership)
            parent = os.open(self.common_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def add_worktree(self, path: Path, branch: str | None, base: str) -> str:
        """Create and register a fresh worktree; a None branch creates detached HEAD."""
        path, base = self._path(path), self._commit_sha(base)
        if branch is not None:
            self._check_branch(branch)
            if branch == self.base_branch:
                raise GitError("base branch cannot be a worker branch")
        with self._records() as records:
            if path.exists() or str(path) in records:
                raise GitError("existing worktree paths cannot be adopted")
            if branch is not None and any(item["branch"] == branch for item in records.values()):
                raise GitError("branch already has an owned worktree")
            args = ["worktree", "add", "--detach"] if branch is None else ["worktree", "add", "-b", branch]
            self.run([*args, str(path), base])
            records[str(path)] = {"path": str(path), "branch": branch, "head": base, "remote_head": None}
        return base

    def _verify_owned(self, path: Path, branch: str | None, expected_head: str,
                      records: dict[str, Any]) -> dict[str, Any]:
        path = self._path(path)
        item = records.get(str(path))
        if (not isinstance(item, dict) or item.get("path") != str(path)
                or item.get("branch") != branch or item.get("head") != expected_head):
            raise GitError("worktree ownership or recorded commit does not match")
        common = self.run(["rev-parse", "--git-common-dir"], cwd=path).strip()
        if (path / common).resolve(strict=True) != self.common_dir:
            raise GitError("worktree belongs to a different repository")
        actual = self.head(path)
        code, symbolic = self._invoke(["symbolic-ref", "-q", "HEAD"], cwd=path)
        if actual != expected_head or (branch is None and code != 1) or (
                branch is not None and (code != 0 or symbolic.strip() != f"refs/heads/{branch}")):
            raise GitError("worktree HEAD moved outside controller ownership")
        if branch is not None:
            if self.run(["rev-parse", f"refs/heads/{branch}"]).strip() != expected_head:
                raise GitError("local branch moved outside controller ownership")
        return item

    def _status_paths(self, path: Path, excludes: Sequence[str] = ()) -> list[str]:
        args = ["status", "--porcelain=v1", "-z", "--untracked-files=all"]
        if excludes:
            args += ["--", ".", *(f":(exclude){name}" for name in excludes)]
        fields = self.run(args, cwd=path).split("\0")
        result = []
        index = 0
        while index < len(fields) and fields[index]:
            row = fields[index]
            if len(row) < 4 or row[2] != " ":
                raise GitError("malformed Git status")
            result.append(row[3:])
            if "R" in row[:2] or "C" in row[:2]:
                index += 1
                if index >= len(fields) or not fields[index]:
                    raise GitError("malformed renamed path status")
                result.append(fields[index])
            index += 1
        return result

    def changed_paths(self, worktree: Path, base: str | None = None) -> list[str]:
        """List changed filenames without shell parsing, including staged/untracked paths."""
        paths = self._status_paths(Path(worktree))
        if base is not None:
            base = self._commit_sha(base)
            paths.extend(self.run(["diff", "--no-renames", "--name-only", "-z", base, "HEAD", "--"],
                                  cwd=worktree).split("\0"))
        return sorted(set(path for path in paths if path))

    def _merge_head(self, path: Path) -> str | None:
        code, output = self._invoke(["rev-parse", "--verify", "--quiet", "MERGE_HEAD"], cwd=path)
        if code == 1:
            return None
        if code or not SHA.fullmatch(output.strip()):
            raise GitError("merge state is invalid")
        return output.strip()

    def commit(self, worktree: Path, message: str) -> str:
        """Commit controller-owned edits, refusing symlink/submodule scope changes."""
        path = self._path(worktree)
        if not isinstance(message, str) or not message.strip() or len(message.encode()) > 65536:
            raise GitError("invalid commit message")
        with self._records() as records:
            item = records.get(str(path), {})
            self._verify_owned(path, item.get("branch"), item.get("head"), records)
            merge_head = self._merge_head(path)
            if merge_head != item.get("merge_base"):
                raise GitError("merge state was not established by the controller")
            changes = self.changed_paths(path)
            if not changes and merge_head is None:
                return item["head"]
            for name in changes:
                file = path / name
                if file.is_symlink() or any(parent.is_symlink() for parent in file.parents if parent != path):
                    raise GitError("symlink changes require explicit review outside the pipeline")
            for row in self.run(["ls-files", "--stage", "-z"], cwd=path).split("\0"):
                if row:
                    metadata, filename = row.split("\t", 1)
                    if filename in changes and metadata.split()[0] in ("120000", "160000"):
                        raise GitError("symlink/submodule changes require explicit review")
            self.run(["add", "--all", "--", "."], cwd=path)
            # Newly staged gitlinks and symlinks must also be refused before a commit exists.
            for row in self.run(["diff", "--cached", "--raw", "--no-abbrev", "-z"], cwd=path).split("\0"):
                if row.startswith(":") and row.split()[1] in ("120000", "160000"):
                    raise GitError("new symlink/submodule entries require explicit review")
            self.run(["diff", "--cached", "--check"], cwd=path)
            code, _ = self._invoke(["commit", "--file=-"], cwd=path, data=message.encode())
            if code:
                raise GitError("controller commit failed")
            item["head"] = self.head(path)
            item.pop("merge_base", None)
            return item["head"]

    def rebase(self, worktree: Path, newbase: str) -> bool:
        """Rebase clean owned work; on conflict abort completely and preserve its old head."""
        path, newbase = self._path(worktree), self._commit_sha(newbase)
        with self._records() as records:
            item = records.get(str(path), {})
            old = item.get("head")
            self._verify_owned(path, item.get("branch"), old, records)
            if self.changed_paths(path) or self._merge_head(path) is not None:
                raise GitError("cannot rebase uncommitted work")
            code, _ = self._invoke(["rebase", newbase], cwd=path)
            if code:
                self.run(["rebase", "--abort"], cwd=path)
                if self.head(path) != old or self.changed_paths(path):
                    raise GitError("failed rebase did not restore the clean original worktree")
                return False
            item["head"] = self.head(path)
            return True

    def begin_merge_owned(self, worktree: Path, newbase: str) -> list[str]:
        """Stage a merge without moving HEAD and return exact unresolved filenames.

        A resolving worker edits this registered worktree; only ``commit`` may
        stage those edits and create the merge commit. The caller must then redo
        independent review and full-gate evidence for the resulting exact SHA.
        """
        path, newbase = self._path(worktree), self._commit_sha(newbase)
        with self._records() as records:
            item = records.get(str(path), {})
            self._verify_owned(path, item.get("branch"), item.get("head"), records)
            if self.changed_paths(path):
                raise GitError("cannot start a merge with uncommitted work")
            if self._merge_head(path) is not None:
                raise GitError("an owned merge is already pending")
            code, _ = self._invoke(["merge", "--no-commit", "--no-ff", "--no-edit", newbase], cwd=path)
            conflicts = [name for name in self.run(["diff", "--name-only", "--diff-filter=U", "-z"],
                                                   cwd=path).split("\0") if name]
            if code != 0 and not conflicts:
                raise GitError("merge failed without a resolvable conflict set")
            if self.head(path) != item["head"]:
                raise GitError("merge unexpectedly moved the recorded source commit")
            merge_head = self._merge_head(path)
            if merge_head is not None:
                if merge_head != newbase:
                    raise GitError("merge selected an unexpected base commit")
                item["merge_base"] = newbase
            return conflicts

    def prepare_validation_worktree(self, path: Path, candidate_sha: str) -> str:
        """Reuse one owned detached gate worktree without deleting its ignored cache.

        Tracked edits and nonignored untracked files refuse the transition.
        Checkout never forces changes or overwrites ignored files that conflict
        with a candidate's tracked paths. Callers archive/remove generated gate
        receipts before switching candidates and stop all prior gate processes.
        """
        path, candidate_sha = self._path(path), self._commit_sha(candidate_sha)
        if not path.exists():
            return self.add_worktree(path, None, candidate_sha)
        with self._records() as records:
            item = records.get(str(path), {})
            self._verify_owned(path, None, item.get("head"), records)
            if self.changed_paths(path) or self._merge_head(path) is not None:
                raise GitError("persistent validation worktree has uncommitted source changes")
            # Host Git follows symlinks when it appends reflogs or replaces the
            # index. The gate never exposes this administration writable, but a
            # planted link here would still be a controller-side write hazard.
            administration = Path(self.run(["rev-parse", "--absolute-git-dir"], cwd=path).strip())
            for entry in administration.rglob("*"):
                if entry.is_symlink():
                    raise GitError("validation worktree Git administration contains a symlink; refuse host reuse")
            self.run(["checkout", "--no-overwrite-ignore", "--detach", candidate_sha], cwd=path)
            item["head"] = self.head(path)
            if item["head"] != candidate_sha:
                raise GitError("validation checkout did not select the candidate")
        return candidate_sha

    def _cleanup_ref(self, branch: str, expected_head: str, item: dict[str, Any]) -> None:
        """Re-prove merged ancestry and delete only the recorded remote ref."""
        base = self.fetch()
        if not self.is_ancestor(expected_head, base):
            raise GitError("worker commit is not merged into remote base")
        remote_head = self._remote_head(branch)
        if item.get("cleanup", {}).get("complete") and remote_head is not None:
            raise GitError("completed worker remote ref has been recreated")
        if remote_head is not None and (remote_head != item.get("remote_head") or remote_head != expected_head):
            raise GitError("remote worker ref no longer matches controller ownership")
        if remote_head:
            ref = f"refs/heads/{branch}"
            self.run(["push", "--porcelain", f"--force-with-lease={ref}:{expected_head}",
                      self.remote, f":{ref}"])

    def _cleanup_missing(self, path: Path, branch: str | None, expected_head: str,
                         item: dict[str, Any]) -> None:
        """Resume only a persisted deletion, with exact remaining Git identities."""
        if path.exists() or path.is_symlink():
            raise GitError("missing-worktree recovery requires the path to remain absent")
        registrations = []
        for block in self.run(["worktree", "list", "--porcelain", "-z"]).split("\0\0"):
            if not block:
                continue
            fields = {}
            for row in block.split("\0"):
                if row:
                    key, _, value = row.partition(" ")
                    fields[key] = value
            registrations.append(fields)
        owned = [row for row in registrations if row.get("worktree") == str(path)]
        if len(owned) > 1:
            raise GitError("worktree registration is ambiguous")
        if owned and item["cleanup"].get("complete"):
            raise GitError("completed worktree registration has been recreated")
        if owned:
            row = owned[0]
            if (row.get("HEAD") != expected_head or "locked" in row
                    or (branch is None and "detached" not in row)
                    or (branch is not None and row.get("branch") != f"refs/heads/{branch}")):
                raise GitError("missing worktree registration no longer matches ownership")
        if branch is not None:
            ref = f"refs/heads/{branch}"
            if any(row.get("branch") == ref and row.get("worktree") != str(path) for row in registrations):
                raise GitError("worker branch is checked out in a foreign worktree")
            code, _ = self._invoke(["symbolic-ref", "-q", ref])
            if code != 1:
                raise GitError("owned worker ref became symbolic")
            code, value = self._invoke(["rev-parse", "--verify", "--quiet", ref])
            if code not in (0, 1) or (code == 0 and value.strip() != expected_head):
                raise GitError("local worker ref no longer matches cleanup intent")
            local_present = code == 0
            if local_present and item["cleanup"].get("complete"):
                raise GitError("completed worker local ref has been recreated")
            self._cleanup_ref(branch, expected_head, item)
        if owned:
            # Only the already-absent, exactly registered owned path is removed;
            # no global prune can erase another controller's registration.
            self.run(["worktree", "remove", "--force", str(path)])
        if branch is not None:
            if local_present:
                self.run(["update-ref", "-d", f"refs/heads/{branch}", expected_head])
            code, _ = self._invoke(["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"])
            if code != 1 or self._remote_head(branch) is not None:
                raise GitError("worker ref reappeared during cleanup")
        item["cleanup"]["complete"] = True

    def cleanup_owned(self, worktree: Path, branch: str | None, expected_head: str,
                      allowed_generated: Sequence[str] = (), *,
                      generated_roots: Sequence[str] = ()) -> bool:
        """Remove only exact owned work after checking dirt, refs and merged ancestry.

        ``allowed_generated`` is an exact relative file allowlist, never glob
        patterns or directories. Unlisted ignored files also block deletion.
        ``generated_roots`` may explicitly contain only ``target`` and
        ``fuzz/target``. These roots must contain no tracked files and must not
        themselves be symlinks. Their nested symlinks are removed, never followed.
        Callers must first quiesce all processes using the worktree.
        A pushed worker branch must still equal its recorded head, and its head
        must already be reachable from the freshly fetched remote base. Intent
        is fsynced before deletion; repeated calls also reconcile absent owned
        paths and refs. Completed tombstones make post-deletion crashes safe.
        """
        path, expected_head = self._path(worktree), self._commit_sha(expected_head)
        with self._records() as records:
            item = records.get(str(path))
            if (not isinstance(item, dict) or item.get("path") != str(path)
                    or item.get("branch") != branch or item.get("head") != expected_head):
                raise GitError("worktree ownership or recorded commit does not match")
            intent = {"allowed_generated": sorted(set(allowed_generated)),
                      "generated_roots": sorted(set(generated_roots)), "complete": False}
            previous = item.get("cleanup")
            if previous is not None and {**previous, "complete": False} != intent:
                raise GitError("cleanup policy differs from its durable intent")
            if not path.exists():
                if previous is None:
                    raise GitError("absent worktree has no durable cleanup intent")
                self._cleanup_missing(path, branch, expected_head, item)
                return True
            if previous is not None and previous.get("complete"):
                raise GitError("a completed worktree path has been recreated")
            self._verify_owned(path, branch, expected_head, records)
            if self._merge_head(path) is not None or item.get("merge_base") is not None:
                raise GitError("cannot clean a pending owned merge")
            allowed = set(allowed_generated)
            roots = set(generated_roots)
            if roots - {"target", "fuzz/target"}:
                raise GitError("only explicit Cargo target roots may be recursively cleaned")
            tracked = set(self.run(["ls-files", "-z"], cwd=path).split("\0"))
            for name in roots:
                directory = path / name
                if any(file == name or file.startswith(name + "/") for file in tracked):
                    raise GitError("generated root contains tracked source")
                if directory.is_symlink() or any(parent.is_symlink() for parent in directory.parents if parent != path):
                    raise GitError("generated root must not traverse a symlink")
                if directory.exists() and not directory.is_dir():
                    raise GitError("generated root is not a directory")
                if not directory.resolve(strict=False).is_relative_to(path):
                    raise GitError("generated root is outside the owned worktree")
            if roots and not shutil.rmtree.avoids_symlink_attacks:
                raise GitError("platform lacks descriptor-safe generated tree cleanup")
            for name in allowed:
                part = Path(name)
                if part.is_absolute() or ".." in part.parts or not part.parts or str(part) != name:
                    raise GitError("generated allowlist must contain exact relative filenames")
            dirty = set(self._status_paths(path, sorted(roots)))
            ignored_args = ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"]
            if roots:
                ignored_args += ["--", ".", *(f":(exclude){name}" for name in sorted(roots))]
            ignored = self.run(ignored_args, cwd=path)
            dirty.update(name for name in ignored.split("\0") if name)
            if dirty - allowed:
                raise GitError("worktree has uncommitted or unowned generated files")
            if dirty & tracked:
                raise GitError("generated allowlist cannot discard modified tracked work")
            for name in dirty:
                file = path / name
                if not file.is_file() or file.is_symlink() or file.resolve().parent != (path / name).parent.resolve():
                    raise GitError("generated cleanup entry is not an owned regular file")
                if any(parent.is_symlink() for parent in file.parents if parent != path):
                    raise GitError("generated cleanup cannot traverse symlinks")
            # The previous clean-source and exact-head checks are durable before
            # any remote ref or local generated output can be removed.
            item["cleanup"] = intent
            self._write_records(records)
            if branch is not None:
                self._cleanup_ref(branch, expected_head, item)
            # Recheck local identity immediately before the only local deletion.
            self._verify_owned(path, branch, expected_head, records)
            for name in dirty:
                (path / name).unlink()
            for name in sorted(roots):
                directory = path / name
                if directory.exists():
                    shutil.rmtree(directory)
            self.run(["worktree", "remove", str(path)])
            self._cleanup_missing(path, branch, expected_head, item)
        return True
