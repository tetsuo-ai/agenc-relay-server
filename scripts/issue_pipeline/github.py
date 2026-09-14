"""Bounded GitHub CLI transport for issue graph, review and qualification state."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .gitops import GitError, MAX_OUTPUT, SHA, _process

MAX_BODY = 1024 * 1024
MAX_PAGES = 100
PAGE_SIZE = 100


class GithubError(RuntimeError):
    """GitHub transport or response validation failed without exposing credentials."""


def _positive(number: int) -> int:
    if type(number) is not int or number < 1:
        raise GithubError("GitHub issue or run number must be a positive integer")
    return number


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GithubError(f"GitHub returned a malformed {label}")
    return value


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GithubError("scheduling graph contains duplicate JSON fields")
        result[key] = value
    return result


def issue_identity(value: Any, repository: str, number: int | None = None) -> tuple[int, int, str]:
    """Validate one REST issue's repository, canonical URLs and immutable IDs.

    Native relationships may legitimately cross repositories. Their issue
    numbers alone are therefore not identities, even on a repository-scoped
    endpoint. Redirected/transferred issues and pull requests are also refused.
    """
    value = _object(value, "issue identity")
    observed = _positive(value.get("number"))
    if (number is not None and observed != _positive(number)) or "pull_request" in value:
        raise GithubError("GitHub returned another issue or a pull request")
    identity = _positive(value.get("id"))
    node = value.get("node_id")
    if (not isinstance(node, str) or not 1 <= len(node) <= 512
            or any(character.isspace() or ord(character) < 32 for character in node)):
        raise GithubError("GitHub issue has no bounded immutable node identity")
    expected = {"repository_url": f"https://api.github.com/repos/{repository}",
                "url": f"https://api.github.com/repos/{repository}/issues/{observed}",
                "html_url": f"https://github.com/{repository}/issues/{observed}"}
    for field, wanted in expected.items():
        actual = value.get(field)
        if not isinstance(actual, str) or actual.casefold() != wanted.casefold():
            raise GithubError("GitHub issue identity crosses the configured repository or issue URL")
    return observed, identity, node


def native_issue_numbers(
    rows: list[dict[str, Any]], repository: str,
    issues: Mapping[int, dict[str, Any]] | Callable[[int], dict[str, Any]],
) -> tuple[int, ...]:
    """Project native links only after matching independently read local IDs.

    Callers with a DAG snapshot reuse its mapping; reconciliation may supply a
    bounded local-issue reader. No relationship row is its own identity proof.
    """
    if not isinstance(rows, list) or len(rows) > MAX_PAGES * PAGE_SIZE:
        raise GithubError("native issue relationships exceed their array bound")
    seen: set[int] = set()
    ids: set[int] = set()
    nodes: set[str] = set()
    numbers = []
    for row in rows:
        identity = issue_identity(row, repository)
        number, stable_id, node = identity
        if number in seen or stable_id in ids or node in nodes:
            raise GithubError("native relationships contain duplicate issue identities")
        local = issues(number) if callable(issues) else issues.get(number)
        if issue_identity(local, repository, number) != identity:
            raise GithubError("native relationship differs from the local immutable issue identity")
        seen.add(number)
        ids.add(stable_id)
        nodes.add(node)
        numbers.append(number)
    return tuple(numbers)


class Github:
    """Use existing ``gh`` authentication; never print tokens, API stderr or shell text."""

    def __init__(self, repo: str, *, cwd: Path | None = None, timeout: float = 60):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise GithubError("repository must be an owner/name pair")
        self.repo = repo
        self.cwd = Path.cwd() if cwd is None else Path(cwd)
        self.timeout = timeout
        self.prefix = f"repos/{repo}/"

    def api(self, path: str, method: str = "GET", data: Any = None) -> Any:
        """Call one repository-scoped REST endpoint using exact JSON on stdin.

        Paths may be repository-relative (``issues/35``) or start with this
        repository's full ``repos/owner/name/`` prefix. Mutation calls are never
        automatically retried: an ambiguous reply must be reconciled by reads.
        """
        if (not isinstance(path, str) or not path or any(character in path for character in "\r\n\0")
                or method not in ("GET", "POST", "PATCH", "PUT", "DELETE")):
            raise GithubError("invalid GitHub API request")
        path = path.lstrip("/")
        if path.startswith("repos/"):
            if not path.startswith(self.prefix):
                raise GithubError("GitHub request crosses repository ownership")
        else:
            path = self.prefix + path
        if any(part in (".", "..") for part in path.split("?", 1)[0].split("/")):
            raise GithubError("GitHub endpoint contains an unsafe component")
        payload = None
        if data is not None:
            try:
                payload = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
            except (TypeError, ValueError) as error:
                raise GithubError("GitHub request is not finite JSON") from error
            if len(payload) > MAX_BODY:
                raise GithubError("GitHub request exceeds its byte bound")
        argv = ["gh", "api", path, "--method", method, "-H", "Accept: application/vnd.github+json",
                "-H", "X-GitHub-Api-Version: 2022-11-28"]
        if payload is not None:
            argv += ["--input", "-"]
        try:
            code, output = _process(argv, self.cwd, self.timeout, payload)
        except (GitError, UnicodeError) as error:
            raise GithubError("GitHub command failed, timed out or exceeded its output bound") from error
        if code:
            raise GithubError(f"GitHub API failed with exit status {code}; reconcile before retrying mutations")
        if not output.strip():
            return None
        try:
            return json.loads(output)
        except ValueError as error:
            raise GithubError("GitHub API did not return valid JSON") from error

    def _pages(self, path: str, member: str | None = None) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        total_bytes = 0
        separator = "&" if "?" in path else "?"
        for page in range(1, MAX_PAGES + 1):
            response = self.api(f"{path}{separator}per_page={PAGE_SIZE}&page={page}")
            if member is not None:
                response = _object(response, "collection").get(member)
            if (not isinstance(response, list) or len(response) > PAGE_SIZE
                    or not all(isinstance(item, dict) for item in response)):
                raise GithubError("GitHub returned a malformed collection page")
            total_bytes += len(json.dumps(response, ensure_ascii=False).encode())
            if total_bytes > MAX_OUTPUT:
                raise GithubError("GitHub collection exceeds its total byte bound")
            result.extend(response)
            if len(response) < PAGE_SIZE:
                return result
        raise GithubError("GitHub collection exceeds its pagination bound")

    def issue(self, number: int) -> dict[str, Any]:
        """Read the live issue, including body, state, labels and update identity."""
        value = _object(self.api(f"issues/{_positive(number)}"), "issue")
        issue_identity(value, self.repo, number)
        if value.get("state") not in ("open", "closed") or not isinstance(value.get("body"), (str, type(None))):
            raise GithubError("GitHub returned an invalid issue state/body")
        return value

    def master_graph(self, number: int) -> dict[str, Any]:
        """Extract exactly one fenced scheduling graph; the controller validates its DAG."""
        body = self.issue(number).get("body") or ""
        if len(body.encode()) > MAX_BODY:
            raise GithubError("master issue body exceeds its byte bound")
        graphs = []
        for encoded in re.findall(r"^```json[ \t]*\r?\n(.*?)^```[ \t]*$", body, re.MULTILINE | re.DOTALL):
            try:
                candidate = json.loads(encoded, object_pairs_hook=_unique_fields)
            except ValueError as error:
                raise GithubError("master issue contains malformed fenced JSON") from error
            if isinstance(candidate, dict) and "tasks" in candidate and "master_issue" in candidate:
                graphs.append(candidate)
        if len(graphs) != 1 or type(graphs[0].get("master_issue")) is not int or graphs[0]["master_issue"] != number:
            raise GithubError("master issue must contain exactly one matching scheduling graph")
        return graphs[0]

    def children(self, number: int) -> list[dict[str, Any]]:
        """Read all native child-issue rows, including the legacy umbrella when present."""
        rows = self._pages(f"issues/{_positive(number)}/sub_issues")
        for row in rows:
            issue_identity(row, self.repo)
        return rows

    def blockers(self, number: int) -> list[dict[str, Any]]:
        """Read all native blocked-by issue relationships."""
        rows = self._pages(f"issues/{_positive(number)}/dependencies/blocked_by")
        for row in rows:
            issue_identity(row, self.repo)
        return rows

    def comments(self, number: int) -> list[dict[str, Any]]:
        """Read bounded, paginated issue comments for idempotent receipt reconciliation."""
        return self._pages(f"issues/{_positive(number)}/comments")

    def comment(self, number: int, body: str) -> dict[str, Any]:
        """Publish an exact comment once; callers reconcile ambiguous outcomes by reads."""
        self._body(body)
        return _object(self.api(f"issues/{_positive(number)}/comments", "POST", {"body": body}), "comment")

    def create_pr(self, head: str, title: str, body: str, *, base: str = "main",
                  draft: bool = False) -> dict[str, Any]:
        """Open a PR without shell interpolation; branch/source verification is caller-owned."""
        self._body(body)
        if not isinstance(title, str) or not title.strip() or len(title) > 256:
            raise GithubError("invalid pull request title")
        if not all(isinstance(name, str) and name and len(name) <= 256 and "\n" not in name
                   and "\0" not in name for name in (head, base)) or type(draft) is not bool:
            raise GithubError("invalid pull request branch or draft setting")
        return _object(self.api("pulls", "POST", {"head": head, "base": base, "title": title,
                                                 "body": body, "draft": draft}), "pull request")

    def pr(self, number: int) -> dict[str, Any]:
        """Read live PR head/base/merged identities; never infer merge from closed alone."""
        value = _object(self.api(f"pulls/{_positive(number)}"), "pull request")
        if type(value.get("number")) is not int or value.get("number") != number or type(value.get("merged")) is not bool:
            raise GithubError("GitHub returned an invalid pull request identity/merge state")
        for side in ("head", "base"):
            sha = _object(value.get(side), f"PR {side}").get("sha")
            if not isinstance(sha, str) or not SHA.fullmatch(sha):
                raise GithubError("pull request has no exact commit identity")
        return value

    def merged_pr(self, number: int, expected_head: str | None = None) -> dict[str, Any]:
        """Require readback proving merged=True and, optionally, the exact reviewed head."""
        value = self.pr(number)
        if value["merged"] is not True or (expected_head is not None and value["head"]["sha"] != expected_head):
            raise GithubError("pull request is not merged at the expected head")
        sha = value.get("merge_commit_sha")
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise GithubError("merged pull request has no exact merge commit")
        return value

    def set_status(self, sha: str, state: str, context: str, description: str,
                   target_url: str | None = None) -> dict[str, Any]:
        """Publish a fixed controller commit status bound to an exact SHA."""
        if not isinstance(sha, str) or not SHA.fullmatch(sha) or state not in ("pending", "success", "failure", "error"):
            raise GithubError("invalid commit status identity/state")
        if (not isinstance(context, str) or not context or len(context) > 100
                or not isinstance(description, str) or len(description) > 140):
            raise GithubError("invalid commit status text")
        data = {"state": state, "context": context, "description": description}
        if target_url is not None:
            if not isinstance(target_url, str) or not target_url.startswith("https://") or len(target_url) > 2048:
                raise GithubError("status target must be a bounded HTTPS URL")
            data["target_url"] = target_url
        return _object(self.api(f"statuses/{sha}", "POST", data), "commit status")

    def close_issue(self, number: int) -> dict[str, Any]:
        """Close an issue after caller-owned completion receipts have been accepted."""
        return _object(self.api(f"issues/{_positive(number)}", "PATCH",
                                {"state": "closed", "state_reason": "completed"}), "closed issue")

    def labels(self, number: int) -> list[str]:
        """Read exact existing label names without replacing unrelated labels."""
        rows = self._pages(f"issues/{_positive(number)}/labels")
        if any(not isinstance(item.get("name"), str) for item in rows):
            raise GithubError("malformed issue label")
        return [item["name"] for item in rows]

    def add_labels(self, number: int, names: Iterable[str]) -> Any:
        """Add bounded existing label names without deleting another actor's labels."""
        values = list(names)
        if len(values) > 100 or any(not isinstance(value, str) or not value or len(value) > 100 for value in values):
            raise GithubError("invalid issue labels")
        return self.api(f"issues/{_positive(number)}/labels", "POST", {"labels": values})

    @staticmethod
    def _body(body: str) -> None:
        if not isinstance(body, str) or not body.strip() or len(body.encode()) > MAX_BODY:
            raise GithubError("GitHub body is empty or exceeds its byte bound")

    def workflow_runs(self, sha: str) -> list[dict[str, Any]]:
        """Read Actions attempts for exactly one commit, without assuming jobs exist."""
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise GithubError("an exact workflow commit SHA is required")
        return self._pages(f"actions/runs?head_sha={sha}", "workflow_runs")

    def hosted_checks(self, sha: str, ignore_contexts: Iterable[str] = ()) -> dict[str, Any]:
        """Classify actual hosted evidence, retaining empty/startup failures as nonpasses.

        The controller's accepted local gate can authorize a merge when GitHub
        has no jobs or only the known zero-job startup failure; this method does
        not call either situation passing. Real failures and unfinished checks
        block. Explicitly ignore the controller's own status context to avoid
        waiting for its pending marker while deciding that same marker.
        """
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise GithubError("an exact check commit SHA is required")
        ignored = set(ignore_contexts)
        checks = self._pages(f"commits/{sha}/check-runs?filter=latest", "check_runs")
        statuses = self._pages(f"commits/{sha}/statuses")
        workflows = self.workflow_runs(sha)
        conclusions: list[str] = []
        latest_statuses: dict[str, dict[str, Any]] = {}
        for status in statuses:
            name = status.get("context")
            if not isinstance(name, str):
                raise GithubError("commit status has no context")
            if name not in ignored:
                latest_statuses.setdefault(name, status)  # API returns most recent first.
        for status in latest_statuses.values():
            state = status.get("state")
            conclusions.append("passed" if state == "success" else "failed" if state in ("failure", "error") else "pending")
        for check in checks:
            if check.get("name") in ignored:
                continue
            if check.get("head_sha") != sha:
                raise GithubError("hosted check belongs to a different commit")
            conclusions.append(self._conclusion(check))
        startup_failures = []
        for workflow in workflows:
            if workflow.get("head_sha") != sha:
                raise GithubError("workflow belongs to a different commit")
            jobs = self._pages(f"actions/runs/{_positive(workflow.get('id'))}/jobs", "jobs")
            if workflow.get("conclusion") == "startup_failure":
                if not jobs:
                    startup_failures.append(workflow)
                    continue
                conclusions.append("failed")
            else:
                workflow_state = self._conclusion(workflow)
                conclusions.append("incomplete" if workflow_state == "passed" and not jobs else workflow_state)
                conclusions.extend(self._conclusion(job) for job in jobs)
        state = next((name for name in ("failed", "pending", "incomplete") if name in conclusions), None)
        if state is None:
            state = "startup_failure" if startup_failures else "passed" if conclusions else "empty"
        return {"sha": sha, "state": state, "blocking": state in ("failed", "pending", "incomplete"),
                "checks": checks, "statuses": list(latest_statuses.values()), "workflows": workflows,
                "startup_failures": startup_failures}

    @staticmethod
    def _conclusion(row: dict[str, Any]) -> str:
        if row.get("status") != "completed":
            return "pending"
        conclusion = row.get("conclusion")
        if conclusion == "success":
            return "passed"
        if conclusion in ("failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"):
            return "failed"
        return "incomplete"
