"""Journal verified discoveries into the master DAG without blind mutation retries.

The caller holds the controller graph lock for register()/reconcile(). GitHub
issue bodies have no compare-and-swap field in the transport: exact preflight and
readback detect conflicting edits, but cannot prevent an external writer racing
between the last GET and PATCH. All detected conflicts retain the journal.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from .agents import validate_result
from .graph import Graph, GraphError
from .github import GithubError, GithubIdentityError, issue_identity, native_issue_numbers


MAX_BODY_BYTES = 60000
_FENCE = re.compile(r"(?m)^```json[ \t]*\n(.*?)\n```[ \t]*$", re.S)
_COUNTS = re.compile(r"\*\*(\d+) actionable work items, (\d+) prerequisite edges, and (\d+) dependency levels\*\*")


class BacklogError(RuntimeError):
    """A discovery needs read-only reconciliation or an explicit manual decision."""


class MasterBlockerInvalid(BacklogError):
    """A confirmed master dependency revokes acceptance even during graph repair."""


class ReviewedCatalogChanged(BacklogError):
    """Confirmed live coverage drift requires review and owned-proof reconciliation."""


class NativeChildrenInvalid(BacklogError):
    """A confirmed child hierarchy differs from the approved flat scheduling DAG."""


def _encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _positive(value):
    if type(value) is not int or value <= 0:
        raise BacklogError("issue identity must be a positive integer")
    return value


def _body(value):
    if type(value) is not str or not value.strip() or len(value.encode()) > MAX_BODY_BYTES:
        raise BacklogError("issue body must be nonempty and at most 60000 UTF-8 bytes")
    return value


def _approved_registration(parent_issue, discovery, source, review):
    """Validate the exact bounded intent that an approving review authorizes."""
    _positive(parent_issue)
    try:
        validate_result("reviewer", review)
    except ValueError as error:
        raise BacklogError("discovery review is malformed") from error
    if review["verdict"] != "approve":
        raise BacklogError("a fresh approving discovery review is required")
    if (type(discovery) is not dict or set(discovery) != {"title", "description", "acceptance"}
            or type(discovery["title"]) is not str or not discovery["title"].strip()
            or len(discovery["title"]) > 180 or "\n" in discovery["title"] or "\r" in discovery["title"]
            or type(discovery["description"]) is not str or not discovery["description"].strip()
            or type(discovery["acceptance"]) is not list or not 1 <= len(discovery["acceptance"]) <= 64
            or any(type(item) is not str or not item.strip() or len(item) > 2048 for item in discovery["acceptance"])
            or type(source) is not str or re.fullmatch(r"[0-9a-f]{40}", source) is None):
        raise BacklogError("discovery requires bounded title/description/acceptance and an exact source SHA")


def _numbers(rows, github, issues=None):
    try:
        return set(native_issue_numbers(rows, github.repo,
                                        github.issue if issues is None else issues))
    except GithubError as error:
        raise BacklogError("native relationship has a foreign or inconsistent issue identity") from error


def _graph_record(body):
    Graph.from_master(body)
    matches = [(match, json.loads(match.group(1))) for match in _FENCE.finditer(body)]
    return next((match, value) for match, value in matches
                if type(value) is dict and "tasks" in value and "master_issue" in value)


def _section(body, heading):
    pattern = re.compile(r"(?m)^## " + re.escape(heading) + r"\n.*?(?=^## |\Z)", re.S)
    matches = list(pattern.finditer(body))
    if len(matches) != 1:
        raise BacklogError(f"master needs exactly one '{heading}' section; reconcile its layout manually")
    return matches[0]


def _render_master(original, repo, parent, number, key, title):
    fence, record = _graph_record(original)
    tasks = record["tasks"]
    previous = {task["issue"]: task for task in tasks}
    parent_task = previous[parent]
    parent_route = Graph.from_master(original).by_issue[parent].route
    tasks.append({"key": key, "issue": number, "depends_on": list(parent_task["depends_on"]),
                  "locks": list(parent_task["locks"]), "external_gate": parent_route != "repository",
                  "level": 0})
    parent_task["depends_on"].append(number)
    levels = {}
    while len(levels) != len(tasks):
        ready = [task for task in tasks if task["issue"] not in levels
                 and all(dep in levels for dep in task["depends_on"])]
        if not ready:
            raise BacklogError("discovery would create a dependency cycle")
        for task in ready:
            task["level"] = max((levels[dep] + 1 for dep in task["depends_on"]), default=0)
            levels[task["issue"]] = task["level"]
    tasks.sort(key=lambda task: (task["level"], task["key"]))
    result = original[:fence.start()] + "```json\n" + _encode(record) + "\n```" + original[fence.end():]

    section = _section(result, "Ordered backlog")
    old = section.group()
    rows = list(re.finditer(r"(?m)^\|\s*\d+\s*\|\s*\d+\s*\|\s*(.*?)\s*\|\s*([^|]*)\|[ \t]*$", old))
    labels = {}
    for row in rows:
        label = row.group(1)
        reference = re.search(r"\[[A-Z][A-Z0-9]*-\d+ #(\d+)\]", label)
        if reference is None or int(reference.group(1)) in labels:
            raise BacklogError("master order table has an ambiguous issue label")
        labels[int(reference.group(1))] = label
    if set(labels) != set(previous) or not rows:
        raise BacklogError("master order table does not cover exactly the original DAG")
    labels[number] = f"[{key} #{number}](https://github.com/{repo}/issues/{number}): " + title.replace("|", "&#124;")
    updated_rows = []
    for order, task in enumerate(tasks, 1):
        deps = ", ".join(f"#{dep}" for dep in task["depends_on"]) or "Ready"
        updated_rows.append(f"| {order} | {task['level']} | {labels[task['issue']]} | {deps} |")
    rendered = old[:rows[0].start()] + "\n".join(updated_rows) + old[rows[-1].end():]
    result = result[:section.start()] + rendered + result[section.end():]

    section = _section(result, "Completion checklist")
    checklist = section.group()
    lines = list(re.finditer(r"(?m)^- \[([ xX])\] #(\d+)([^\n]*)$", checklist))
    checks = {int(line.group(2)): line.group() for line in lines}
    wanted = set(previous) | {record["legacy_umbrella"]["issue"]}
    if set(checks) != wanted or len(checks) != len(lines):
        raise BacklogError("master completion checklist differs from the original DAG")
    checks[number] = f"- [ ] #{number} — {key}: discovered prerequisite for #{parent}"
    ordered_checks = [checks[task["issue"]] for task in tasks]
    ordered_checks.append(checks[record["legacy_umbrella"]["issue"]])
    rendered = checklist[:lines[0].start()] + "\n".join(ordered_checks) + checklist[lines[-1].end():]
    result = result[:section.start()] + rendered + result[section.end():]

    counts = list(_COUNTS.finditer(result))
    if len(counts) != 1:
        raise BacklogError("master current-count sentence is missing or ambiguous")
    count = counts[0]
    current = f"**{len(tasks)} actionable work items, {sum(len(task['depends_on']) for task in tasks)} prerequisite edges, and {max(levels.values()) + 1} dependency levels**"
    result = result[:count.start()] + current + result[count.end():]
    if "<!-- issue-pipeline-original-audit-counts -->" not in result:
        snapshot = ("<!-- issue-pipeline-original-audit-counts -->\nOriginal audited backlog snapshot: "
                    f"{count[1]} work items, {count[2]} prerequisite edges, {count[3]} dependency levels.\n\n")
        boundary = result.find("\n\n")
        if boundary < 0:
            raise BacklogError("master introductory paragraph is malformed")
        result = result[:boundary + 2] + snapshot + result[boundary + 2:]
    result, count = re.subn(r"Completion requires all \d+ children", f"Completion requires all {len(tasks)} children", result, count=1)
    if count != 1:
        raise BacklogError("master completion-count boundary is missing")
    result = result.replace("This is the initial audited DAG.",
                            "This is the current scheduling DAG; its source identifies the original audit baseline.")
    Graph.from_master(result)  # Proves all nodes, including discovery, still reach final acceptance.
    return _body(result)


class Backlog:
    """Register only independently approved discoveries under an external graph lock."""

    def __init__(self, github, state_dir: Path, master_issue: int, *, publication_guard=None):
        self.github = github
        self.master_issue = _positive(master_issue)
        # Controller supplies its immutable review/queue binding. Keep this
        # check at every publication boundary, including interrupted replay.
        self.publication_guard = publication_guard
        self.directory = Path(state_dir) / "backlog"
        if self.directory.is_symlink():
            raise BacklogError("backlog journal directory cannot be a symlink")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.stat().st_uid != os.getuid():
            raise BacklogError("backlog journals must belong to the current user")
        self.directory.chmod(0o700)

    def _save(self, path, journal):
        data = _encode(journal).encode()
        descriptor, temporary = tempfile.mkstemp(prefix=".journal-", dir=self.directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _load(self, path):
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise BacklogError(f"unsafe or oversized journal: {path}")
        journal = json.loads(path.read_text())
        if (type(journal) is not dict or journal.get("version") != 1
                or journal.get("repo") != self.github.repo or journal.get("master") != self.master_issue):
            raise BacklogError(f"journal belongs to another repository/master or version: {path}")
        return journal

    def _conflict(self, path, message):
        raise BacklogError(f"{message}; preserve {path} and reconcile manually before resuming graph writes")

    def _master_blockers(self, graph=None, issues=None):
        """Keep confirmed master revocation distinct from transport or partial repair."""
        try:
            blockers = set(native_issue_numbers(self.github.blockers(self.master_issue),
                                               self.github.repo, self.github.issue if issues is None else issues))
        except GithubIdentityError as error:
            raise MasterBlockerInvalid("native master blocker has an invalid identity; preserve the discovery journal") from error
        if graph is not None:
            try:
                graph.validate_master_blockers(blockers)
            except GraphError as error:
                raise MasterBlockerInvalid("native master blocker is outside the managed graph; preserve the discovery journal") from error
        return blockers

    def _children(self, graph, issues=None, *, prospective=None, complete=False):
        """Validate every managed child collection, including an exact owned discovery."""
        if graph.master_issue != self.master_issue:
            raise NativeChildrenInvalid("native child hierarchy names a different master")
        original = set(graph.by_issue) | {int(graph.legacy_umbrella["issue"])}
        members = original | ({prospective} if prospective is not None else set())
        try:
            snapshots = issues if issues is not None else {n: self.github.issue(n) for n in sorted(members)}
            children = {n: native_issue_numbers(self.github.children(n), self.github.repo, snapshots)
                        for n in sorted(members | {self.master_issue})}
        except GithubIdentityError as error:
            raise NativeChildrenInvalid("native child has a foreign or inconsistent issue identity; preserve the discovery journal") from error
        for owner in members:
            if children[owner]:
                raise NativeChildrenInvalid(f"native nested children for #{owner} are not authorized by the flat scheduling graph")
        if set(children[self.master_issue]) not in ((members,) if complete else (original, members)):
            raise NativeChildrenInvalid("native master children differ from the approved graph and its exact prospective discovery")
        return children

    def _guard(self, journal, path, *, complete=False):
        graph = Graph.from_master(journal["master_before"])
        members = set(graph.by_issue) | {int(graph.legacy_umbrella["issue"])}
        blockers = self._master_blockers()
        # A lost create response may precede legitimate native links. Only its
        # exact owned issue can extend the master; it must itself remain a leaf.
        child = journal["child"]
        if child is None and journal["create_started"]:
            matches = self._find_marker(journal["marker"])
            if len(matches) == 1:
                child = matches[0]
        admitted = None
        if child is not None:
            prospective = self.github.issue(child)
            if (prospective["state"] == "open" and prospective.get("body") == journal["child_body"]
                    and prospective.get("title") == journal["title"]):
                admitted = child
                members.add(child)
        if not blockers <= members:
            raise MasterBlockerInvalid(f"native master blocker is outside this approved managed graph; preserve {path} and reconcile manually")
        if complete and admitted != journal["child"]:
            self._conflict(path, "final discovery child no longer has its exact approved identity")
        self._children(graph, prospective=admitted, complete=complete)
        if self.publication_guard is not None:
            self.publication_guard(journal, path)
        # Keep issue acceptance/state reads after the potentially slow native
        # identity reads and before the next durable publication intent.
        for number, old, new in ((self.master_issue, journal["master_before"], journal.get("master_after")),
                                 (journal["parent"], journal["parent_before"], journal.get("parent_after"))):
            live = self.github.issue(number)
            allowed = {old} | ({new} if new is not None else set())
            if live["state"] != "open" or live.get("body") not in allowed:
                self._conflict(path, f"issue #{number} changed since discovery preparation")

    def _find_marker(self, marker):
        matches = []
        for page in range(1, 101):
            rows = self.github.api(f"issues?state=all&sort=created&direction=desc&per_page=100&page={page}")
            if type(rows) is not list or len(rows) > 100:
                raise BacklogError("cannot reconcile discovery: malformed issue list")
            for row in rows:
                if type(row) is not dict:
                    raise BacklogError("cannot reconcile discovery: malformed issue row")
                if "pull_request" not in row and marker in (row.get("body") or ""):
                    matches.append(_positive(row.get("number")))
            if len(rows) < 100:
                return matches
        raise BacklogError("issue listing exceeds reconciliation bound; locate the exact marker manually")

    def _identity_path(self, parent_issue, discovery):
        identity = hashlib.sha256(_encode([self.github.repo, self.master_issue,
                                          _positive(parent_issue), discovery]).encode()).hexdigest()
        return identity, self.directory / f"{identity}.json"

    def registration_started(self, parent_issue: int, discovery: dict, source: str, review: dict) -> bool:
        """Whether this exact approved intent already owns a durable journal.

        Its original review context must still pass the publication guard during
        recovery; only this operation's exact changes may differ from the catalog.
        This is read-only and does not infer an intent from a matching title.
        """
        _, path = self._identity_path(parent_issue, discovery)
        if not path.exists():
            return False
        journal = self._load(path)
        if (journal.get("parent") != parent_issue or journal.get("discovery") != discovery
                or journal.get("source") != source or journal.get("review") != review):
            self._conflict(path, "existing registration belongs to a different approved intent")
        return True

    def pending_registrations(self) -> list[dict]:
        """Read every incomplete journal's exact approval identity without replay.

        The controller must bind all returned intents to their durable queue
        entries and source/catalog receipts before calling reconcile(). Callers
        hold the graph lock through validation and replay.
        """
        pending = []
        for path in sorted(self.directory.glob("*.json")):
            journal = self._load(path)
            if journal.get("status") == "complete":
                continue
            if journal.get("status") != "pending":
                self._conflict(path, "invalid discovery journal status")
            descriptor = {field: journal.get(field) for field in ("parent", "discovery", "source", "review")}
            _approved_registration(descriptor["parent"], descriptor["discovery"],
                                   descriptor["source"], descriptor["review"])
            identity, expected = self._identity_path(descriptor["parent"], descriptor["discovery"])
            if path != expected or journal.get("marker") != f"<!-- issue-pipeline-discovery:{identity} -->":
                self._conflict(path, "discovery journal identity differs from its approved intent")
            pending.append({"path": str(path), **descriptor})
        return pending

    def register(self, parent_issue: int, discovery: dict, source: str, review: dict) -> int:
        """Create/link one verified prerequisite or resume its exact prior journal."""
        parent_issue = _positive(parent_issue)
        _approved_registration(parent_issue, discovery, source, review)
        identity, path = self._identity_path(parent_issue, discovery)
        if self.registration_started(parent_issue, discovery, source, review):
            return self._resume(self._load(path), path)
        if self.pending_registrations():
            raise BacklogError("reconcile existing discovery journals with their original approval before reviewing a new registration")
        master = self.github.issue(self.master_issue)
        parent = self.github.issue(parent_issue)
        original = _body(master.get("body"))
        graph = Graph.from_master(original)
        if graph.master_issue != self.master_issue or parent_issue not in graph.by_issue:
            raise BacklogError("affected issue must be an existing task in this master DAG")
        if master["state"] != "open" or parent["state"] != "open":
            raise BacklogError("master and affected parent must be open; completed acceptance needs manual invalidation")
        task = graph.by_issue[parent_issue]
        expected_children = set(graph.by_issue) | {graph.legacy_umbrella["issue"]}
        issues = {number: self.github.issue(number) for number in expected_children}
        try:
            graph.validate_native_links(self._children(graph, issues),
                                        {**{number: _numbers(self.github.blockers(number), self.github, issues)
                                            for number in expected_children},
                                         self.master_issue: self._master_blockers(graph, issues)})
        except ValueError as error:
            raise BacklogError("native master links differ from the prepared graph") from error
        key = next((f"FIX-{index:02}" for index in range(1, 100) if f"FIX-{index:02}" not in graph.by_key), None)
        if key is None:
            raise BacklogError("FIX-01..99 exhausted; extend the naming contract explicitly")
        marker = f"<!-- issue-pipeline-discovery:{identity} -->"
        prerequisites = ", ".join(f"#{number}" for number in task.depends_on) or "None"
        child_body = _body(
            f"{marker}\nMaster: #{self.master_issue} · Plan key: `{key}` · Required by #{parent_issue}\n\n"
            f"**Closure prerequisites:** {prerequisites}\n\n"
            f"**Shared write scopes:** {', '.join('`' + scope + '`' for scope in task.locks) or 'claim exact files'}\n\n"
            f"**Inherited execution route:** {task.route}. Specialized work requires its explicit route and evidence.\n\n"
            f"## Verified discovery and source\n\nSource: [`{source}`](https://github.com/{self.github.repo}/tree/{source}). "
            f"Discovered while completing #{parent_issue}; independently reviewed before registration.\n\n"
            f"{discovery['description']}\n\n## Acceptance criteria\n\n"
            + "\n".join("- [ ] " + item for item in discovery["acceptance"])
            + f"\n\n## Execution and closure\n\nFollow #{self.master_issue}, the parent issue's normative references, "
            "and repository AGENTS.md. Preserve every parent acceptance criterion. Plan exact files and checks; "
            "separate any new normative contract PR from dependent implementation. Supply source-anchored "
            "before/after evidence and required negative/restart/resource scenarios. Do not weaken checks. "
            "A fresh independent review, the controller's mandatory gate, and accepted merged-source receipts "
            "are required for repository changes; specialized routes retain their external/native proof. "
            f"This issue must close with accepted evidence before #{parent_issue} resumes.\n\n"
            f"## Discovery review\n\n{review['summary']}\n")
        journal = {"version": 1, "repo": self.github.repo, "master": self.master_issue,
                   "parent": parent_issue, "source": source, "discovery": copy.deepcopy(discovery),
                   "review": copy.deepcopy(review), "key": key, "marker": marker,
                   "master_before": original, "parent_before": _body(parent.get("body")),
                   "prior_deps": list(task.depends_on), "title": f"[{key}] {discovery['title']}",
                   "child_body": child_body, "child": None, "create_started": False,
                   "intent": "prepared", "status": "pending"}
        # Validate all render/layout/body bounds before creating a remote issue.
        _render_master(original, self.github.repo, parent_issue, max(expected_children) + 1,
                       key, discovery["title"])
        self._parent_body(journal, max(expected_children) + 1)
        self._save(path, journal)
        return self._resume(journal, path)

    def _resume(self, journal, path):
        try:
            return self._finish(journal, path)
        except BacklogError:
            raise
        except Exception as error:
            raise BacklogError(f"discovery operation interrupted; reconcile journal {path} before any new graph writes") from error

    def _parent_body(self, journal, number):
        return _body(journal["parent_before"] +
            f"\n\n## Additional prerequisite discovered by the pipeline\n\n{journal['marker']}\n\n"
            f"{journal['key']} #{number} must close with accepted evidence before this issue resumes. "
            "This extends the original closure prerequisites; all original acceptance criteria remain required. "
            f"The current master #{self.master_issue} DAG governs scheduling.\n")

    def _intent(self, journal, path, description):
        self._guard(journal, path)
        journal["intent"] = description
        self._save(path, journal)

    def _link(self, journal, path, owner, child, kind):
        reader = self.github.children if kind == "sub_issues" else self.github.blockers
        target = self.github.issue(child)
        identity = issue_identity(target, self.github.repo, child)
        def linked():
            # Pin this target across the mutation and ambiguous-response readback.
            def local(number):
                return target if number == child else self.github.issue(number)
            return child in _numbers(reader(owner), self.github, local)
        if linked():
            return
        self._intent(journal, path, f"link:{owner}:{kind}:{child}")
        payload = {"sub_issue_id" if kind == "sub_issues" else "issue_id": identity[1]}
        try:
            self.github.api(f"issues/{owner}/{kind}", "POST", payload)
        except Exception:
            if not linked():
                raise
        if not linked():
            self._conflict(path, f"native {kind} link #{owner} to #{child} did not persist")

    def _patch_body(self, journal, path, number, before, after):
        live = self.github.issue(number).get("body")
        if live == after:
            return
        if live != before:
            self._conflict(path, f"issue #{number} body changed before update")
        self._intent(journal, path, f"body:{number}")
        try:
            self.github.api(f"issues/{number}", "PATCH", {"body": after})
        except Exception:
            if self.github.issue(number).get("body") != after:
                raise
        if self.github.issue(number).get("body") != after:
            self._conflict(path, f"issue #{number} body update has divergent readback")

    def _finish(self, journal, path):
        if journal["status"] == "complete":
            # Later legitimate graph edits need not match this historical snapshot.
            # A controller still replaying an uncheckpointed queue entry must
            # validate that entry's original approval before adopting completion.
            if self.publication_guard is not None:
                self.publication_guard(journal, path)
            number = _positive(journal["child"])
            child = self.github.issue(number)
            graph = Graph.from_master(self.github.issue(self.master_issue).get("body") or "")
            self._master_blockers(graph)
            self._children(graph)
            if (journal["marker"] not in (child.get("body") or "") or number not in graph.by_issue
                    or number not in graph.by_issue[journal["parent"]].depends_on):
                self._conflict(path, "completed discovery registration no longer exists in the live graph")
            if self.publication_guard is not None:
                self.publication_guard(journal, path)
            return number
        self._guard(journal, path)
        if journal["child"] is None:
            matches = self._find_marker(journal["marker"])
            if len(matches) > 1:
                self._conflict(path, "multiple issues contain the exact discovery marker")
            if matches:
                journal["child"] = matches[0]
            elif journal["create_started"]:
                self._conflict(path, "issue creation was ambiguous and no exact marker is visible; do not repeat POST")
            else:
                journal["create_started"] = True
                self._intent(journal, path, "create_issue")
                try:
                    created = self.github.api("issues", "POST", {"title": journal["title"], "body": journal["child_body"]})
                    journal["child"] = _positive(created.get("number"))
                except Exception:
                    matches = self._find_marker(journal["marker"])
                    if len(matches) != 1:
                        self._conflict(path, "issue creation has an ambiguous outcome; locate its exact marker")
                    journal["child"] = matches[0]
            self._save(path, journal)
        number = _positive(journal["child"])
        child = self.github.issue(number)
        if child.get("body") != journal["child_body"] or child.get("title") != journal["title"] or child["state"] != "open":
            self._conflict(path, "discovery issue differs from its exact prepared content")
        if "master_after" not in journal:
            journal["master_after"] = _render_master(journal["master_before"], self.github.repo,
                                                     journal["parent"], number, journal["key"],
                                                     journal["discovery"]["title"])
            journal["parent_after"] = self._parent_body(journal, number)
            self._save(path, journal)
        self._link(journal, path, self.master_issue, number, "sub_issues")
        for dependency in journal["prior_deps"]:
            self._link(journal, path, number, dependency, "dependencies/blocked_by")
        self._link(journal, path, journal["parent"], number, "dependencies/blocked_by")
        self._patch_body(journal, path, journal["parent"], journal["parent_before"], journal["parent_after"])
        self._patch_body(journal, path, self.master_issue, journal["master_before"], journal["master_after"])
        self._guard(journal, path)
        graph = Graph.from_master(self.github.issue(self.master_issue)["body"])
        all_numbers = set(graph.by_issue) | {graph.legacy_umbrella["issue"]}
        issues = {issue: self.github.issue(issue) for issue in all_numbers}
        graph.validate_native_links(self._children(graph, issues),
                                    {**{issue: _numbers(self.github.blockers(issue), self.github, issues)
                                        for issue in all_numbers},
                                     self.master_issue: self._master_blockers(graph, issues)})
        if self.github.issue(number).get("body") != journal["child_body"]:
            self._conflict(path, "discovery body changed before final readback")
        self._guard(journal, path, complete=True)
        journal.update(status="complete", intent="readback_verified")
        self._save(path, journal)
        return number

    def reconcile(self) -> list[int]:
        """Finish known incomplete operations, or leave an actionable conflict journal."""
        completed = []
        for path in sorted(self.directory.glob("*.json")):
            journal = self._load(path)
            if journal["status"] != "complete":
                completed.append(self._resume(journal, path))
        return completed
