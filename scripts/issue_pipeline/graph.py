"""Validate the authoritative issue DAG before scheduling any work.

Issue closure is necessary but insufficient: ``ready`` also requires a caller
provided accepted-proof predicate for every dependency. Routing is deliberately
independent of readiness and of the external-gate flag.
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping


class GraphError(ValueError):
    """The master issue or its native dependency links are inconsistent."""


def _integer(value: object, label: str, *, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise GraphError(f"{label} must be an integer >= {minimum}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise GraphError(f"{label} must be a nonempty trimmed string")
    return value


def _numbers(value: object, label: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise GraphError(f"{label} must be an array")
    numbers = tuple(_integer(item, label) for item in value)
    if len(set(numbers)) != len(numbers):
        raise GraphError(f"{label} contains duplicate issue numbers")
    return numbers


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GraphError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


@dataclass(frozen=True)
class Task:
    """One immutable task from the checked master graph."""

    key: str
    issue: int
    depends_on: tuple[int, ...]
    locks: tuple[str, ...]
    external_gate: bool
    level: int

    @property
    def route(self) -> str:
        """Return an execution route; specialized work is never a generic PR."""
        if self.key in {"STO-01", "STO-02"}:
            return "upstream"
        if self.external_gate or self.key in {"ENC-11", "REL-13"}:
            return "external"
        if self.key == "REL-01":
            return "host"
        if self.key.startswith("REL-") and 4 <= int(self.key[4:]) <= 12:
            return "native"
        return "repository"


@dataclass(frozen=True)
class Graph:
    """A validated graph, including the separately tracked legacy umbrella."""

    source: str
    master_issue: int
    final_issue: int
    lock_policy: str
    legacy_umbrella: dict[str, object]
    tasks: tuple[Task, ...]
    version: int = 1

    @property
    def by_issue(self) -> dict[int, Task]:
        return {task.issue: task for task in self.tasks}

    @property
    def by_key(self) -> dict[str, Task]:
        return {task.key: task for task in self.tasks}

    @classmethod
    def from_master(cls, body: str) -> Graph:
        """Parse exactly one version-1 graph in a fenced JSON block."""
        if not isinstance(body, str) or len(body) > 1_048_576:
            raise GraphError("master body must be text no larger than one MiB")
        candidates: list[dict[str, object]] = []
        for block in re.findall(r"(?m)^```json[ \t]*\n(.*?)\n```[ \t]*$", body, re.S):
            try:
                value = json.loads(block, object_pairs_hook=_object)
            except (json.JSONDecodeError, RecursionError) as error:
                raise GraphError(f"invalid fenced JSON: {error}") from error
            if isinstance(value, dict) and ("tasks" in value or "master_issue" in value):
                candidates.append(value)
        if len(candidates) != 1:
            raise GraphError("master must contain exactly one fenced scheduling graph")
        value = candidates[0]
        fields = {
            "version", "source", "master_issue", "final_issue", "lock_policy",
            "legacy_umbrella", "tasks",
        }
        if set(value) != fields or type(value["version"]) is not int or value["version"] != 1:
            raise GraphError("graph must match the closed version-1 schema")
        source = value["source"]
        if not isinstance(source, str) or re.fullmatch(r"[0-9a-f]{40}", source) is None:
            raise GraphError("source must be a full lowercase Git SHA-1")
        master = _integer(value["master_issue"], "master_issue")
        final = _integer(value["final_issue"], "final_issue")
        policy = _text(value["lock_policy"], "lock_policy")
        raw_tasks = value["tasks"]
        if not isinstance(raw_tasks, list) or not 1 <= len(raw_tasks) <= 10_000:
            raise GraphError("tasks must contain between one and 10000 tasks")
        tasks: list[Task] = []
        task_fields = {"key", "issue", "depends_on", "locks", "external_gate", "level"}
        for raw in raw_tasks:
            if not isinstance(raw, dict) or set(raw) != task_fields:
                raise GraphError("task must match the closed version-1 schema")
            key = _text(raw["key"], "task key")
            if re.fullmatch(r"[A-Z][A-Z0-9]*-[0-9]{2,}", key) is None:
                raise GraphError(f"invalid task key: {key}")
            issue = _integer(raw["issue"], f"{key} issue")
            deps = _numbers(raw["depends_on"], f"{key} depends_on")
            raw_locks = raw["locks"]
            if not isinstance(raw_locks, list):
                raise GraphError(f"{key} locks must be an array")
            locks = tuple(_text(item, f"{key} lock") for item in raw_locks)
            if len(set(locks)) != len(locks):
                raise GraphError(f"{key} has duplicate locks")
            if type(raw["external_gate"]) is not bool:
                raise GraphError(f"{key} external_gate must be a boolean")
            tasks.append(Task(key, issue, deps, locks, raw["external_gate"],
                              _integer(raw["level"], f"{key} level", minimum=0)))
        numbers = {task.issue for task in tasks}
        if len(numbers) != len(tasks) or len({task.key for task in tasks}) != len(tasks):
            raise GraphError("task issue numbers and keys must be unique")
        if final not in numbers or master in numbers:
            raise GraphError("final must be a task and master must not be a task")
        for task in tasks:
            if task.issue in task.depends_on or not set(task.depends_on) <= numbers:
                raise GraphError(f"{task.key} has a self or unknown dependency")
        legacy = value["legacy_umbrella"]
        if not isinstance(legacy, dict) or set(legacy) != {"issue", "depends_on"}:
            raise GraphError("legacy_umbrella must match the closed schema")
        legacy_issue = _integer(legacy["issue"], "legacy issue")
        legacy_deps = _numbers(legacy["depends_on"], "legacy depends_on")
        if legacy_issue in numbers | {master} or not set(legacy_deps) <= numbers:
            raise GraphError("legacy umbrella must be separate with known prerequisites")

        by_issue = {task.issue: task for task in tasks}
        successors: dict[int, list[int]] = {number: [] for number in numbers}
        remaining = {task.issue: len(task.depends_on) for task in tasks}
        for task in tasks:
            for dep in task.depends_on:
                successors[dep].append(task.issue)
        queue = deque(task.issue for task in tasks if not task.depends_on)
        levels: dict[int, int] = {}
        while queue:
            number = queue.popleft()
            task = by_issue[number]
            levels[number] = max((levels[dep] + 1 for dep in task.depends_on), default=0)
            for child in successors[number]:
                remaining[child] -= 1
                if not remaining[child]:
                    queue.append(child)
        if len(levels) != len(tasks):
            raise GraphError("dependency graph contains a cycle")
        if any(task.level != levels[task.issue] for task in tasks):
            raise GraphError("stored task levels contradict dependency order")
        ancestors: set[int] = set()
        pending = [final]
        while pending:
            number = pending.pop()
            if number not in ancestors:
                ancestors.add(number)
                pending.extend(by_issue[number].depends_on)
        if ancestors != numbers:
            raise GraphError("every task must be a prerequisite of final acceptance")
        return cls(source, master, final, policy,
                   {"issue": legacy_issue, "depends_on": legacy_deps}, tuple(tasks))

    def ready(
        self,
        issue_snapshots: Mapping[int, Mapping[str, object]],
        completed: set[int] | Callable[[int], bool],
        occupied_scopes: Iterable[str] = (),
    ) -> list[Task]:
        """Select open unclaimed tasks whose closed blockers have accepted proof."""
        proven = completed if callable(completed) else lambda number: number in completed
        occupied = set(occupied_scopes)

        def state(number: int) -> str:
            snapshot = issue_snapshots.get(number, {})
            value = snapshot.get("state")
            return value.upper() if isinstance(value, str) else ""

        return [
            task for task in self.tasks
            if state(task.issue) == "OPEN" and not occupied.intersection(task.locks)
            and all(state(dep) == "CLOSED" and proven(dep) for dep in task.depends_on)
        ]

    def validate_native_links(
        self, subissues: Iterable[int], blockers: Mapping[int, Iterable[int]]
    ) -> None:
        """Require an exact native subissue/blocker mirror, including legacy."""
        children = tuple(_integer(number, "native subissue") for number in subissues)
        legacy_issue = int(self.legacy_umbrella["issue"])
        expected = {task.issue: set(task.depends_on) for task in self.tasks}
        expected[legacy_issue] = set(self.legacy_umbrella["depends_on"])
        if len(children) != len(set(children)) or set(children) != set(expected):
            raise GraphError("native subissues differ from the scheduling graph")
        if any(type(number) is not int for number in blockers) or set(blockers) != set(expected):
            raise GraphError("native blocker records are incomplete or contain unknown children")
        for number, wanted in expected.items():
            observed = tuple(_integer(dep, "native blocker") for dep in blockers[number])
            if len(observed) != len(set(observed)) or set(observed) != wanted:
                raise GraphError(f"native blockers for #{number} differ from the scheduling graph")
