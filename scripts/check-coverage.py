#!/usr/bin/env python3
"""Enforce overall and reviewed critical-region coverage."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import NoReturn

MINIMUM_PERCENT = 90.0
CRITICAL_PERCENT = 100.0
CARGO_LLVM_COV_VERSION = "0.9.0"
LLVM_COVERAGE_EXPORT_TYPE = "llvm.coverage.json.export"
LLVM_COVERAGE_EXPORT_VERSION = "3.1.0"
REQUIRED_CATEGORIES = {
    "parser-error-discriminants",
    "authorization-decisions",
    "protocol-enum-arms",
    "persistence-recovery",
    "section-27-invariant-checkers",
}
REGION_FIELDS = {
    "id",
    "category",
    "file",
    "source_sha256",
    "start_line",
    "end_line",
    "metric",
    "reason",
}
DEFERRED_FIELDS = {"category", "until_task", "reason"}
FILE_FIELDS = {
    "branches",
    "mcdc_records",
    "expansions",
    "filename",
    "segments",
    "summary",
}
SUMMARY_METRICS = {
    "branches",
    "functions",
    "instantiations",
    "lines",
    "mcdc",
    "regions",
}
UNCOVERED_METRICS = {"branches", "mcdc", "regions"}
REGION_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{2,63}")
SOURCE_PATH_RE = re.compile(r"crates/[a-z0-9_-]+/src/[A-Za-z0-9_./-]+\.rs")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
TASK_ID_RE = re.compile(r"S\d{2}-(?:\d{3}|900)")
TODO_TASK_RE = re.compile(
    r"^- \[([ x])\] `(S\d{2}-(?:\d{3}|900))`",
    flags=re.MULTILINE,
)


class CoverageError(ValueError):
    """A malformed policy, report, or coverage result."""


def task_states(root: Path) -> dict[str, bool]:
    """Return task completion states from the implementation plan."""
    text = (root / "TODO.md").read_text(encoding="utf-8")
    states: dict[str, bool] = {}
    for marker, task_id in TODO_TASK_RE.findall(text):
        if task_id in states:
            raise CoverageError(f"TODO.md contains duplicate task {task_id}")
        states[task_id] = marker == "x"
    if not states:
        raise CoverageError("TODO.md contains no implementation tasks")
    return states


def load_policy(path: Path) -> dict[str, object]:
    """Load the reviewed critical-region policy."""
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CoverageError(f"cannot read coverage policy: {error}") from error


def production_source_inventory(root: Path) -> tuple[int, str]:
    """Hash every production Rust source path and its current bytes."""
    records: list[tuple[str, bytes]] = []
    for path in sorted((root / "crates").glob("*/src/**/*.rs")):
        relative = path.relative_to(root).as_posix()
        if SOURCE_PATH_RE.fullmatch(relative) is None or path.is_symlink() or not path.is_file():
            raise CoverageError(f"production source inventory contains invalid path {relative!r}")
        cursor = root
        for part in relative.split("/"):
            cursor /= part
            if cursor.is_symlink():
                raise CoverageError(
                    f"production source inventory may not traverse a symbolic link: {relative}"
                )
        records.append((relative, path.read_bytes()))
    if not records:
        raise CoverageError("production source inventory contains no Rust sources")
    digest = hashlib.sha256()
    for relative, source in records:
        path_bytes = relative.encode("utf-8")
        for field in (path_bytes, source):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return len(records), digest.hexdigest()


def validate_source_inventory(root: Path, file_count: object, source_hash: object) -> None:
    """Require the policy to cover the complete production source tree."""
    if type(file_count) is not int or file_count <= 0:
        raise CoverageError("coverage policy has an invalid reviewed source count")
    if not isinstance(source_hash, str) or SHA256_RE.fullmatch(source_hash) is None:
        raise CoverageError("coverage policy has an invalid reviewed source hash")
    actual_count, actual_hash = production_source_inventory(root)
    if file_count != actual_count or source_hash != actual_hash:
        raise CoverageError(
            "coverage policy production source inventory is stale; review every changed "
            "source for new critical ranges"
        )


def validate_policy_data(
    root: Path,
    policy: dict[str, object],
) -> list[dict[str, object]]:
    """Validate the closed policy and return its reviewed regions."""
    if set(policy) != {
        "schema_version",
        "minimum_overall_branch_percent",
        "minimum_overall_line_percent",
        "critical_region_percent",
        "required_categories",
        "reviewed_source_files",
        "reviewed_source_sha256",
        "region",
        "deferred",
    }:
        raise CoverageError("coverage policy has invalid top-level fields")
    schema_version = policy.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise CoverageError("coverage policy schema_version must be 1")
    if policy.get("minimum_overall_branch_percent") != MINIMUM_PERCENT:
        raise CoverageError("coverage policy branch threshold is stale")
    if policy.get("minimum_overall_line_percent") != MINIMUM_PERCENT:
        raise CoverageError("coverage policy line threshold is stale")
    if policy.get("critical_region_percent") != CRITICAL_PERCENT:
        raise CoverageError("coverage policy critical threshold must be 100")
    categories = policy.get("required_categories")
    if not isinstance(categories, list) or set(categories) != REQUIRED_CATEGORIES:
        raise CoverageError("coverage policy required categories are stale")
    if categories != sorted(categories) or len(categories) != len(set(categories)):
        raise CoverageError("coverage policy categories must be sorted and unique")
    validate_source_inventory(
        root,
        policy.get("reviewed_source_files"),
        policy.get("reviewed_source_sha256"),
    )

    raw_regions = policy.get("region")
    if not isinstance(raw_regions, list) or not raw_regions:
        raise CoverageError("coverage policy has no reviewed regions")
    regions: list[dict[str, object]] = []
    region_ids: set[str] = set()
    active_categories: set[str] = set()
    for index, raw_region in enumerate(raw_regions):
        if not isinstance(raw_region, dict) or set(raw_region) != REGION_FIELDS:
            raise CoverageError(f"coverage region {index} has invalid fields")
        identifier = raw_region.get("id")
        if not isinstance(identifier, str) or REGION_ID_RE.fullmatch(identifier) is None:
            raise CoverageError(f"coverage region {index} has an invalid ID")
        if identifier in region_ids:
            raise CoverageError(f"duplicate coverage region ID: {identifier}")
        region_ids.add(identifier)
        category = raw_region.get("category")
        if not isinstance(category, str) or category not in REQUIRED_CATEGORIES:
            raise CoverageError(f"coverage region {identifier} has an invalid category")
        active_categories.add(category)
        source_path = raw_region.get("file")
        if not isinstance(source_path, str) or SOURCE_PATH_RE.fullmatch(source_path) is None:
            raise CoverageError(f"coverage region {identifier} has an invalid source path")
        path_parts = source_path.split("/")
        if any(part in {"", ".", ".."} for part in path_parts):
            raise CoverageError(f"coverage region {identifier} has an invalid source path")
        path = root.joinpath(*path_parts)
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise CoverageError(
                f"coverage region {identifier} source cannot be read: {error}"
            ) from error
        source_root = (root / "crates").resolve(strict=True)
        if not resolved.is_relative_to(source_root) or not resolved.is_file():
            raise CoverageError(f"coverage region {identifier} has an invalid source path")
        cursor = root
        for part in path_parts:
            cursor /= part
            if cursor.is_symlink():
                raise CoverageError(
                    f"coverage region {identifier} source path may not traverse a symbolic link"
                )
        source = resolved.read_bytes()
        source_hash = raw_region.get("source_sha256")
        if not isinstance(source_hash, str) or SHA256_RE.fullmatch(source_hash) is None:
            raise CoverageError(f"coverage region {identifier} has an invalid source hash")
        if hashlib.sha256(source).hexdigest() != source_hash:
            raise CoverageError(f"coverage region {identifier} has a stale source hash")
        start_line = raw_region.get("start_line")
        end_line = raw_region.get("end_line")
        line_count = len(source.splitlines())
        if (
            type(start_line) is not int
            or type(end_line) is not int
            or not 1 <= start_line <= end_line <= line_count
        ):
            raise CoverageError(f"coverage region {identifier} has invalid line bounds")
        if raw_region.get("metric") not in {"branches", "regions"}:
            raise CoverageError(f"coverage region {identifier} has an invalid metric")
        reason = raw_region.get("reason")
        if not isinstance(reason, str) or not 1 <= len(reason) <= 512:
            raise CoverageError(f"coverage region {identifier} has an invalid reason")
        regions.append(raw_region)

    states = task_states(root)
    raw_deferred = policy.get("deferred")
    if not isinstance(raw_deferred, list):
        raise CoverageError("coverage policy deferred categories must be an array")
    deferred_categories: set[str] = set()
    for index, raw_deferment in enumerate(raw_deferred):
        if not isinstance(raw_deferment, dict) or set(raw_deferment) != DEFERRED_FIELDS:
            raise CoverageError(f"coverage deferment {index} has invalid fields")
        category = raw_deferment.get("category")
        if not isinstance(category, str) or category not in REQUIRED_CATEGORIES:
            raise CoverageError(f"coverage deferment {index} has an invalid category")
        if category in deferred_categories:
            raise CoverageError(f"duplicate coverage deferment: {category}")
        deferred_categories.add(category)
        until_task = raw_deferment.get("until_task")
        if not isinstance(until_task, str) or TASK_ID_RE.fullmatch(until_task) is None:
            raise CoverageError(f"coverage deferment {category} has an invalid task")
        if until_task not in states:
            raise CoverageError(f"coverage deferment {category} names an unknown task")
        if states[until_task]:
            raise CoverageError(
                f"coverage deferment {category} expired when {until_task} completed"
            )
        reason = raw_deferment.get("reason")
        if not isinstance(reason, str) or not 1 <= len(reason) <= 512:
            raise CoverageError(f"coverage deferment {category} has an invalid reason")

    overlap = active_categories & deferred_categories
    if overlap:
        raise CoverageError(
            "coverage categories cannot be active and deferred: " + ", ".join(sorted(overlap))
        )
    missing = REQUIRED_CATEGORIES - active_categories - deferred_categories
    if missing:
        raise CoverageError("coverage categories are unreviewed: " + ", ".join(sorted(missing)))
    return regions


def summary_counts(
    summary: dict[str, object],
    metric: str,
    *,
    allow_empty: bool,
) -> tuple[int, int, float]:
    """Return one closed, internally consistent coverage summary metric."""
    value = summary.get(metric)
    if not isinstance(value, dict):
        raise CoverageError(f"coverage report has no {metric} summary")
    expected_fields = {"count", "covered", "percent"}
    if metric in UNCOVERED_METRICS:
        expected_fields.add("notcovered")
    if set(value) != expected_fields:
        raise CoverageError(f"coverage report has invalid {metric} summary fields")
    count = value.get("count")
    covered = value.get("covered")
    percent = value.get("percent")
    if type(count) is not int or count < 0 or (count == 0 and not allow_empty):
        raise CoverageError(f"coverage report has no measurable {metric}")
    if type(covered) is not int or not 0 <= covered <= count:
        raise CoverageError(f"coverage report has an invalid {metric} covered count")
    if type(percent) not in {int, float} or not 0.0 <= percent <= 100.0:
        raise CoverageError(f"coverage report has an invalid {metric} percentage")
    if metric in UNCOVERED_METRICS and value.get("notcovered") != count - covered:
        raise CoverageError(f"coverage report has inconsistent uncovered {metric} totals")
    expected = 100.0 * covered / count if count else 0.0
    if abs(float(percent) - expected) > 1e-6:
        raise CoverageError(f"coverage report has inconsistent {metric} summary")
    return count, covered, float(percent)


def percentage(totals: dict[str, object], metric: str) -> float:
    """Return one nonempty, internally consistent coverage percentage."""
    return summary_counts(totals, metric, allow_empty=False)[2]


def validate_file_summaries(
    files: list[object],
    totals: dict[str, object],
) -> None:
    """Reconcile every closed file summary with the merged report totals."""
    aggregate = {metric: [0, 0] for metric in SUMMARY_METRICS}
    filenames: set[str] = set()
    for index, raw_file in enumerate(files):
        if not isinstance(raw_file, dict) or set(raw_file) != FILE_FIELDS:
            raise CoverageError(f"coverage file {index} has invalid detailed fields")
        filename = raw_file.get("filename")
        if not isinstance(filename, str) or not filename:
            raise CoverageError(f"coverage file {index} has an invalid filename")
        if filename in filenames:
            raise CoverageError(f"coverage report contains duplicate file {filename}")
        filenames.add(filename)
        for field in ("branches", "mcdc_records", "expansions", "segments"):
            if not isinstance(raw_file.get(field), list):
                raise CoverageError(f"coverage file {filename} has invalid {field}")
        summary = raw_file.get("summary")
        if not isinstance(summary, dict) or set(summary) != SUMMARY_METRICS:
            raise CoverageError(f"coverage file {filename} has invalid summary fields")
        for metric in SUMMARY_METRICS:
            count, covered, _percent = summary_counts(summary, metric, allow_empty=True)
            aggregate[metric][0] += count
            aggregate[metric][1] += covered

    for metric in SUMMARY_METRICS:
        count, covered, _percent = summary_counts(totals, metric, allow_empty=True)
        if aggregate[metric] != [count, covered]:
            raise CoverageError(
                f"coverage report merged {metric} totals do not equal its file summaries"
            )


def report_file(
    files: list[object],
    source_path: str,
) -> dict[str, object]:
    """Find one report file by its repository-relative suffix."""
    suffix = "/" + source_path
    matches = [
        item
        for item in files
        if isinstance(item, dict)
        and isinstance(item.get("filename"), str)
        and (item["filename"] == source_path or item["filename"].endswith(suffix))
    ]
    if len(matches) != 1:
        raise CoverageError(
            f"coverage report has {len(matches)} matches for reviewed file {source_path}"
        )
    return matches[0]


def branch_counts(
    file_record: dict[str, object],
    start_line: int,
    end_line: int,
) -> tuple[int, int]:
    """Count covered outcomes for branch records starting in one line range."""
    raw_branches = file_record.get("branches")
    if not isinstance(raw_branches, list):
        raise CoverageError("detailed coverage file has no branch records")
    coordinates: dict[tuple[int, int, int, int], list[int]] = {}
    for branch in raw_branches:
        if not isinstance(branch, list) or len(branch) != 9:
            raise CoverageError("coverage report contains a malformed branch record")
        if not all(type(value) is int and value >= 0 for value in branch):
            raise CoverageError("coverage report contains invalid branch counts")
        line, column, branch_end_line, end_column, true_count, false_count = branch[:6]
        if (
            line < 1
            or column < 1
            or branch_end_line < line
            or end_column < 1
            or branch[8] != 4
        ):
            raise CoverageError("coverage report contains invalid branch counts")
        if start_line <= line <= end_line:
            counts = coordinates.setdefault(
                (line, column, branch_end_line, end_column),
                [0, 0],
            )
            counts[0] += true_count
            counts[1] += false_count
    total = 2 * len(coordinates)
    covered = sum(int(count > 0) for counts in coordinates.values() for count in counts)
    return covered, total


def region_counts(
    file_record: dict[str, object],
    start_line: int,
    end_line: int,
) -> tuple[int, int]:
    """Count covered executable region entries in one line range."""
    raw_segments = file_record.get("segments")
    if not isinstance(raw_segments, list):
        raise CoverageError("detailed coverage file has no segment records")
    total = 0
    covered = 0
    for segment in raw_segments:
        if not isinstance(segment, list) or len(segment) != 6:
            raise CoverageError("coverage report contains a malformed segment record")
        line, column, count, has_count, is_entry, is_gap = (
            segment[0],
            segment[1],
            segment[2],
            segment[3],
            segment[4],
            segment[5],
        )
        if (
            type(line) is not int
            or line < 1
            or type(column) is not int
            or column < 1
            or type(count) is not int
            or count < 0
        ):
            raise CoverageError("coverage report contains invalid segment counts")
        if not all(isinstance(value, bool) for value in (has_count, is_entry, is_gap)):
            raise CoverageError("coverage report contains invalid segment flags")
        if start_line <= line <= end_line and has_count and is_entry and not is_gap:
            total += 1
            covered += int(count > 0)
    return covered, total


def validate_report(
    report: dict[str, object],
    regions: list[dict[str, object]],
) -> tuple[float, float, int]:
    """Validate one detailed report against all reviewed regions."""
    if set(report) != {"cargo_llvm_cov", "data", "type", "version"}:
        raise CoverageError("coverage report has an invalid top-level schema")
    if report.get("type") != LLVM_COVERAGE_EXPORT_TYPE:
        raise CoverageError("coverage report has an invalid export type")
    if report.get("version") != LLVM_COVERAGE_EXPORT_VERSION:
        raise CoverageError("coverage report has an unsupported export version")
    tool = report.get("cargo_llvm_cov")
    if not isinstance(tool, dict) or tool.get("version") != CARGO_LLVM_COV_VERSION:
        raise CoverageError("coverage report came from an unpinned cargo-llvm-cov version")
    data = report.get("data")
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise CoverageError("coverage report must contain exactly one merged data set")
    data_set = data[0]
    if set(data_set) != {"files", "functions", "totals"}:
        raise CoverageError("coverage report is not a detailed llvm-cov export")
    files = data_set.get("files")
    functions = data_set.get("functions")
    totals = data_set.get("totals")
    if not isinstance(files, list) or not files:
        raise CoverageError("detailed coverage report has no files")
    if not isinstance(functions, list):
        raise CoverageError("detailed coverage report has no functions")
    if not isinstance(totals, dict):
        raise CoverageError("coverage report has no totals")
    if set(totals) != {
        "branches",
        "functions",
        "instantiations",
        "lines",
        "mcdc",
        "regions",
    }:
        raise CoverageError("coverage report has invalid merged total fields")
    validate_file_summaries(files, totals)
    branch_percent = percentage(totals, "branches")
    line_percent = percentage(totals, "lines")
    failures: list[str] = []
    if branch_percent < MINIMUM_PERCENT:
        failures.append(
            f"branch coverage {branch_percent:.2f}% is below {MINIMUM_PERCENT:.2f}%"
        )
    if line_percent < MINIMUM_PERCENT:
        failures.append(
            f"line coverage {line_percent:.2f}% is below {MINIMUM_PERCENT:.2f}%"
        )

    for region in regions:
        identifier = str(region["id"])
        file_record = report_file(files, str(region["file"]))
        start_line = int(region["start_line"])
        end_line = int(region["end_line"])
        if region["metric"] == "branches":
            covered, total = branch_counts(file_record, start_line, end_line)
        else:
            covered, total = region_counts(file_record, start_line, end_line)
        if total == 0:
            failures.append(
                f"critical region {identifier} ({region['file']}:{start_line}-{end_line}) "
                "matched no executable coverage data"
            )
        elif covered != total:
            percent = 100.0 * covered / total
            failures.append(
                f"critical region {identifier} ({region['file']}:{start_line}-{end_line}) "
                f"is {covered}/{total} ({percent:.2f}%), below {CRITICAL_PERCENT:.2f}%"
            )
    if failures:
        raise CoverageError("; ".join(failures))
    return branch_percent, line_percent, len(regions)


def load_report(path: Path) -> dict[str, object]:
    """Load one llvm-cov JSON object without ambiguous duplicate keys."""
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise CoverageError(f"coverage report contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        report = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=object_pairs,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise CoverageError(f"cannot read coverage report: {error}") from error
    if not isinstance(report, dict):
        raise CoverageError("coverage report must be a JSON object")
    return report


def validate(root: Path, report_path: Path, policy_path: Path) -> tuple[float, float, int]:
    """Validate the reviewed policy and one detailed llvm-cov report."""
    regions = validate_policy_data(root, load_policy(policy_path))
    return validate_report(load_report(report_path), regions)


def expect_rejection(label: str, action: object, fragment: str) -> None:
    """Require one seeded mutation to reach its intended rejection branch."""
    if not callable(action):
        raise CoverageError(f"self-test {label!r} is not callable")
    try:
        action()
    except CoverageError as error:
        if fragment not in str(error):
            raise CoverageError(f"self-test {label!r} reached the wrong branch: {error}") from error
        return
    raise CoverageError(f"self-test {label!r} was accepted")


def self_test(root: Path, policy_path: Path) -> int:
    """Exercise policy and report rejection paths."""
    policy = load_policy(policy_path)
    regions = validate_policy_data(root, policy)
    cases = 0

    with tempfile.TemporaryDirectory(prefix="agenc-coverage-json-") as temporary:
        duplicate_json = Path(temporary) / "duplicate.json"
        duplicate_json.write_text('{"type":"first","type":"second"}\n', encoding="utf-8")
        expect_rejection(
            "duplicate report key",
            lambda: load_report(duplicate_json),
            "duplicate JSON key",
        )
        cases += 1

    boolean_schema = copy.deepcopy(policy)
    boolean_schema["schema_version"] = True
    expect_rejection(
        "boolean policy schema",
        lambda: validate_policy_data(root, boolean_schema),
        "schema_version must be 1",
    )
    cases += 1

    path_traversal = copy.deepcopy(policy)
    path_traversal["region"][0]["file"] = (  # type: ignore[index]
        "crates/agenc-ircd-client-wire/src/../../agenc-ircd-domain/src/decision.rs"
    )
    expect_rejection(
        "policy path traversal",
        lambda: validate_policy_data(root, path_traversal),
        "invalid source path",
    )
    cases += 1

    stale_hash = copy.deepcopy(policy)
    stale_hash["region"][0]["source_sha256"] = "0" * 64  # type: ignore[index]
    expect_rejection(
        "stale policy source",
        lambda: validate_policy_data(root, stale_hash),
        "stale source hash",
    )
    cases += 1
    stale_inventory = copy.deepcopy(policy)
    stale_inventory["reviewed_source_sha256"] = "0" * 64
    expect_rejection(
        "stale production source inventory",
        lambda: validate_policy_data(root, stale_inventory),
        "production source inventory is stale",
    )
    cases += 1
    with tempfile.TemporaryDirectory(prefix="agenc-coverage-inventory-") as temporary:
        temporary_root = Path(temporary)
        first_source = temporary_root / "crates/example/src/lib.rs"
        first_source.parent.mkdir(parents=True)
        first_source.write_text("pub fn first() {}\n", encoding="utf-8")
        inventory_count, inventory_hash = production_source_inventory(temporary_root)
        validate_source_inventory(temporary_root, inventory_count, inventory_hash)
        (first_source.parent / "new_critical.rs").write_text(
            "pub fn newly_added_critical_branch() {}\n",
            encoding="utf-8",
        )
        expect_rejection(
            "new unreviewed production source",
            lambda: validate_source_inventory(
                temporary_root,
                inventory_count,
                inventory_hash,
            ),
            "production source inventory is stale",
        )
        cases += 1
    duplicate_region = copy.deepcopy(policy)
    duplicate_region["region"].append(  # type: ignore[union-attr,index]
        copy.deepcopy(duplicate_region["region"][0])
    )
    expect_rejection(
        "duplicate policy region",
        lambda: validate_policy_data(root, duplicate_region),
        "duplicate coverage region ID",
    )
    cases += 1
    expired = copy.deepcopy(policy)
    expired["deferred"][0]["until_task"] = "S04-014"  # type: ignore[index]
    expect_rejection(
        "expired category deferment",
        lambda: validate_policy_data(root, expired),
        "expired",
    )
    cases += 1
    missing_category = copy.deepcopy(policy)
    missing_category["required_categories"].pop()  # type: ignore[union-attr]
    expect_rejection(
        "missing required category",
        lambda: validate_policy_data(root, missing_category),
        "required categories are stale",
    )
    cases += 1

    region = regions[0]
    source_path = str(region["file"])
    synthetic_region = {
        "id": "synthetic-critical-region",
        "file": source_path,
        "start_line": 2,
        "end_line": 2,
        "metric": "branches",
    }
    report: dict[str, object] = {
        "cargo_llvm_cov": {"version": CARGO_LLVM_COV_VERSION},
        "type": LLVM_COVERAGE_EXPORT_TYPE,
        "version": LLVM_COVERAGE_EXPORT_VERSION,
        "data": [
            {
                "files": [
                    {
                        "filename": f"/workspace/{source_path}",
                        "branches": [[2, 1, 2, 2, 1, 1, 0, 0, 4]],
                        "mcdc_records": [],
                        "expansions": [],
                        "segments": [[2, 1, 1, True, True, False]],
                        "summary": {
                            "branches": {
                                "count": 2,
                                "covered": 2,
                                "notcovered": 0,
                                "percent": 100.0,
                            },
                            "functions": {"count": 0, "covered": 0, "percent": 0.0},
                            "instantiations": {
                                "count": 0,
                                "covered": 0,
                                "percent": 0.0,
                            },
                            "lines": {"count": 1, "covered": 1, "percent": 100.0},
                            "mcdc": {
                                "count": 0,
                                "covered": 0,
                                "notcovered": 0,
                                "percent": 0.0,
                            },
                            "regions": {
                                "count": 1,
                                "covered": 1,
                                "notcovered": 0,
                                "percent": 100.0,
                            },
                        },
                    }
                ],
                "functions": [],
                "totals": {
                    "branches": {
                        "count": 2,
                        "covered": 2,
                        "notcovered": 0,
                        "percent": 100.0,
                    },
                    "functions": {"count": 0, "covered": 0, "percent": 0.0},
                    "instantiations": {"count": 0, "covered": 0, "percent": 0.0},
                    "lines": {"count": 1, "covered": 1, "percent": 100.0},
                    "mcdc": {
                        "count": 0,
                        "covered": 0,
                        "notcovered": 0,
                        "percent": 0.0,
                    },
                    "regions": {
                        "count": 1,
                        "covered": 1,
                        "notcovered": 0,
                        "percent": 100.0,
                    },
                },
            }
        ],
    }
    validate_report(report, [synthetic_region])

    duplicate_instantiation = copy.deepcopy(report)
    duplicate_instantiation["data"][0]["files"][0]["branches"].append(  # type: ignore[index]
        [2, 1, 2, 2, 0, 0, 1, 0, 4]
    )
    validate_report(duplicate_instantiation, [synthetic_region])

    outside_range = copy.deepcopy(report)
    outside_range["data"][0]["files"][0]["branches"].append(  # type: ignore[index]
        [3, 1, 3, 2, 0, 0, 0, 0, 4]
    )
    validate_report(outside_range, [synthetic_region])

    wrong_export = copy.deepcopy(report)
    wrong_export["version"] = "unknown"
    expect_rejection(
        "unsupported export schema",
        lambda: validate_report(wrong_export, [synthetic_region]),
        "unsupported export version",
    )
    cases += 1

    summary_only = copy.deepcopy(report)
    summary_only["data"][0].pop("functions")  # type: ignore[index,union-attr]
    expect_rejection(
        "summary-only report",
        lambda: validate_report(summary_only, [synthetic_region]),
        "not a detailed",
    )
    cases += 1
    low_overall = copy.deepcopy(report)
    low_overall["data"][0]["totals"]["branches"] = {  # type: ignore[index]
        "count": 10,
        "covered": 8,
        "notcovered": 2,
        "percent": 80.0,
    }
    low_overall["data"][0]["files"][0]["summary"]["branches"] = {  # type: ignore[index]
        "count": 10,
        "covered": 8,
        "notcovered": 2,
        "percent": 80.0,
    }
    expect_rejection(
        "low overall coverage",
        lambda: validate_report(low_overall, [synthetic_region]),
        "branch coverage",
    )
    cases += 1
    forged_total = copy.deepcopy(report)
    forged_total["data"][0]["totals"]["branches"] = {  # type: ignore[index]
        "count": 10,
        "covered": 10,
        "notcovered": 0,
        "percent": 100.0,
    }
    expect_rejection(
        "forged aggregate totals",
        lambda: validate_report(forged_total, [synthetic_region]),
        "do not equal its file summaries",
    )
    cases += 1
    uncovered_branch = copy.deepcopy(report)
    uncovered_branch["data"][0]["files"][0]["branches"][0][5] = 0  # type: ignore[index]
    expect_rejection(
        "uncovered critical branch",
        lambda: validate_report(uncovered_branch, [synthetic_region]),
        "below 100.00%",
    )
    cases += 1
    region_metric = dict(synthetic_region)
    region_metric["metric"] = "regions"
    uncovered_region = copy.deepcopy(report)
    uncovered_region["data"][0]["files"][0]["segments"][0][2] = 0  # type: ignore[index]
    expect_rejection(
        "uncovered critical region",
        lambda: validate_report(uncovered_region, [region_metric]),
        "below 100.00%",
    )
    cases += 1
    empty_range = dict(synthetic_region)
    empty_range["start_line"] = 3
    empty_range["end_line"] = 3
    expect_rejection(
        "empty critical range",
        lambda: validate_report(report, [empty_range]),
        "matched no executable",
    )
    cases += 1
    missing_file = dict(synthetic_region)
    missing_file["file"] = "crates/missing/src/lib.rs"
    expect_rejection(
        "missing critical file",
        lambda: validate_report(report, [missing_file]),
        "0 matches",
    )
    cases += 1
    malformed_branch = copy.deepcopy(report)
    malformed_branch["data"][0]["files"][0]["branches"] = [[2]]  # type: ignore[index]
    expect_rejection(
        "malformed branch record",
        lambda: validate_report(malformed_branch, [synthetic_region]),
        "malformed branch",
    )
    cases += 1
    malformed_segment = copy.deepcopy(report)
    malformed_segment["data"][0]["files"][0]["segments"] = [[2]]  # type: ignore[index]
    expect_rejection(
        "malformed segment record",
        lambda: validate_report(malformed_segment, [region_metric]),
        "malformed segment",
    )
    cases += 1
    inconsistent_uncovered = copy.deepcopy(report)
    inconsistent_uncovered["data"][0]["totals"]["branches"]["notcovered"] = 1  # type: ignore[index]
    expect_rejection(
        "inconsistent uncovered total",
        lambda: validate_report(inconsistent_uncovered, [synthetic_region]),
        "inconsistent uncovered branches",
    )
    cases += 1
    unpinned = copy.deepcopy(report)
    unpinned["cargo_llvm_cov"]["version"] = "latest"  # type: ignore[index]
    expect_rejection(
        "unpinned coverage tool",
        lambda: validate_report(unpinned, [synthetic_region]),
        "unpinned",
    )
    cases += 1
    return cases


def fail(message: str) -> NoReturn:
    """Print a stable command-line error and exit unsuccessfully."""
    print(f"coverage check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Dispatch coverage validation and negative self-tests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    parser.add_argument("report_or_policy", type=Path)
    parser.add_argument("policy", nargs="?", type=Path)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "check":
            if arguments.policy is None:
                raise CoverageError("check requires a detailed report and a policy")
            branch_percent, line_percent, region_count = validate(
                root,
                arguments.report_or_policy,
                arguments.policy,
            )
            print(
                "coverage threshold: ok "
                f"(branches {branch_percent:.2f}%, lines {line_percent:.2f}%, "
                f"{region_count} critical regions at 100%)"
            )
        else:
            if arguments.policy is not None:
                raise CoverageError("self-test accepts only the policy path")
            cases = self_test(root, arguments.report_or_policy)
            print(f"coverage self-test: ok ({cases} rejection cases)")
    except (CoverageError, OSError, UnicodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
