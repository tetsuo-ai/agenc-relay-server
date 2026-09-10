#!/usr/bin/env python3
"""Run the capacity demonstration or the seven-day sustained-operation campaign."""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from release_qualification.daemon_tests import DaemonTests
from release_qualification.driver import context, finish
from release_qualification.policy import load_policy
from release_qualification.process import execute
from release_qualification.records import QualificationError, canonical, read_record, require_integer, write_once

CAMPAIGN_TEST = "stage_ten_capacity::sustained_operation_campaign"
CAPACITY_SECONDS = 300
CAPACITY_CONNECTIONS = 64
SOAK_CONNECTIONS = 256
LATENCY_CLASSES = ["admission", "durable_mutation", "fanout", "message", "opaque", "snapshot"]
SCENARIOS = ["reconnect", "churn", "rekey", "index_transition", "snapshot", "backup", "disk_pressure", "peer_loss"]
MAX_SAMPLES = 10**7
RESOURCE_SOURCES = ("cgroup", "procfs")
SAMPLE_TRIPLES = ("anonymous_bytes", "sockets", "close_wait", "tasks")
DELEGATED_SCOPE = ["systemd-run", "--user", "--scope", "--quiet", "-p", "Delegate=yes", "--"]


def delegated_scope_wrapper(root: Path, evidence: Path) -> list[str]:
    """The launcher that runs the engine alone in a delegated cgroup, or nothing.

    The daemon is non-dumpable, so the engine samples memory and tasks from a
    cgroup leaf per daemon; without a delegated cgroup it falls back to procfs
    and fails where the host hides the daemon's entry.
    """
    if shutil.which("systemd-run") is None:
        return []
    probe = execute([*DELEGATED_SCOPE, "true"], root, dict(os.environ), evidence / "delegated-scope-probe.log", 60)
    return list(DELEGATED_SCOPE) if probe["exit_code"] == 0 and probe["failure"] is None else []


def validate_samples(samples: list[Any], connections: int, elapsed_ns: int) -> int:
    live = 0
    previous_ns = -1
    for sample in samples:
        if not isinstance(sample, dict) or type(sample.get("at_ns")) is not int:
            raise QualificationError("campaign sample has an unknown shape")
        require_integer(sample["at_ns"], previous_ns + 1, elapsed_ns, "campaign sample time")
        previous_ns = sample["at_ns"]
        for name in SAMPLE_TRIPLES:
            values = sample.get(name)
            if not isinstance(values, list) or len(values) != 3 or any(type(value) is not int or value < 0 for value in values):
                raise QualificationError(f"campaign sample lacks a {name} triple")
        if any(sample["anonymous_bytes"][index] == 0 for index in range(3)):
            raise QualificationError("campaign sample recorded zero anonymous memory for a daemon")
        if any(sample["tasks"][index] == 0 for index in range(3)):
            raise QualificationError("campaign sample recorded zero tasks for a daemon")
        require_integer(sample.get("live_client_connections"), 0, 750_000, "live client connections")
        live = max(live, sample["live_client_connections"])
    if live < connections:
        raise QualificationError("campaign never held the configured connection count")
    return live


def validate_campaign(report: dict[str, Any], minimum_seconds: int, connections: int) -> dict[str, Any]:
    """Check the engine's record against the Section 28.7 requirements before attesting."""
    if report.get("schema_version") != 1 or type(report.get("elapsed_ns")) is not int:
        raise QualificationError("campaign record has an unknown schema")
    if report.get("resource_source") not in RESOURCE_SOURCES:
        raise QualificationError("campaign record does not name its resource source")
    if report["elapsed_ns"] < minimum_seconds * 10**9:
        raise QualificationError("campaign ran shorter than its required duration")
    require_integer(report.get("connections"), 4, 250_000, "configured connections")
    if report.get("connections") != connections:
        raise QualificationError("campaign ran with a different connection count")
    samples = report.get("samples")
    if not isinstance(samples, list) or len(samples) < 2 or len(samples) > MAX_SAMPLES:
        raise QualificationError("campaign record lacks resource samples")
    peak_live = validate_samples(samples, connections, report["elapsed_ns"])
    classes = report.get("latency_classes")
    if not isinstance(classes, dict) or sorted(classes) != LATENCY_CLASSES:
        raise QualificationError("campaign record omits a latency class")
    for name, values in classes.items():
        if not isinstance(values, dict) or type(values.get("count")) is not int or values["count"] < 1:
            raise QualificationError(f"latency class {name} has no samples")
        previous = 0
        for key in ("p50_ns", "p95_ns", "p99_ns"):
            require_integer(values.get(key), previous, report["elapsed_ns"], f"{name} {key}")
            previous = values[key]
    counts = report.get("scenario_counts")
    if not isinstance(counts, dict) or sorted(counts) != sorted(SCENARIOS):
        raise QualificationError("campaign record omits a scenario")
    for scenario in SCENARIOS:
        if type(counts[scenario]) is not int or counts[scenario] < 1:
            raise QualificationError(f"scenario {scenario} did not run")
    for field in ("missed_events", "envelope_violations", "population_shortfalls", "sample_failures"):
        require_integer(report.get(field), 0, 0, field)
    for field in ("messages_sent", "messages_received", "messages_refused"):
        if type(report.get(field)) is not int or report[field] < 0:
            raise QualificationError(f"campaign record lacks an integer {field}")
    if report["messages_received"] == 0:
        raise QualificationError("campaign observed no channel fanout")
    if report.get("returned_to_envelope") is not True:
        raise QualificationError("resources did not return to the warm envelope")
    stopped = report.get("daemons_stopped_cleanly")
    if not isinstance(stopped, list) or len(stopped) != 3 or any(value is not True for value in stopped):
        raise QualificationError("a daemon did not stop cleanly")
    hardware = report.get("hardware")
    if not isinstance(hardware, str) or not hardware.strip():
        raise QualificationError("campaign record omits the hardware description")
    return {"elapsed_ns": report["elapsed_ns"], "samples": len(samples), "missed_events": 0, "envelope_violations": 0,
            "returned_to_envelope": True, "scenario_counts": {scenario: counts[scenario] for scenario in SCENARIOS},
            "latency_classes": LATENCY_CLASSES, "workload_demonstrated": True, "hardware": hardware.strip(),
            "connections": connections, "peak_live_connections": peak_live,
            "resource_source": report["resource_source"], "messages_refused": report["messages_refused"]}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("capacity", "soak"):
        raise QualificationError("usage: qualify-stage-ten-capacity.py capacity|soak")
    mode = sys.argv[1]
    root = Path(__file__).resolve().parent.parent
    candidate, directory, attempt, target = context(root)
    policy = load_policy(root)
    seconds = CAPACITY_SECONDS if mode == "capacity" else int(policy["soak_elapsed_seconds"])
    connections = CAPACITY_CONNECTIONS if mode == "capacity" else SOAK_CONNECTIONS
    job_id = "capacity" if mode == "capacity" else "soak"
    tests = DaemonTests(root, directory, attempt, candidate, target)
    tests.compile(["stage_eight_e2ee"])
    campaign = attempt / "work/campaign"
    campaign.mkdir(mode=0o700, parents=True)
    wrapper = delegated_scope_wrapper(root, attempt / "evidence")
    started = time.monotonic_ns()
    tests.run(f"{mode}-campaign", "stage_eight_e2ee", CAMPAIGN_TEST, ignored=True,
              environment={"AGENC_STAGE10_CAMPAIGN_DIR": str(campaign), "AGENC_STAGE10_CAMPAIGN_SECONDS": str(seconds),
                           "AGENC_STAGE10_CAMPAIGN_CONNECTIONS": str(connections)},
              timeout=seconds + 3600, wrapper=wrapper)
    elapsed_ns = time.monotonic_ns() - started
    report = read_record(campaign / "campaign.json")
    if report.get("elapsed_ns", 0) > elapsed_ns:
        raise QualificationError("campaign record claims more time than the driver measured")
    facts = validate_campaign(report, seconds, connections)
    facts["elapsed_ns"] = min(facts["elapsed_ns"], elapsed_ns)
    for name in ("campaign.json", "worker-errors.log"):
        shutil.copyfile(campaign / name, attempt / "evidence" / f"{mode}-{name}")
    write_once(attempt / "evidence" / f"{mode}-driver.json", canonical({"driver_elapsed_ns": elapsed_ns, "seconds": seconds,
                                                                        "connections": connections, "mode": mode, "wrapper": wrapper}))
    finish(attempt, job_id, facts)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (QualificationError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"capacity qualification: {error}", file=sys.stderr)
        sys.exit(1)
