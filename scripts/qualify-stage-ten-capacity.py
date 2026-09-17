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
# Nodes that admit campaign clients: the two edges. The coordinator is node 0
# of every per-node triple and admits no campaign client.
CLIENT_NODES = 2
# Section 19.2 default simultaneous client connections, PER NODE. Section 28.7
# requires the advertised configuration of a node, so the campaign population
# is that default on every client-admitting edge and the aggregate is its
# consequence. A population that only sums to the default across the nodes
# proves no node's advertised capacity.
CAPACITY_PER_NODE_CONNECTIONS = 50_000
CAPACITY_CONNECTIONS = CAPACITY_PER_NODE_CONNECTIONS * CLIENT_NODES
SOAK_CONNECTIONS = 256
SOAK_PER_NODE_CONNECTIONS = SOAK_CONNECTIONS // CLIENT_NODES
LATENCY_CLASSES = ["admission", "durable_mutation", "fanout", "message", "opaque", "snapshot"]
SCENARIOS = ["reconnect", "churn", "rekey", "index_transition", "snapshot", "backup", "disk_pressure", "peer_loss"]
MAX_SAMPLES = 10**7
# The Section 19.2 hard maximum client population, which also bounds every
# other counted quantity in a record.
MAX_CAMPAIGN_CONNECTIONS = 250_000
RESOURCE_SOURCES = ("cgroup", "procfs")
SAMPLE_TRIPLES = ("anonymous_bytes", "sockets", "close_wait", "tasks", "live_client_connections",
                  "memory_charged_bytes", "memory_budget_bytes")
DELEGATED_SCOPE = ["systemd-run", "--user", "--scope", "--quiet", "-p", "Delegate=yes", "--"]
WORKLOAD_FIELDS = {"profile", "qualifying", "per_node_connections", "total_connections", "load_channels",
                   "connections_per_address", "generator_addresses_per_node", "generator_subnets_per_node", "blockers"}
# The Section 19.2 startup arithmetic of the unchanged Appendix C defaults
# (B = 6 GiB, four crypto workers). A record that names any other value raised
# a ceiling or a reserve to pass and cannot support a default-configuration
# capacity claim.
DEFAULT_NODE_BUDGET = {"budget_bytes": 6_442_450_944, "headroom_bytes": 805_306_368,
                       "storage_handoff_bytes": 117_440_480, "crypto_pool_bytes": 301_989_888,
                       "protocol_pool_bytes": 5_217_714_208}
# Section 19.2 default members per channel and hard maximum connections per /32.
MEMBERS_PER_CHANNEL = 4_096
MAX_CONNECTIONS_PER_ADDRESS = 256
BLOCKER_NAMES = ("population_below_default", "idle_charges_exceed_pool", "overload_stops_admission",
                 "generator_address_space")
# What each mode's record must claim about the workload it ran. The seven-day
# soak deliberately runs the 256-client minimum, which is below the per-node
# default, so its capacity profile is below-default and it closes sustained
# operation rather than the capacity claim.
MODES = {
    "capacity": {"connections": CAPACITY_CONNECTIONS, "per_node": CAPACITY_PER_NODE_CONNECTIONS,
                 "profile": "production", "qualifying": True, "blockers": []},
    "soak": {"connections": SOAK_CONNECTIONS, "per_node": SOAK_PER_NODE_CONNECTIONS,
             "profile": "below-default", "qualifying": False, "blockers": ["population_below_default"]},
}


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


def validate_sample_budgets(sample: dict[str, Any]) -> None:
    """Require every node to have run the unchanged default live pool."""
    for index in range(3):
        require_integer(sample["live_client_connections"][index], 0, MAX_CAMPAIGN_CONNECTIONS, "live client connections")
        if sample["memory_budget_bytes"][index] != DEFAULT_NODE_BUDGET["protocol_pool_bytes"]:
            raise QualificationError("campaign node did not run the default live protocol pool")
        if sample["memory_charged_bytes"][index] > sample["memory_budget_bytes"][index]:
            raise QualificationError("campaign node charged more than its own live pool")


def validate_samples(samples: list[Any], connections: int, per_node: int, elapsed_ns: int) -> tuple[int, int]:
    """Return the peak aggregate population and the peak simultaneous per-node one."""
    live = 0
    per_node_live = 0
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
        validate_sample_budgets(sample)
        live = max(live, sum(sample["live_client_connections"]))
        # Node 0 is the coordinator; only the client-admitting edges count
        # towards the per-node requirement, and the smallest of them decides.
        per_node_live = max(per_node_live, min(sample["live_client_connections"][1:]))
    if live < connections:
        raise QualificationError("campaign never held the configured connection count")
    if per_node_live < per_node:
        raise QualificationError("no client-admitting node held the per-node population simultaneously; "
                                 "clients spread across nodes cannot substitute for a per-node limit")
    return live, per_node_live


def validate_workload(report: dict[str, Any], mode: dict[str, Any]) -> dict[str, Any]:
    """Check the selected workload matrix and the untouched node budget."""
    workload = report.get("workload")
    if not isinstance(workload, dict) or set(workload) != WORKLOAD_FIELDS:
        raise QualificationError("campaign record omits its workload matrix")
    if workload["profile"] != mode["profile"] or workload["qualifying"] is not mode["qualifying"]:
        raise QualificationError("campaign workload profile differs from the mode it ran")
    if workload["blockers"] != mode["blockers"]:
        raise QualificationError("campaign workload blockers differ from the mode's accepted set")
    if any(name not in BLOCKER_NAMES for name in workload["blockers"]):
        raise QualificationError("campaign workload names an unknown blocker")
    require_integer(workload["per_node_connections"], mode["per_node"], MAX_CAMPAIGN_CONNECTIONS, "per-node population")
    require_integer(workload["total_connections"], mode["connections"], MAX_CAMPAIGN_CONNECTIONS, "workload population")
    require_integer(workload["connections_per_address"], 1, MAX_CONNECTIONS_PER_ADDRESS, "connections per address")
    minimum_channels = -(-workload["total_connections"] // MEMBERS_PER_CHANNEL)
    require_integer(workload["load_channels"], minimum_channels, MAX_CAMPAIGN_CONNECTIONS, "load channels")
    minimum_addresses = -(-workload["per_node_connections"] // workload["connections_per_address"])
    require_integer(workload["generator_addresses_per_node"], minimum_addresses, MAX_CAMPAIGN_CONNECTIONS, "generator addresses")
    require_integer(workload["generator_subnets_per_node"], 1, MAX_CAMPAIGN_CONNECTIONS, "generator subnets")
    budget = report.get("node_budget")
    if not isinstance(budget, dict) or budget != DEFAULT_NODE_BUDGET:
        raise QualificationError("campaign record does not report the unchanged default node budget")
    return workload


def validate_campaign(report: dict[str, Any], minimum_seconds: int, mode: dict[str, Any]) -> dict[str, Any]:
    """Check the engine's record against the Section 28.7 requirements before attesting."""
    connections = mode["connections"]
    if report.get("schema_version") != 1 or type(report.get("elapsed_ns")) is not int:
        raise QualificationError("campaign record has an unknown schema")
    if report.get("resource_source") not in RESOURCE_SOURCES:
        raise QualificationError("campaign record does not name its resource source")
    if report["elapsed_ns"] < minimum_seconds * 10**9:
        raise QualificationError("campaign ran shorter than its required duration")
    require_integer(report.get("connections"), 4, MAX_CAMPAIGN_CONNECTIONS, "configured connections")
    if report.get("connections") != connections:
        raise QualificationError("campaign ran with a different connection count")
    workload = validate_workload(report, mode)
    samples = report.get("samples")
    if not isinstance(samples, list) or len(samples) < 2 or len(samples) > MAX_SAMPLES:
        raise QualificationError("campaign record lacks resource samples")
    peak_live, peak_node_live = validate_samples(samples, connections, mode["per_node"], report["elapsed_ns"])
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
            "per_node_connections": workload["per_node_connections"],
            "peak_node_live_connections": peak_node_live,
            "workload_profile": workload["profile"], "capacity_qualifying": workload["qualifying"],
            "node_budget": dict(DEFAULT_NODE_BUDGET),
            "resource_source": report["resource_source"], "messages_refused": report["messages_refused"]}


def pilot_verdict(report: dict[str, Any]) -> dict[str, Any]:
    """Summarize a development pilot's record without attesting anything.

    A pilot demonstrates that the harness runs and names the blockers between
    the population it ran and a production capacity claim. It closes no job,
    and a record that claims to qualify is refused here rather than mistaken
    for production evidence.
    """
    workload = report.get("workload")
    if not isinstance(workload, dict) or set(workload) != WORKLOAD_FIELDS:
        raise QualificationError("pilot record omits its workload matrix")
    blockers = workload["blockers"]
    if not isinstance(blockers, list) or any(name not in BLOCKER_NAMES for name in blockers):
        raise QualificationError("pilot record names an unknown blocker")
    if workload["qualifying"] is not False or workload["profile"] == "production" or not blockers:
        raise QualificationError("a development pilot may not claim a production capacity population")
    require_integer(workload["per_node_connections"], 1, MAX_CAMPAIGN_CONNECTIONS, "pilot per-node population")
    samples = report.get("samples")
    if not isinstance(samples, list) or not samples:
        raise QualificationError("pilot record lacks resource samples")
    peak = max(min(sample["live_client_connections"][1:]) for sample in samples)
    return {"profile": workload["profile"], "per_node_connections": workload["per_node_connections"],
            "peak_node_live_connections": peak, "blockers": list(blockers),
            "production_per_node_connections": CAPACITY_PER_NODE_CONNECTIONS, "qualifying": False}


def report_pilot(path: Path) -> int:
    """Print a development pilot's verdict; it closes no qualification job."""
    verdict = pilot_verdict(read_record(path))
    print(canonical(verdict).decode("utf-8"))
    print(f"development pilot: {verdict['per_node_connections']} clients per node against a required "
          f"{verdict['production_per_node_connections']}; blockers: {', '.join(verdict['blockers'])}", file=sys.stderr)
    return 0


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "pilot":
        return report_pilot(Path(sys.argv[2]))
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        raise QualificationError("usage: qualify-stage-ten-capacity.py capacity|soak|pilot <campaign.json>")
    name = sys.argv[1]
    mode = MODES[name]
    root = Path(__file__).resolve().parent.parent
    candidate, directory, attempt, target = context(root)
    policy = load_policy(root)
    seconds = CAPACITY_SECONDS if name == "capacity" else int(policy["soak_elapsed_seconds"])
    connections = mode["connections"]
    job_id = name
    tests = DaemonTests(root, directory, attempt, candidate, target)
    tests.compile(["stage_eight_e2ee"])
    campaign = attempt / "work/campaign"
    campaign.mkdir(mode=0o700, parents=True)
    wrapper = delegated_scope_wrapper(root, attempt / "evidence")
    started = time.monotonic_ns()
    tests.run(f"{name}-campaign", "stage_eight_e2ee", CAMPAIGN_TEST, ignored=True,
              environment={"AGENC_STAGE10_CAMPAIGN_DIR": str(campaign), "AGENC_STAGE10_CAMPAIGN_SECONDS": str(seconds),
                           "AGENC_STAGE10_CAMPAIGN_CONNECTIONS": str(connections)},
              timeout=seconds + 3600, wrapper=wrapper)
    elapsed_ns = time.monotonic_ns() - started
    report = read_record(campaign / "campaign.json")
    if report.get("elapsed_ns", 0) > elapsed_ns:
        raise QualificationError("campaign record claims more time than the driver measured")
    facts = validate_campaign(report, seconds, mode)
    facts["elapsed_ns"] = min(facts["elapsed_ns"], elapsed_ns)
    for artifact in ("campaign.json", "worker-errors.log"):
        shutil.copyfile(campaign / artifact, attempt / "evidence" / f"{name}-{artifact}")
    write_once(attempt / "evidence" / f"{name}-driver.json",
               canonical({"driver_elapsed_ns": elapsed_ns, "seconds": seconds, "connections": connections,
                          "per_node_connections": mode["per_node"], "mode": name, "wrapper": wrapper}))
    finish(attempt, job_id, facts)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (QualificationError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"capacity qualification: {error}", file=sys.stderr)
        sys.exit(1)
