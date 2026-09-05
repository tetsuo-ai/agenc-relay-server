#!/usr/bin/env python3
"""Regression tests for immutable evidence, hostile input, and child supervision."""

from __future__ import annotations

import copy
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from release_qualification.build import immutable_image, release_archive
from release_qualification.decision import verify_signature
from release_qualification.signing import DOMAIN
from release_qualification.locks import exclusive
from release_qualification.policy import fuzz_jobs, load_policy
from release_qualification.process import execute
from release_qualification.records import (QualificationError, canonical, digest, file_digest, read_bytes,
                                           read_record, require_integer, safe_path, timestamp, write_once)
from release_qualification.verify import verify_report


class RecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="agenc-release-test-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_records_cannot_replace_previous_evidence(self) -> None:
        path = self.root / "one/result.json"
        write_once(path, canonical({"outcome": "failed"}))
        with self.assertRaises(QualificationError):
            write_once(path, canonical({"outcome": "passed"}))
        self.assertEqual(read_record(path), {"outcome": "failed"})

    def test_json_rejects_duplicates_nonfinite_values_and_nonobjects(self) -> None:
        for index, value in enumerate((b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}', b'{"a":-1e999}', b'[]', b'null', b'{"a":')):
            path = self.root / str(index)
            path.write_bytes(value)
            with self.subTest(value=value), self.assertRaises(QualificationError):
                read_record(path)

    def test_reads_reject_symlinks_fifos_and_excessive_bytes(self) -> None:
        regular = self.root / "regular"
        regular.write_bytes(b"abc")
        link = self.root / "link"
        link.symlink_to(regular)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (link, fifo):
            with self.subTest(path=path), self.assertRaises(QualificationError):
                read_bytes(path)
            with self.assertRaises(QualificationError):
                file_digest(path)
        with self.assertRaises(QualificationError):
            read_bytes(regular, 2)

    def test_artifact_paths_reject_traversal_and_intermediate_links(self) -> None:
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        for value in ("../outside", "/etc/passwd", "a//b", "a/./b", "a/../b", "a\\b", "link/child", ""):
            with self.subTest(value=value), self.assertRaises(QualificationError):
                safe_path(self.root, value)

    def test_numeric_measurements_reject_booleans_and_negative_values(self) -> None:
        for value in (True, False, -1, 1.0, "1", 101):
            with self.subTest(value=value), self.assertRaises(QualificationError):
                require_integer(value, 0, 100, "measurement")

    def test_timestamps_reject_ambiguous_or_non_utc_spellings(self) -> None:
        for value in ("20260905T120000Z", "2026-09-05 12:00:00Z", "2026-09-05T12:00:00+00:00", "2026-09-05T25:00:00Z", None):
            with self.subTest(value=value), self.assertRaises(QualificationError):
                timestamp(value)
        self.assertEqual(timestamp("2026-09-05T12:00:00Z").hour, 12)

    def test_log_capture_joins_descendants_after_the_leader_exits(self) -> None:
        script = "import subprocess,sys\nsubprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
        result = execute([sys.executable, "-c", script], self.root, dict(os.environ), self.root / "descendant.log", 2)
        self.assertEqual(result["exit_code"], 0)
        self.assertLess(result["elapsed_ns"], 2 * 10**9)

    def test_only_one_runner_can_hold_a_candidate(self) -> None:
        with exclusive(self.root):
            with self.assertRaises(QualificationError):
                with exclusive(self.root):
                    self.fail("second runner acquired the candidate")
        with exclusive(self.root):
            pass

    def test_release_archives_are_byte_reproducible(self) -> None:
        first = release_archive(b"binary", "agenc-ircd", 1234567890)
        self.assertEqual(first, release_archive(b"binary", "agenc-ircd", 1234567890))
        self.assertNotEqual(first, release_archive(b"changed", "agenc-ircd", 1234567890))

    def test_failed_child_retains_exit_code_and_raw_output(self) -> None:
        result = execute([sys.executable, "-c", "import sys; print('failure evidence'); sys.exit(7)"], self.root, dict(os.environ), self.root / "child.log", 2)
        self.assertEqual(result["exit_code"], 7)
        self.assertIsNone(result["failure"])
        self.assertEqual((self.root / "child.log").read_text(), "failure evidence\n")
        self.assertGreater(result["elapsed_ns"], 0)
        self.assertGreater(result["cpu_user_ns"] + result["cpu_system_ns"], 0)

    def test_output_limit_terminates_a_noisy_child(self) -> None:
        result = execute([sys.executable, "-c", "import os\nwhile True: os.write(1, b'x'*4096)"], self.root, dict(os.environ), self.root / "noise.log", 2, 1024)
        self.assertEqual(result["failure"], "log_limit")
        self.assertEqual(result["log_bytes"], 1024)
        self.assertLess(result["elapsed_ns"], 2 * 10**9)

    def test_timeout_is_a_failure_and_reaps_the_process(self) -> None:
        result = execute([sys.executable, "-c", "import time; time.sleep(30)"], self.root, dict(os.environ), self.root / "timeout.log", 1)
        self.assertEqual(result["failure"], "timeout")
        self.assertLess(result["exit_code"], 0)
        self.assertLess(result["elapsed_ns"], 3 * 10**9)

    def test_start_failure_is_recorded(self) -> None:
        result = execute(["/absent-agenc-test-command"], self.root, dict(os.environ), self.root / "missing.log", 1)
        self.assertEqual(result["failure"], "execution_error")
        self.assertIsNone(result["exit_code"])

    def test_release_report_rejects_short_fuzzing_and_altered_artifacts(self) -> None:
        path = self.root / "corpus.json"
        path.write_bytes(b"{}\n")
        job = {"id": "fuzz.parser"}
        report = {"schema_version": 1, "job_id": job["id"], "candidate_sha256": "a" * 64,
                  "target": "x86_64-unknown-linux-gnu", "artifacts": {path.name: file_digest(path)},
                  "facts": {"fuzz_target": "parser", "cpu_ns": 86400 * 10**9, "sanitizer": "address", "corpus_before": "b" * 64, "corpus_after": "c" * 64, "crashes": 0}}
        verify_report(self.root, report, job, "a" * 64, report["target"])
        short = copy.deepcopy(report)
        short["facts"]["cpu_ns"] -= 1
        with self.assertRaises(QualificationError):
            verify_report(self.root, short, job, "a" * 64, report["target"])
        path.write_bytes(b"changed")
        with self.assertRaises(QualificationError):
            verify_report(self.root, report, job, "a" * 64, report["target"])

    def test_capacity_report_requires_resource_source_and_refusal_count(self) -> None:
        path = self.root / "campaign.json"
        path.write_bytes(b"{}\n")
        job = {"id": "capacity"}
        facts = {"elapsed_ns": 300 * 10**9, "samples": 2, "missed_events": 0, "envelope_violations": 0,
                 "returned_to_envelope": True, "capacity_demonstrated": True, "hardware": "test host",
                 "scenario_counts": {name: 1 for name in ("reconnect", "churn", "rekey", "index_transition", "snapshot", "backup", "disk_pressure", "peer_loss")},
                 "latency_classes": ["admission", "durable_mutation", "fanout", "message", "opaque", "snapshot"],
                 "resource_source": "cgroup", "messages_refused": 0}
        report = {"schema_version": 1, "job_id": "capacity", "candidate_sha256": "a" * 64, "target": "x86_64-unknown-linux-gnu",
                  "artifacts": {path.name: file_digest(path)}, "facts": facts}
        verify_report(self.root, report, job, "a" * 64, report["target"])
        for mutate in (
            lambda facts: facts.pop("resource_source"),
            lambda facts: facts.__setitem__("resource_source", "guess"),
            lambda facts: facts.pop("messages_refused"),
            lambda facts: facts.__setitem__("messages_refused", -1),
            lambda facts: facts.__setitem__("missed_events", 1),
        ):
            changed = copy.deepcopy(report)
            mutate(changed["facts"])
            with self.subTest(facts=changed["facts"]), self.assertRaises(QualificationError):
                verify_report(self.root, changed, job, "a" * 64, report["target"])

    def test_job_inventory_includes_every_committed_parser(self) -> None:
        root = Path(__file__).resolve().parent.parent
        policy = load_policy(root, require_drivers=False)
        jobs = fuzz_jobs(root)
        self.assertGreaterEqual(len(jobs), 20)
        self.assertEqual(len({job["id"] for job in jobs}), len(jobs))
        self.assertEqual(policy["fuzz_cpu_seconds_per_target"], 86400)
        self.assertEqual(policy["soak_elapsed_seconds"], 604800)

    def test_container_images_require_content_digests(self) -> None:
        for image in ("ubuntu:latest", "sha256:" + "A" * 64, "sha256:" + "a" * 63, "repo@sha256:" + "a" * 64 + "\n", None):
            with self.subTest(image=image), self.assertRaises(QualificationError):
                immutable_image(image)
        for image in ("sha256:" + "a" * 64, "registry.test/release@sha256:" + "b" * 64):
            self.assertEqual(immutable_image(image), image)

    def test_release_signature_rejects_wrong_key_message_domain_and_length(self) -> None:
        # These disposable keys test the verifier and never authorize a release.
        keys = []
        for name in ("one", "two"):
            private = self.root / f"{name}.key"
            public = self.root / f"{name}.pub"
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
            keys.append((private, public))
        message = self.root / "message"
        message.write_bytes(DOMAIN + canonical({"fixture": "signature verification"}))
        signature_path = self.root / "signature"
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(keys[0][0]), "-in", str(message), "-out", str(signature_path)], check=True, capture_output=True)
        signature = signature_path.read_bytes()
        verify_signature(message.read_bytes(), signature, keys[0][1])
        cases = [
            (message.read_bytes(), signature, keys[1][1]),
            (message.read_bytes() + b"changed", signature, keys[0][1]),
            (message.read_bytes().removeprefix(DOMAIN), signature, keys[0][1]),
            (message.read_bytes(), signature[:-1], keys[0][1]),
            (message.read_bytes(), signature + b"x", keys[0][1]),
        ]
        for payload, signed, key in cases:
            with self.subTest(length=len(signed), key=key.name), self.assertRaises(QualificationError):
                verify_signature(payload, signed, key)



class SyntheticCandidate:
    """A throwaway candidate under disposable keys; it can never become release evidence."""

    SOURCE = {"commit": "f" * 40, "source_sha256": "1" * 64, "lock_sha256": "2" * 64}
    TARGETS = ("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu")

    def __init__(self, root: Path, directory: Path, targets: tuple[str, ...] = TARGETS) -> None:
        from release_qualification.policy import fuzz_jobs as jobs_of, load_policy as policy_of, policy_identity

        self.root = root
        self.directory = directory
        policy = policy_of(root, require_drivers=False)
        self.jobs = policy["job"] + jobs_of(root)
        artifacts = []
        for target in sorted(targets):
            build = self.synthetic_build(target)
            artifacts.append({"target": target, "path": f"artifacts/{target}/agenc-ircd",
                              "sha256": build["binary_sha256"], "build_record": f"artifacts/{target}/build.json",
                              "build_record_sha256": digest(canonical(build))})
        self.record = {"schema_version": 1, "created_at": timestamp_now(), "source": self.SOURCE,
                       "policy": policy_identity(root), "jobs": self.jobs, "artifacts": artifacts,
                       "claims": ["core-v1", "federated-v1", "encrypted-v1", "wss", "history"], "targets": sorted(targets)}
        write_once(directory / "candidate.json", canonical(self.record))
        self.hash = digest(canonical(self.record))

    def synthetic_build(self, target: str) -> dict:
        directory = self.directory / "artifacts" / target
        directory.mkdir(parents=True)
        files = {"agenc-ircd": f"binary for {target}".encode(), "sbom.spdx.json": b"{}\n",
                 "THIRD-PARTY-NOTICES.txt": b"notices\n", "build-a.log": b"a\n", "build-b.log": b"b\n"}
        archive = f"agenc-ircd-{self.SOURCE['commit'][:12]}-{target}.tar.gz"
        files[archive] = b"archive"
        for name, data in files.items():
            (directory / name).write_bytes(data)
        record = {"schema_version": 1, "source": self.SOURCE, "target": target, "features": ["history", "wss"],
                  "image": "sha256:" + "3" * 64, "source_date_epoch": 1, "binary": "agenc-ircd",
                  "binary_sha256": digest(files["agenc-ircd"]), "replica_sha256": digest(files["agenc-ircd"]),
                  "sbom": "sbom.spdx.json", "sbom_sha256": digest(files["sbom.spdx.json"]),
                  "notices": "THIRD-PARTY-NOTICES.txt", "notices_sha256": digest(files["THIRD-PARTY-NOTICES.txt"]),
                  "archive": archive, "archive_sha256": digest(files[archive]),
                  "tools": {"rustc": "rustc 1.98.0", "cargo": "cargo 1.98.0", "cc": "cc", "ld": "ld", "native_libraries": []},
                  "logs": [{"path": "build-a.log", "sha256": digest(b"a\n")}, {"path": "build-b.log", "sha256": digest(b"b\n")}]}
        write_once(directory / "build.json", canonical(record))
        return record

    def host(self, target: str) -> dict:
        return {"target": target, "kernel": "test", "cpu_affinity": [0], "tools": {}, "cpu_model_sha256": "4" * 64,
                "os_release_sha256": "5" * 64}

    def passing_facts(self, job: dict) -> dict:
        name = job["id"]
        if name == "workspace":
            return {"feature_combinations": [[], ["history"], ["wss"], ["history", "wss"]], "branch_percent": 90.5,
                    "line_percent": 92.0, "critical_percent": 100, "critical_inventory_complete": True,
                    "critical_categories": ["authorization-decisions", "parser-error-discriminants", "persistence-recovery",
                                            "protocol-enum-arms", "section-27-invariant-checkers"]}
        if name.startswith("fuzz."):
            return {"fuzz_target": name.removeprefix("fuzz."), "cpu_ns": 86400 * 10**9, "sanitizer": "address",
                    "corpus_before": "6" * 64, "corpus_after": "7" * 64, "crashes": 0}
        if name in ("capacity", "soak"):
            return {"elapsed_ns": (604800 if name == "soak" else 300) * 10**9, "samples": 2, "missed_events": 0,
                    "envelope_violations": 0, "returned_to_envelope": True, "capacity_demonstrated": True,
                    "scenario_counts": {scenario: 1 for scenario in ("reconnect", "churn", "rekey", "index_transition", "snapshot", "backup", "disk_pressure", "peer_loss")},
                    "latency_classes": ["admission", "durable_mutation", "fanout", "message", "opaque", "snapshot"], "hardware": "synthetic", "resource_source": "cgroup", "messages_refused": 0}
        if name == "reproducibility":
            return {"independent_builds": 2, "native_target": None, "binary_sha256": None}
        from release_qualification.verify import REQUIRED_FACTS
        return {field: True for field in REQUIRED_FACTS[name]}

    def fake_execute(self, *, exit_code: int = 0, interrupt: bool = False):
        candidate = self

        def execute(argv, cwd, environment, log, timeout_seconds, maximum_log_bytes=MAX_LOG_BYTES_FOR_TESTS):
            if interrupt:
                raise KeyboardInterrupt
            attempt = Path(environment["AGENC_RELEASE_ATTEMPT"])
            target = environment["AGENC_RELEASE_TARGET"]
            log.write_bytes(b"synthetic driver output\n")
            job = next(job for job in candidate.jobs if job["argv"] == argv)
            facts = candidate.passing_facts(job)
            if job["id"] == "reproducibility":
                artifact = next(item for item in candidate.record["artifacts"] if item["target"] == target)
                facts.update({"native_target": target, "binary_sha256": artifact["sha256"]})
            if exit_code == 0:
                (attempt / "evidence").mkdir()
                (attempt / "evidence/driver.log").write_bytes(b"evidence\n")
                report = {"schema_version": 1, "job_id": job["id"], "candidate_sha256": candidate.hash, "target": target,
                          "facts": facts, "artifacts": {"evidence/driver.log": digest(b"evidence\n")}}
                write_once(attempt / "report.json", canonical(report))
            return {"exit_code": exit_code, "failure": None, "elapsed_ns": 604800 * 10**9, "cpu_user_ns": 86400 * 10**9,
                    "cpu_system_ns": 0, "maximum_rss_kib": 1, "log_sha256": file_digest(log), "log_bytes": log.stat().st_size}

        return execute


MAX_LOG_BYTES_FOR_TESTS = 64 * 1024 * 1024


def timestamp_now() -> str:
    from release_qualification.records import utc_now
    return utc_now()


class RunnerTests(unittest.TestCase):
    """End-to-end runner behaviour on a synthetic candidate with patched execution."""

    def setUp(self) -> None:
        import contextlib
        from unittest import mock

        from release_qualification import candidate as candidate_module
        from release_qualification.policy import load_policy as policy_of

        self.temporary = tempfile.TemporaryDirectory(prefix="agenc-runner-test-")
        self.root = Path(__file__).resolve().parent.parent
        self.directory = Path(self.temporary.name) / "candidate"
        self.directory.mkdir(mode=0o700)
        self.candidate = SyntheticCandidate(self.root, self.directory)
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(mock.patch.object(candidate_module, "source_identity", return_value=dict(SyntheticCandidate.SOURCE)))
        self.stack.enter_context(mock.patch.object(candidate_module, "load_policy", lambda root, **kw: policy_of(root, require_drivers=False)))
        self.host_target = "x86_64-unknown-linux-gnu"
        self.stack.enter_context(mock.patch.object(candidate_module, "host_identity", lambda root: self.candidate.host(self.host_target)))

    def tearDown(self) -> None:
        self.stack.close()
        self.temporary.cleanup()

    def run_job(self, job_id: str, *, resume: bool = False, exit_code: int = 0, interrupt: bool = False,
                candidate: SyntheticCandidate | None = None):
        from unittest import mock

        from release_qualification import candidate as candidate_module
        from release_qualification.candidate import run_job

        candidate = candidate or self.candidate
        with mock.patch.object(candidate_module, "execute", candidate.fake_execute(exit_code=exit_code, interrupt=interrupt)):
            return run_job(self.root, candidate.directory, job_id, resume=resume)

    def status(self, candidate: SyntheticCandidate | None = None, targets: list[str] | None = None):
        from release_qualification.candidate import validate_candidate
        from release_qualification.verify import status

        directory = (candidate or self.candidate).directory
        return status(directory, validate_candidate(self.root, directory, check_source=False), targets)

    def single_target_candidate(self) -> SyntheticCandidate:
        directory = Path(self.temporary.name) / "single"
        directory.mkdir(mode=0o700)
        return SyntheticCandidate(self.root, directory, ("x86_64-unknown-linux-gnu",))

    def test_prepare_records_only_the_named_targets(self) -> None:
        from unittest import mock

        from release_qualification import candidate as candidate_module
        from release_qualification.candidate import prepare, validate_candidate

        builds = {target: self.directory / "artifacts" / target / "build.json" for target in SyntheticCandidate.TARGETS}
        output = Path(self.temporary.name) / "prepared"
        with mock.patch.object(candidate_module, "source_identity", return_value=dict(SyntheticCandidate.SOURCE)):
            with self.assertRaises(QualificationError):
                prepare(self.root, output, list(builds.values()), ["x86_64-unknown-linux-gnu"])
            with self.assertRaises(QualificationError):
                prepare(self.root, output, [builds["x86_64-unknown-linux-gnu"]], [])
            with self.assertRaises(QualificationError):
                prepare(self.root, output, [builds["x86_64-unknown-linux-gnu"]], ["riscv64gc-unknown-linux-gnu"])
            prepare(self.root, output, [builds["x86_64-unknown-linux-gnu"]], ["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"])
        record = validate_candidate(self.root, output, check_source=False)
        self.assertEqual(record["targets"], ["x86_64-unknown-linux-gnu"])
        self.assertEqual([artifact["target"] for artifact in record["artifacts"]], ["x86_64-unknown-linux-gnu"])
        candidate_path = output / "candidate.json"
        original = candidate_path.read_bytes()
        candidate_path.write_bytes(original.replace(b'"targets":["x86_64-unknown-linux-gnu"]', b'"targets":["aarch64-unknown-linux-gnu","x86_64-unknown-linux-gnu"]'))
        with self.assertRaises(QualificationError):
            validate_candidate(self.root, output, check_source=False)

    def test_single_target_candidate_runs_and_closes_only_its_target(self) -> None:
        from unittest import mock

        from release_qualification import candidate as candidate_module
        from release_qualification.decision import verify_decision
        from release_qualification.signing import close

        single = self.single_target_candidate()
        self.host_target = "aarch64-unknown-linux-gnu"
        with self.assertRaises(QualificationError):
            self.run_job("claims", candidate=single)
        self.host_target = "x86_64-unknown-linux-gnu"
        for job in single.jobs:
            self.assertEqual(self.run_job(job["id"], candidate=single)["outcome"], "passed", job["id"])
        summary = self.status(single)
        self.assertTrue(summary["ready"])
        self.assertEqual(summary["targets"], ["x86_64-unknown-linux-gnu"])
        with self.assertRaises(QualificationError):
            self.status(single, ["aarch64-unknown-linux-gnu"])
        private, public = self.keys("single")
        with mock.patch.object(candidate_module, "source_identity", return_value=dict(SyntheticCandidate.SOURCE)):
            decision = close(self.root, single.directory, private, public, ["core-v1"], None)
        self.assertEqual(decision["targets"], ["x86_64-unknown-linux-gnu"])
        self.assertEqual([artifact["target"] for artifact in decision["artifacts"]], ["x86_64-unknown-linux-gnu"])
        self.assertEqual(verify_decision(self.root, single.directory, public)["targets"], ["x86_64-unknown-linux-gnu"])

    def test_two_target_candidate_can_close_the_finished_target_alone(self) -> None:
        from unittest import mock

        from release_qualification import candidate as candidate_module
        from release_qualification.decision import verify_decision
        from release_qualification.signing import close

        self.host_target = "x86_64-unknown-linux-gnu"
        for job in self.candidate.jobs:
            self.assertEqual(self.run_job(job["id"])["outcome"], "passed", job["id"])
        self.assertFalse(self.status()["ready"])
        self.assertTrue(self.status(targets=["x86_64-unknown-linux-gnu"])["ready"])
        private, public = self.keys("scoped")
        with mock.patch.object(candidate_module, "source_identity", return_value=dict(SyntheticCandidate.SOURCE)):
            with self.assertRaises(QualificationError):
                close(self.root, self.directory, private, public, ["core-v1"], None)
            with self.assertRaises(QualificationError):
                close(self.root, self.directory, private, public, ["core-v1"], None, ["aarch64-unknown-linux-gnu"])
            with self.assertRaises(QualificationError):
                close(self.root, self.directory, private, public, ["core-v1"], None, ["riscv64gc-unknown-linux-gnu"])
            decision = close(self.root, self.directory, private, public, ["core-v1", "wss"], None, ["x86_64-unknown-linux-gnu"])
        self.assertEqual(decision["targets"], ["x86_64-unknown-linux-gnu"])
        self.assertEqual(len(decision["artifacts"]), 1)
        verified = verify_decision(self.root, self.directory, public)
        self.assertEqual(verified["targets"], ["x86_64-unknown-linux-gnu"])
        qualification = read_record(self.directory / "decision/qualification.json")
        self.assertEqual(qualification["targets"], ["x86_64-unknown-linux-gnu"])
        self.assertTrue(all(name.startswith("x86_64-unknown-linux-gnu/") for name in qualification["passed"]))
        # Widening the signed scope after the fact breaks the signature.
        release = self.directory / "decision/release.json"
        original = release.read_bytes()
        release.write_bytes(original.replace(b'"targets":["x86_64-unknown-linux-gnu"]', b'"targets":["aarch64-unknown-linux-gnu","x86_64-unknown-linux-gnu"]'))
        with self.assertRaises(QualificationError):
            verify_decision(self.root, self.directory, public)
        release.write_bytes(original)
        verify_decision(self.root, self.directory, public)

    def test_pass_fail_interrupt_and_resume_retain_every_attempt(self) -> None:
        result = self.run_job("claims")
        self.assertEqual(result["outcome"], "passed")
        with self.assertRaises(QualificationError):
            self.run_job("claims")
        self.assertEqual(self.run_job("claims", resume=True)["outcome"], "passed")
        self.assertEqual(sorted((self.directory / "runs/x86_64-unknown-linux-gnu/claims").iterdir())[-1].name, "0001")
        failed = self.run_job("sources", exit_code=7)
        self.assertEqual(failed["outcome"], "failed")
        with self.assertRaises(KeyboardInterrupt):
            self.run_job("sources", resume=True, interrupt=True)
        summary = self.status()
        self.assertIn("x86_64-unknown-linux-gnu/sources/0001", summary["failed"])
        self.assertIn("x86_64-unknown-linux-gnu/sources/0002", summary["interrupted"])
        self.assertFalse(summary["ready"])
        self.assertEqual(self.run_job("sources", resume=True)["outcome"], "passed")
        summary = self.status()
        self.assertIn("x86_64-unknown-linux-gnu/sources", summary["passed"])
        self.assertIn("x86_64-unknown-linux-gnu/sources/0001", summary["failed"])
        self.assertIn("x86_64-unknown-linux-gnu/sources/0002", summary["interrupted"])

    def test_running_job_is_reported_and_blocks_a_second_attempt(self) -> None:
        from release_qualification.locks import job_lock

        attempts = self.directory / "runs/x86_64-unknown-linux-gnu/claims"
        attempts.mkdir(parents=True)
        (attempts / "0001").mkdir()
        with job_lock(attempts):
            summary = self.status()
            self.assertEqual(summary["running"], ["x86_64-unknown-linux-gnu/claims/0001"])
            self.assertFalse(summary["ready"])
            with self.assertRaises(QualificationError):
                self.run_job("claims", resume=True)
        self.assertEqual(self.status()["interrupted"], ["x86_64-unknown-linux-gnu/claims/0001"])

    def test_wrong_host_target_cannot_attempt_a_job(self) -> None:
        self.host_target = "riscv64gc-unknown-linux-gnu"
        with self.assertRaises(QualificationError):
            self.run_job("claims")

    def complete_every_job(self) -> None:
        for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
            self.host_target = target
            for job in self.candidate.jobs:
                self.assertEqual(self.run_job(job["id"])["outcome"], "passed", job["id"])

    def keys(self, name: str) -> tuple[Path, Path]:
        private = Path(self.temporary.name) / f"{name}.key"
        public = Path(self.temporary.name) / f"{name}.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
        return private, public

    def test_close_and_verify_bind_evidence_claims_and_trust_anchor(self) -> None:
        from unittest import mock

        from release_qualification import candidate as candidate_module
        from release_qualification.decision import verify_decision
        from release_qualification.signing import close

        with self.assertRaises(QualificationError):
            close(self.root, self.directory, Path("/absent"), Path("/absent"), ["core-v1"], None)
        self.complete_every_job()
        self.assertTrue(self.status()["ready"])
        private, public = self.keys("release")
        _, other_public = self.keys("other")
        with self.assertRaises(QualificationError):
            close(self.root, self.directory, private, public, ["encrypted-v1"], None)
        review = Path(self.temporary.name) / "review.json"
        report = Path(self.temporary.name) / "review-report"
        report.write_bytes(b"review report\n")
        record = {"task": "S08-039", "source_commit": SyntheticCandidate.SOURCE["commit"], "reviewer": "reviewer",
                  "completed_at": timestamp_now(), "open_findings": 1, "report": "review-report",
                  "report_sha256": digest(b"review report\n"), "remediation_verified": True}
        review.write_bytes(canonical(record))
        with self.assertRaises(QualificationError):
            close(self.root, self.directory, private, public, ["encrypted-v1"], review)
        with mock.patch.object(candidate_module, "source_identity", return_value=dict(SyntheticCandidate.SOURCE)):
            decision = close(self.root, self.directory, private, public, ["core-v1", "wss"], None)
        self.assertEqual(decision["claims"], ["core-v1", "wss"])
        self.assertEqual(verify_decision(self.root, self.directory, public)["claims"], ["core-v1", "wss"])
        with self.assertRaises(QualificationError):
            verify_decision(self.root, self.directory, other_public)
        with self.assertRaises(QualificationError):
            close(self.root, self.directory, private, public, ["core-v1"], None)
        log = self.directory / "runs/x86_64-unknown-linux-gnu/claims/0001/output.log"
        original = log.read_bytes()
        log.write_bytes(original + b"tampered\n")
        with self.assertRaises(QualificationError):
            verify_decision(self.root, self.directory, public)
        log.write_bytes(original)
        verify_decision(self.root, self.directory, public)
        moved = self.directory / "runs/x86_64-unknown-linux-gnu/claims/0001"
        moved.rename(self.directory / "runs/x86_64-unknown-linux-gnu/sources/0002")
        with self.assertRaises(QualificationError):
            verify_decision(self.root, self.directory, public)

    def test_symlinked_and_foreign_attempt_entries_are_rejected(self) -> None:
        attempts = self.directory / "runs/x86_64-unknown-linux-gnu/claims"
        attempts.mkdir(parents=True)
        (attempts / "0001").symlink_to(self.directory / "artifacts", target_is_directory=True)
        with self.assertRaises(QualificationError):
            self.status()
        (attempts / "0001").unlink()
        (attempts / "notes.txt").write_bytes(b"x")
        with self.assertRaises(QualificationError):
            self.status()

    def test_altered_report_or_start_record_fails_verification(self) -> None:
        from release_qualification.candidate import validate_candidate
        from release_qualification.verify import verify_attempt

        self.run_job("claims")
        attempt = self.directory / "runs/x86_64-unknown-linux-gnu/claims/0001"
        candidate = validate_candidate(self.root, self.directory, check_source=False)
        verify_attempt(self.directory, candidate, attempt)
        for name in ("report.json", "start.json"):
            path = attempt / name
            original = path.read_bytes()
            path.write_bytes(original.replace(b"x86_64", b"x86_65"))
            with self.assertRaises(QualificationError):
                verify_attempt(self.directory, candidate, attempt)
            path.write_bytes(original)
        verify_attempt(self.directory, candidate, attempt)


class WorkerGroupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="agenc-workers-test-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_group_runs_workers_together_and_charges_their_cpu(self) -> None:
        from release_qualification.workers import execute_group

        script = "import time\nend=time.monotonic()+0.5\nwhile time.monotonic()<end: pass\nprint('done')"
        commands = [([sys.executable, "-c", script], self.root / f"worker-{index}.log") for index in range(3)]
        results = execute_group(commands, self.root, dict(os.environ), 10)
        self.assertEqual([result["exit_code"] for result in results], [0, 0, 0])
        self.assertTrue(all(result["failure"] is None for result in results))
        self.assertLess(results[0]["elapsed_ns"], 1_400_000_000)
        self.assertGreater(sum(result["cpu_user_ns"] + result["cpu_system_ns"] for result in results), 1_000_000_000)
        self.assertEqual((self.root / "worker-1.log").read_bytes(), b"done\n")

    def test_first_failing_worker_stops_the_group_and_every_child_is_joined(self) -> None:
        from release_qualification.workers import execute_group

        commands = [([sys.executable, "-c", "import time; time.sleep(30)"], self.root / "slow.log"),
                    ([sys.executable, "-c", "import sys; print('boom'); sys.exit(3)"], self.root / "fast.log")]
        results = execute_group(commands, self.root, dict(os.environ), 10)
        self.assertEqual(results[1]["exit_code"], 3)
        self.assertLess(results[0]["exit_code"], 0)
        self.assertEqual(results[0]["failure"], "worker_failed")
        self.assertLess(results[0]["elapsed_ns"], 5 * 10**9)
        self.assertEqual((self.root / "fast.log").read_bytes(), b"boom\n")

    def test_group_timeout_and_log_limit_terminate_every_worker(self) -> None:
        from release_qualification.workers import execute_group

        commands = [([sys.executable, "-c", "import time; time.sleep(30)"], self.root / "a.log"),
                    ([sys.executable, "-c", "import time; time.sleep(30)"], self.root / "b.log")]
        results = execute_group(commands, self.root, dict(os.environ), 1)
        self.assertEqual([result["failure"] for result in results], ["timeout", "timeout"])
        noisy = [([sys.executable, "-c", "import os\nwhile True: os.write(1, b'x'*4096)"], self.root / "noisy.log"),
                 ([sys.executable, "-c", "import time; time.sleep(30)"], self.root / "quiet.log")]
        results = execute_group(noisy, self.root, dict(os.environ), 10, 2048)
        self.assertEqual(results[0]["failure"], "log_limit")
        self.assertEqual(results[0]["log_bytes"], 2048)
        self.assertEqual(results[1]["failure"], "log_limit")


class ProbeAndCorpusTests(unittest.TestCase):
    def test_tool_probe_output_is_bounded_while_running(self) -> None:
        from release_qualification.policy import checked_run

        root = Path(__file__).resolve().parent.parent
        self.assertEqual(checked_run(root, [sys.executable, "-c", "print('ok')"]), "ok")
        with self.assertRaises(QualificationError):
            checked_run(root, [sys.executable, "-c", "import os\nfor _ in range(2000): os.write(1, b'x'*4096)"])
        with self.assertRaises(QualificationError):
            checked_run(root, [sys.executable, "-c", "import sys; sys.exit(2)"])

    def test_every_fuzz_target_has_a_committed_seed_directory(self) -> None:
        from release_qualification.fuzz import corpus_entries, seed_directory, snapshot_corpus

        root = Path(__file__).resolve().parent.parent
        for job in fuzz_jobs(root):
            name = job["id"].removeprefix("fuzz.")
            directory = seed_directory(root, name)
            self.assertTrue(corpus_entries(directory), name)
            with tempfile.TemporaryDirectory(prefix="agenc-corpus-") as scratch:
                first = snapshot_corpus(directory, Path(scratch) / "one.tar.gz")
                second = snapshot_corpus(directory, Path(scratch) / "two.tar.gz")
                self.assertEqual(first, second)
                self.assertEqual((Path(scratch) / "one.tar.gz").read_bytes(), (Path(scratch) / "two.tar.gz").read_bytes())
        with self.assertRaises(QualificationError):
            seed_directory(root, "absent_target")



class StorageDriverTests(unittest.TestCase):
    """The storage driver's summary validation is the release contract for S10-006."""

    @staticmethod
    def driver():
        import importlib.util

        path = Path(__file__).resolve().parent / "qualify-stage-ten-storage.py"
        specification = importlib.util.spec_from_file_location("qualify_stage_ten_storage", path)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module

    @classmethod
    def summary(cls, driver, maximum: int = 4096) -> dict:
        names = driver.REQUIRED_CASES + driver.BACKUP_CASES + driver.PHASE_CASES
        cases = []
        for name in names:
            delta = 0 if name.endswith("plus-one") else maximum
            cases.append({"name": name, "allocated_before": 1000, "allocated_after": 1000 + delta, "positive_delta": delta})
        return {"schema_version": 1, "target": "x86_64-unknown-linux-gnu", "filesystem_type": driver.EXT4_SUPER_MAGIC,
                "block_size": 4096, "mount_flags": 4128, "kernel_release": "test", "maximum_observed_growth": maximum,
                "qualified_growth_ceiling": driver.QUALIFIED_GROWTH_CEILING, "physical_growth_reserve": driver.PHYSICAL_GROWTH_RESERVE,
                "sample_count": 10, "ballast_bytes": 0, "cases": cases}

    def test_valid_summary_passes_and_each_weakening_is_refused(self) -> None:
        driver = self.driver()
        good = self.summary(driver)
        cases = driver.validate_summary(good, "x86_64-unknown-linux-gnu")
        self.assertEqual(len(cases), len(good["cases"]))
        over = self.summary(driver, driver.QUALIFIED_GROWTH_CEILING + 1)
        with self.assertRaises(QualificationError):
            driver.validate_summary(over, "x86_64-unknown-linux-gnu")
        with self.assertRaises(QualificationError):
            driver.validate_summary(good, "aarch64-unknown-linux-gnu")
        for field, value in (("filesystem_type", 0x9123683E), ("block_size", 3000), ("qualified_growth_ceiling", 1), ("maximum_observed_growth", 1)):
            changed = self.summary(driver)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(QualificationError):
                driver.validate_summary(changed, "x86_64-unknown-linux-gnu")
        missing = self.summary(driver)
        missing["cases"] = [case for case in missing["cases"] if case["name"] != "guard-rename"]
        with self.assertRaises(QualificationError):
            driver.validate_summary(missing, "x86_64-unknown-linux-gnu")
        refused = self.summary(driver)
        for case in refused["cases"]:
            if case["name"] == "reserve-plus-one":
                case["allocated_after"] = case["allocated_before"] + 8
                case["positive_delta"] = 8
        with self.assertRaises(QualificationError):
            driver.validate_summary(refused, "x86_64-unknown-linux-gnu")

    def test_embedded_tuple_must_be_this_targets_ext4_report(self) -> None:
        driver = self.driver()
        metadata = {"storage_qualification": {"tuples": [{"target": "x86_64-unknown-linux-gnu", "filesystem_type": driver.EXT4_SUPER_MAGIC,
                                                            "block_size": 4096, "mount_flags": 4128, "maximum_observed_growth": 33570816}]}}
        self.assertEqual(driver.embedded_tuple(metadata, "x86_64-unknown-linux-gnu")["block_size"], 4096)
        with self.assertRaises(QualificationError):
            driver.embedded_tuple(metadata, "aarch64-unknown-linux-gnu")
        with self.assertRaises(QualificationError):
            driver.embedded_tuple({"storage_qualification": {"tuples": []}}, "x86_64-unknown-linux-gnu")



class CapacityDriverTests(unittest.TestCase):
    """The capacity driver's record validation is the release contract for S10-007."""

    @staticmethod
    def driver():
        import importlib.util

        path = Path(__file__).resolve().parent / "qualify-stage-ten-capacity.py"
        specification = importlib.util.spec_from_file_location("qualify_stage_ten_capacity", path)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module

    @staticmethod
    def sample(live: int) -> dict:
        return {"at_ns": 10, "anonymous_bytes": [3_000_000, 2_000_000, 2_000_000], "sockets": [2, 40, 40], "close_wait": [0, 0, 0],
                "tasks": [12, 12, 12], "federation_links": 2, "live_client_connections": live}

    @classmethod
    def record(cls, driver, seconds: int = 300, connections: int = 64) -> dict:
        return {"schema_version": 1, "elapsed_ns": seconds * 10**9, "connections": connections, "resource_source": "cgroup",
                "samples": [cls.sample(connections), cls.sample(connections - 1)],
                "latency_classes": {name: {"count": 5, "p50_ns": 1, "p95_ns": 2, "p99_ns": 3} for name in driver.LATENCY_CLASSES},
                "scenario_counts": {name: 1 for name in driver.SCENARIOS}, "missed_events": 0, "envelope_violations": 0,
                "messages_sent": 100, "messages_received": 700, "messages_refused": 0,
                "returned_to_envelope": True, "daemons_stopped_cleanly": [True, True, True], "hardware": "test host"}

    def test_complete_record_passes_and_each_shortfall_is_refused(self) -> None:
        driver = self.driver()
        facts = driver.validate_campaign(self.record(driver), 300, 64)
        self.assertEqual(facts["scenario_counts"]["rekey"], 1)
        self.assertEqual(facts["latency_classes"], driver.LATENCY_CLASSES)
        self.assertEqual(facts["resource_source"], "cgroup")
        procfs = self.record(driver)
        procfs["resource_source"] = "procfs"
        self.assertEqual(driver.validate_campaign(procfs, 300, 64)["resource_source"], "procfs")
        short = self.record(driver, seconds=299)
        with self.assertRaises(QualificationError):
            driver.validate_campaign(short, 300, 64)
        for mutate in (
            lambda record: record["scenario_counts"].__setitem__("disk_pressure", 0),
            lambda record: record.__setitem__("missed_events", 1),
            lambda record: record.__setitem__("envelope_violations", 2),
            lambda record: record.__setitem__("returned_to_envelope", False),
            lambda record: record.__setitem__("daemons_stopped_cleanly", [True, False, True]),
            lambda record: record["latency_classes"].pop("opaque"),
            lambda record: record["latency_classes"]["fanout"].__setitem__("count", 0),
            lambda record: record.__setitem__("samples", record["samples"][:1]),
            lambda record: record.__setitem__("samples", [self.sample(10), self.sample(10)]),
            lambda record: record["samples"][0].__setitem__("anonymous_bytes", [0, 2_000_000, 2_000_000]),
            lambda record: record["samples"][1].__setitem__("tasks", [12, 0, 12]),
            lambda record: record["samples"][1].pop("sockets"),
            lambda record: record["samples"][1].__setitem__("close_wait", [0, -1, 0]),
            lambda record: record.__setitem__("resource_source", "guess"),
            lambda record: record.__setitem__("messages_received", 0),
            lambda record: record.pop("messages_refused"),
            lambda record: record.__setitem__("messages_refused", -1),
            lambda record: record.pop("resource_source"),
            lambda record: record.__setitem__("hardware", " "),
        ):
            changed = self.record(driver)
            mutate(changed)
            with self.subTest(record=changed), self.assertRaises(QualificationError):
                driver.validate_campaign(changed, 300, 64)
        with self.assertRaises(QualificationError):
            driver.validate_campaign(self.record(driver), 300, 65)


class DrillsDriverTests(unittest.TestCase):
    """The drills driver only counts a drill that wrote a well-formed passing record."""

    @staticmethod
    def driver():
        import importlib.util

        path = Path(__file__).resolve().parent / "qualify-stage-ten-drills.py"
        specification = importlib.util.spec_from_file_location("qualify_stage_ten_drills", path)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module

    @staticmethod
    def record(name: str = "restore", passed: bool = True) -> dict:
        return {"schema_version": 1, "drill": name, "passed": passed, "elapsed_ns": 12_000,
                "steps": [{"name": "backup", "elapsed_ns": 5_000, "detail": "40 rows"}],
                "facts": {"recovery_epoch": "abc", "daemons_stopped_cleanly": "[true, true, true]"}}

    def test_record_shape_and_verdict_are_enforced(self) -> None:
        driver = self.driver()
        self.assertEqual(driver.DRILLS, sorted(driver.DRILLS, key=driver.DRILLS.index))
        self.assertEqual(len(driver.DRILLS), 16)
        self.assertTrue(driver.validate_record(self.record(), "restore"))
        self.assertFalse(driver.validate_record(self.record(passed=False), "restore"))
        for mutate in (
            lambda record: record.__setitem__("drill", "rekey"),
            lambda record: record.__setitem__("schema_version", 2),
            lambda record: record.__setitem__("steps", []),
            lambda record: record["steps"].__setitem__(0, {"name": "x"}),
            lambda record: record.__setitem__("facts", {"n": 1}),
            lambda record: record.__setitem__("passed", "yes"),
            lambda record: record["facts"].__setitem__("error", "boom"),
            lambda record: record.__setitem__("elapsed_ns", -1),
        ):
            changed = self.record()
            mutate(changed)
            with self.subTest(record=changed), self.assertRaises(QualificationError):
                driver.validate_record(changed, "restore")


class DecisionFixtureTests(unittest.TestCase):
    """The committed fixture binds the Python signer and the daemon's verifier to one domain."""

    ROOT = Path(__file__).resolve().parent.parent
    FIXTURE = ROOT / "test-data/release-decision"
    SEED = b"agenc-ircd release decision seed"
    PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")

    def test_fixture_signature_is_reproduced_from_the_seed_under_the_shared_domain(self) -> None:
        from release_qualification.signing import sign_payload

        self.assertEqual(DOMAIN, b"agenc-chat release decision v1")
        payload = (self.FIXTURE / "release.json").read_bytes()
        committed = (self.FIXTURE / "release.sig").read_bytes()
        public = self.FIXTURE / "release-public.pem"
        with tempfile.TemporaryDirectory(prefix="agenc-fixture-key-") as temporary:
            der = Path(temporary) / "seed.der"
            der.write_bytes(self.PKCS8_PREFIX + self.SEED)
            private = Path(temporary) / "seed.pem"
            derived_public = Path(temporary) / "seed-public.pem"
            subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", str(der), "-out", str(private)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(derived_public)], check=True, capture_output=True)
            self.assertEqual(derived_public.read_bytes(), public.read_bytes())
            self.assertEqual(sign_payload(DOMAIN + payload, private, public), committed)
        verify_signature(DOMAIN + payload, committed, public)
        with self.assertRaises(QualificationError):
            verify_signature(DOMAIN + payload, committed, self.FIXTURE / "untrusted-public.pem")
        with self.assertRaises(QualificationError):
            verify_signature(b"agenc-ircd release decision v1\x00" + payload, committed, public)
        decision = read_record(self.FIXTURE / "release.json")
        self.assertEqual(decision["public_key_sha256"], file_digest(public))
        self.assertEqual(decision["targets"], ["x86_64-unknown-linux-gnu"])
        self.assertEqual(decision["artifacts"][0]["sha256"], digest(b"agenc-ircd release decision fixture executable\n"))
        seed = self.ROOT / "test-data/fuzz-corpus/release-decision/canonical"
        self.assertEqual(seed.read_bytes(), payload)


class SourcesDriverTests(unittest.TestCase):
    """Every cited source has a recorded decision, and any status drift is a named failure."""

    ROOT = Path(__file__).resolve().parent.parent

    @staticmethod
    def driver():
        import importlib.util

        path = Path(__file__).resolve().parent / "check-release-sources.py"
        specification = importlib.util.spec_from_file_location("check_release_sources", path)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module

    def test_ledger_inventory_matches_the_recorded_decisions(self) -> None:
        driver = self.driver()
        ledger = read_bytes(self.ROOT / driver.LEDGER_PATH)
        decisions = driver.load_decisions(self.ROOT)
        self.assertEqual(decisions["ledger_sha256"], digest(ledger))
        numbers = driver.ledger_rfc_numbers(ledger.decode())
        self.assertEqual({entry["number"] for entry in decisions["rfc"]}, numbers)
        self.assertIn(8446, numbers)
        self.assertEqual(next(entry for entry in decisions["rfc"] if entry["number"] == 8446)["decision"], "supersede")
        self.assertEqual([entry["name"] for entry in decisions["draft"]], ["draft-ietf-mls-pq-ciphersuites"])
        self.assertEqual(len(decisions["repository"]), 3)
        self.assertEqual(driver.ledger_rfc_numbers("\n## 2. x\nRFC 2119 and RFCs 2810-2813 plus RFC-9180-exporter\n## 3. y\nRFC 9999\n"), {2119, 2810, 2811, 2812, 2813})
        with self.assertRaises(QualificationError):
            driver.ledger_rfc_numbers("\n## 2. x\nRFCs 100-900\n## 3. y\n")

    def test_status_drift_is_a_failure_that_names_the_source(self) -> None:
        driver = self.driver()
        entry = {"number": 9846, "status": "PROPOSED STANDARD", "obsoleted_by": [], "updated_by": [], "decision": "adopt", "note": "n"}
        record = {"doc_id": "RFC9846", "status": "PROPOSED STANDARD", "obsoleted_by": [], "updated_by": [], "pub_date": "July 2026", "errata_url": "https://www.rfc-editor.org/errata/rfc9846"}
        self.assertEqual(driver.check_rfc(entry, record)["status"], "PROPOSED STANDARD")
        for change in ({"status": "HISTORIC"}, {"obsoleted_by": ["RFC9999"]}, {"updated_by": ["RFC9999"]}, {"doc_id": "RFC9847"}):
            with self.subTest(change=change), self.assertRaisesRegex(QualificationError, "RFC 984"):
                driver.check_rfc(entry, {**record, **change})
        draft = {"name": "draft-ietf-mls-pq-ciphersuites", "revision": "06", "updated": "2026-07-21T09:18:03Z", "states": ["active", "chair-w", "idexists"], "decision": "reject", "note": "n"}
        document = {"name": draft["name"], "rev": "06", "time": "2026-07-21T09:18:03Z", "expires": "2027-01-22T09:18:03Z"}
        states = [{"slug": "idexists"}, {"slug": "active"}, {"slug": "chair-w"}]
        self.assertEqual(driver.check_draft(draft, document, states)["revision"], "06")
        for changed_document, changed_states in (({**document, "rev": "07"}, states), ({**document, "time": "2026-09-01T00:00:00Z"}, states), (document, states[:2])):
            with self.subTest(document=changed_document), self.assertRaisesRegex(QualificationError, "draft-ietf-mls-pq-ciphersuites"):
                driver.check_draft(draft, changed_document, changed_states)
        listing = "ref: refs/heads/main\tHEAD\n" + "a" * 40 + "\tHEAD\n"
        self.assertEqual(driver.parse_ls_remote(listing), ("refs/heads/main", "a" * 40))
        repository = {"name": "Tor specifications", "url": "https://example.test/torspec", "pinned_commit": "b" * 40, "default_branch": "refs/heads/main", "head_commit": "a" * 40, "decision": "adopt", "note": "n"}
        self.assertEqual(driver.check_repository(repository, listing)["head_commit"], "a" * 40)
        with self.assertRaisesRegex(QualificationError, "Tor specifications"):
            driver.check_repository(repository, "ref: refs/heads/main\tHEAD\n" + "c" * 40 + "\tHEAD\n")
        with self.assertRaisesRegex(QualificationError, "Tor specifications"):
            driver.check_repository(repository, "ref: refs/heads/master\tHEAD\n" + "a" * 40 + "\tHEAD\n")
        with self.assertRaises(QualificationError):
            driver.parse_ls_remote("garbage\n")

    def test_decisions_need_explicit_words_and_notes(self) -> None:
        driver = self.driver()
        original = (self.ROOT / driver.DECISIONS_PATH).read_text()
        with tempfile.TemporaryDirectory(prefix="agenc-sources-test-") as temporary:
            root = Path(temporary)
            (root / "conformance").mkdir()
            for text in (original.replace('decision = "supersede"', 'decision = "maybe"'), original.replace('note = "Requirement words."', 'note = " "'),
                         original.replace("[[draft]]", "[[drafts]]"), original.replace('schema_version = 1', 'schema_version = 2')):
                (root / driver.DECISIONS_PATH).write_text(text)
                with self.subTest(text=text[:60]), self.assertRaises(QualificationError):
                    driver.load_decisions(root)
            (root / driver.DECISIONS_PATH).write_text(original)
            self.assertEqual(driver.load_decisions(root)["schema_version"], 1)


class ClaimsDriverTests(unittest.TestCase):
    """The claims driver compares the binary, the baseline, and the ledgers field by field."""

    ROOT = Path(__file__).resolve().parent.parent

    @staticmethod
    def driver():
        import importlib.util

        path = Path(__file__).resolve().parent / "check-release-claims.py"
        specification = importlib.util.spec_from_file_location("check_release_claims", path)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module

    def policy(self):
        return load_policy(self.ROOT, require_drivers=False)

    def test_claims_policy_requires_every_job_and_every_limit(self) -> None:
        driver = self.driver()
        claims = driver.load_claims_policy(self.ROOT, self.policy())
        self.assertEqual(sorted(claim["id"] for claim in claims["claim"]), sorted(["core-v1", "federated-v1", "encrypted-v1", "wss", "history"]))
        original = (self.ROOT / driver.CLAIMS_PATH).read_text()
        with tempfile.TemporaryDirectory(prefix="agenc-claims-test-") as temporary:
            root = Path(temporary)
            (root / "conformance").mkdir()
            (root / "docs").mkdir()
            for name in claims["documents"]:
                (root / name).write_text("placeholder\n")
            for text in (original.replace('"soak", ', "", 1), original.replace('limits = ["metadata", "tor"]', 'limits = ["metadata", "absent"]', 1),
                         original.replace('id = "history"', 'id = "core-v1"'), original.replace('external_review = "S08-039"', 'external_review = "S08-001"'),
                         original.replace("[[claim]]\nid = \"wss\"", "[[claim]]\nid = \"wss2\"")):
                (root / driver.CLAIMS_PATH).write_text(text)
                with self.subTest(text=text[:40]), self.assertRaises(QualificationError):
                    driver.load_claims_policy(root, self.policy())
            (root / driver.CLAIMS_PATH).write_text(original)
            driver.load_claims_policy(root, self.policy())

    def test_metadata_is_compared_field_by_field(self) -> None:
        driver = self.driver()
        candidate = {"source": dict(SyntheticCandidate.SOURCE)}
        build = {"features": ["history", "wss"], "tools": {"rustc": "rustc 1.98.0 (abc 2026-01-01)\nbinary: rustc\nhost: x86_64-unknown-linux-gnu"}}
        expected = driver.expected_metadata(candidate, build, "x86_64-unknown-linux-gnu")
        self.assertEqual(expected["compiler"], "rustc 1.98.0 (abc 2026-01-01)")
        metadata = dict(expected)
        driver.check_metadata(metadata, expected, "version")
        for field, value in (("compiler", "rustc 1.97.0"), ("target", "aarch64-unknown-linux-gnu"), ("features", {"history": True, "wss": False}), ("storage_schema_generation", 1)):
            with self.subTest(field=field), self.assertRaisesRegex(QualificationError, field):
                driver.check_metadata({**metadata, field: value}, expected, "version")
        baseline = driver.load_baseline(self.ROOT)
        conformance = driver.expected_conformance(baseline)
        self.assertEqual(conformance["qualified_claims"], [])
        self.assertEqual(len(conformance["base_profile_sha256"]), 64)
        with self.assertRaisesRegex(QualificationError, "qualified_claims"):
            driver.check_metadata({**conformance, "qualified_claims": ["core-v1"]}, conformance, "conformance")

    def test_ledgers_keep_their_limits_and_claim_nothing_early(self) -> None:
        driver = self.driver()
        claims = driver.load_claims_policy(self.ROOT, self.policy())
        lint = driver.lint_documents(self.ROOT, claims, False)
        self.assertEqual(lint["documents"], claims["documents"])
        with tempfile.TemporaryDirectory(prefix="agenc-lint-test-") as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "conformance").mkdir()
            for name in claims["documents"]:
                (root / name).write_text("quiet\n")
            (root / driver.LIMITS_DOCUMENT).write_text(" ".join(claims["limits"].values()).replace(". ", ".\n") + "\n")
            driver.lint_documents(root, claims, False)
            (root / driver.LIMITS_DOCUMENT).write_text(" ".join(list(claims["limits"].values())[1:]) + "\n")
            with self.assertRaises(QualificationError):
                driver.lint_documents(root, claims, False)
            (root / driver.LIMITS_DOCUMENT).write_text(" ".join(claims["limits"].values()) + "\n")
            (root / "README.md").write_text("No Stage 10 release decision has been signed. Nothing is complete\nuntil the release decision has been signed.\n")
            driver.lint_documents(root, claims, False)
            (root / "README.md").write_text("The Stage 10 release decision\nHAS been signed.\n")
            with self.assertRaisesRegex(QualificationError, "README.md"):
                driver.lint_documents(root, claims, False)
            driver.lint_documents(root, claims, True)
            self.assertIsNone(driver.asserted_completion("Stage 10 is not complete. The soak has not completed.", claims))
            self.assertEqual(driver.asserted_completion("Done: Stage 10 is complete.", claims), "stage 10 is complete")

    def test_foreign_decision_never_names_the_candidate(self) -> None:
        driver = self.driver()
        with tempfile.TemporaryDirectory(prefix="agenc-foreign-test-") as temporary:
            directory = Path(temporary) / "candidate"
            directory.mkdir()
            candidate = SyntheticCandidate(self.ROOT, directory)
            public = Path(temporary) / "public.pem"
            public.write_bytes(b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n")
            decision = driver.foreign_decision(candidate.record, "x86_64-unknown-linux-gnu", public)
            self.assertEqual(decision["source"]["commit"], "0" * 40)
            self.assertNotEqual(decision["candidate_sha256"], candidate.hash)
            self.assertNotEqual(decision["source"], candidate.record["source"])
            self.assertEqual(decision["targets"], ["x86_64-unknown-linux-gnu"])
            self.assertEqual(decision["artifacts"][0]["sha256"], candidate.record["artifacts"][1]["sha256"])
            self.assertEqual(decision["public_key_sha256"], file_digest(public))


if __name__ == "__main__":
    unittest.main()
