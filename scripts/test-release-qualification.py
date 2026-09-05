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

    def __init__(self, root: Path, directory: Path) -> None:
        from release_qualification.policy import fuzz_jobs as jobs_of, load_policy as policy_of, policy_identity

        self.root = root
        self.directory = directory
        policy = policy_of(root, require_drivers=False)
        self.jobs = policy["job"] + jobs_of(root)
        artifacts = []
        for target in ("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"):
            build = self.synthetic_build(target)
            artifacts.append({"target": target, "path": f"artifacts/{target}/agenc-ircd",
                              "sha256": build["binary_sha256"], "build_record": f"artifacts/{target}/build.json",
                              "build_record_sha256": digest(canonical(build))})
        self.record = {"schema_version": 1, "created_at": timestamp_now(), "source": self.SOURCE,
                       "policy": policy_identity(root), "jobs": self.jobs, "artifacts": artifacts,
                       "claims": ["core-v1", "federated-v1", "encrypted-v1", "wss", "history"]}
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
                    "latency_classes": ["admission", "durable_mutation", "fanout", "message", "opaque", "snapshot"], "hardware": "synthetic"}
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

    def run_job(self, job_id: str, *, resume: bool = False, exit_code: int = 0, interrupt: bool = False):
        from unittest import mock

        from release_qualification import candidate as candidate_module
        from release_qualification.candidate import run_job

        with mock.patch.object(candidate_module, "execute", self.candidate.fake_execute(exit_code=exit_code, interrupt=interrupt)):
            return run_job(self.root, self.directory, job_id, resume=resume)

    def status(self):
        from release_qualification.candidate import validate_candidate
        from release_qualification.verify import status

        return status(self.directory, validate_candidate(self.root, self.directory, check_source=False))

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


if __name__ == "__main__":
    unittest.main()
