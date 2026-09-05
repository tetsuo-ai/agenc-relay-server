"""Detached Ed25519 release decisions, verified before publication."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .candidate import validate_candidate
from .records import QualificationError, canonical, digest, file_digest, read_bytes, read_record, sync_directory, utc_now, write_once
from .verify import status

DOMAIN = b"agenc-ircd release decision v1\x00"


def close(root: Path, directory: Path, key: Path, public_key: Path, claims: list[str], review: Path | None) -> dict[str, Any]:
    candidate = validate_candidate(root, directory)
    summary = status(directory, candidate)
    if not summary["ready"]:
        raise QualificationError("release decision requires all native jobs to pass without unresolved failed or interrupted attempts")
    if not claims or len(claims) != len(set(claims)) or any(claim not in candidate["claims"] for claim in claims):
        raise QualificationError("release claims must be a nonempty subset of compiled profiles")
    review_hash = None
    review_files = {}
    if "encrypted-v1" in claims:
        if review is None:
            raise QualificationError("encrypted-v1 requires the completed S08-039 external review record")
        review_record = read_record(review)
        from .records import require_fields, timestamp
        require_fields(review_record, {"task", "source_commit", "reviewer", "completed_at", "open_findings", "report", "report_sha256", "remediation_verified"}, "external review")
        if review_record["task"] != "S08-039" or review_record["source_commit"] != candidate["source"]["commit"] or not isinstance(review_record["reviewer"], str) or not review_record["reviewer"].strip() or type(review_record["open_findings"]) is not int or review_record["open_findings"] != 0 or review_record["remediation_verified"] is not True:
            raise QualificationError("external review scope or remediation is incomplete")
        timestamp(review_record["completed_at"])
        from .records import safe_path
        report = safe_path(review.parent, review_record["report"])
        if file_digest(report) != review_record["report_sha256"]:
            raise QualificationError("external review report differs")
        review_hash = digest(canonical(review_record))
        review_files = {"external-review.json": canonical(review_record), "external-review-report": read_bytes(report)}
    decision = {"schema_version": 1, "candidate_sha256": digest(canonical(candidate)),
                "source": candidate["source"], "claims": sorted(claims), "decided_at": utc_now(),
                "artifacts": candidate["artifacts"], "qualification_sha256": digest(canonical(summary)),
                "external_review_sha256": review_hash, "public_key_sha256": file_digest(public_key)}
    payload = DOMAIN + canonical(decision)
    with tempfile.TemporaryDirectory(prefix="agenc-release-sign-") as temporary:
        message = Path(temporary) / "decision"
        signature = Path(temporary) / "signature"
        message.write_bytes(payload)
        try:
            public_der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            if len(public_der) != 44 or not public_der.startswith(bytes.fromhex("302a300506032b6570032100")):
                raise QualificationError("the release public key must be Ed25519")
            subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(message), "-out", str(signature)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            encoded = read_bytes(signature, 64)
            if len(encoded) != 64:
                raise QualificationError("release signer did not produce an Ed25519 signature")
            subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_key), "-in", str(message), "-sigfile", str(signature)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        except (subprocess.SubprocessError, OSError) as error:
            raise QualificationError("release signing or public-key verification failed") from error
    # Publish the decision as one directory, so a failed signer or interrupted
    # write never leaves a partially installed release decision.
    final = directory / "decision"
    if final.exists():
        raise QualificationError("this candidate already has a release decision")
    with tempfile.TemporaryDirectory(prefix=".decision-", dir=directory) as temporary:
        staged = Path(temporary) / "complete"
        files = {"qualification.json": canonical(summary), "release.json": canonical(decision),
                 "release.sig": encoded, "release-public.pem": read_bytes(public_key, 4096), **review_files}
        for name, data in files.items():
            write_once(staged / name, data)
        staged.rename(final)
        sync_directory(directory)
    return decision
