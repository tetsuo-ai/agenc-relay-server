"""Verify release decisions with a caller-supplied trust anchor."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .candidate import validate_candidate
from .records import (QualificationError, canonical, digest, file_digest, read_bytes,
                      read_record, require_fields, safe_path, target_scope, timestamp)
from .signing import DOMAIN
from .verify import status

DECISION_FIELDS = {"schema_version", "candidate_sha256", "source", "claims", "decided_at", "targets",
                   "artifacts", "qualification_sha256", "external_review_sha256", "public_key_sha256"}


def verify_signature(payload: bytes, signature: bytes, public_key: Path) -> None:
    if len(signature) != 64:
        raise QualificationError("release signature must contain exactly 64 bytes")
    key_bytes = read_bytes(public_key, 4096)
    with tempfile.TemporaryDirectory(prefix="agenc-decision-verify-") as temporary:
        directory = Path(temporary)
        key = directory / "public.pem"
        key.write_bytes(key_bytes)
        message = directory / "message"
        message.write_bytes(payload)
        signed = directory / "signature"
        signed.write_bytes(signature)
        try:
            der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(key), "-outform", "DER"],
                                          stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            if len(der) != 44 or not der.startswith(bytes.fromhex("302a300506032b6570032100")):
                raise QualificationError("release trust anchor must be Ed25519")
            subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(key),
                            "-in", str(message), "-sigfile", str(signed)], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            raise QualificationError("release signature verification failed") from error


def verify_decision(root: Path, directory: Path, public_key: Path) -> dict[str, Any]:
    decision_directory = safe_path(directory, "decision")
    decision = read_record(decision_directory / "release.json")
    require_fields(decision, DECISION_FIELDS, "release decision")
    if type(decision["schema_version"]) is not int or decision["schema_version"] != 1:
        raise QualificationError("unknown release decision schema")
    # The key shipped beside a signature is evidence, never its trust anchor.
    if file_digest(public_key) != decision["public_key_sha256"]:
        raise QualificationError("release decision was not signed by the supplied trust anchor")
    verify_signature(DOMAIN + canonical(decision), read_bytes(decision_directory / "release.sig", 64), public_key)
    candidate = validate_candidate(root, directory, check_source=False)
    scope = target_scope(candidate["targets"], decision["targets"])
    if decision["targets"] != scope:
        raise QualificationError("release decision targets are not in canonical order")
    covered = [artifact for artifact in candidate["artifacts"] if artifact["target"] in scope]
    if decision["candidate_sha256"] != digest(canonical(candidate)) or decision["source"] != candidate["source"] or decision["artifacts"] != covered:
        raise QualificationError("release decision belongs to another candidate")
    claims = decision["claims"]
    if not isinstance(claims, list) or not claims or any(not isinstance(claim, str) for claim in claims) or claims != sorted(set(claims)) or any(claim not in candidate["claims"] for claim in claims):
        raise QualificationError("invalid qualified release claims")
    summary = status(directory, candidate, scope)
    if not summary["ready"] or decision["qualification_sha256"] != digest(canonical(summary)) or read_record(decision_directory / "qualification.json") != summary:
        raise QualificationError("release qualification is incomplete or differs from the signed decision")
    decided_at = timestamp(decision["decided_at"])
    for relative in summary["attempts"]:
        if timestamp(read_record(safe_path(directory, relative) / "result.json")["finished_at"]) > decided_at:
            raise QualificationError("release decision predates its evidence")
    if "encrypted-v1" in claims:
        review = read_record(decision_directory / "external-review.json")
        if digest(canonical(review)) != decision["external_review_sha256"] or file_digest(decision_directory / "external-review-report") != review["report_sha256"]:
            raise QualificationError("external review differs from the signed decision")
        if review["source_commit"] != candidate["source"]["commit"] or review["task"] != "S08-039" or review["remediation_verified"] is not True or type(review["open_findings"]) is not int or review["open_findings"] != 0 or timestamp(review["completed_at"]) > decided_at:
            raise QualificationError("external review does not close the encrypted profile")
    elif decision["external_review_sha256"] is not None:
        raise QualificationError("unexpected external review binding")
    return decision
