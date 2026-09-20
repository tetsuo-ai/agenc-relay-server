"""Detached Ed25519 release decisions, verified before publication."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .candidate import validate_candidate
from .records import (QualificationError, canonical, digest, file_digest, read_bytes,
                      sync_directory, target_scope, utc_now, write_once)
from .verify import status

# The daemon verifies the same bytes under agenc_ircd_crypto's
# SignatureDomain::ReleaseDecision, whose direct-prefix label this is.
DOMAIN = b"agenc-chat release decision v1"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def sign_payload(payload: bytes, key: Path, public_key: Path) -> bytes:
    """Sign with openssl and verify with the matching public key before returning."""
    with tempfile.TemporaryDirectory(prefix="agenc-release-sign-") as temporary:
        message = Path(temporary) / "decision"
        signature = Path(temporary) / "signature"
        message.write_bytes(payload)
        try:
            public_der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            if len(public_der) != 44 or not public_der.startswith(ED25519_SPKI_PREFIX):
                raise QualificationError("the release public key must be Ed25519")
            subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(message), "-out", str(signature)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            encoded = read_bytes(signature, 64)
            if len(encoded) != 64:
                raise QualificationError("release signer did not produce an Ed25519 signature")
            subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_key), "-in", str(message), "-sigfile", str(signature)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        except (subprocess.SubprocessError, OSError) as error:
            raise QualificationError("release signing or public-key verification failed") from error
    return encoded


def decision_record(candidate: dict[str, Any], summary: dict[str, Any], claims: list[str], targets: list[str],
                    public_key: Path) -> dict[str, Any]:
    """The flat decision document the daemon's reader accepts."""
    return {"schema_version": 1, "candidate_sha256": digest(canonical(candidate)),
            "source": candidate["source"], "claims": sorted(claims), "decided_at": utc_now(), "targets": targets,
            "artifacts": [artifact for artifact in candidate["artifacts"] if artifact["target"] in targets],
            "qualification_sha256": digest(canonical(summary)), "public_key_sha256": file_digest(public_key)}


def close(root: Path, directory: Path, key: Path, public_key: Path, claims: list[str],
          targets: list[str] | None = None) -> dict[str, Any]:
    """Sign a decision for the selected targets once every job in that scope passed."""
    candidate = validate_candidate(root, directory)
    scope = target_scope(candidate["targets"], targets)
    summary = status(directory, candidate, scope)
    if not summary["ready"]:
        raise QualificationError("release decision requires all native jobs to pass without unresolved failed or interrupted attempts")
    if not claims or len(claims) != len(set(claims)) or any(claim not in candidate["claims"] for claim in claims):
        raise QualificationError("release claims must be a nonempty subset of compiled profiles")
    decision = decision_record(candidate, summary, claims, scope, public_key)
    encoded = sign_payload(DOMAIN + canonical(decision), key, public_key)
    # Publish the decision as one directory, so a failed signer or interrupted
    # write never leaves a partially installed release decision.
    final = directory / "decision"
    if final.exists():
        raise QualificationError("this candidate already has a release decision")
    with tempfile.TemporaryDirectory(prefix=".decision-", dir=directory) as temporary:
        staged = Path(temporary) / "complete"
        files = {"qualification.json": canonical(summary), "release.json": canonical(decision),
                 "release.sig": encoded, "release-public.pem": read_bytes(public_key, 4096)}
        for name, data in files.items():
            write_once(staged / name, data)
        staged.rename(final)
        sync_directory(directory)
    return decision
