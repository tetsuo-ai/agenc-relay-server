#!/usr/bin/env python3
"""Check the candidate binary's metadata, the documented limits, and decision inspection.

The binary's `version --json` and `conformance --json` output is compared
field by field with the candidate build record, the frozen specification
baseline, and the closed claim set in conformance/release-claims.toml. The
ledgers are linted for the limit statements they must keep and for claims of
completion they may not make before a decision exists. Finally the binary's
own decision inspection is exercised with disposable keys: it must refuse a
decision under an untrusted key, and a verified decision for another source
must grant it nothing. No disposable decision ever names this candidate.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

from release_qualification.driver import command, context, finish
from release_qualification.policy import load_policy
from release_qualification.process import execute
from release_qualification.records import CLAIMS, QualificationError, canonical, digest, read_bytes, read_record, safe_path, write_once
from release_qualification.signing import DOMAIN, sign_payload

CLAIMS_PATH = "conformance/release-claims.toml"
BASELINE_PATH = "conformance/spec-baseline.toml"
LIMITS_DOCUMENT = "docs/stage-10-qualification.md"
STORAGE_SCHEMA_GENERATION = 2
COMPILED = {"core-v1": True, "federated-v1": True, "encrypted-v1": True, "history": True, "wss": True}
FOREIGN_COMMIT = "0" * 40
WHITESPACE = re.compile(r"\s+")
SENTENCE_END = re.compile(r"(?<=[.!?])\s+|\n")


def load_claims_policy(root: Path, policy: dict[str, Any]) -> dict[str, Any]:
    try:
        claims = tomllib.loads(read_bytes(root / CLAIMS_PATH).decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise QualificationError("release claims policy is not valid TOML") from error
    if set(claims) != {"schema_version", "documents", "completion_phrases", "negations", "limits", "claim"} or claims["schema_version"] != 1:
        raise QualificationError("release claims policy has an unknown shape")
    negations = claims["negations"]
    if not isinstance(negations, list) or not negations or any(not isinstance(word, str) or not word.strip() for word in negations):
        raise QualificationError("release claims policy needs its negation words")
    documents = claims["documents"]
    if not isinstance(documents, list) or not documents or any(not isinstance(name, str) or not (root / name).is_file() for name in documents):
        raise QualificationError("release claims policy names a missing document")
    if LIMITS_DOCUMENT not in documents:
        raise QualificationError("release claims policy must lint the qualification document")
    phrases = claims["completion_phrases"]
    if not isinstance(phrases, list) or not phrases or any(not isinstance(phrase, str) or not phrase.strip() for phrase in phrases):
        raise QualificationError("release claims policy needs completion phrases")
    limits = claims["limits"]
    if not isinstance(limits, dict) or not limits or any(not isinstance(text, str) or not text.strip() for text in limits.values()):
        raise QualificationError("release claims policy needs limit statements")
    required_jobs = sorted([job["id"] for job in policy["job"]] + ["fuzz.*"])
    seen: set[str] = set()
    for claim in claims["claim"]:
        fields = {"id", "jobs", "limits"} | ({"external_review"} if claim.get("id") == "encrypted-v1" else set())
        if not isinstance(claim, dict) or set(claim) != fields or claim["id"] not in CLAIMS or claim["id"] in seen:
            raise QualificationError("release claims policy has an unknown or repeated claim")
        seen.add(claim["id"])
        if sorted(claim["jobs"]) != required_jobs:
            raise QualificationError(f"claim {claim['id']} does not require every qualification job")
        if not claim["limits"] or any(name not in limits for name in claim["limits"]):
            raise QualificationError(f"claim {claim['id']} names an unknown limit statement")
        if claim["id"] == "encrypted-v1" and claim["external_review"] != policy["external_review_task"]:
            raise QualificationError("encrypted-v1 must require the external review task")
    if seen != set(CLAIMS):
        raise QualificationError("release claims policy must cover every compiled claim")
    return claims


def expected_metadata(candidate: dict[str, Any], build: dict[str, Any], target: str) -> dict[str, Any]:
    """The build-record view of what the binary must report about itself."""
    compiler = build["tools"]["rustc"].splitlines()[0] if isinstance(build["tools"].get("rustc"), str) else None
    return {"schema_version": 1, "name": "agenc-ircd", "source_commit": candidate["source"]["commit"],
            "source_sha256": candidate["source"]["source_sha256"], "cargo_lock_sha256": candidate["source"]["lock_sha256"],
            "target": target, "compiler": compiler, "features": {name: True for name in build["features"]},
            "storage_schema_generation": STORAGE_SCHEMA_GENERATION}


def load_baseline(root: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(read_bytes(root / BASELINE_PATH).decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise QualificationError("specification baseline is not valid TOML") from error


def expected_conformance(baseline: dict[str, Any]) -> dict[str, Any]:
    documents = {record["role"]: record["sha256"] for record in baseline["artifacts"]}
    profiles = baseline["profiles"]
    return {"architecture_document_sha256": documents["architecture"], "encrypted_document_sha256": documents["e2ee-companion"],
            "base_profile_sha256": profiles["base_federation_v1"]["sha256"], "encrypted_profile_sha256": profiles["e2ee_mls_v1"]["sha256"],
            "profiles": {"base_sha256_base64url": profiles["base_federation_v1"]["base64url"],
                         "encrypted_sha256_base64url": profiles["e2ee_mls_v1"]["base64url"]},
            "compiled": COMPILED, "qualified_claims": [], "qualification": "requires detached signed release decision"}


def check_metadata(metadata: dict[str, Any], expected: dict[str, Any], name: str) -> None:
    for field, value in expected.items():
        if metadata.get(field) != value:
            raise QualificationError(f"{name} metadata differs from its candidate: {field}")


def normalize(text: str) -> str:
    return WHITESPACE.sub(" ", text).strip()


def sentences(text: str) -> list[str]:
    """Lowercased sentences of a normalized document, split at sentence punctuation."""
    return [sentence.strip().lower() for sentence in SENTENCE_END.split(normalize(text)) if sentence.strip()]


def asserted_completion(document: str, claims: dict[str, Any]) -> str | None:
    """The first completion phrase a sentence asserts without one of the recorded negations."""
    phrases = [normalize(phrase).lower() for phrase in claims["completion_phrases"]]
    negations = [negation.lower() for negation in claims["negations"]]
    for sentence in sentences(document):
        padded = f" {sentence} "
        if any(negation in padded for negation in negations):
            continue
        for phrase in phrases:
            if phrase in sentence:
                return phrase
    return None


def lint_documents(root: Path, claims: dict[str, Any], decided: bool) -> dict[str, Any]:
    """Limit statements must be present; completion claims must wait for a decision."""
    qualification = normalize(read_bytes(root / LIMITS_DOCUMENT).decode("utf-8"))
    for name, sentence in claims["limits"].items():
        if normalize(sentence) not in qualification:
            raise QualificationError(f"qualification document lost its {name} limit statement")
    checked = []
    for relative in claims["documents"]:
        text = read_bytes(root / relative).decode("utf-8")
        if not decided:
            phrase = asserted_completion(text, claims)
            if phrase is not None:
                raise QualificationError(f"{relative} asserts completion before a decision exists: {phrase!r}")
        checked.append(relative)
    return {"limit_statements": sorted(claims["limits"]), "documents": checked, "decision_present": decided}


def disposable_keys(directory: Path) -> tuple[Path, Path, Path]:
    """Two throwaway Ed25519 pairs; the private keys never leave this attempt."""
    directory.mkdir(mode=0o700, parents=True)
    pairs = []
    for name in ("signer", "untrusted"):
        private = directory / f"{name}.key"
        public = directory / f"{name}-public.pem"
        try:
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            raise QualificationError("could not create disposable inspection keys") from error
        pairs.append((private, public))
    return pairs[0][0], pairs[0][1], pairs[1][1]


def foreign_decision(candidate: dict[str, Any], target: str, public_key: Path) -> dict[str, Any]:
    """A decision for a source this candidate is not; it can never cover the binary."""
    artifact = next(item for item in candidate["artifacts"] if item["target"] == target)
    source = {"commit": FOREIGN_COMMIT, "source_sha256": digest(b"foreign source\n"), "lock_sha256": digest(b"foreign lock\n")}
    return {"schema_version": 1, "candidate_sha256": digest(b"foreign candidate\n"), "source": source, "claims": ["core-v1"],
            "decided_at": "2026-01-01T00:00:00Z", "targets": [target], "artifacts": [dict(artifact)],
            "qualification_sha256": digest(b"foreign qualification\n"), "external_review_sha256": None,
            "public_key_sha256": digest(read_bytes(public_key, 4096))}


def inspection_facts(root: Path, attempt: Path, binary: Path, candidate: dict[str, Any], target: str) -> dict[str, Any]:
    work = attempt / "work"
    signer, signer_public, untrusted_public = disposable_keys(work / "keys")
    decision_directory = work / "foreign-decision"
    decision_directory.mkdir(mode=0o700)
    decision = foreign_decision(candidate, target, signer_public)
    payload = canonical(decision)
    write_once(decision_directory / "release.json", payload)
    write_once(decision_directory / "release.sig", sign_payload(DOMAIN + payload, signer, signer_public))
    evidence = attempt / "evidence"
    environment = dict(os.environ)
    refused = execute([str(binary), "conformance", "--json", "--release-decision", str(decision_directory), "--trusted-public-key", str(untrusted_public)],
                      root, environment, evidence / "decision-untrusted.log", 60)
    if refused["exit_code"] == 0 or refused["failure"] is not None:
        raise QualificationError("binary accepted a release decision under an untrusted key")
    accepted = execute([str(binary), "conformance", "--json", "--release-decision", str(decision_directory), "--trusted-public-key", str(signer_public)],
                       root, environment, evidence / "decision-foreign.log", 60)
    if accepted["exit_code"] != 0 or accepted["failure"] is not None:
        raise QualificationError("binary could not inspect a well-signed decision")
    metadata = json.loads(read_bytes(evidence / "decision-foreign.log"))
    if metadata.get("qualified_claims") != [] or metadata.get("qualification") != "signed release decision names another source commit" or "release_decision" in metadata:
        raise QualificationError("binary granted claims from a decision for another source")
    write_once(evidence / "decision-inspection.json", canonical({"untrusted_key_refused": True, "foreign_source_excluded": True,
                                                                  "signer_public_sha256": digest(read_bytes(signer_public, 4096)),
                                                                  "note": "disposable keys generated for this attempt; no decision names this candidate"}))
    return {"untrusted_key_refused": True, "foreign_source_excluded": True}


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    candidate, directory, attempt, target = context(root)
    policy = load_policy(root)
    claims = load_claims_policy(root, policy)
    artifact = next(item for item in candidate["artifacts"] if item["target"] == target)
    binary = safe_path(directory, artifact["path"])
    build = read_record(safe_path(directory, artifact["build_record"]))
    expected = expected_metadata(candidate, build, target)
    for name in ("version", "conformance"):
        command(root, attempt, name, [str(binary), name, "--json"], 30)
        metadata = json.loads(read_bytes(attempt / f"evidence/{name}.log"))
        check_metadata(metadata, expected, name)
        if name == "conformance":
            check_metadata(metadata, expected_conformance(load_baseline(root)), name)
            if binary.stat().st_size == 0 or metadata.get("storage_qualification", {}).get("tuples") == []:
                raise QualificationError("binary embeds no storage qualification tuple")
    decided = (directory / "decision").is_dir()
    lint = lint_documents(root, claims, decided)
    inspection = inspection_facts(root, attempt, binary, candidate, target)
    write_once(attempt / "evidence/claims.json", canonical({"target": target, "expected": expected, "lint": lint, "inspection": inspection,
                                                             "claims": sorted(claim["id"] for claim in claims["claim"])}))
    finish(attempt, "claims", {"binary_identity": True, "separate_claims": True, "privacy_limits": True,
                               "documentation_current": True, "decision_inspection": True})


if __name__ == "__main__":
    try:
        main()
    except (QualificationError, OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        print(f"release claims: {error}", file=sys.stderr)
        sys.exit(1)
