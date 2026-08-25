#!/usr/bin/env python3
"""Generate and validate the normative requirement ledger."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

ARCHITECTURE_PATH = "docs/ircd-architecture-and-implementation-spec.md"
E2EE_PATH = "docs/irc-mls-e2ee-extension.md"
LEDGER_PATH = "conformance/requirements.toml"
BINDINGS_PATH = "conformance/requirement-bindings.toml"

CRATES = frozenset(
    {
        "agenc-ircd",
        "agenc-ircd-admin",
        "agenc-ircd-auth",
        "agenc-ircd-client-wire",
        "agenc-ircd-config",
        "agenc-ircd-crypto",
        "agenc-ircd-domain",
        "agenc-ircd-e2ee",
        "agenc-ircd-federation-wire",
        "agenc-ircd-runtime",
        "agenc-ircd-storage",
        "agenc-ircd-testkit",
        "agenc-ircd-types",
    }
)
TERMS = (
    "MUST NOT",
    "SHALL NOT",
    "SHOULD NOT",
    "NOT RECOMMENDED",
    "MUST",
    "REQUIRED",
    "SHALL",
    "SHOULD",
    "RECOMMENDED",
    "MAY",
)
TERM_RE = re.compile(
    r"(?<![A-Z0-9_])(" + "|".join(map(re.escape, TERMS)) + r")(?![A-Z0-9_])"
)
BOLD_TERM_RE = re.compile(r"\*\*(" + "|".join(map(re.escape, TERMS)) + r")\*\*")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$")
LIST_RE = re.compile(r"^\s*(?:[-*+] |\d+[.)] )(.*)$")
TABLE_DIVIDER_RE = re.compile(r"^\|?(?:\s*:?-{3,}:?\s*\|)+\s*$")
INVARIANT_RE = re.compile(
    r"^\|\s*`((?:TRN|ID|AUTH|PRV|STA|E2E|FED|DUR|CON|OPS)-\d{2})`\s*\|\s*(.*?)\s*\|$"
)
ID_RE = re.compile(r"(?:ARCH|E2EE)-(?:REQ-[0-9A-F]{20}|(?:TRN|ID|AUTH|PRV|STA|E2E|FED|DUR|CON|OPS)-\d{2})")
EVIDENCE_ID_RE = re.compile(r"EVID-(?:ARCH|E2EE)-(?:REQ-[0-9A-F]{20}|(?:TRN|ID|AUTH|PRV|STA|E2E|FED|DUR|CON|OPS)-\d{2})")
TASK_ID_RE = re.compile(r"S\d{2}-(?:\d{3}|900)")
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class LedgerError(ValueError):
    """A requirement-ledger validation failure."""


@dataclass(frozen=True)
class Block:
    """One Markdown block with stable source context."""

    text: str
    line: int
    section: str
    kind: str


@dataclass(frozen=True)
class SourceDocument:
    """One normative source and its ledger namespace."""

    key: str
    prefix: str
    path: str


DOCUMENTS = (
    SourceDocument("architecture", "ARCH", ARCHITECTURE_PATH),
    SourceDocument("e2ee-companion", "E2EE", E2EE_PATH),
)


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def normalize_text(text: str) -> str:
    """Normalize Markdown wrapping without changing normative spelling."""
    return " ".join(text.replace("**", "").split())


def normative_matches(text: str, *, bold_only: bool = False) -> list[re.Match[str]]:
    """Return each BCP 14 occurrence under the selected document rule."""
    pattern = BOLD_TERM_RE if bold_only else TERM_RE
    return list(pattern.finditer(text))


def normative_terms(text: str) -> tuple[str, ...]:
    """Return BCP 14 terms for Markdown block expansion."""
    return tuple(match.group(1) for match in normative_matches(text))


def markdown_blocks(text: str) -> list[Block]:
    """Collect paragraphs, list items, table rows, and normative code lines."""
    blocks: list[Block] = []
    pending: list[str] = []
    pending_line = 0
    pending_kind = "prose"
    section = "Document preface"
    in_fence = False

    def flush() -> None:
        nonlocal pending, pending_line, pending_kind
        if pending:
            blocks.append(
                Block("\n".join(pending), pending_line, section, pending_kind)
            )
        pending = []
        pending_line = 0
        pending_kind = "prose"

    for line_number, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            flush()
            in_fence = not in_fence
            continue
        if in_fence:
            if normative_terms(stripped):
                blocks.append(Block(stripped, line_number, section, "code"))
            continue

        heading = HEADING_RE.match(raw_line)
        if heading is not None:
            flush()
            section = normalize_text(heading.group(1))
            continue
        if not stripped:
            flush()
            continue
        if stripped.startswith("|"):
            flush()
            if TABLE_DIVIDER_RE.fullmatch(stripped) is None:
                blocks.append(Block(stripped, line_number, section, "table"))
            continue

        list_item = LIST_RE.match(raw_line)
        if list_item is not None:
            flush()
            pending = [list_item.group(1)]
            pending_line = line_number
            pending_kind = "list"
            continue

        if pending and pending_kind == "list" and raw_line[:1].isspace():
            pending.append(stripped)
            continue
        if pending and pending_kind == "list":
            flush()
        if not pending:
            pending_line = line_number
            pending_kind = "prose"
        pending.append(stripped)

    flush()
    return expand_normative_lists(blocks)


def expand_normative_lists(blocks: list[Block]) -> list[Block]:
    """Expand a `MUST:` list introduction into one statement per item."""
    expanded: list[Block] = []
    index = 0
    while index < len(blocks):
        block = blocks[index]
        terms = normative_terms(block.text)
        if block.kind == "prose" and terms and block.text.endswith(":"):
            following: list[Block] = []
            cursor = index + 1
            while cursor < len(blocks):
                candidate = blocks[cursor]
                if candidate.kind != "list" or candidate.section != block.section:
                    break
                following.append(candidate)
                cursor += 1
            if following:
                prefix = block.text[:-1]
                for item in following:
                    text = item.text if normative_terms(item.text) else f"{prefix} {item.text}"
                    expanded.append(Block(text, item.line, item.section, "list"))
                index = cursor
                continue
        expanded.append(block)
        index += 1
    return expanded


def split_sentences(block: Block) -> list[Block]:
    """Split prose into independently traceable normative sentences."""
    if block.kind in {"table", "code"}:
        return [block]
    boundaries = list(re.finditer(r"(?<=[.!?])\s+(?=[`*\[(A-Z0-9])", block.text))
    starts = [0] + [match.end() for match in boundaries]
    ends = [match.start() for match in boundaries] + [len(block.text)]
    sentences: list[Block] = []
    for start, end in zip(starts, ends, strict=True):
        part = block.text[start:end]
        if not part:
            continue
        line = block.line + block.text[:start].count("\n")
        sentences.append(Block(part, line, block.section, block.kind))
    return sentences


def section_number(section: str) -> int | None:
    """Return the leading numbered top-level section, when present."""
    match = re.match(r"(\d+)\.", section)
    return int(match.group(1)) if match is not None else None


def architecture_target(section: str, invariant: str | None = None) -> str:
    """Assign primary crate ownership for one architecture requirement."""
    if invariant is not None:
        prefix = invariant.split("-", 1)[0]
        return {
            "TRN": "agenc-ircd-client-wire",
            "ID": "agenc-ircd-types",
            "AUTH": "agenc-ircd-auth",
            "PRV": "agenc-ircd-domain",
            "STA": "agenc-ircd-domain",
            "E2E": "agenc-ircd-e2ee",
            "FED": "agenc-ircd-federation-wire",
            "DUR": "agenc-ircd-storage",
            "CON": "agenc-ircd-runtime",
            "OPS": "agenc-ircd-runtime",
        }[prefix]

    number = section_number(section)
    by_number = {
        1: "agenc-ircd",
        2: "agenc-ircd-types",
        3: "agenc-ircd-types",
        4: "agenc-ircd-config",
        5: "agenc-ircd-domain",
        6: "agenc-ircd-runtime",
        7: "agenc-ircd-types",
        8: "agenc-ircd-runtime",
        9: "agenc-ircd-client-wire",
        10: "agenc-ircd-client-wire",
        11: "agenc-ircd-auth",
        12: "agenc-ircd-domain",
        13: "agenc-ircd-domain",
        14: "agenc-ircd-domain",
        15: "agenc-ircd-domain",
        16: "agenc-ircd-domain",
        17: "agenc-ircd-storage",
        18: "agenc-ircd-e2ee",
        19: "agenc-ircd-runtime",
        20: "agenc-ircd-federation-wire",
        21: "agenc-ircd-runtime",
        22: "agenc-ircd-config",
        23: "agenc-ircd-storage",
        24: "agenc-ircd-runtime",
        25: "agenc-ircd-runtime",
        26: "agenc-ircd-types",
        27: "agenc-ircd-runtime",
        28: "agenc-ircd-testkit",
        29: "agenc-ircd",
        30: "agenc-ircd",
    }
    if number is not None:
        return by_number.get(number, "agenc-ircd-runtime")
    if section.startswith("Appendix A"):
        return "agenc-ircd-client-wire"
    if section.startswith("Appendix B"):
        return "agenc-ircd-federation-wire"
    if section.startswith("Appendix C"):
        return "agenc-ircd-config"
    if section.startswith(("Appendix D", "Appendix E")):
        return "agenc-ircd-testkit"
    return "agenc-ircd"


def e2ee_target(section: str) -> str:
    """Assign primary crate ownership for one companion requirement."""
    number = section_number(section)
    if number == 7:
        return "agenc-ircd-crypto"
    if number == 11:
        return "agenc-ircd-client-wire"
    if number == 12:
        return "agenc-ircd-federation-wire"
    if number == 21:
        return "agenc-ircd-testkit"
    return "agenc-ircd-e2ee"


def target_for(document: SourceDocument, section: str, invariant: str | None = None) -> str:
    """Return the one primary implementation crate for a requirement."""
    if document.key == "architecture":
        return architecture_target(section, invariant)
    return e2ee_target(section)


def task_for(document: SourceDocument, section: str, invariant: str | None = None) -> str:
    """Assign the implementation stage that first closes one requirement."""
    if invariant is not None:
        family = invariant.split("-", 1)[0]
        return {
            "TRN": "S06-900",
            "ID": "S03-900",
            "AUTH": "S04-900",
            "PRV": "S06-900",
            "STA": "S03-900",
            "E2E": "S08-900",
            "FED": "S07-900",
            "DUR": "S05-900",
            "CON": "S06-900",
            "OPS": "S10-900",
        }[family]
    if document.key == "e2ee-companion":
        if section.startswith("2.3"):
            return "S01-010"
        if section.startswith(("11.2", "11.10")):
            return "S01-009"
        return "S08-900"
    if section.startswith("7."):
        return "S01-005"
    if section.startswith("9.5"):
        return "S01-006"
    if section.startswith("Appendix A"):
        return "S01-001"
    if section.startswith("Appendix B"):
        return "S01-008"
    if section.startswith("30.3"):
        return "S01-010"
    if section.startswith("24.1"):
        return "S00-004"
    if section.startswith("24.3"):
        return "S00-005"
    if section.startswith("24.5"):
        return "S00-006"
    if section.startswith("28.1"):
        return "S00-007"
    if section.startswith("28.8"):
        return "S00-009"
    return "S10-900"


def record_for_statement(
    document: SourceDocument,
    source_hash: str,
    block: Block,
    term: str,
    term_ordinal: int,
    term_offset: int,
) -> dict[str, object]:
    """Create one deterministic ledger record for one normative occurrence."""
    normalized = normalize_text(block.text)
    text_hash = sha256_bytes(normalized.encode("utf-8"))
    stable_material = (
        f"{document.key}\0{block.section}\0{normalized}\0{term}\0{term_ordinal}"
    ).encode("utf-8")
    identifier = f"{document.prefix}-REQ-{sha256_bytes(stable_material)[:20].upper()}"
    return {
        "id": identifier,
        "kind": "bcp14",
        "normative_terms": [term],
        "document": document.key,
        "source_section": block.section,
        "source_line": block.line + block.text[:term_offset].count("\n"),
        "source_sha256": source_hash,
        "text_sha256": text_hash,
        "text": normalized,
        "applicable": True,
    }


def record_for_invariant(
    document: SourceDocument,
    source_hash: str,
    block: Block,
    invariant: str,
    text: str,
) -> dict[str, object]:
    """Create one deterministic ledger record for a Section-27 invariant."""
    normalized = normalize_text(text)
    identifier = f"ARCH-{invariant}"
    return {
        "id": identifier,
        "kind": "invariant",
        "normative_terms": ["INVARIANT"],
        "document": document.key,
        "source_section": block.section,
        "source_line": block.line,
        "source_sha256": source_hash,
        "text_sha256": sha256_bytes(normalized.encode("utf-8")),
        "text": normalized,
        "applicable": True,
    }


def extract(root: Path) -> tuple[list[dict[str, object]], dict[str, str]]:
    """Extract every BCP 14 statement and every Section-27 invariant."""
    records: list[dict[str, object]] = []
    source_hashes: dict[str, str] = {}
    for document in DOCUMENTS:
        path = root / document.path
        raw = path.read_bytes()
        source_hash = sha256_bytes(raw)
        source_hashes[document.key] = source_hash
        text = raw.decode("utf-8")
        for block in markdown_blocks(text):
            invariant_match = INVARIANT_RE.fullmatch(block.text)
            if document.key == "architecture" and invariant_match is not None:
                records.append(
                    record_for_invariant(
                        document,
                        source_hash,
                        block,
                        invariant_match.group(1),
                        invariant_match.group(2),
                    )
                )
                continue
            for sentence in split_sentences(block):
                matches = normative_matches(
                    sentence.text,
                    bold_only=document.key == "e2ee-companion",
                )
                if not matches:
                    continue
                if normalize_text(sentence.text).startswith("The key words MUST, MUST NOT"):
                    continue
                term_counts: dict[str, int] = {}
                for match in matches:
                    term = match.group(1)
                    ordinal = term_counts.get(term, 0)
                    term_counts[term] = ordinal + 1
                    records.append(
                        record_for_statement(
                            document,
                            source_hash,
                            sentence,
                            term,
                            ordinal,
                            match.start(),
                        )
                    )

    records.sort(key=lambda item: (str(item["document"]), int(item["source_line"]), str(item["id"])))
    identifiers = [str(record["id"]) for record in records]
    duplicate_ids = sorted({identifier for identifier in identifiers if identifiers.count(identifier) > 1})
    if duplicate_ids:
        raise LedgerError(f"stable requirement ID collision: {', '.join(duplicate_ids)}")
    return records, source_hashes


def quote(value: str) -> str:
    """Render one TOML basic string with JSON-compatible escaping."""
    return json.dumps(value, ensure_ascii=False)


def default_binding(record: dict[str, object]) -> dict[str, object]:
    """Create the initial reviewed-binding shape for one extracted record."""
    document_key = str(record["document"])
    document = next(item for item in DOCUMENTS if item.key == document_key)
    identifier = str(record["id"])
    invariant = identifier.removeprefix("ARCH-") if record["kind"] == "invariant" else None
    section = str(record["source_section"])
    task_id = task_for(document, section, invariant)
    return {
        "id": identifier,
        "target_crates": [target_for(document, section, invariant)],
        "task_ids": [task_id],
        "evidence_ids": [f"EVID-{identifier}"],
        "status": "implemented" if task_id.startswith("S00-") else "unimplemented",
    }


def render_bindings(bindings: list[dict[str, object]]) -> str:
    """Render reviewed implementation bindings in canonical TOML order."""
    lines = [
        "# Reviewed implementation ownership; normative text remains generated separately.",
        "schema_version = 1",
        f"binding_count = {len(bindings)}",
        "",
    ]
    for binding in sorted(bindings, key=lambda item: str(item["id"])):
        lines.append("[[binding]]")
        for field in ("id", "target_crates", "task_ids", "evidence_ids", "status"):
            value = binding[field]
            if isinstance(value, str):
                rendered = quote(value)
            elif isinstance(value, list):
                rendered = "[" + ", ".join(quote(str(item)) for item in value) + "]"
            else:
                raise LedgerError(f"cannot render binding field {field!r}")
            lines.append(f"{field} = {rendered}")
        lines.append("")
    return "\n".join(lines)


def load_bindings(path: Path) -> dict[str, object]:
    """Load the reviewed requirement-binding overlay."""
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise LedgerError(f"cannot read requirement bindings: {error}") from error


def validate_bindings(
    data: dict[str, object], records: list[dict[str, object]]
) -> list[dict[str, object]]:
    """Validate complete binding coverage without permitting waivers."""
    if set(data) != {"schema_version", "binding_count", "binding"}:
        raise LedgerError("requirement bindings have an invalid top-level schema")
    if data.get("schema_version") != 1:
        raise LedgerError("requirement binding schema_version must be 1")
    raw_bindings = data.get("binding")
    if not isinstance(raw_bindings, list) or data.get("binding_count") != len(raw_bindings):
        raise LedgerError("requirement binding_count does not match its array")
    expected_ids = {str(record["id"]) for record in records}
    by_id: dict[str, dict[str, object]] = {}
    required_fields = {"id", "target_crates", "task_ids", "evidence_ids", "status"}
    for index, raw_binding in enumerate(raw_bindings):
        if not isinstance(raw_binding, dict) or set(raw_binding) != required_fields:
            raise LedgerError(f"requirement binding {index} has invalid fields")
        identifier = raw_binding.get("id")
        if not isinstance(identifier, str) or ID_RE.fullmatch(identifier) is None:
            raise LedgerError(f"requirement binding {index} has an invalid ID")
        if identifier in by_id:
            raise LedgerError(f"duplicate requirement binding: {identifier}")
        targets = raw_binding.get("target_crates")
        if (
            not isinstance(targets, list)
            or not targets
            or targets != sorted(set(map(str, targets)))
            or any(target not in CRATES for target in targets)
        ):
            raise LedgerError(f"{identifier} has invalid target crates")
        tasks = raw_binding.get("task_ids")
        if (
            not isinstance(tasks, list)
            or not tasks
            or tasks != sorted(set(map(str, tasks)))
            or any(not isinstance(task, str) or TASK_ID_RE.fullmatch(task) is None for task in tasks)
        ):
            raise LedgerError(f"{identifier} has invalid task IDs")
        evidence = raw_binding.get("evidence_ids")
        if (
            not isinstance(evidence, list)
            or not evidence
            or f"EVID-{identifier}" not in evidence
            or evidence != sorted(set(map(str, evidence)))
            or any(
                not isinstance(item, str) or EVIDENCE_ID_RE.fullmatch(item) is None
                for item in evidence
            )
        ):
            raise LedgerError(f"{identifier} has invalid evidence IDs")
        if raw_binding.get("status") not in {"implemented", "unimplemented"}:
            raise LedgerError(f"{identifier} has an invalid or waived status")
        by_id[identifier] = raw_binding
    missing = sorted(expected_ids - set(by_id))
    stale = sorted(set(by_id) - expected_ids)
    if missing or stale:
        raise LedgerError(f"requirement binding coverage differs; missing={missing}, stale={stale}")
    return [by_id[identifier] for identifier in sorted(by_id)]


def merge_bindings(
    records: list[dict[str, object]], bindings: list[dict[str, object]]
) -> list[dict[str, object]]:
    """Merge reviewed implementation metadata into extracted source records."""
    by_id = {str(binding["id"]): binding for binding in bindings}
    merged: list[dict[str, object]] = []
    for record in records:
        binding = by_id[str(record["id"])]
        candidate = dict(record)
        for field in ("target_crates", "task_ids", "evidence_ids", "status"):
            candidate[field] = copy.deepcopy(binding[field])
        merged.append(candidate)
    return merged


def render(records: list[dict[str, object]], source_hashes: dict[str, str]) -> str:
    """Render a deterministic TOML ledger."""
    lines = [
        "# Generated by scripts/requirements.py; do not edit by hand.",
        "schema_version = 1",
        'generated_by = "scripts/requirements.py"',
        f"requirement_count = {len(records)}",
        f"architecture_sha256 = {quote(source_hashes['architecture'])}",
        f"e2ee_companion_sha256 = {quote(source_hashes['e2ee-companion'])}",
        "",
    ]
    field_order = (
        "id",
        "kind",
        "normative_terms",
        "document",
        "source_section",
        "source_line",
        "source_sha256",
        "text_sha256",
        "text",
        "target_crates",
        "task_ids",
        "evidence_ids",
        "status",
        "applicable",
    )
    for record in records:
        lines.append("[[requirement]]")
        for field in field_order:
            value = record[field]
            if isinstance(value, str):
                rendered = quote(value)
            elif isinstance(value, bool):
                rendered = "true" if value else "false"
            elif isinstance(value, int):
                rendered = str(value)
            elif isinstance(value, list):
                rendered = "[" + ", ".join(quote(str(item)) for item in value) + "]"
            else:
                raise LedgerError(f"cannot render field {field!r}")
            lines.append(f"{field} = {rendered}")
        lines.append("")
    return "\n".join(lines)


def load_ledger(path: Path) -> dict[str, object]:
    """Load the generated TOML ledger."""
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise LedgerError(f"cannot read requirement ledger: {error}") from error


def validate_data(
    ledger: dict[str, object],
    expected: list[dict[str, object]],
    source_hashes: dict[str, str],
) -> None:
    """Validate structure and exact source coverage."""
    errors: list[str] = []
    if ledger.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if ledger.get("generated_by") != "scripts/requirements.py":
        errors.append("generated_by is not the authoritative generator")
    if ledger.get("architecture_sha256") != source_hashes["architecture"]:
        errors.append("architecture source hash is stale")
    if ledger.get("e2ee_companion_sha256") != source_hashes["e2ee-companion"]:
        errors.append("E2EE companion source hash is stale")

    raw_records = ledger.get("requirement")
    if not isinstance(raw_records, list):
        raise LedgerError("requirement must be an array of tables")
    if ledger.get("requirement_count") != len(raw_records):
        errors.append("requirement_count does not equal the record count")

    actual_by_id: dict[str, dict[str, object]] = {}
    evidence_owner: dict[str, str] = {}
    required_fields = set(expected[0]) if expected else set()
    for index, raw_record in enumerate(raw_records):
        if not isinstance(raw_record, dict):
            errors.append(f"requirement record {index} is not a table")
            continue
        record = raw_record
        identifier = record.get("id")
        if not isinstance(identifier, str) or ID_RE.fullmatch(identifier) is None:
            errors.append(f"requirement record {index} has an invalid ID")
            continue
        if identifier in actual_by_id:
            errors.append(f"duplicate requirement ID: {identifier}")
        actual_by_id[identifier] = record
        if set(record) != required_fields:
            errors.append(f"{identifier} fields differ from the closed schema")
        source_hash = record.get("source_sha256")
        document = record.get("document")
        if not isinstance(source_hash, str) or SHA256_RE.fullmatch(source_hash) is None:
            errors.append(f"{identifier} has an invalid source hash")
        elif source_hash != source_hashes.get(str(document)):
            errors.append(f"{identifier} has a stale source hash")
        text = record.get("text")
        text_hash = record.get("text_sha256")
        if not isinstance(text, str) or not text:
            errors.append(f"{identifier} has empty requirement text")
        elif text_hash != sha256_bytes(text.encode("utf-8")):
            errors.append(f"{identifier} text hash does not match its text")
        targets = record.get("target_crates")
        if not isinstance(targets, list) or not targets or any(target not in CRATES for target in targets):
            errors.append(f"{identifier} has invalid target crates")
        tasks = record.get("task_ids")
        if (
            not isinstance(tasks, list)
            or not tasks
            or any(not isinstance(task, str) or TASK_ID_RE.fullmatch(task) is None for task in tasks)
        ):
            errors.append(f"{identifier} has invalid task IDs")
        if record.get("applicable") is not True:
            errors.append(f"{identifier} is not applicable")
        if record.get("status") not in {"implemented", "unimplemented"}:
            errors.append(f"{identifier} has an invalid or waived status")
        terms = record.get("normative_terms")
        if record.get("kind") == "bcp14" and (
            not isinstance(terms, list) or len(terms) != 1 or terms[0] not in TERMS
        ):
            errors.append(f"{identifier} does not represent exactly one normative occurrence")
        evidence_ids = record.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids:
            errors.append(f"{identifier} has no evidence ID")
            continue
        if f"EVID-{identifier}" not in evidence_ids:
            errors.append(f"{identifier} lacks its stable evidence ID")
        for evidence_id in evidence_ids:
            if not isinstance(evidence_id, str) or EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
                errors.append(f"{identifier} has an invalid evidence ID")
                continue
            previous = evidence_owner.get(evidence_id)
            if previous is not None and previous != identifier:
                errors.append(f"duplicate evidence ID {evidence_id} on {previous} and {identifier}")
            evidence_owner[evidence_id] = identifier

    expected_by_id = {str(record["id"]): record for record in expected}
    missing = sorted(set(expected_by_id) - set(actual_by_id))
    stale = sorted(set(actual_by_id) - set(expected_by_id))
    if missing:
        errors.append("unmapped normative requirements: " + ", ".join(missing))
    if stale:
        errors.append("stale requirement records: " + ", ".join(stale))
    for identifier in sorted(set(expected_by_id) & set(actual_by_id)):
        if actual_by_id[identifier] != expected_by_id[identifier]:
            errors.append(f"{identifier} does not exactly match its normative source mapping")

    if errors:
        raise LedgerError("; ".join(errors))


def validate(root: Path) -> int:
    """Validate the checked-in ledger and return its requirement count."""
    extracted, source_hashes = extract(root)
    binding_data = load_bindings(root / BINDINGS_PATH)
    bindings = validate_bindings(binding_data, extracted)
    expected = merge_bindings(extracted, bindings)
    ledger = load_ledger(root / LEDGER_PATH)
    validate_data(ledger, expected, source_hashes)
    expected_rendering = render(expected, source_hashes)
    actual_rendering = (root / LEDGER_PATH).read_text(encoding="utf-8")
    if actual_rendering != expected_rendering:
        raise LedgerError("ledger is structurally valid but not in canonical generated form")
    return len(expected)


def validate_stage(root: Path, stage: int) -> int:
    """Require every binding owned by one completed stage to be implemented."""
    extracted, _source_hashes = extract(root)
    bindings = validate_bindings(load_bindings(root / BINDINGS_PATH), extracted)
    prefix = f"S{stage:02d}-"
    owned = [
        binding
        for binding in bindings
        if any(str(task).startswith(prefix) for task in binding["task_ids"])
    ]
    incomplete = sorted(
        str(binding["id"])
        for binding in owned
        if binding["status"] != "implemented"
    )
    if incomplete:
        raise LedgerError(
            f"Stage {stage:02d} has unimplemented owned requirements: {', '.join(incomplete)}"
        )
    return len(owned)


def expect_rejection(
    label: str,
    ledger: dict[str, object],
    expected: list[dict[str, object]],
    source_hashes: dict[str, str],
    fragment: str,
) -> None:
    """Require one malformed fixture to reach the intended rejection branch."""
    try:
        validate_data(ledger, expected, source_hashes)
    except LedgerError as error:
        if fragment not in str(error):
            raise LedgerError(f"self-test {label!r} reached the wrong branch: {error}") from error
        return
    raise LedgerError(f"self-test {label!r} was accepted")


def self_test(root: Path) -> int:
    """Exercise every required negative validation category."""
    extracted, source_hashes = extract(root)
    bindings = validate_bindings(load_bindings(root / BINDINGS_PATH), extracted)
    expected = merge_bindings(extracted, bindings)
    valid = load_ledger(root / LEDGER_PATH)
    validate_data(valid, expected, source_hashes)
    cases = 0

    missing = copy.deepcopy(valid)
    missing["requirement"].pop()  # type: ignore[union-attr]
    missing["requirement_count"] = len(missing["requirement"])  # type: ignore[arg-type]
    expect_rejection("missing", missing, expected, source_hashes, "unmapped normative")
    cases += 1

    duplicate = copy.deepcopy(valid)
    duplicate["requirement"].append(copy.deepcopy(duplicate["requirement"][0]))  # type: ignore[union-attr,index]
    duplicate["requirement_count"] = len(duplicate["requirement"])  # type: ignore[arg-type]
    expect_rejection("duplicate ID", duplicate, expected, source_hashes, "duplicate requirement ID")
    cases += 1

    stale_hash = copy.deepcopy(valid)
    stale_hash["requirement"][0]["source_sha256"] = "0" * 64  # type: ignore[index]
    expect_rejection("stale hash", stale_hash, expected, source_hashes, "stale source hash")
    cases += 1

    bad_target = copy.deepcopy(valid)
    bad_target["requirement"][0]["target_crates"] = ["agenc-ircd-invalid"]  # type: ignore[index]
    expect_rejection("target", bad_target, expected, source_hashes, "invalid target crates")
    cases += 1

    missing_evidence = copy.deepcopy(valid)
    missing_evidence["requirement"][0]["evidence_ids"] = []  # type: ignore[index]
    expect_rejection("evidence", missing_evidence, expected, source_hashes, "no evidence ID")
    cases += 1

    waived = copy.deepcopy(valid)
    waived["requirement"][0]["status"] = "waived"  # type: ignore[index]
    expect_rejection("waiver", waived, expected, source_hashes, "invalid or waived")
    cases += 1

    changed_text = copy.deepcopy(valid)
    changed_text["requirement"][0]["text"] = "changed"  # type: ignore[index]
    expect_rejection("text hash", changed_text, expected, source_hashes, "text hash")
    cases += 1

    stale_record = copy.deepcopy(valid)
    extra = copy.deepcopy(stale_record["requirement"][0])  # type: ignore[index]
    extra["id"] = "ARCH-REQ-00000000000000000000"
    extra["evidence_ids"] = ["EVID-ARCH-REQ-00000000000000000000"]
    stale_record["requirement"].append(extra)  # type: ignore[union-attr]
    stale_record["requirement_count"] = len(stale_record["requirement"])  # type: ignore[arg-type]
    expect_rejection("stale record", stale_record, expected, source_hashes, "stale requirement")
    cases += 1

    duplicate_evidence = copy.deepcopy(valid)
    first = duplicate_evidence["requirement"][0]  # type: ignore[index]
    second = duplicate_evidence["requirement"][1]  # type: ignore[index]
    second["evidence_ids"] = first["evidence_ids"]  # type: ignore[index]
    expect_rejection("duplicate evidence", duplicate_evidence, expected, source_hashes, "duplicate evidence ID")
    cases += 1

    return cases


def fail(message: str) -> NoReturn:
    """Print a stable command-line error and exit unsuccessfully."""
    print(f"requirement ledger failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Dispatch generate, check, and negative self-test commands."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("generate", "generate-bindings", "check", "check-stage-zero", "check-stage-one", "self-test"),
    )
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "generate":
            extracted, source_hashes = extract(root)
            bindings = validate_bindings(load_bindings(root / BINDINGS_PATH), extracted)
            records = merge_bindings(extracted, bindings)
            (root / LEDGER_PATH).write_text(render(records, source_hashes), encoding="utf-8")
            print(f"requirement ledger: generated {len(records)} records")
        elif arguments.command == "generate-bindings":
            records, _source_hashes = extract(root)
            defaults = [default_binding(record) for record in records]
            (root / BINDINGS_PATH).write_text(render_bindings(defaults), encoding="utf-8")
            print(f"requirement bindings: generated {len(defaults)} records")
        elif arguments.command == "check":
            count = validate(root)
            print(f"requirement ledger: ok ({count} records)")
        elif arguments.command in {"check-stage-zero", "check-stage-one"}:
            stage = 0 if arguments.command.endswith("zero") else 1
            count = validate_stage(root, stage)
            print(f"requirement Stage {stage:02d}: ok ({count} owned records)")
        else:
            cases = self_test(root)
            print(f"requirement ledger self-test: ok ({cases} rejection cases)")
    except (LedgerError, OSError, UnicodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
