#!/usr/bin/env python3
"""Compare primary-source publication status with the recorded release decisions.

Every RFC the source ledger cites is checked against the RFC Editor's
structured status record, the pinned Internet-Draft against the Datatracker
document record and its state names, and each living specification repository
against its remote default-branch head plus a fetch of the pinned commit. The
responses are retained as raw evidence. A field that differs from
conformance/release-source-decisions.toml fails the job and names the source,
so a new revision or a status change has to be reviewed and decided before a
candidate can pass.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from release_qualification.driver import command, context, finish
from release_qualification.records import QualificationError, canonical, digest, read_bytes, utc_now, write_once

LEDGER_PATH = "docs/protocol-sources-and-decisions.md"
DECISIONS_PATH = "conformance/release-source-decisions.toml"
RFC_STATUS_URL = "https://www.rfc-editor.org/rfc/rfc{number}.json"
DRAFT_STATUS_URL = "https://datatracker.ietf.org/api/v1/doc/document/{name}/?format=json"
DATATRACKER_ORIGIN = "https://datatracker.ietf.org"
MAX_BODY_BYTES = 1024 * 1024
MAX_RFCS = 128
MAX_STATES = 16
DECISIONS = ("adopt", "narrow", "supersede", "reject")
RFC_MENTION = re.compile(r"\bRFCs?\s+(\d{3,5})(?:-(\d{3,5}))?")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
HTTPS_URL = re.compile(r"https://[A-Za-z0-9./_-]+\Z")
STATE_URI = re.compile(r"/api/v1/doc/state/\d{1,6}/\Z")
FETCH_TIMEOUT_SECONDS = 30


def fetch_json(url: str) -> tuple[bytes, Any]:
    """Fetch one HTTPS status record with a bounded body."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise QualificationError("primary-source checks require HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "agenc-ircd-release-qualification/1", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        if urllib.parse.urlsplit(response.geturl()).scheme != "https":
            raise QualificationError("primary source redirected away from HTTPS")
        body = response.read(MAX_BODY_BYTES + 1)
    if len(body) > MAX_BODY_BYTES:
        raise QualificationError("primary source exceeds the capture bound")
    try:
        return body, json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"primary source is not JSON: {url}") from error


def ledger_section(text: str, number: int) -> str:
    """The body of one numbered top-level ledger section."""
    start = text.find(f"\n## {number}. ")
    if start < 0:
        raise QualificationError(f"source ledger lacks section {number}")
    end = text.find(f"\n## {number + 1}. ", start)
    return text[start:end if end >= 0 else len(text)]


def ledger_rfc_numbers(text: str) -> set[int]:
    """Every RFC number the published-standards section names, ranges included."""
    numbers: set[int] = set()
    for first, last in RFC_MENTION.findall(ledger_section(text, 2)):
        low = int(first)
        high = int(last) if last else low
        if not 1 <= low <= high <= 99_999 or high - low > 16:
            raise QualificationError("source ledger names an implausible RFC range")
        numbers.update(range(low, high + 1))
    if not numbers or len(numbers) > MAX_RFCS:
        raise QualificationError("source ledger names no RFC or too many")
    return numbers


def string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value) or value != sorted(value):
        raise QualificationError(f"{label} must be a sorted list of names")
    return value


def decided(entry: dict[str, Any], label: str, fields: set[str]) -> None:
    if not isinstance(entry, dict) or set(entry) != fields:
        raise QualificationError(f"{label} has missing or unknown fields")
    if entry["decision"] not in DECISIONS:
        raise QualificationError(f"{label} needs an explicit adopt, narrow, supersede, or reject decision")
    if not isinstance(entry["note"], str) or not entry["note"].strip():
        raise QualificationError(f"{label} needs a note")


def load_decisions(root: Path) -> dict[str, Any]:
    try:
        decisions = tomllib.loads(read_bytes(root / DECISIONS_PATH).decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise QualificationError("release source decisions are not valid TOML") from error
    if set(decisions) != {"schema_version", "ledger_sha256", "decided_on", "rfc", "draft", "repository"} or decisions["schema_version"] != 1:
        raise QualificationError("release source decisions have an unknown shape")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(decisions["decided_on"])):
        raise QualificationError("release source decisions need a decision date")
    seen: set[int] = set()
    for entry in decisions["rfc"]:
        decided(entry, "RFC decision", {"number", "status", "obsoleted_by", "updated_by", "decision", "note"})
        if type(entry["number"]) is not int or entry["number"] in seen:
            raise QualificationError("RFC decisions must have distinct integer numbers")
        seen.add(entry["number"])
        string_list(entry["obsoleted_by"], f"RFC {entry['number']} obsoleted_by")
        string_list(entry["updated_by"], f"RFC {entry['number']} updated_by")
    for entry in decisions["draft"]:
        decided(entry, "draft decision", {"name", "revision", "updated", "states", "decision", "note"})
        if not re.fullmatch(r"draft-[a-z0-9-]{1,80}", entry["name"]) or not re.fullmatch(r"\d{2}", entry["revision"]):
            raise QualificationError("draft decisions need a draft name and two-digit revision")
        string_list(entry["states"], f"{entry['name']} states")
    for entry in decisions["repository"]:
        decided(entry, "repository decision", {"name", "url", "pinned_commit", "default_branch", "head_commit", "decision", "note"})
        if not HTTPS_URL.fullmatch(entry["url"]) or not COMMIT.fullmatch(entry["pinned_commit"]) or not COMMIT.fullmatch(entry["head_commit"]) or not entry["default_branch"].startswith("refs/heads/"):
            raise QualificationError(f"repository decision for {entry['name']} has an invalid pin")
    if not decisions["rfc"] or not decisions["draft"] or not decisions["repository"]:
        raise QualificationError("release source decisions must cover RFCs, drafts, and repositories")
    return decisions


def check_rfc(entry: dict[str, Any], record: Any) -> dict[str, Any]:
    """The RFC Editor record must carry exactly the decided status fields."""
    number = entry["number"]
    if not isinstance(record, dict) or record.get("doc_id") != f"RFC{number}":
        raise QualificationError(f"RFC {number}: status record names another document")
    observed = {"status": record.get("status"), "obsoleted_by": sorted(record.get("obsoleted_by") or []),
                "updated_by": sorted(record.get("updated_by") or [])}
    for field, value in observed.items():
        if value != entry[field]:
            raise QualificationError(f"RFC {number}: {field} is now {value!r}; review the ledger and record a decision")
    return {"doc_id": record["doc_id"], "pub_date": record.get("pub_date"), "errata_url": record.get("errata_url"), **observed}


def check_draft(entry: dict[str, Any], record: Any, states: list[Any]) -> dict[str, Any]:
    """The Datatracker record must still be the decided revision, time, and states."""
    name = entry["name"]
    if not isinstance(record, dict) or record.get("name") != name:
        raise QualificationError(f"{name}: status record names another document")
    slugs = sorted(str(state.get("slug")) for state in states if isinstance(state, dict))
    observed = {"revision": record.get("rev"), "updated": record.get("time"), "states": slugs}
    for field, value in observed.items():
        if value != entry[field]:
            raise QualificationError(f"{name}: {field} is now {value!r}; review the draft and record a decision")
    return {"name": name, "expires": record.get("expires"), **observed}


def parse_ls_remote(text: str) -> tuple[str, str]:
    """The default branch and its head from `git ls-remote --symref <url> HEAD`."""
    branch = head = None
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) == 2 and fields[1] == "HEAD":
            if fields[0].startswith("ref: "):
                branch = fields[0].removeprefix("ref: ")
            elif COMMIT.fullmatch(fields[0]):
                head = fields[0]
    if branch is None or head is None:
        raise QualificationError("ls-remote output lacks the default branch or its head")
    return branch, head


def check_repository(entry: dict[str, Any], ls_remote: str) -> dict[str, Any]:
    branch, head = parse_ls_remote(ls_remote)
    name = entry["name"]
    if branch != entry["default_branch"]:
        raise QualificationError(f"{name}: default branch is now {branch}; review and record a decision")
    if head != entry["head_commit"]:
        raise QualificationError(f"{name}: default branch head moved to {head}; review the diff and record a decision")
    return {"name": name, "url": entry["url"], "default_branch": branch, "head_commit": head, "pinned_commit": entry["pinned_commit"]}


def state_records(document: Any, retain) -> list[Any]:
    uris = document.get("states") if isinstance(document, dict) else None
    if not isinstance(uris, list) or len(uris) > MAX_STATES or any(not isinstance(uri, str) or not STATE_URI.fullmatch(uri) for uri in uris):
        raise QualificationError("draft status record has an invalid state list")
    records = []
    for index, uri in enumerate(sorted(uris)):
        body, record = fetch_json(f"{DATATRACKER_ORIGIN}{uri}?format=json")
        retain(f"draft-state-{index:02d}.json", body)
        records.append(record)
    return records


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    candidate, _, attempt, _ = context(root)
    evidence = attempt / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)

    def retain(name: str, body: bytes) -> None:
        write_once(evidence / name, body)

    ledger_bytes = read_bytes(root / LEDGER_PATH)
    decisions = load_decisions(root)
    if decisions["ledger_sha256"] != digest(ledger_bytes):
        raise QualificationError("the source ledger changed after its decisions were recorded; review and update the decisions")
    numbers = ledger_rfc_numbers(ledger_bytes.decode("utf-8"))
    recorded = {entry["number"]: entry for entry in decisions["rfc"]}
    if set(recorded) != numbers:
        missing = sorted(numbers - set(recorded))
        stale = sorted(set(recorded) - numbers)
        raise QualificationError(f"RFC decisions do not match the ledger: undecided {missing}, stale {stale}")
    captured: dict[str, Any] = {"rfc": [], "draft": [], "repository": []}
    for number in sorted(numbers):
        body, record = fetch_json(RFC_STATUS_URL.format(number=number))
        retain(f"rfc{number}.json", body)
        captured["rfc"].append(check_rfc(recorded[number], record))
    for entry in decisions["draft"]:
        body, record = fetch_json(DRAFT_STATUS_URL.format(name=entry["name"]))
        retain(f"{entry['name']}.json", body)
        captured["draft"].append(check_draft(entry, record, state_records(record, retain)))
    work = attempt / "work"
    for index, entry in enumerate(decisions["repository"]):
        command(root, attempt, f"ls-remote-{index}", ["git", "ls-remote", "--symref", entry["url"], "HEAD"], 300)
        listing = read_bytes(evidence / f"ls-remote-{index}.log").decode("utf-8", errors="replace")
        captured["repository"].append(check_repository(entry, listing))
        # A shallow fetch of the pinned commit proves the remote still serves it.
        mirror = work / f"pinned-{index}"
        command(root, attempt, f"pinned-init-{index}", ["git", "init", "--bare", "--quiet", str(mirror)], 60)
        command(root, attempt, f"pinned-fetch-{index}", ["git", "-C", str(mirror), "fetch", "--quiet", "--depth", "1", entry["url"], entry["pinned_commit"]], 900)
    command(root, attempt, "audit", ["cargo", "audit", "--deny", "warnings"], 1800)
    command(root, attempt, "deny", ["cargo", "deny", "check"], 1800)
    record = {"checked_at": utc_now(), "source_commit": candidate["source"]["commit"], "ledger_sha256": decisions["ledger_sha256"],
              "decided_on": decisions["decided_on"], "captured": captured}
    write_once(evidence / "sources.json", canonical(record))
    finish(attempt, "sources", {"primary_sources": True, "advisories": True, "dependency_policy": True, "decisions_current": True})


if __name__ == "__main__":
    try:
        main()
    except (QualificationError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"release sources: {error}", file=sys.stderr)
        sys.exit(1)
