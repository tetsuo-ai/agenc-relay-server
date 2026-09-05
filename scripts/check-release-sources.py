#!/usr/bin/env python3
"""Capture primary-source status and require a matching recorded decision set."""

import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from release_qualification.driver import command, context, finish
from release_qualification.records import QualificationError, canonical, digest, read_bytes, read_record, require_fields, utc_now, write_once

MAX_SOURCE_BYTES = 16 * 1024 * 1024


def fetch(url: str) -> tuple[str, bytes]:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise QualificationError("primary-source checks require HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "agenc-ircd-release-qualification/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        final_url = response.geturl()
        if urllib.parse.urlsplit(final_url).scheme != "https":
            raise QualificationError("primary source redirected away from HTTPS")
        body = response.read(MAX_SOURCE_BYTES + 1)
        if len(body) > MAX_SOURCE_BYTES:
            raise QualificationError("primary source exceeds the capture bound")
        return final_url, body


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    candidate, _, attempt, _ = context(root)
    ledger = read_bytes(root / "docs/protocol-sources-and-decisions.md").decode()
    urls = sorted(set(re.findall(r"https://[^\s<>\]\[)]+", ledger)))
    if not urls or len(urls) > 256:
        raise QualificationError("source ledger has an invalid URL inventory")
    captured = {}
    for index, url in enumerate(urls):
        final_url, body = fetch(url.rstrip(".,;"))
        write_once(attempt / f"evidence/source-{index:03d}.body", body)
        captured[url] = {"final_url": final_url, "sha256": digest(body)}
    record = {"checked_at": utc_now(), "source_commit": candidate["source"]["commit"], "sources": captured}
    write_once(attempt / "evidence/sources.json", canonical(record))
    command(root, attempt, "audit", ["cargo", "audit", "--deny", "warnings"], 1800)
    command(root, attempt, "deny", ["cargo", "deny", "check"], 1800)
    decisions = root / "conformance/release-source-decisions.json"
    if not decisions.is_file():
        raise QualificationError("source responses are retained; their release decision record has not been written")
    accepted = read_record(decisions)
    require_fields(accepted, {"schema_version", "ledger_sha256", "sources"}, "release source decisions")
    if accepted["schema_version"] != 1 or accepted["ledger_sha256"] != digest(read_bytes(root / "docs/protocol-sources-and-decisions.md")) or accepted["sources"] != captured:
        raise QualificationError("primary sources changed or the recorded decisions are stale; review before creating another candidate")
    finish(attempt, "sources", {"primary_sources": True, "advisories": True, "dependency_policy": True, "decisions_current": True})


if __name__ == "__main__":
    try:
        main()
    except (QualificationError, OSError, ValueError) as error:
        print(f"release sources: {error}", file=sys.stderr)
        sys.exit(1)
