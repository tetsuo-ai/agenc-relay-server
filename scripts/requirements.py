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
TODO_TASK_RE = re.compile(
    r"^- \[([ x])\] `(S\d{2}-(?:\d{3}|900))`",
    flags=re.MULTILINE,
)

# These are closure owners, not the first task that exercises one slice of an
# invariant. Each entry names the task after which the complete invariant can
# be claimed. Keeping the IDs explicit prevents one completed family member
# from closing every invariant with the same prefix.
INVARIANT_CLOSURE_TASKS = {
    "TRN-01": "S07-001",
    "TRN-02": "S06-003",
    "TRN-03": "S07-001",
    "TRN-04": "S08-900",
    "TRN-05": "S08-900",
    "TRN-06": "S08-900",
    "ID-01": "S08-900",
    "ID-02": "S08-900",
    "ID-03": "S06-009",
    "ID-04": "S06-014",
    "ID-05": "S07-003",
    "ID-06": "S08-017",
    "ID-07": "S05-014",
    "AUTH-01": "S04-014",
    "AUTH-02": "S06-009",
    "AUTH-03": "S07-003",
    "AUTH-04": "S04-014",
    "AUTH-05": "S06-009",
    "AUTH-06": "S07-003",
    "AUTH-07": "S06-009",
    "AUTH-08": "S06-009",
    "AUTH-09": "S04-014",
    "AUTH-10": "S04-014",
    "AUTH-11": "S06-009",
    "PRV-01": "S10-005",
    "PRV-02": "S10-009",
    "PRV-03": "S09-005",
    "PRV-04": "S10-012",
    "STA-01": "S07-006",
    "STA-02": "S08-004",
    "STA-03": "S07-006",
    "STA-04": "S06-010",
    "STA-05": "S09-003",
    "STA-06": "S07-007",
    "STA-07": "S07-005",
    "STA-08": "S08-014",
    "STA-09": "S09-004",
    "STA-10": "S07-011",
    "E2E-01": "S08-002",
    "E2E-02": "S08-021",
    "E2E-03": "S08-016",
    "E2E-04": "S08-011",
    "E2E-05": "S08-900",
    "E2E-06": "S08-011",
    "E2E-07": "S08-015",
    "FED-01": "S07-010",
    "FED-02": "S08-009",
    "FED-03": "S08-009",
    "FED-04": "S07-004",
    "FED-05": "S07-009",
    "FED-06": "S07-009",
    "FED-07": "S07-007",
    "FED-08": "S07-008",
    "FED-09": "S07-010",
    "FED-10": "S08-009",
    "FED-11": "S08-016",
    "FED-12": "S08-016",
    "FED-13": "S07-011",
    "DUR-01": "S08-016",
    "DUR-02": "S08-016",
    "DUR-03": "S05-002",
    "DUR-04": "S05-010",
    "DUR-05": "S05-012",
    "DUR-06": "S05-007",
    "DUR-07": "S05-008",
    "DUR-08": "S05-010",
    "DUR-09": "S05-011",
    "DUR-10": "S05-014",
    "DUR-11": "S05-015",
    "DUR-12": "S05-011",
    "CON-01": "S08-017",
    "CON-02": "S08-017",
    "CON-03": "S08-016",
    "CON-04": "S08-017",
    "CON-05": "S08-017",
    "OPS-01": "S10-009",
    "OPS-02": "S06-001",
    "OPS-03": "S06-012",
    "OPS-04": "S10-004",
    "OPS-05": "S06-012",
}

ARCHITECTURE_REQUIREMENT_TASKS = {
    "ARCH-REQ-5360DEAA68502E5731EC": "S10-012",
    "ARCH-REQ-2E4DE537C3C8E8643DAE": "S10-013",
    "ARCH-REQ-09CFFBA54F24F91ED37D": "S09-002",
    "ARCH-REQ-3BFE92E0E09C7C1C45E5": "S00-001",
    "ARCH-REQ-951E6893F2B754847C8E": "S06-004",
    "ARCH-REQ-0EC008E51ACF33B486A7": "S06-010",
    "ARCH-REQ-2DE781FEE0904A7D417F": "S06-010",
    "ARCH-REQ-76933F949C4BA311D15E": "S06-009",
    "ARCH-REQ-8E6BD0E1ADFA47B0488A": "S06-004",
    "ARCH-REQ-113DC460E840E6189DDD": "S10-009",
    "ARCH-REQ-00FBB19D3A47F35629EA": "S08-015",
    "ARCH-REQ-1E370EA2716EA3954DE5": "S10-004",
    "ARCH-REQ-437D151873A9CD5C587B": "S06-008",
    "ARCH-REQ-A1C186F162F73F71282D": "S07-010",
    "ARCH-REQ-E86BF5CACDB29BBF69B3": "S10-002",
    "ARCH-REQ-2B7287527206F6EE909C": "S10-012",
    "ARCH-REQ-78FAB57061FA01E1805E": "S00-006",
    "ARCH-REQ-239F20852008EFEBC14C": "S06-004",
    "ARCH-REQ-6ED8CC0935B62D48C171": "S06-004",
    "ARCH-REQ-91A4F778BFA1744C7579": "S06-004",
    "ARCH-REQ-1077079A5B8E236B2E7E": "S06-004",
    "ARCH-REQ-AF83DC2BF6651C1ADCAB": "S06-004",
    "ARCH-REQ-1BC68D62C88F9901863C": "S06-004",
    "ARCH-REQ-0ED2BB6143B32AC67530": "S06-004",
    "ARCH-REQ-D8752DA6EC2A4D543D27": "S06-004",
    "ARCH-REQ-89A52EAEFEB27B78EA3F": "S06-004",
    "ARCH-REQ-B640E662E68B7720C8CE": "S06-004",
    "ARCH-REQ-97C72A89521508665EA0": "S06-004",
    "ARCH-REQ-C33F2C188FAB745A4008": "S06-003",
    "ARCH-REQ-3EDADEB5374091A7FCD9": "S06-003",
    "ARCH-REQ-1F847B93E38E57D5492E": "S06-003",
    "ARCH-REQ-533C4FC96F4E21250FF2": "S06-015",
    "ARCH-REQ-D9709F92FF869A201DA0": "S06-009",
    "ARCH-REQ-32BBA90BC88CB72E6AD1": "S07-003",
    "ARCH-REQ-BEEFCAD41A137797EE06": "S10-005",
    "ARCH-REQ-D74CDEA02D46EEA2E9AD": "S08-002",
    "ARCH-REQ-0A2DFA591F93494434CA": "S06-010",
    "ARCH-REQ-F236FC1F5FD8129AB518": "S08-002",
    "ARCH-REQ-705219A4555AC2842B77": "S08-002",
    "ARCH-REQ-630535C69EC8B9414843": "S08-015",
    "ARCH-REQ-AC500B2D79C7A16B554A": "S06-011",
    "ARCH-REQ-71EF3D90A56EB55DF930": "S10-007",
    "ARCH-REQ-0B5E5D62113344CD5B9E": "S07-008",
    "ARCH-REQ-CAFA64060EE32DC7419D": "S05-001",
    "ARCH-REQ-D621F68B6C389E5B7660": "S05-004",
    "ARCH-REQ-30183AFAFED8128B6541": "S05-004",
    "ARCH-REQ-497991387ADD6957DDBE": "S05-004",
    "ARCH-REQ-61DDBED6FB176354A9BF": "S05-004",
    "ARCH-REQ-61C6AFF8B1137410D0FD": "S05-004",
    "ARCH-REQ-EE3343E6DDAA279E4E23": "S05-004",
    "ARCH-REQ-29DE85F5026ADD8EF114": "S05-013",
    "ARCH-REQ-081595C2CCFFAF608E38": "S06-008",
    "ARCH-REQ-DE27E4D7727B11384C1F": "S06-008",
    "ARCH-REQ-D8DDA49F3C32422D93B3": "S08-016",
    "ARCH-REQ-E592762A378E0D95835A": "S08-016",
    "ARCH-REQ-415192C9AE3C7492C527": "S07-009",
    "ARCH-REQ-17B30148DD5160683953": "S07-009",
    "ARCH-REQ-F235013D840DBE992D6C": "S05-014",
    "ARCH-REQ-A028640A3B71B72E5F38": "S07-004",
    "ARCH-REQ-C70A2FA24AD661DB7BC3": "S05-013",
    "ARCH-REQ-2DAB3DDD73C2AE873977": "S05-011",
    "ARCH-REQ-351F91DD2F9F7B09DD4C": "S05-013",
    "ARCH-REQ-A8B38178C6FCDD5EB7ED": "S06-014",
    "ARCH-REQ-48ECE41B610BE7FF1950": "S00-002",
    "ARCH-REQ-F3D92EF9C888E0675CB4": "S00-002",
    "ARCH-REQ-49AAC75AD4C65F0466B2": "S00-002",
    "ARCH-REQ-B45135D9F5992114B394": "S00-002",
}

E2EE_REQUIREMENT_TASKS = {
    "E2EE-REQ-03E795692C36DFAE083B": "S08-023",
    "E2EE-REQ-04B0129952BBBB1F3D22": "S08-001",
    "E2EE-REQ-0950B248DBB87C569FE7": "S08-021",
    "E2EE-REQ-0A1FB6761AFBE1A76113": "S10-005",
    "E2EE-REQ-0DAEDE4522366E3A68A9": "S08-021",
    "E2EE-REQ-0EE614CD32C84FA9F408": "S08-003",
    "E2EE-REQ-1AB78DA63741FF0B38CF": "S08-021",
    "E2EE-REQ-1BFDC5AC26176497302E": "S08-020",
    "E2EE-REQ-1CF30FAFE8FA36F5CF2E": "S01-010",
    "E2EE-REQ-208C5CAB7399B4AC15B8": "S08-017",
    "E2EE-REQ-21F466D08365E6787EFF": "S08-023",
    "E2EE-REQ-226E2E46DD9A8986A73D": "S10-005",
    "E2EE-REQ-28CC5A2874FBFEDC8694": "S08-025",
    "E2EE-REQ-2F0777EEA2E2B0559F6D": "S08-027",
    "E2EE-REQ-37736EFE55D201CBE671": "S08-021",
    "E2EE-REQ-37CAE24A086303163D86": "S08-027",
    "E2EE-REQ-3823DB12FF1BAAB21A9C": "S10-005",
    "E2EE-REQ-3AE1FE848688A346F9F1": "S08-005",
    "E2EE-REQ-3DDAFB884DFFB22C1F74": "S08-002",
    "E2EE-REQ-3DFFF778DA62F4CEEF8F": "S08-023",
    "E2EE-REQ-3F31F96A8E03DA4C101C": "S08-037",
    "E2EE-REQ-3F6EB7E7803E9A17D029": "S08-024",
    "E2EE-REQ-47F62E0752E7757399CD": "S08-025",
    "E2EE-REQ-48C5B151716A5DA59976": "S08-022",
    "E2EE-REQ-4A2736C8DC8339780AA6": "S08-036",
    "E2EE-REQ-4A2B327FEB0ED0D66724": "S08-020",
    "E2EE-REQ-4B9FA0731463AF395EEF": "S08-037",
    "E2EE-REQ-4E4E130CEAB680D99587": "S08-005",
    "E2EE-REQ-4ECEEB84B918BCA2DBE3": "S08-024",
    "E2EE-REQ-4EE6451842066B972713": "S10-012",
    "E2EE-REQ-4EFBE464A39690115414": "S08-023",
    "E2EE-REQ-532CF56360A03DCF3C39": "S08-034",
    "E2EE-REQ-54D3BF177A5D79854AEC": "S08-027",
    "E2EE-REQ-5754ACC17005856FB5B2": "S10-005",
    "E2EE-REQ-5B3475BE0506C311BEF2": "S08-027",
    "E2EE-REQ-5B7791BEAEA4EF6B0D60": "S08-027",
    "E2EE-REQ-5E00851700473A8BFE36": "S10-012",
    "E2EE-REQ-67059195AB3AA10AAD9B": "S08-002",
    "E2EE-REQ-6A1A40DF827404DFC2E0": "S08-024",
    "E2EE-REQ-72ECA857E694D0439A70": "S08-003",
    "E2EE-REQ-73270B473C2AB773AF11": "S08-023",
    "E2EE-REQ-74E9B5BFDE9BE0345707": "S08-034",
    "E2EE-REQ-75819BD50FB3E71F2B91": "S08-024",
    "E2EE-REQ-7FE02BCBD9EEB3934B70": "S08-027",
    "E2EE-REQ-805F50731EF74A9AA48F": "S10-005",
    "E2EE-REQ-845B04F1228AFD8867F1": "S08-029",
    "E2EE-REQ-865E52D8D04B59FEEFBE": "S08-023",
    "E2EE-REQ-87B4B4DBBAD9DB97F76A": "S08-024",
    "E2EE-REQ-8AB2B222BF622D4C4BDF": "S08-005",
    "E2EE-REQ-8B777BE6D9A7ED988687": "S08-028",
    "E2EE-REQ-8C607B4410F376797BD2": "S08-025",
    "E2EE-REQ-9641FAA02EEEC75A2E7D": "S08-027",
    "E2EE-REQ-98421AA3C0425E259F8F": "S08-023",
    "E2EE-REQ-986A7772723E16360520": "S08-028",
    "E2EE-REQ-98C7F0834891533DE1BC": "S08-021",
    "E2EE-REQ-9A4E05845BDB4B1C7D30": "S08-017",
    "E2EE-REQ-9EA1028E2CE3115F5EEB": "S08-027",
    "E2EE-REQ-A0EFEAB7474EA0A450F5": "S04-005",
    "E2EE-REQ-A119B1A71D9F208380BC": "S08-040",
    "E2EE-REQ-A141AC00A13A398685DC": "S08-022",
    "E2EE-REQ-A1A7120BFAC343370E75": "S10-005",
    "E2EE-REQ-A5E4E2058896C2016403": "S08-022",
    "E2EE-REQ-A7C32D4A15F7F0AF4F82": "S08-017",
    "E2EE-REQ-AC36B134578CBDB4F7A2": "S08-024",
    "E2EE-REQ-B1A07872530E53E1C5E0": "S08-020",
    "E2EE-REQ-B341221DC3B1063B9F41": "S08-036",
    "E2EE-REQ-B73C16A97C1278CDDE0B": "S08-023",
    "E2EE-REQ-B8F44A765000AE5B6944": "S08-032",
    "E2EE-REQ-B93A7B094027B1B00105": "S08-027",
    "E2EE-REQ-B99A6DD4949FED0CE02A": "S08-027",
    "E2EE-REQ-BFA20A50D15399A2F088": "S08-024",
    "E2EE-REQ-C345CFA457EB0B500D2A": "S08-030",
    "E2EE-REQ-C8997B4345158FD54D44": "S08-017",
    "E2EE-REQ-CA268835A931F5051D79": "S08-025",
    "E2EE-REQ-CED437B1C62CF9CD0A79": "S08-023",
    "E2EE-REQ-D07C2C1AA58D16CA582D": "S08-037",
    "E2EE-REQ-D150C4C93D931F51EE12": "S08-021",
    "E2EE-REQ-D2C711B6BB260BFB72FD": "S08-024",
    "E2EE-REQ-D70B8B9850E29E082F85": "S08-027",
    "E2EE-REQ-D8D8C1DBDAE5F09E95FD": "S08-043",
    "E2EE-REQ-DB900449D8D52DA92117": "S08-017",
    "E2EE-REQ-DF1E11F99D8CA9C38917": "S08-002",
    "E2EE-REQ-DFF4835BF134E29328E1": "S08-021",
    "E2EE-REQ-E84E3DF2CF6A849CCBA8": "S08-027",
    "E2EE-REQ-E9D6A931BDD262B08F93": "S08-024",
    "E2EE-REQ-EC03C8374D88E32F6776": "S08-031",
    "E2EE-REQ-ED359F4450E30FD76278": "S08-023",
    "E2EE-REQ-EFECC9F9EB196FD2CF16": "S08-020",
    "E2EE-REQ-F14B7B01F4CFF98A804E": "S08-023",
    "E2EE-REQ-F252168A3A468701F674": "S08-023",
    "E2EE-REQ-FDA89A1D5714375C1B4F": "S08-023",
}

E2EE_TESTKIT_REQUIREMENTS = frozenset(
    {
        "E2EE-REQ-0A1FB6761AFBE1A76113",
        "E2EE-REQ-226E2E46DD9A8986A73D",
        "E2EE-REQ-3823DB12FF1BAAB21A9C",
        "E2EE-REQ-5754ACC17005856FB5B2",
        "E2EE-REQ-805F50731EF74A9AA48F",
        "E2EE-REQ-A1A7120BFAC343370E75",
    }
)

E2EE_CRYPTO_REQUIREMENTS = frozenset(
    {
        "E2EE-REQ-A0EFEAB7474EA0A450F5",
    }
)


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


def e2ee_target(section: str, identifier: str | None = None) -> str:
    """Assign primary crate ownership for one companion requirement."""
    if identifier in E2EE_TESTKIT_REQUIREMENTS:
        return "agenc-ircd-testkit"
    if identifier in E2EE_CRYPTO_REQUIREMENTS:
        return "agenc-ircd-crypto"
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


def target_for(
    document: SourceDocument,
    section: str,
    invariant: str | None = None,
    identifier: str | None = None,
) -> str:
    """Return the one primary implementation crate for a requirement."""
    if document.key == "architecture":
        return architecture_target(section, invariant)
    return e2ee_target(section, identifier)


def task_for(
    document: SourceDocument,
    section: str,
    invariant: str | None = None,
    identifier: str | None = None,
) -> str:
    """Return the task that closes the complete normative clause."""
    if invariant is not None:
        try:
            return INVARIANT_CLOSURE_TASKS[invariant]
        except KeyError as error:
            raise LedgerError(f"invariant {invariant} has no reviewed closure task") from error
    if document.key == "e2ee-companion":
        if identifier is None:
            raise LedgerError(f"E2EE section {section!r} lacks a concrete requirement ID")
        try:
            return E2EE_REQUIREMENT_TASKS[identifier]
        except KeyError as error:
            raise LedgerError(
                f"E2EE requirement {identifier} has no reviewed closure task"
            ) from error
    if identifier is None:
        raise LedgerError(f"architecture section {section!r} lacks a concrete requirement ID")
    try:
        return ARCHITECTURE_REQUIREMENT_TASKS[identifier]
    except KeyError as error:
        raise LedgerError(
            f"architecture requirement {identifier} has no reviewed closure task"
        ) from error


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


def validate_closure_task_catalog(records: list[dict[str, object]]) -> None:
    """Require exact reviewed task ownership for every extracted clause."""
    actual_invariants = {
        str(record["id"]).removeprefix("ARCH-")
        for record in records
        if record["kind"] == "invariant"
    }
    actual_architecture = {
        str(record["id"])
        for record in records
        if record["document"] == "architecture" and record["kind"] == "bcp14"
    }
    actual_e2ee = {
        str(record["id"])
        for record in records
        if record["document"] == "e2ee-companion"
    }
    catalogs = (
        ("invariant", actual_invariants, set(INVARIANT_CLOSURE_TASKS)),
        ("architecture", actual_architecture, set(ARCHITECTURE_REQUIREMENT_TASKS)),
        ("E2EE", actual_e2ee, set(E2EE_REQUIREMENT_TASKS)),
    )
    errors: list[str] = []
    for label, actual, reviewed in catalogs:
        missing = sorted(actual - reviewed)
        stale = sorted(reviewed - actual)
        if missing or stale:
            errors.append(f"{label} missing={missing}, stale={stale}")
    if errors:
        raise LedgerError("reviewed closure-task catalog differs: " + "; ".join(errors))


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
    validate_closure_task_catalog(records)
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
    task_id = task_for(document, section, invariant, identifier)
    return {
        "id": identifier,
        "target_crates": [target_for(document, section, invariant, identifier)],
        "task_ids": [task_id],
        "evidence_ids": [f"EVID-{identifier}"],
        "status": "unimplemented",
    }


def task_states(root: Path) -> dict[str, bool]:
    """Read the checked task state from the implementation plan."""
    text = (root / "TODO.md").read_text(encoding="utf-8")
    states: dict[str, bool] = {}
    for marker, task_id in TODO_TASK_RE.findall(text):
        if task_id in states:
            raise LedgerError(f"TODO.md contains duplicate task {task_id}")
        states[task_id] = marker == "x"
    if not states:
        raise LedgerError("TODO.md contains no implementation tasks")
    return states


def binding_with_current_status(
    record: dict[str, object], states: dict[str, bool]
) -> dict[str, object]:
    """Build one reviewed binding and derive status from its closure task."""
    binding = default_binding(record)
    tasks = binding["task_ids"]
    if not isinstance(tasks, list):
        raise LedgerError(f"{binding['id']} has invalid generated task ownership")
    missing = [str(task) for task in tasks if str(task) not in states]
    if missing:
        raise LedgerError(f"TODO.md lacks closure tasks: {', '.join(missing)}")
    binding["status"] = (
        "implemented" if all(states[str(task)] for task in tasks) else "unimplemented"
    )
    return binding


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
    data: dict[str, object],
    records: list[dict[str, object]],
    states: dict[str, bool],
) -> list[dict[str, object]]:
    """Validate complete binding coverage without permitting waivers."""
    if set(data) != {"schema_version", "binding_count", "binding"}:
        raise LedgerError("requirement bindings have an invalid top-level schema")
    schema_version = data.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
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
    expected_by_id = {
        str(record["id"]): binding_with_current_status(record, states) for record in records
    }
    for identifier in sorted(by_id):
        if by_id[identifier] != expected_by_id[identifier]:
            raise LedgerError(
                f"{identifier} ownership or status differs from its reviewed closure task"
            )
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
    schema_version = ledger.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
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
    bindings = validate_bindings(binding_data, extracted, task_states(root))
    expected = merge_bindings(extracted, bindings)
    ledger = load_ledger(root / LEDGER_PATH)
    validate_data(ledger, expected, source_hashes)
    expected_rendering = render(expected, source_hashes)
    actual_rendering = (root / LEDGER_PATH).read_text(encoding="utf-8")
    if actual_rendering != expected_rendering:
        raise LedgerError("ledger is structurally valid but not in canonical generated form")
    return len(expected)


def validate_stage_data(
    ledger: dict[str, object],
    expected: list[dict[str, object]],
    source_hashes: dict[str, str],
    stage: int,
) -> int:
    """Validate a fresh ledger before checking one stage's closure owners."""
    validate_data(ledger, expected, source_hashes)
    prefix = f"S{stage:02d}-"
    owned = [
        record
        for record in expected
        if any(str(task).startswith(prefix) for task in record["task_ids"])
    ]
    incomplete = sorted(
        str(record["id"])
        for record in owned
        if record["status"] != "implemented"
    )
    if incomplete:
        raise LedgerError(
            f"Stage {stage:02d} has unimplemented owned requirements: {', '.join(incomplete)}"
        )
    return len(owned)


def validate_stage(root: Path, stage: int) -> int:
    """Require every fresh requirement owned by one stage to be implemented."""
    extracted, source_hashes = extract(root)
    bindings = validate_bindings(
        load_bindings(root / BINDINGS_PATH), extracted, task_states(root)
    )
    expected = merge_bindings(extracted, bindings)
    ledger = load_ledger(root / LEDGER_PATH)
    count = validate_stage_data(ledger, expected, source_hashes, stage)
    if (root / LEDGER_PATH).read_text(encoding="utf-8") != render(expected, source_hashes):
        raise LedgerError("ledger is structurally valid but not in canonical generated form")
    return count


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
    bindings = validate_bindings(
        load_bindings(root / BINDINGS_PATH), extracted, task_states(root)
    )
    expected = merge_bindings(extracted, bindings)
    valid = load_ledger(root / LEDGER_PATH)
    validate_data(valid, expected, source_hashes)
    cases = 0

    boolean_binding_version = copy.deepcopy(load_bindings(root / BINDINGS_PATH))
    boolean_binding_version["schema_version"] = True
    try:
        validate_bindings(boolean_binding_version, extracted, task_states(root))
    except LedgerError as error:
        if "binding schema_version must be 1" not in str(error):
            raise LedgerError(
                f"self-test 'boolean binding schema' reached the wrong branch: {error}"
            ) from error
    else:
        raise LedgerError("self-test 'boolean binding schema' was accepted")
    cases += 1

    boolean_ledger_version = copy.deepcopy(valid)
    boolean_ledger_version["schema_version"] = True
    expect_rejection(
        "boolean ledger schema",
        boolean_ledger_version,
        expected,
        source_hashes,
        "schema_version must be 1",
    )
    cases += 1

    try:
        validate_closure_task_catalog(extracted[:-1])
    except LedgerError as error:
        if "reviewed closure-task catalog differs" not in str(error):
            raise LedgerError(
                f"self-test 'closure-task catalog' reached the wrong branch: {error}"
            ) from error
    else:
        raise LedgerError("self-test 'closure-task catalog' was accepted")
    cases += 1

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

    stale_stage = copy.deepcopy(valid)
    stale_stage["architecture_sha256"] = "0" * 64
    try:
        validate_stage_data(stale_stage, expected, source_hashes, 0)
    except LedgerError as error:
        if "architecture source hash is stale" not in str(error):
            raise LedgerError(
                f"self-test 'standalone stage freshness' reached the wrong branch: {error}"
            ) from error
    else:
        raise LedgerError("self-test 'standalone stage freshness' was accepted")
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
        choices=(
            "generate",
            "generate-bindings",
            "check",
            "check-stage-zero",
            "check-stage-one",
            "check-stage-two",
            "check-stage-three",
            "check-stage-four",
            "check-stage-five",
            "check-stage-six",
            "check-stage-seven",
            "check-stage-eight",
            "self-test",
        ),
    )
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "generate":
            extracted, source_hashes = extract(root)
            bindings = validate_bindings(
                load_bindings(root / BINDINGS_PATH), extracted, task_states(root)
            )
            records = merge_bindings(extracted, bindings)
            (root / LEDGER_PATH).write_text(render(records, source_hashes), encoding="utf-8")
            print(f"requirement ledger: generated {len(records)} records")
        elif arguments.command == "generate-bindings":
            records, _source_hashes = extract(root)
            states = task_states(root)
            defaults = [binding_with_current_status(record, states) for record in records]
            (root / BINDINGS_PATH).write_text(render_bindings(defaults), encoding="utf-8")
            print(f"requirement bindings: generated {len(defaults)} records")
        elif arguments.command == "check":
            count = validate(root)
            print(f"requirement ledger: ok ({count} records)")
        elif arguments.command.startswith("check-stage-"):
            stage = {
                "check-stage-zero": 0,
                "check-stage-one": 1,
                "check-stage-two": 2,
                "check-stage-three": 3,
                "check-stage-four": 4,
                "check-stage-five": 5,
                "check-stage-six": 6,
                "check-stage-seven": 7,
                "check-stage-eight": 8,
            }[arguments.command]
            count = validate_stage(root, stage)
            print(f"requirement ownership for Stage {stage:02d}: ok ({count} closure records)")
        else:
            cases = self_test(root)
            print(f"requirement ledger self-test: ok ({cases} rejection cases)")
    except (LedgerError, OSError, UnicodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
