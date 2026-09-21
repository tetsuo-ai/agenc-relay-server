#!/usr/bin/env python3
"""Enforce safe-Rust, panic-path, bounded-channel, and code-shape policy."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

FORBID_ATTRIBUTE_RE = re.compile(r"#!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\]")
ASSERT_RE = re.compile(r"\bassert(?:_eq|_ne)?\s*!\s*\(")
FUNCTION_RE = re.compile(r"\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
DECISION_RE = re.compile(r"\b(?:if|match|for|while|loop)\b|&&|\|\|")
FOCUS_ANNOTATION_RE = re.compile(
    r"//\s*agenc-review:\s*focus\s+owner=\S+\s+reviewed=\d{4}-\d{2}-\d{2}\s+reason=\S.*"
)
ASSERT_ANNOTATION_RE = re.compile(
    r"//\s*agenc-review:\s*internal-assert\s+owner=\S+\s+reviewed=\d{4}-\d{2}-\d{2}\s+reason=\S.*"
)
ALLOW_ANNOTATION_RE = re.compile(
    r"//\s*agenc-review:\s*allow\s+owner=\S+\s+reviewed=\d{4}-\d{2}-\d{2}\s+reason=\S.*"
)
ALLOW_RE = re.compile(
    r"#\s*!?\s*\[\s*(?:allow\s*\(|cfg_attr\s*\([^]]*\ballow\s*\()"
)
CFG_TEST_MODULE_RE = re.compile(
    r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{"
)
POLICY = {
    "schema_version": 1,
    "function_logical_line_review": 60,
    "control_nesting_review": 3,
    "cyclomatic_complexity_review": 10,
    "review_annotation": "// agenc-review: focus owner=<name> reviewed=<YYYY-MM-DD> reason=<specific reason>",
    "assert_annotation": "// agenc-review: internal-assert owner=<name> reviewed=<YYYY-MM-DD> reason=<unforgeable precondition>",
    "allow_annotation": "// agenc-review: allow owner=<name> reviewed=<YYYY-MM-DD> reason=<specific reason>",
    "forbid_unsafe": True,
    "forbid_panic_macros": True,
    "forbid_unbounded_channels": True,
    "forbid_unreviewed_allows": True,
    "e2ee_separation": True,
}
# Companion Section 20 and architecture Section 18: the server-side E2EE
# surfaces never name an MLS secret, plaintext, decryption, or a private key.
# The e2ee crate additionally never signs; the runtime's sequencer does.
E2EE_CRATE_ROOT = ("crates", "agenc-relay-e2ee", "src")
E2EE_RUNTIME_ROOT = ("crates", "agenc-relay-runtime", "src", "e2ee")
E2EE_CRATE_FORBIDDEN_RE = re.compile(
    r"\b(?:epoch_secret|init_key_private|private_key|plaintext|decrypt\w*|"
    r"Ed25519SecretKey|SecretBytes|OpenedStoragePlaintext|sign_canonical|SigningKey)\b"
)
E2EE_RUNTIME_FORBIDDEN_RE = re.compile(
    r"\b(?:epoch_secret|init_key_private|plaintext|decrypt\w*|group_secret|mls_secret)\b"
)
BANNED_PATTERNS = (
    (re.compile(r"\bunsafe\b"), "unsafe Rust token"),
    (re.compile(r"\.(?:unwrap|expect)\s*\("), "unwrap/expect panic path"),
    (
        re.compile(r"\b(?:panic|todo|unimplemented|unreachable|debug_assert|debug_assert_eq|debug_assert_ne)\s*!\s*\("),
        "panic/placeholder macro",
    ),
    (
        re.compile(
            r"(?:\bstd\s*::\s*sync\s*::\s*mpsc\s*::\s*(?:channel\b|"
            r"\{[^}]*\bchannel\b)|"
            r"\buse\s+std\s*::\s*sync\s*::\s*mpsc\s*(?:;|\s+as\b)|"
            r"\bunbounded_channel\b|"
            r"\b(?:async_channel|crossbeam_channel|flume)\s*::\s*(?:unbounded\b|"
            r"\{[^}]*\bunbounded\b)|"
            r"\buse\s+(?:async_channel|crossbeam_channel|flume)\s*(?:;|\s+as\b)|"
            r"\bUnbounded(?:Sender|Receiver)\b)"
        ),
        "unbounded channel",
    ),
    (
        re.compile(
            r"(?:\b(?:panic_any|resume_unwind)\b|"
            r"\bstd\s*::\s*process\s*::\s*(?:abort\b|\{[^}]*\babort\b))"
        ),
        "panic/abort function",
    ),
    (re.compile(r"\.fetch_sub\s*\("), "wrapping atomic decrement"),
)


class SourcePolicyError(ValueError):
    """One or more Rust source-policy violations."""


@dataclass(frozen=True)
class FunctionShape:
    """Approximate review-trigger metrics for one Rust function body."""

    name: str
    line: int
    logical_lines: int
    nesting: int
    complexity: int


def load_policy(root: Path) -> None:
    """Ensure policy thresholds cannot drift away from the checker."""
    path = root / "conformance/source-policy.toml"
    try:
        policy = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise SourcePolicyError(f"cannot read source policy: {error}") from error
    if policy != POLICY:
        raise SourcePolicyError("source policy differs from the checker's reviewed closed form")
    try:
        workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise SourcePolicyError(f"cannot read workspace lint policy: {error}") from error
    clippy = workspace.get("workspace", {}).get("lints", {}).get("clippy", {})
    if not isinstance(clippy, dict) or clippy.get("indexing_slicing") != "deny":
        raise SourcePolicyError("workspace must deny clippy::indexing_slicing")


def sanitize_rust(source: str) -> str:
    """Blank comments and string contents while preserving byte/line positions."""
    output = list(source)
    index = 0
    length = len(source)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if output[position] != "\n":
                output[position] = " "

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end == -1 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            blank(start, index)
            continue

        raw = re.match(r"(?:br|r)(#{0,255})\"", source[index:])
        if raw is not None:
            start = index
            hashes = raw.group(1)
            index += raw.end()
            terminator = '"' + hashes
            end = source.find(terminator, index)
            index = length if end == -1 else end + len(terminator)
            blank(start, index)
            continue
        if source[index] == '"':
            start = index
            index += 1
            escaped = False
            while index < length:
                character = source[index]
                index += 1
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    break
            blank(start, index)
            continue
        index += 1
    return "".join(output)


def line_number(source: str, offset: int) -> int:
    """Return a one-based line number for one source offset."""
    return source.count("\n", 0, offset) + 1


def cfg_test_ranges(sanitized: str) -> list[tuple[int, int]]:
    """Return byte ranges occupied by complete `#[cfg(test)]` modules."""
    ranges: list[tuple[int, int]] = []
    for match in CFG_TEST_MODULE_RE.finditer(sanitized):
        brace = sanitized.find("{", match.start(), match.end())
        if brace == -1:
            continue
        depth = 0
        for position in range(brace, len(sanitized)):
            character = sanitized[position]
            if character == "{":
                depth += 1
                continue
            if character != "}":
                continue
            depth -= 1
            if depth == 0:
                ranges.append((match.start(), position + 1))
                break
    return ranges


def offset_in_ranges(offset: int, ranges: list[tuple[int, int]]) -> bool:
    """Return whether one source offset is inside a known half-open range."""
    return any(start <= offset < end for start, end in ranges)


def has_annotation(
    source_lines: list[str],
    source_line: int,
    pattern: re.Pattern[str],
) -> bool:
    """Find a complete review annotation immediately above a construct."""
    start = max(0, source_line - 4)
    return any(pattern.fullmatch(line.strip()) is not None for line in source_lines[start : source_line - 1])


def function_shapes(sanitized: str) -> list[FunctionShape]:
    """Compute conservative function review triggers without parsing macros."""
    shapes: list[FunctionShape] = []
    for match in FUNCTION_RE.finditer(sanitized):
        brace = sanitized.find("{", match.end())
        semicolon = sanitized.find(";", match.end())
        if brace == -1 or (semicolon != -1 and semicolon < brace):
            continue
        depth = 0
        maximum_depth = 0
        end = brace
        for position in range(brace, len(sanitized)):
            character = sanitized[position]
            if character == "{":
                depth += 1
                maximum_depth = max(maximum_depth, depth)
            elif character == "}":
                depth -= 1
                if depth == 0:
                    end = position + 1
                    break
        if depth != 0:
            continue
        body = sanitized[brace:end]
        logical_lines = sum(
            1 for line in body.splitlines() if line.strip() not in {"", "{", "}"}
        )
        complexity = 1 + len(DECISION_RE.findall(body))
        shapes.append(
            FunctionShape(
                match.group(1),
                line_number(sanitized, match.start()),
                logical_lines,
                max(0, maximum_depth - 1),
                complexity,
            )
        )
    return shapes


def is_compilation_root(relative: Path) -> bool:
    """Return whether a Rust file is an independently compiled crate root."""
    parts = relative.parts
    name = relative.name
    if name == "build.rs" or name in {"lib.rs", "main.rs"}:
        return True
    return any(part in {"tests", "examples", "benches"} for part in parts)


def e2ee_separation_pattern(relative: Path) -> re.Pattern[str] | None:
    """Return the separation rule that governs a production E2EE source."""
    parts = relative.parts
    if parts[: len(E2EE_CRATE_ROOT)] == E2EE_CRATE_ROOT:
        return E2EE_CRATE_FORBIDDEN_RE
    if parts[: len(E2EE_RUNTIME_ROOT)] == E2EE_RUNTIME_ROOT:
        return E2EE_RUNTIME_FORBIDDEN_RE
    return None


def is_test_source(relative: Path) -> bool:
    """Return whether assertions are inherently confined to a test target."""
    return any(part in {"tests", "benches"} for part in relative.parts)


def scan_source(relative: Path, source: str) -> list[str]:
    """Return all policy violations in one Rust source file."""
    errors: list[str] = []
    sanitized = sanitize_rust(source)
    lines = source.splitlines()
    test_ranges = cfg_test_ranges(sanitized)

    if is_compilation_root(relative) and FORBID_ATTRIBUTE_RE.search(sanitized) is None:
        errors.append(f"{relative}: compilation root lacks #![forbid(unsafe_code)]")
    for pattern, description in BANNED_PATTERNS:
        for match in pattern.finditer(sanitized):
            errors.append(f"{relative}:{line_number(sanitized, match.start())}: {description}")

    for match in ALLOW_RE.finditer(sanitized):
        source_line = line_number(sanitized, match.start())
        if not has_annotation(lines, source_line, ALLOW_ANNOTATION_RE):
            errors.append(f"{relative}:{source_line}: lint allow lacks review annotation")

    separation = e2ee_separation_pattern(relative)
    if separation is not None and not is_test_source(relative):
        for match in separation.finditer(sanitized):
            if offset_in_ranges(match.start(), test_ranges):
                continue
            errors.append(
                f"{relative}:{line_number(sanitized, match.start())}: "
                f"E2EE separation forbids {match.group(0)!r} in a server-side E2EE surface"
            )

    if not is_test_source(relative):
        for match in ASSERT_RE.finditer(sanitized):
            if offset_in_ranges(match.start(), test_ranges):
                continue
            source_line = line_number(sanitized, match.start())
            if not has_annotation(lines, source_line, ASSERT_ANNOTATION_RE):
                errors.append(
                    f"{relative}:{source_line}: production assertion lacks internal-proof review annotation"
                )
        for shape in function_shapes(sanitized):
            offset = sum(len(line) + 1 for line in sanitized.splitlines()[: shape.line - 1])
            if offset_in_ranges(offset, test_ranges):
                continue
            triggers: list[str] = []
            if shape.logical_lines > POLICY["function_logical_line_review"]:
                triggers.append(f"{shape.logical_lines} logical lines")
            if shape.nesting > POLICY["control_nesting_review"]:
                triggers.append(f"nesting {shape.nesting}")
            if shape.complexity > POLICY["cyclomatic_complexity_review"]:
                triggers.append(f"complexity {shape.complexity}")
            if triggers and not has_annotation(lines, shape.line, FOCUS_ANNOTATION_RE):
                errors.append(
                    f"{relative}:{shape.line}: function {shape.name} requires decomposition review "
                    f"({', '.join(triggers)})"
                )
    return errors


def rust_sources(root: Path) -> list[Path]:
    """Return every checked-in workspace Rust source candidate."""
    paths = list((root / "crates").glob("**/*.rs"))
    paths.extend((root / "crates").glob("*/build.rs"))
    return sorted(set(paths))


def validate(root: Path) -> int:
    """Run the complete source policy scan."""
    load_policy(root)
    paths = rust_sources(root)
    if not paths:
        raise SourcePolicyError("workspace contains no Rust sources")
    errors: list[str] = []
    for path in paths:
        relative = path.relative_to(root)
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            errors.append(f"{relative}: cannot read UTF-8 source: {error}")
            continue
        errors.extend(scan_source(relative, source))
    if errors:
        raise SourcePolicyError("; ".join(errors))
    return len(paths)


def expect_violation(label: str, source: str, fragment: str) -> None:
    """Require one seeded Rust source violation to be detected."""
    errors = scan_source(Path("crates/fixture/src/lib.rs"), source)
    if not any(fragment in error for error in errors):
        raise SourcePolicyError(f"self-test {label!r} was not rejected: {errors}")


def self_test(root: Path) -> int:
    """Exercise every source-policy rejection category and false-positive guard."""
    load_policy(root)
    valid = "#![forbid(unsafe_code)]\n\npub fn left_aligned(value: bool) -> bool {\n    if !value { return false; }\n    true\n}\n"
    if scan_source(Path("crates/fixture/src/lib.rs"), valid):
        raise SourcePolicyError("self-test valid fixture was rejected")
    cases = 0

    fixtures = (
        ("missing forbid", "pub fn value() {}\n", "lacks #![forbid"),
        (
            "comment-only forbid",
            "// #![forbid(unsafe_code)]\npub fn value() {}\n",
            "lacks #![forbid",
        ),
        ("unsafe", valid + "unsafe fn bad() {}\n", "unsafe Rust token"),
        ("panic", valid + "fn bad() { panic!(\"bad\"); }\n", "panic/placeholder"),
        ("unreachable", valid + "fn bad() { unreachable!(); }\n", "panic/placeholder"),
        ("debug assert", valid + "fn bad() { debug_assert!(true); }\n", "panic/placeholder"),
        ("todo", valid + "fn bad() { todo!(); }\n", "panic/placeholder"),
        ("unwrap", valid + "fn bad(v: Option<u8>) { v.unwrap(); }\n", "unwrap/expect"),
        (
            "unbounded",
            valid + "fn bad() { let _ = tokio::sync::mpsc::unbounded_channel::<u8>(); }\n",
            "unbounded channel",
        ),
        (
            "aliased unbounded",
            valid + "use tokio::sync::mpsc::unbounded_channel as queue;\n",
            "unbounded channel",
        ),
        (
            "imported standard channel",
            valid
            + "use std::sync::mpsc::channel;\n"
            + "fn bad() { let _queue = channel::<u8>(); }\n",
            "unbounded channel",
        ),
        (
            "group-imported standard channel",
            valid
            + "use std::sync::mpsc::{channel};\n"
            + "fn bad() { let _queue = channel::<u8>(); }\n",
            "unbounded channel",
        ),
        (
            "aliased channel namespace",
            valid
            + "use std::sync::mpsc as queue;\n"
            + "fn bad() { let _queue = queue::channel::<u8>(); }\n",
            "unbounded channel",
        ),
        (
            "escaped channel constructor",
            valid
            + "fn bad() { let constructor = std::sync::mpsc::channel::<u8>; "
            + "let _queue = constructor(); }\n",
            "unbounded channel",
        ),
        (
            "panic any",
            valid + "fn bad() { std::panic::panic_any(\"bad\"); }\n",
            "panic/abort function",
        ),
        (
            "resume unwind",
            valid
            + "fn bad(payload: Box<dyn std::any::Any + Send>) { "
            + "std::panic::resume_unwind(payload); }\n",
            "panic/abort function",
        ),
        (
            "process abort",
            valid + "fn bad() { std::process::abort(); }\n",
            "panic/abort function",
        ),
        (
            "wrapping atomic decrement",
            valid
            + "fn bad(value: &std::sync::atomic::AtomicUsize) { "
            + "value.fetch_sub(1, std::sync::atomic::Ordering::AcqRel); }\n",
            "wrapping atomic decrement",
        ),
        (
            "conditional allow",
            valid + "#[cfg_attr(not(test), allow(dead_code))]\nfn hidden() {}\n",
            "lint allow lacks",
        ),
        ("assert", valid + "fn bad() { assert!(true); }\n", "assertion lacks"),
        (
            "unreviewed allow",
            valid + "#[allow(dead_code)]\nfn hidden() {}\n",
            "lint allow lacks",
        ),
        (
            "long function",
            valid + "fn long() {\n" + "    let _value = 1;\n" * 61 + "}\n",
            "logical lines",
        ),
        (
            "nesting",
            valid + "fn nested() { if true { if true { if true { if true { let _v = 1; } } } } }\n",
            "nesting",
        ),
        (
            "complexity",
            valid + "fn complex(v: bool) { if v {} if v {} if v {} if v {} if v {} if v {} if v {} if v {} if v {} if v {} }\n",
            "complexity",
        ),
    )
    for label, source, fragment in fixtures:
        expect_violation(label, source, fragment)
        cases += 1

    harmless = valid + (
        "// unsafe { panic!(\"comment\"); tokio::sync::mpsc::unbounded_channel(); }\n"
        "const TEXT: &str = \"unsafe panic! unwrap unbounded_channel\";\n"
        "const RAW: &str = r#\"todo! unsafe\"#;\n"
        "fn bounded() { let _queue = std::sync::mpsc::sync_channel::<u8>(1); }\n"
    )
    harmless_errors = scan_source(Path("crates/fixture/src/lib.rs"), harmless)
    if harmless_errors:
        raise SourcePolicyError(f"comment/string false-positive guard failed: {harmless_errors}")
    cases += 1
    e2ee_root = Path("crates/agenc-relay-e2ee/src/lib.rs")
    e2ee_secret = valid + "fn bad(epoch_secret: &[u8]) -> usize { epoch_secret.len() }\n"
    if not any("E2EE separation" in error for error in scan_source(e2ee_root, e2ee_secret)):
        raise SourcePolicyError("self-test 'e2ee secret surface' was not rejected")
    e2ee_signing = valid + "fn bad() { let _ = sign_canonical; }\n"
    if not any("E2EE separation" in error for error in scan_source(e2ee_root, e2ee_signing)):
        raise SourcePolicyError("self-test 'e2ee signing surface' was not rejected")
    e2ee_test = valid + "#[cfg(test)]\nmod tests { fn ok(epoch_secret: u8) -> u8 { epoch_secret } }\n"
    if any("E2EE separation" in error for error in scan_source(e2ee_root, e2ee_test)):
        raise SourcePolicyError("self-test 'e2ee test surface' was rejected")
    runtime_root = Path("crates/agenc-relay-runtime/src/e2ee/mod.rs")
    runtime_signing = valid + "fn ok() { let _ = sign_canonical; }\n"
    if any("E2EE separation" in error for error in scan_source(runtime_root, runtime_signing)):
        raise SourcePolicyError("self-test 'runtime sequencer signing' was rejected")
    runtime_secret = valid + "fn bad(plaintext: &[u8]) -> usize { plaintext.len() }\n"
    if not any("E2EE separation" in error for error in scan_source(runtime_root, runtime_secret)):
        raise SourcePolicyError("self-test 'runtime plaintext surface' was not rejected")
    cases += 5
    cfg_test_assertion = valid + "#[cfg(test)]\nmod tests { #[test] fn works() { assert!(true); } }\n"
    cfg_test_errors = scan_source(Path("crates/fixture/src/lib.rs"), cfg_test_assertion)
    if cfg_test_errors:
        raise SourcePolicyError(f"cfg(test) assertion guard failed: {cfg_test_errors}")
    cases += 1
    return cases


def fail(message: str) -> NoReturn:
    """Print a stable command-line error and exit unsuccessfully."""
    print(f"source policy failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Dispatch the source scan and seeded negative tests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "check":
            count = validate(root)
            print(f"source policy: ok ({count} Rust files)")
        else:
            cases = self_test(root)
            print(f"source policy self-test: ok ({cases} cases)")
    except SourcePolicyError as error:
        fail(str(error))


if __name__ == "__main__":
    main()
