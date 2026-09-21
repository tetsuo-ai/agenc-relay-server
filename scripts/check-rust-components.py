#!/usr/bin/env python3
"""Probe the exact LLVM tools shipped by the active stable Rust compiler."""

from __future__ import annotations

import argparse
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

# Three five-second child limits leave cleanup time inside the recorder's
# separate 30-second timeout for this helper.
COMMAND_TIMEOUT_SECONDS = 5.0
MAX_STREAM_BYTES = 64 * 1024
READ_CHUNK_BYTES = 4 * 1024
PROCESS_EXIT_GRACE_SECONDS = 1.0
COMPONENT_FILES = {
    "llvm-cov": "llvm-cov",
    "llvm-profdata": "llvm-profdata",
}
HOST_PATTERN = re.compile(
    r"[A-Za-z0-9_]+(?:[.][A-Za-z0-9_]+)*"
    r"(?:-[A-Za-z0-9_]+(?:[.][A-Za-z0-9_]+)*)+"
)
FORBIDDEN_LINE_CHARACTERS = frozenset(
    {"\r", "\x00", "\x0b", "\x0c", "\x85", "\u2028", "\u2029"}
)


class ProbeError(ValueError):
    """A compiler-discovery, path-validation, or command-execution failure."""


@dataclass(frozen=True)
class CommandOutput:
    """Bounded output and status from one child process."""

    stdout: bytes
    stderr: bytes
    returncode: int


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill one isolated child process group and close its captured streams."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        if process.poll() is None:
            process.kill()

    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()

    try:
        process.wait(timeout=PROCESS_EXIT_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=PROCESS_EXIT_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    timeout_seconds: float = COMMAND_TIMEOUT_SECONDS,
    max_stream_bytes: int = MAX_STREAM_BYTES,
) -> CommandOutput:
    """Run one command with hard time and per-stream memory ceilings."""
    if not argv or any(not argument for argument in argv):
        raise ProbeError("command argv must contain nonempty arguments")
    if timeout_seconds <= 0:
        raise ProbeError("command timeout must be positive")
    if max_stream_bytes <= 0:
        raise ProbeError("command output limit must be positive")

    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=None if environment is None else dict(environment),
            close_fds=True,
            start_new_session=True,
            shell=False,
        )
    except OSError as error:
        raise ProbeError(f"cannot execute {argv[0]!r}: {error}") from error

    stdout = process.stdout
    stderr = process.stderr
    if stdout is None or stderr is None:
        terminate_process_group(process)
        raise ProbeError("cannot capture child-process output")

    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    failed = True
    try:
        for name, stream in (("stdout", stdout), ("stderr", stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError(f"command timed out after {timeout_seconds:g} seconds")
            events = selector.select(remaining)
            if not events:
                continue

            for key, _ in events:
                name = key.data
                buffer = buffers[name]
                read_size = min(
                    READ_CHUNK_BYTES,
                    max_stream_bytes + 1 - len(buffer),
                )
                try:
                    chunk = os.read(key.fileobj.fileno(), read_size)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > max_stream_bytes:
                    raise ProbeError(
                        f"command {name} exceeded {max_stream_bytes} bytes"
                    )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError(f"command timed out after {timeout_seconds:g} seconds")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise ProbeError(
                f"command timed out after {timeout_seconds:g} seconds"
            ) from error
        failed = False
    except (OSError, ValueError) as error:
        if isinstance(error, ProbeError):
            raise
        raise ProbeError(f"cannot read bounded command output: {error}") from error
    finally:
        selector.close()
        if failed:
            terminate_process_group(process)
        else:
            for stream in (stdout, stderr):
                if not stream.closed:
                    stream.close()

    return CommandOutput(
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        returncode=returncode,
    )


def checked_stdout(
    argv: Sequence[str],
    label: str,
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    timeout_seconds: float = COMMAND_TIMEOUT_SECONDS,
    max_stream_bytes: int = MAX_STREAM_BYTES,
) -> bytes:
    """Run one command and require successful, quiet, exact UTF-8 output."""
    output = run_bounded(
        argv,
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout_seconds,
        max_stream_bytes=max_stream_bytes,
    )
    if output.returncode != 0:
        raise ProbeError(f"{label} exited with status {output.returncode}")
    if output.stderr:
        raise ProbeError(f"{label} wrote to stderr")
    try:
        output.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ProbeError(f"{label} stdout is not valid UTF-8") from error
    if not output.stdout:
        raise ProbeError(f"{label} produced empty stdout")
    return output.stdout


def single_output_line(stdout: bytes, label: str) -> str:
    """Decode one exact LF-terminated UTF-8 output line."""
    try:
        text = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ProbeError(f"{label} stdout is not valid UTF-8") from error
    if not text.endswith("\n") or "\n" in text[:-1]:
        raise ProbeError(f"{label} must emit exactly one LF-terminated line")
    value = text[:-1]
    if not value or any(character in value for character in FORBIDDEN_LINE_CHARACTERS):
        raise ProbeError(f"{label} contains an invalid line value")
    return value


def parse_sysroot(stdout: bytes) -> Path:
    """Validate and return rustc's canonical absolute sysroot."""
    value = single_output_line(stdout, "rustc sysroot query")
    try:
        sysroot = Path(value)
        if not sysroot.is_absolute():
            raise ProbeError("rustc sysroot is not absolute")
        if str(sysroot) != value:
            raise ProbeError("rustc sysroot is not lexically canonical")
        resolved = sysroot.resolve(strict=True)
        metadata = resolved.stat()
    except ProbeError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise ProbeError(f"rustc sysroot cannot be resolved: {error}") from error
    if resolved != sysroot or str(resolved) != value:
        raise ProbeError("rustc sysroot is not canonical")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ProbeError("rustc sysroot is not a directory")
    return resolved


def parse_host(stdout: bytes) -> str:
    """Extract one valid Rust host triple from rustc verbose-version output."""
    try:
        text = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ProbeError("rustc verbose-version stdout is not valid UTF-8") from error
    if not text.endswith("\n") or any(
        character in text for character in FORBIDDEN_LINE_CHARACTERS
    ):
        raise ProbeError("rustc verbose-version output has invalid line framing")
    host_lines = [
        line.removeprefix("host: ")
        for line in text[:-1].split("\n")
        if line.startswith("host: ")
    ]
    if len(host_lines) != 1:
        raise ProbeError("rustc verbose-version output must contain exactly one host")
    host = host_lines[0]
    if len(host.encode("utf-8")) > 255 or HOST_PATTERN.fullmatch(host) is None:
        raise ProbeError("rustc verbose-version output contains an invalid host")
    return host


def resolve_component(sysroot: Path, host: str, selector: str) -> Path:
    """Resolve one selected LLVM component without accepting caller paths."""
    filename = COMPONENT_FILES.get(selector)
    if filename is None:
        raise ProbeError(f"unsupported Rust component selector: {selector!r}")
    if HOST_PATTERN.fullmatch(host) is None:
        raise ProbeError("cannot derive a component path from an invalid host")

    candidate = sysroot / "lib" / "rustlib" / host / "bin" / filename
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as error:
        raise ProbeError(f"Rust component {selector!r} is missing") from error
    except (OSError, RuntimeError) as error:
        raise ProbeError(f"Rust component {selector!r} cannot be resolved: {error}") from error

    try:
        resolved.relative_to(sysroot)
    except ValueError as error:
        raise ProbeError(
            f"Rust component {selector!r} resolves outside the compiler sysroot"
        ) from error

    try:
        metadata = resolved.stat()
    except OSError as error:
        raise ProbeError(f"Rust component {selector!r} cannot be inspected: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ProbeError(f"Rust component {selector!r} is not a regular file")
    if not os.access(resolved, os.X_OK):
        raise ProbeError(f"Rust component {selector!r} is not executable")
    return resolved


def probe_component(
    selector: str,
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    timeout_seconds: float = COMMAND_TIMEOUT_SECONDS,
    max_stream_bytes: int = MAX_STREAM_BYTES,
) -> bytes:
    """Return one component's exact version bytes after closed-path validation."""
    if selector not in COMPONENT_FILES:
        raise ProbeError(f"unsupported Rust component selector: {selector!r}")
    sysroot_stdout = checked_stdout(
        ["rustc", "--print", "sysroot"],
        "rustc sysroot query",
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout_seconds,
        max_stream_bytes=max_stream_bytes,
    )
    sysroot = parse_sysroot(sysroot_stdout)
    verbose_stdout = checked_stdout(
        ["rustc", "-vV"],
        "rustc verbose-version query",
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout_seconds,
        max_stream_bytes=max_stream_bytes,
    )
    host = parse_host(verbose_stdout)
    component = resolve_component(sysroot, host, selector)
    return checked_stdout(
        [str(component), "--version"],
        f"Rust component {selector!r}",
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout_seconds,
        max_stream_bytes=max_stream_bytes,
    )


def write_python_program(path: Path, body: str) -> None:
    """Create one executable Python fixture for the internal self-test."""
    interpreter = Path(sys.executable).resolve(strict=True)
    if "\n" in str(interpreter):
        raise ProbeError("self-test Python interpreter path contains a newline")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"#!{interpreter}\nimport os\nimport sys\nimport time\n{body}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def make_fixture(
    root: Path,
    *,
    sysroot_stdout: bytes | None = None,
    verbose_stdout: bytes | None = None,
) -> tuple[Path, dict[str, str]]:
    """Create a fake rustc and canonical sysroot for one self-test case."""
    root.mkdir(parents=True)
    sysroot = root / "sysroot"
    sysroot.mkdir()
    canonical_sysroot = sysroot.resolve(strict=True)
    if sysroot_stdout is None:
        sysroot_stdout = f"{canonical_sysroot}\n".encode("utf-8")
    if verbose_stdout is None:
        verbose_stdout = (
            b"rustc 1.98.0 (88d9e12ae 2026-08-18)\n"
            b"host: x86_64-unknown-linux-gnu\n"
            b"release: 1.98.0\n"
        )

    fake_bin = root / "fake-bin"
    write_python_program(
        fake_bin / "rustc",
        "arguments = sys.argv[1:]\n"
        f"sysroot_stdout = {sysroot_stdout!r}\n"
        f"verbose_stdout = {verbose_stdout!r}\n"
        "if arguments == ['--print', 'sysroot']:\n"
        "    os.write(sys.stdout.fileno(), sysroot_stdout)\n"
        "elif arguments == ['-vV']:\n"
        "    os.write(sys.stdout.fileno(), verbose_stdout)\n"
        "else:\n"
        "    raise SystemExit(64)",
    )
    environment = dict(os.environ)
    environment["PATH"] = str(fake_bin) + os.pathsep + environment.get("PATH", "")
    return canonical_sysroot, environment


def install_component(sysroot: Path, selector: str, body: str) -> Path:
    """Install one executable component fixture beneath a fake sysroot."""
    path = sysroot / "lib" / "rustlib" / "x86_64-unknown-linux-gnu" / "bin" / selector
    write_python_program(path, body)
    return path


def expect_probe_error(
    label: str,
    operation: Callable[[], object],
    expected_text: str,
) -> None:
    """Require one self-test operation to fail for the expected reason."""
    try:
        operation()
    except ProbeError as error:
        if expected_text not in str(error):
            raise ProbeError(
                f"self-test {label!r} failed for the wrong reason: {error}"
            ) from error
        return
    raise ProbeError(f"self-test {label!r} unexpectedly succeeded")


def self_test() -> None:
    """Exercise success plus path, process, encoding, and resource failures."""
    checks = 0
    with tempfile.TemporaryDirectory(prefix="agenc-relay-rust-components-") as directory:
        root = Path(directory).resolve(strict=True)

        for selector, version in (
            ("llvm-cov", b"LLVM version 20.1.8\n"),
            ("llvm-profdata", b"llvm-profdata version 20.1.8\n"),
        ):
            case_root = root / f"success-{selector}"
            sysroot, environment = make_fixture(case_root)
            install_component(
                sysroot,
                selector,
                f"os.write(sys.stdout.fileno(), {version!r})",
            )
            observed = probe_component(
                selector,
                cwd=case_root,
                environment=environment,
            )
            if observed != version:
                raise ProbeError(
                    f"self-test did not preserve {selector} version bytes"
                )
            checks += 1

        _, environment = make_fixture(
            root / "relative-sysroot",
            sysroot_stdout=b"relative/sysroot\n",
        )
        expect_probe_error(
            "relative sysroot",
            lambda: probe_component("llvm-cov", environment=environment),
            "not absolute",
        )
        checks += 1

        _, environment = make_fixture(
            root / "invalid-sysroot-utf8",
            sysroot_stdout=b"\xff\n",
        )
        expect_probe_error(
            "invalid sysroot UTF-8",
            lambda: probe_component("llvm-cov", environment=environment),
            "not valid UTF-8",
        )
        checks += 1

        _, environment = make_fixture(
            root / "invalid-host",
            verbose_stdout=b"rustc test\nhost: ../../outside\nrelease: test\n",
        )
        expect_probe_error(
            "invalid host",
            lambda: probe_component("llvm-cov", environment=environment),
            "invalid host",
        )
        checks += 1

        _, environment = make_fixture(
            root / "invalid-host-utf8",
            verbose_stdout=b"rustc test\nhost: x86_64-unknown-linux-gnu\xff\n",
        )
        expect_probe_error(
            "invalid host UTF-8",
            lambda: probe_component("llvm-cov", environment=environment),
            "not valid UTF-8",
        )
        checks += 1

        _, environment = make_fixture(root / "missing")
        expect_probe_error(
            "missing component",
            lambda: probe_component("llvm-cov", environment=environment),
            "is missing",
        )
        checks += 1

        sysroot, environment = make_fixture(root / "nonregular")
        component = (
            sysroot
            / "lib"
            / "rustlib"
            / "x86_64-unknown-linux-gnu"
            / "bin"
            / "llvm-cov"
        )
        component.mkdir(parents=True)
        expect_probe_error(
            "nonregular component",
            lambda: probe_component("llvm-cov", environment=environment),
            "not a regular file",
        )
        checks += 1

        sysroot, environment = make_fixture(root / "nonexecutable")
        component = install_component(
            sysroot,
            "llvm-cov",
            "os.write(sys.stdout.fileno(), b'version\\n')",
        )
        component.chmod(0o644)
        expect_probe_error(
            "nonexecutable component",
            lambda: probe_component("llvm-cov", environment=environment),
            "not executable",
        )
        checks += 1

        sysroot, environment = make_fixture(root / "out-of-tree")
        outside = root / "outside-component"
        write_python_program(
            outside,
            "os.write(sys.stdout.fileno(), b'outside\\n')",
        )
        component = (
            sysroot
            / "lib"
            / "rustlib"
            / "x86_64-unknown-linux-gnu"
            / "bin"
            / "llvm-cov"
        )
        component.parent.mkdir(parents=True)
        component.symlink_to(outside)
        expect_probe_error(
            "out-of-tree symlink",
            lambda: probe_component("llvm-cov", environment=environment),
            "outside the compiler sysroot",
        )
        checks += 1

        sysroot, environment = make_fixture(root / "timeout")
        install_component(sysroot, "llvm-cov", "time.sleep(5)")
        expect_probe_error(
            "component timeout",
            lambda: probe_component(
                "llvm-cov",
                environment=environment,
                timeout_seconds=0.5,
            ),
            "timed out",
        )
        checks += 1

        sysroot, environment = make_fixture(root / "nonzero")
        install_component(sysroot, "llvm-cov", "raise SystemExit(9)")
        expect_probe_error(
            "component nonzero status",
            lambda: probe_component("llvm-cov", environment=environment),
            "status 9",
        )
        checks += 1

        sysroot, environment = make_fixture(root / "stderr")
        install_component(
            sysroot,
            "llvm-cov",
            "os.write(sys.stderr.fileno(), b'unexpected')",
        )
        expect_probe_error(
            "component stderr",
            lambda: probe_component("llvm-cov", environment=environment),
            "wrote to stderr",
        )
        checks += 1

        sysroot, environment = make_fixture(root / "oversize-stdout")
        install_component(
            sysroot,
            "llvm-cov",
            "os.write(sys.stdout.fileno(), b'x' * 4096); time.sleep(5)",
        )
        expect_probe_error(
            "component stdout limit",
            lambda: probe_component(
                "llvm-cov",
                environment=environment,
                max_stream_bytes=256,
            ),
            "stdout exceeded 256 bytes",
        )
        checks += 1

        sysroot, environment = make_fixture(root / "oversize-stderr")
        install_component(
            sysroot,
            "llvm-cov",
            "os.write(sys.stderr.fileno(), b'x' * 4096); time.sleep(5)",
        )
        expect_probe_error(
            "component stderr limit",
            lambda: probe_component(
                "llvm-cov",
                environment=environment,
                max_stream_bytes=256,
            ),
            "stderr exceeded 256 bytes",
        )
        checks += 1

        sysroot, environment = make_fixture(root / "invalid-tool-utf8")
        install_component(
            sysroot,
            "llvm-cov",
            "os.write(sys.stdout.fileno(), b'\\xff\\n')",
        )
        expect_probe_error(
            "component invalid UTF-8",
            lambda: probe_component("llvm-cov", environment=environment),
            "not valid UTF-8",
        )
        checks += 1

        _, environment = make_fixture(root / "selector-traversal")
        expect_probe_error(
            "selector traversal",
            lambda: probe_component("../llvm-cov", environment=environment),
            "unsupported Rust component selector",
        )
        checks += 1

    print(f"Rust component probe self-test passed ({checks} checks)")


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    """Parse the closed command-line interface."""
    parser = argparse.ArgumentParser(
        description="Probe LLVM tools from the active stable Rust compiler sysroot."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    probe_parser = subparsers.add_parser(
        "probe",
        help="emit one validated component version",
    )
    probe_parser.add_argument("selector", choices=tuple(COMPONENT_FILES))
    subparsers.add_parser("self-test", help="run the internal negative-test matrix")
    return parser.parse_args(argv)


def fail(message: str) -> NoReturn:
    """Print one probe failure and exit unsuccessfully."""
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main(argv: Sequence[str] | None = None) -> None:
    """Run the selected probe operation."""
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        if arguments.command == "self-test":
            self_test()
            return
        output = probe_component(arguments.selector)
    except ProbeError as error:
        fail(str(error))
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
