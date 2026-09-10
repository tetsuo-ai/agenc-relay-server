#!/usr/bin/env python3
"""Run one pinned IRC client inside the qualification tools container."""

from __future__ import annotations

import argparse
import errno
import os
import pty
import selectors
import subprocess
import time
from pathlib import Path


def session(client: str, port: int) -> None:
    home = Path("/tmp/client")
    home.mkdir(mode=0o700)
    if client == "weechat":
        commands = [
            "/set weechat.network.gnutls_ca_system off",
            "/set weechat.network.gnutls_ca_user /fixture/ca.pem",
            f"/server add qualification node.test/{port} -tls",
            "/set irc.server.qualification.nicks QualWeeChat",
            "/set irc.server.qualification.tls_verify on",
            "/set irc.server.qualification.tls_priorities NORMAL:-VERS-ALL:+VERS-TLS1.3",
            "/connect qualification",
            "/wait 5s /join -server qualification #qual-public,#qual-secret",
            "/wait 7s /msg -server qualification #qual-public weechat-public-proof",
            "/wait 8s /msg -server qualification #qual-secret weechat-secret-proof",
            "/wait 10s /quit qualification-complete",
        ]
        argv = ["weechat-headless", "--dir", str(home), "--stdout", "--no-connect", "--plugins", "irc"]
        for command in commands:
            argv.extend(["--run-command", command])
        schedule = []
    else:
        argv = ["irssi", "--home", str(home), "--noconnect"]
        schedule = [
            (1, f"/connect -4 -tls -tls_verify -tls_cafile /fixture/ca.pem node.test {port} - QualIrssi"),
            (5, "/join #qual-public,#qual-secret"),
            (7, "/msg #qual-public irssi-public-proof"),
            (8, "/msg #qual-secret irssi-secret-proof"),
            (10, "/quit qualification-complete"),
        ]
    master, slave = pty.openpty()
    environment = {**os.environ, "TERM": "xterm", "HOME": str(home), "LANG": "C.UTF-8"}
    child = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=environment)
    os.close(slave)
    os.set_blocking(master, False)
    started = time.monotonic()
    size = 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(master, selectors.EVENT_READ)
            while child.poll() is None:
                elapsed = time.monotonic() - started
                if elapsed > 30:
                    raise RuntimeError("IRC client exceeded its session budget")
                while schedule and elapsed >= schedule[0][0]:
                    _, command = schedule.pop(0)
                    os.write(master, command.encode() + b"\n")
                for _, _ in selector.select(0.1):
                    try:
                        data = os.read(master, 16384)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            continue
                        raise
                    size += len(data)
                    if size > 1024 * 1024:
                        raise RuntimeError("IRC client exceeded its output budget")
                    os.write(1, data)
            if child.returncode != 0:
                raise RuntimeError(f"IRC client exited with {child.returncode}")
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        os.close(master)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", choices=("weechat", "irssi"))
    parser.add_argument("port", type=int)
    arguments = parser.parse_args()
    if not 1 <= arguments.port <= 65535:
        parser.error("port is outside the TCP range")
    session(arguments.client, arguments.port)
