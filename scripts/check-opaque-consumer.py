#!/usr/bin/env python3
"""Exercise the reviewed OPAQUE edge from a separately rooted Git consumer."""

import argparse
import json
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
import tomllib


CONSUMER = """#![forbid(unsafe_code)]

use agenc_relay_auth::{OPAQUE_REGISTRATION_REQUEST_BYTES, client::registration_start};
use agenc_relay_auth::profile::FallibleOpaqueRng;
use agenc_relay_types::{EntropyError, EntropySource};

struct FixtureEntropy;

impl EntropySource for FixtureEntropy {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(0x51);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = FallibleOpaqueRng::new(FixtureEntropy);
    let started = registration_start(&mut rng, "fixed consumer test password")?;
    assert_eq!(started.request.len(), OPAQUE_REGISTRATION_REQUEST_BYTES);
    Ok(())
}
"""


def verify(root: Path, git_url: str, revision: str) -> None:
    """Build and run outside the server workspace with a consumer-owned lock."""
    checker = runpy.run_path(str(root / "scripts/check-workspace.py"))
    expected = next(patch for patch in checker["VENDORED_PATCHES"] if patch["package"] == "opaque-ke")
    with tempfile.TemporaryDirectory(prefix="arcd-opaque-consumer-") as directory:
        consumer = Path(directory)
        (consumer / "src").mkdir()
        (consumer / "src/main.rs").write_text(CONSUMER, encoding="utf-8")
        git_dependency = f"git = {json.dumps(git_url)}, rev = {json.dumps(revision)}"
        (consumer / "Cargo.toml").write_text(
            '[package]\nname = "arcd-opaque-consumer"\nversion = "0.0.0"\n'
            'edition = "2024"\npublish = false\n\n[workspace]\nresolver = "3"\n\n[dependencies]\n'
            f"agenc-relay-auth = {{ {git_dependency} }}\n"
            f"agenc-relay-types = {{ {git_dependency} }}\n",
            encoding="utf-8",
        )

        cargo = ["cargo", "+1.98.0"]
        metadata = json.loads(
            subprocess.check_output([*cargo, "metadata", "--format-version", "1"], cwd=consumer)
        )
        packages = metadata["packages"]
        auth = [package for package in packages if package["name"] == "agenc-relay-auth"]
        opaque = [package for package in packages if package["name"] == expected["package"]]
        if len(auth) != 1 or len(opaque) != 1:
            raise ValueError("expected exactly one auth package and one OPAQUE package")
        source = auth[0]["source"]
        if (
            not isinstance(source, str)
            or not source.startswith("git+")
            or not source.endswith(f"#{revision}")
            or opaque[0]["source"] != source
            or opaque[0]["version"] != expected["version"]
        ):
            raise ValueError("OPAQUE does not resolve from the exact pinned auth Git source")
        checkout = Path(auth[0]["manifest_path"]).parents[2]
        vendor = checkout / expected["path"]
        if Path(opaque[0]["manifest_path"]) != vendor / "Cargo.toml":
            raise ValueError("OPAQUE does not resolve from the reviewed vendored directory")
        if checker["vendored_tree_sha256"](vendor) != expected["tree_sha256"]:
            raise ValueError("the resolved vendored tree differs from the reviewed source")

        lock = tomllib.loads((consumer / "Cargo.lock").read_text(encoding="utf-8"))
        entries = [entry for entry in lock["package"] if entry["name"] == expected["package"]]
        if (
            len(entries) != 1
            or entries[0].get("source") != source
            or entries[0].get("version") != expected["version"]
            or "checksum" in entries[0]
        ):
            raise ValueError("the consumer lock does not select the reviewed Git package")
        subprocess.run([*cargo, "run", "--locked", "--quiet"], cwd=consumer, check=True)
        print(f"OPAQUE consumer: one reviewed {expected['version']} package from {revision}")


def main() -> None:
    """Require an immutable Git commit and run the consumer check."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git", help="server Git URL (default: this checkout)")
    parser.add_argument("--rev", help="full server commit for --git (default: checked-out HEAD)")
    arguments = parser.parse_args()
    if (arguments.git is None) != (arguments.rev is None):
        parser.error("supply --git and --rev together")
    if arguments.rev is not None and re.fullmatch(r"[0-9a-f]{40}", arguments.rev) is None:
        parser.error("--rev requires a full lowercase Git commit hash")
    root = Path(__file__).resolve().parent.parent
    try:
        revision = arguments.rev or subprocess.check_output(
            ["git", "rev-parse", "--verify", "HEAD^{commit}"], cwd=root, text=True
        ).strip()
        verify(root, arguments.git or root.as_uri(), revision)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"OPAQUE consumer check failed: {error}\n")


if __name__ == "__main__":
    main()
