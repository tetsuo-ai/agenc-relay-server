"""The mount plan must preserve storage tuples without revealing host HOME."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from issue_pipeline.config import Config
from issue_pipeline.sandbox import DOCKER_HOST, IMAGE, SandboxFailure, filesystem_command


class SandboxPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.config = Config(state_dir=str(self.home / "state"))
        self.worktree = self.config.worktrees / "validation"
        self.output = self.config.state / "gates" / "attempt"
        self.common = self.config.clone / ".git"
        self.admin = self.common / "worktrees" / "validation"
        self.cargo = self.config.state / "gate-cache" / "cargo"
        self.rustup = self.home / ".rustup"
        self.cargo_bin = self.home / ".cargo" / "bin"
        for path in (self.worktree, self.output, self.admin, self.cargo, self.rustup, self.cargo_bin):
            path.mkdir(parents=True)
        for name in ("HEAD", "gitdir", "commondir"):
            (self.admin / name).write_text("benign fixture\n")
        self.source = "a" * 40
        self.identity = "d" * 64
        self.create_result = 0
        self.created = None
        self.unit = "agenc-ircd-pipeline-gate-" + "b" * 32 + ".service"
        self.unit_record = {"unit": self.unit, "source": self.source,
                            "state_dir": str(self.config.state), "repository": self.config.repository}
        (self.output / "unit.json").write_text(json.dumps(self.unit_record))
        self.repo = mock.Mock()
        self.repo.head.return_value = self.source
        self.repo.run.side_effect = lambda argv, **kw: str(self.admin if "--absolute-git-dir" in argv else self.common)

    def command(self):
        def which(name):
            # Exercise ownership checks on a standard executable, without
            # requiring Docker to be installed for this offline test suite.
            return "/usr/bin/env" if name == "docker" else str(self.cargo_bin / "rustup")
        def create(argv, *args, **kwargs):
            self.created = argv
            self.assertIn("create", argv)
            self.assertNotIn("start", argv)
            self.assertTrue((self.output / "container.json").exists())
            return self.create_result, self.identity
        with mock.patch("issue_pipeline.sandbox.Path.home", return_value=self.home), \
                mock.patch("issue_pipeline.sandbox.shutil.which", side_effect=which), \
                mock.patch("issue_pipeline.sandbox.prepare_cargo_cache", return_value=self.cargo), \
                mock.patch("issue_pipeline.sandbox._process", side_effect=create), \
                mock.patch("issue_pipeline.sandbox.record_created_container", return_value=self.identity), \
                mock.patch.dict(os.environ, {"RUSTUP_HOME": str(self.rustup)}):
            return filesystem_command(self.config, self.repo, self.worktree, self.output, probe_only=True)

    def test_exact_owned_pinned_local_container_and_identity_are_recorded_before_launch(self):
        command = self.command()
        self.assertEqual(command[-3:], ["start", "--attach", self.identity])
        command = self.created
        record = json.loads((self.output / "container.json").read_text())
        policy = json.loads((self.output / "filesystem-policy.json").read_text())
        self.assertEqual(record["name"] + ".service", self.unit)
        self.assertEqual(record["image"], IMAGE)
        self.assertEqual(record["source"], self.source)
        self.assertEqual(record["labels"]["agenc-ircd.pipeline.repository"], self.config.repository)
        self.assertEqual(command[command.index("--host") + 1], DOCKER_HOST)
        self.assertIn("--pull=never", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--security-opt=no-new-privileges", command)
        self.assertNotIn("--privileged", command)
        self.assertNotIn("--network=host", command)
        self.assertNotIn("--pid=host", command)
        self.assertEqual(command[command.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
        self.assertEqual(policy["bootstrap"]["home"], str(self.home))
        self.assertEqual(policy["bootstrap"]["home_mount_flags"], os.statvfs(record["private_home"]).f_flag)
        self.assertEqual(policy["bootstrap"]["home_device"], os.stat(record["private_home"]).st_dev)
        self.assertFalse(Path(policy["bootstrap"]["home_scratch"]).exists())

    def test_failed_inert_create_never_authorizes_start(self):
        self.create_result = 1
        with self.assertRaisesRegex(SandboxFailure, "inert gate container creation failed"):
            self.command()
        self.assertTrue((self.output / "container.json").exists())
        self.assertFalse((self.output / "container-id.json").exists())
        self.assertIn("create", self.created)
        self.assertNotIn("start", self.created)

    def test_only_private_home_backs_home_and_protected_mount_ancestors_are_immutable(self):
        self.command()
        record = json.loads((self.output / "container.json").read_text())
        policy = json.loads((self.output / "filesystem-policy.json").read_text())
        mounts = {entry["target"]: entry for entry in policy["mounts"]}
        self.assertEqual(mounts[str(self.home)]["source"], record["private_home"])
        self.assertFalse(mounts[str(self.home)]["readonly"])
        self.assertNotIn(str(self.home), [entry["source"] for entry in mounts.values()])
        for target in (self.home / ".cargo", self.config.state, self.config.worktrees):
            self.assertTrue(mounts[str(target)]["readonly"])
            self.assertTrue(Path(mounts[str(target)]["source"]).is_relative_to(record["private_home"]))
        for target in (self.worktree, self.common, self.output, self.cargo_bin, self.rustup,
                       self.cargo / "registry", self.cargo / "registry/src", self.cargo / "registry/cache",
                       self.admin / "HEAD", self.admin / "gitdir", self.admin / "commondir"):
            self.assertTrue(mounts[str(target)]["readonly"], str(target))
        for target in (self.worktree / "target", self.worktree / "fuzz/target", self.admin,
                       self.worktree / "conformance/evidence/artifacts", self.cargo / "registry/index"):
            self.assertFalse(mounts[str(target)]["readonly"], str(target))
        self.assertFalse(any("docker.sock" in entry["source"] or entry["source"].startswith("/run/")
                             for entry in mounts.values()))

    def test_wrong_source_or_state_record_cannot_create_container_authority(self):
        for field, value in (("source", "c" * 40), ("state_dir", "/different-state")):
            with self.subTest(field=field):
                record = {**self.unit_record, field: value}
                (self.output / "unit.json").write_text(json.dumps(record))
                with self.assertRaises(SandboxFailure):
                    self.command()
                self.assertFalse((self.output / "container.json").exists())
                (self.output / "readonly-canary").unlink()

    def test_candidate_generated_symlink_cannot_redirect_writable_mount(self):
        (self.worktree / "target").symlink_to(self.output, target_is_directory=True)
        with self.assertRaisesRegex(SandboxFailure, "generated directory"):
            self.command()
        self.assertFalse((self.output / "container.json").exists())


if __name__ == "__main__":
    unittest.main()
