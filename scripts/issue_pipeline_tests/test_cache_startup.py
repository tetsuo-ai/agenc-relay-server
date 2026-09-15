"""Cold installed startup reaches actual permission preparation using public fixtures.

No host Cargo cache, model session, network, Docker or user service is used.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

from issue_pipeline.config import Config
from issue_pipeline.installer import install
from issue_pipeline.sandbox import (CACHE_CONTROL_TEXT, CACHE_SEED_TEXT, DEPENDENCY_CACHE_PATHS,
                                    SandboxFailure, prepare_cargo_cache)
from issue_pipeline_tests.test_controller import ScriptedGithub, git


REGISTRY = "index.crates.io-1949cf8c6b5b557f"


def public_registry(path):
    for category in ("src", "cache", "index"):
        public = path / "registry" / category / REGISTRY
        public.mkdir(parents=True)
        (public / "public-fixture").write_text("public registry fixture\n")
        private = path / "registry" / category / "private.example-0123456789abcdef"
        private.mkdir()
        (private / "private-fixture").write_text("PRIVATE_REGISTRY_SENTINEL\n")
    for name in ("config.toml", "credentials.toml"):
        (path / name).write_text("PRIVATE_CONFIGURATION_SENTINEL\n")
    (path / "git").mkdir()
    (path / "git/private-checkout").write_text("PRIVATE_GIT_SENTINEL\n")


class CachePreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agenc-cache-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.original = self.root / "host-cargo"
        public_registry(self.original)
        self.config = Config(state_dir=str(self.root / "state"))
        self.cache = self.config.state / "gate-cache/cargo"
        environment = mock.patch.dict(os.environ, {"CARGO_HOME": str(self.original)})
        environment.start()
        self.addCleanup(environment.stop)

    def test_cold_seed_contains_only_public_registry_data_and_all_exact_controls(self):
        self.assertFalse(self.cache.exists())
        self.assertEqual(prepare_cargo_cache(self.config), self.cache)
        for category in ("src", "cache", "index"):
            self.assertEqual((self.cache / "registry" / category / REGISTRY / "public-fixture").read_text(),
                             "public registry fixture\n")
            self.assertFalse((self.cache / "registry" / category / "private.example-0123456789abcdef").exists())
        for relative in DEPENDENCY_CACHE_PATHS:
            control = self.cache / relative / ".gate-readonly-canary"
            self.assertEqual(control.read_text(), CACHE_CONTROL_TEXT)
            self.assertEqual(control.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.cache / ".public-registry-seeded").read_text(), CACHE_SEED_TEXT)
        self.assertFalse((self.cache / "config.toml").exists())
        self.assertFalse((self.cache / "credentials.toml").exists())
        self.assertFalse((self.cache / "git/private-checkout").exists())
        self.assertEqual((self.original / "credentials.toml").read_text(), "PRIVATE_CONFIGURATION_SENTINEL\n")

    def test_repeat_start_validates_without_recopying_or_replacing_controls(self):
        prepare_cargo_cache(self.config)
        files = [self.cache / ".public-registry-seeded",
                 *(self.cache / relative / ".gate-readonly-canary" for relative in DEPENDENCY_CACHE_PATHS)]
        identities = [(path.stat().st_ino, path.read_bytes()) for path in files]
        with mock.patch("issue_pipeline.sandbox.subprocess.run") as copy, \
                mock.patch.dict(os.environ, {"CARGO_HOME": str(self.root / "absent-source")}):
            self.assertEqual(prepare_cargo_cache(self.config), self.cache)
        copy.assert_not_called()
        self.assertEqual([(path.stat().st_ino, path.read_bytes()) for path in files], identities)

    def test_absent_host_registry_still_prepares_first_session_controls(self):
        with mock.patch.dict(os.environ, {"CARGO_HOME": str(self.root / "absent-source")}):
            prepare_cargo_cache(self.config)
        self.assertTrue((self.cache / "registry/index").is_dir())
        for relative in DEPENDENCY_CACHE_PATHS:
            self.assertEqual((self.cache / relative / ".gate-readonly-canary").read_text(), CACHE_CONTROL_TEXT)

    def test_interrupted_copy_retains_one_stage_and_refuses_accumulating_retry_copies(self):
        def interrupted(argv, **kwargs):
            self.assertGreater(kwargs["timeout"], 0)
            self.assertLessEqual(kwargs["timeout"], 180)
            staged = Path(argv[-1])
            staged.mkdir()
            (staged / "partial").write_text("retained partial bytes\n")
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        with mock.patch("issue_pipeline.sandbox.subprocess.run", side_effect=interrupted):
            with self.assertRaisesRegex(SandboxFailure, "retain partial cache"):
                prepare_cargo_cache(self.config)
        stages = list(self.cache.glob("registry/*/.seed-*"))
        self.assertEqual(len(stages), 1)
        self.assertFalse((self.cache / ".public-registry-seeded").exists())
        with mock.patch("issue_pipeline.sandbox.subprocess.run") as copy:
            for _ in range(2):
                with self.assertRaisesRegex(SandboxFailure, "interrupted public Cargo seed remains"):
                    prepare_cargo_cache(self.config)
            copy.assert_not_called()
        self.assertEqual(list(self.cache.glob("registry/*/.seed-*")), stages)
        self.assertEqual((stages[0] / "partial").read_text(), "retained partial bytes\n")

    def test_invalid_marker_and_control_are_preserved_and_refused(self):
        prepare_cargo_cache(self.config)
        for relative in (".public-registry-seeded", "registry/src/.gate-readonly-canary"):
            path = self.cache / relative
            original = path.read_bytes()
            path.write_bytes(b"invalid\n")
            with self.assertRaisesRegex(SandboxFailure, "control is invalid"):
                prepare_cargo_cache(self.config)
            self.assertEqual(path.read_bytes(), b"invalid\n")
            path.write_bytes(original)

    def test_symlink_ancestors_and_control_aliases_never_touch_foreign_files(self):
        foreign = self.root / "foreign"
        foreign.mkdir()
        self.config.state.mkdir()
        (self.config.state / "gate-cache").symlink_to(foreign, target_is_directory=True)
        with self.assertRaisesRegex(SandboxFailure, "symlinks"):
            prepare_cargo_cache(self.config)
        self.assertEqual(list(foreign.iterdir()), [])
        (self.config.state / "gate-cache").unlink()
        prepare_cargo_cache(self.config)
        control = self.cache / "registry/src/.gate-readonly-canary"
        control.unlink()
        target = foreign / "untouched"
        target.write_text(CACHE_CONTROL_TEXT)
        control.symlink_to(target)
        with self.assertRaises(SandboxFailure):
            prepare_cargo_cache(self.config)
        self.assertEqual(target.read_text(), CACHE_CONTROL_TEXT)
        control.unlink()
        os.link(target, control)
        with self.assertRaisesRegex(SandboxFailure, "control is invalid"):
            prepare_cargo_cache(self.config)
        self.assertEqual(target.read_text(), CACHE_CONTROL_TEXT)

    def test_fifo_control_is_rejected_without_blocking(self):
        prepare_cargo_cache(self.config)
        control = self.cache / "registry/cache/.gate-readonly-canary"
        control.unlink()
        os.mkfifo(control, 0o600)
        with self.assertRaisesRegex(SandboxFailure, "control is invalid"):
            prepare_cargo_cache(self.config)

    def test_inventory_and_total_copy_deadline_are_bounded(self):
        with mock.patch("issue_pipeline.sandbox.MAX_REGISTRY_ROOTS", 0), \
                mock.patch("issue_pipeline.sandbox.subprocess.run") as copy:
            with self.assertRaisesRegex(SandboxFailure, "inventory exceeds"):
                prepare_cargo_cache(self.config)
            copy.assert_not_called()
        with mock.patch("issue_pipeline.sandbox.time.monotonic", side_effect=[0, 181]), \
                mock.patch("issue_pipeline.sandbox.subprocess.run") as copy:
            with self.assertRaisesRegex(SandboxFailure, "startup deadline"):
                prepare_cargo_cache(self.config)
            copy.assert_not_called()
        self.assertFalse((self.cache / ".public-registry-seeded").exists())

    def test_retained_inventory_is_bounded_before_any_new_copy(self):
        prepare_cargo_cache(self.config)
        index = self.cache / "registry/index"
        for number in range(33):
            (index / ("retained-" + str(number))).mkdir()
        with mock.patch("issue_pipeline.sandbox.subprocess.run") as copy:
            with self.assertRaisesRegex(SandboxFailure, "inventory exceeds"):
                prepare_cargo_cache(self.config)
            copy.assert_not_called()
        self.assertEqual(len(list(index.glob("retained-*"))), 33)

    def test_existing_canary_does_not_reduce_the_repeat_start_registry_limit(self):
        prepare_cargo_cache(self.config)
        with mock.patch("issue_pipeline.sandbox.MAX_REGISTRY_ROOTS", 1):
            self.assertEqual(prepare_cargo_cache(self.config), self.cache)


class InstalledColdStartTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agenc-installed-cold-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.original = self.home / "public-cargo"
        public_registry(self.original)
        environment = mock.patch.dict(os.environ, {"CARGO_HOME": str(self.original),
                                                    "RUSTUP_HOME": str(self.home / "rustup")})
        environment.start()
        self.addCleanup(environment.stop)
        home = mock.patch("pathlib.Path.home", return_value=self.home)
        home.start()
        self.addCleanup(home.stop)
        self.source = self.root / "source"
        self.source.mkdir()
        git(self.root, "init", "--initial-branch=main", str(self.source))
        for key, value in (("user.name", "Offline Cold Start"), ("user.email", "cold@example.invalid")):
            git(self.source, "config", key, value)
        scripts = Path(__file__).resolve().parents[1]
        shutil.copytree(scripts / "issue_pipeline", self.source / "scripts/issue_pipeline",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copyfile(scripts / "issue-pipeline.py", self.source / "scripts/issue-pipeline.py")
        (self.source / "Cargo.toml").write_text('[workspace]\n')
        git(self.source, "add", ".")
        git(self.source, "commit", "-m", "Frozen offline installed controller fixture")
        self.sha = git(self.source, "rev-parse", "HEAD")
        self.remote = self.root / "remote.git"
        git(self.root, "init", "--bare", "--initial-branch=main", str(self.remote))
        git(self.source, "remote", "add", "origin", str(self.remote))
        git(self.source, "push", "origin", "main")
        configuration = self.root / "install.toml"
        configuration.write_text('version = 1\nstate_dir = ' + json.dumps(str(self.home / "state"))
                                 + '\nmax_issues = 1\nminimum_free_gib = 1\n')
        configuration.chmod(0o600)
        def manager(*args):
            if args == ("show", "--property=ActiveState", "--value", "agenc-ircd-issue-pipeline.service"):
                return "inactive\n"
            if args == ("daemon-reload",):
                return ""
            self.fail("offline installer attempted a service start")
        with mock.patch("issue_pipeline.installer._systemctl", side_effect=manager):
            installed = install(configuration, self.source, self.sha)
        self.alias = "installed_cold_pipeline_" + uuid.uuid4().hex
        package = Path(installed["release_path"]) / "scripts/issue_pipeline"
        spec = importlib.util.spec_from_file_location(self.alias, package / "__init__.py",
                                                    submodule_search_locations=[str(package)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[self.alias] = module
        spec.loader.exec_module(module)
        self.addCleanup(lambda: [sys.modules.pop(name) for name in list(sys.modules)
                                 if name == self.alias or name.startswith(self.alias + ".")])
        self.control = importlib.import_module(self.alias + ".controller")
        self.permissions = importlib.import_module(self.alias + ".permissions")
        self.sandbox = importlib.import_module(self.alias + ".sandbox")
        self.states = importlib.import_module(self.alias + ".state")
        config_module = importlib.import_module(self.alias + ".config")
        self.config = config_module.Config.load(Path(installed["config_path"]))
        self.cache = self.config.state / "gate-cache/cargo"
        self.assertFalse(self.cache.exists())
        git(self.root, "clone", str(self.remote), str(self.config.clone))
        repo_module = importlib.import_module(self.alias + ".gitops")
        self.repo = repo_module.GitRepo(self.config.clone, worktree_root=self.config.worktrees)
        self.github = ScriptedGithub(self.repo, self.sha, self.config.repository)
        self.github.issues[41]["state"] = "closed"
        self.gate = mock.Mock()
        self.calls = []
        self.events = []
        tools = self.home / "trusted-tools"
        tools.mkdir()
        roots = mock.patch(self.alias + ".permissions._tool_roots", return_value=[tools])
        roots.start()
        self.addCleanup(roots.stop)
        self.runner = mock.Mock()
        self.runner.run.side_effect = self.first_session
        self.controller = self.control.Controller(self.config, repo=self.repo, github=self.github,
                                                  runner=self.runner, gate=self.gate)
        self.addCleanup(self.controller.state.close)
        self.controller.log = mock.Mock()
        actual_cleanup = self.control.halt_children
        def list_owned_units(argv, **kwargs):
            self.assertEqual(argv, ["systemctl", "--user", "list-units", "--all", "--no-legend",
                                    "--plain", "--no-pager"])
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        def cleanup(state):
            with mock.patch(self.alias + ".controller.subprocess.run", side_effect=list_owned_units):
                actual_cleanup(state)
            self.events.append("cleanup")
        cleanup_patch = mock.patch(self.alias + ".controller.halt_children", side_effect=cleanup)
        cleanup_patch.start()
        self.addCleanup(cleanup_patch.stop)

    def first_session(self, role, worktree, prompt, output, **kwargs):
        self.assertEqual(role, "planner")
        self.assertEqual(self.events, ["cleanup"])
        with self.assertRaises(self.states.ClaimConflict):
            with self.states.SupervisorLock(self.config.state / "supervisor.lock"):
                self.fail("startup preparation and admission escaped the supervisor lock")
        output.mkdir(parents=True)
        launcher = self.home / "trusted-tools" / "srt"
        launcher.write_text("#!/bin/sh\nexit 0\n")
        launcher.chmod(0o700)
        profile = self.permissions.prepare_permissions(worktree, output, role, str(launcher))
        policy = json.loads((output / "permissions.json").read_text())
        filesystem = policy["settings"]["sandbox"]["filesystem"]
        self.assertIn(str(self.cache), filesystem["allowRead"])
        self.assertIn(str(self.cache), filesystem["denyWrite"])
        self.assertIn(str(self.home) + "/", filesystem["denyRead"])
        self.assertEqual(set(policy["environment"]), {"TMPDIR", "CARGO_HOME", "RUSTUP_HOME"})
        for relative in DEPENDENCY_CACHE_PATHS:
            self.assertEqual((self.cache / relative / ".gate-readonly-canary").read_text(), CACHE_CONTROL_TEXT)
        self.assertEqual((self.cache / ".public-registry-seeded").read_text(), CACHE_SEED_TEXT)
        for path in policy["probe"]["readonly"]:
            self.assertTrue(Path(path).is_file(), path)
        private_cargo = Path(profile.environment["CARGO_HOME"])
        self.assertEqual((private_cargo / "registry/src").resolve(), self.cache / "registry/src")
        self.assertFalse((self.cache / "credentials.toml").exists())
        self.calls.append((role, worktree, profile))
        self.events.append("planner")
        result = {"status": "blocked", "summary": "First planner reached actual permission admission.",
                  "phases": [], "blockers": ["Offline model boundary stops after admission."]}
        (output / "result.json").write_text(json.dumps(result))
        return result

    def test_installed_bundle_cold_start_reaches_first_planner_without_any_prior_gate(self):
        self.assertIn("releases", self.control.__file__)
        self.controller.run(once=True)
        self.assertEqual(self.events, ["cleanup", "planner"])
        self.assertEqual(len(self.calls), 1)
        self.gate.run.assert_not_called()
        self.assertFalse(self.calls[0][1].exists())
        marker = self.cache / ".public-registry-seeded"
        identity = marker.stat().st_ino
        with mock.patch.object(self.sandbox.subprocess, "run", wraps=subprocess.run) as commands:
            self.controller.run(once=True)
        self.assertFalse(any(call.args[0][0] == "cp" for call in commands.call_args_list))
        self.assertEqual(marker.stat().st_ino, identity)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.events, ["cleanup", "planner", "cleanup"])

    def test_cleanup_refusal_prevents_cache_preparation_and_first_session(self):
        with mock.patch(self.alias + ".controller.halt_children",
                        side_effect=self.control.PipelineBlocked("owned child cleanup remains uncertain")):
            with self.assertRaisesRegex(self.control.PipelineBlocked, "cleanup remains uncertain"):
                self.controller.run(once=True)
        self.assertFalse(self.cache.exists())
        self.runner.run.assert_not_called()
        self.gate.run.assert_not_called()

    def test_startup_preparation_failure_retains_checkpoint_and_dispatches_no_session(self):
        self.controller.state.set_task(41, "blocked", {"retained": "existing accepted context"})
        self.cache.mkdir(parents=True)
        marker = self.cache / ".public-registry-seeded"
        marker.write_text("corrupt retained marker\n")
        with self.assertRaisesRegex(self.sandbox.SandboxFailure, "control is invalid"):
            self.controller.run(once=True)
        self.assertEqual(marker.read_text(), "corrupt retained marker\n")
        self.assertEqual(self.controller.state.get_task(41)["data"], {"retained": "existing accepted context"})
        self.assertEqual(self.events, ["cleanup"])
        self.runner.run.assert_not_called()
        self.gate.run.assert_not_called()
