"""Filesystem and local-Git installation proofs; systemd is always mocked."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from issue_pipeline.installer import InstallError, SERVICE, _quote, install


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=root,
                          text=True, capture_output=True, timeout=30, check=True).stdout.strip()


class InstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="agenc-installer-")
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.home = self.parent / "home %n $name"
        self.home.mkdir()
        self.state = self.home / "private state"
        self.source = self.parent / "source"
        self.source.mkdir()
        git(self.source, "init", "--initial-branch=main")
        git(self.source, "config", "user.name", "Installer Test")
        git(self.source, "config", "user.email", "installer@example.invalid")
        package = self.source / "scripts" / "issue_pipeline"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text('"""Fixture package."""\n')
        (package / "config.py").write_text('"""Fixture configuration module."""\n')
        (package / "controller.py").write_text('"""Fixture controller."""\nVALUE = "trusted bytes"\n')
        (package / "schemas").mkdir()
        (package / "schemas" / "worker.json").write_text('{"type":"object"}\n')
        (self.source / "scripts" / "issue-pipeline.py").write_text('#!/usr/bin/python3\nprint("fixture CLI")\n')
        (self.source / "unrelated.txt").write_text("whole-source cleanliness matters\n")
        git(self.source, "add", ".")
        git(self.source, "commit", "-m", "trusted fixture")
        self.sha = git(self.source, "rev-parse", "HEAD")
        self.config = self.parent / "controller.toml"
        self.config.write_text('version = 1\nstate_dir = ' + json.dumps(str(self.state))
                               + '\nmodel = "gpt-6-astra"\nreasoning_effort = "xhigh"\n')
        self.config.chmod(0o600)
        self.home_patch = patch("pathlib.Path.home", return_value=self.home)
        self.home_patch.start()
        self.addCleanup(self.home_patch.stop)
        self.systemctl = patch("issue_pipeline.installer._systemctl", side_effect=self.systemd)
        self.mock_systemctl = self.systemctl.start()
        self.addCleanup(self.systemctl.stop)

    @staticmethod
    def systemd(*args: str) -> str:
        if args == ("show", "--property=ActiveState", "--value", SERVICE):
            return "inactive\n"
        if args == ("daemon-reload",):
            return ""
        raise AssertionError(f"installer attempted an unexpected service operation: {args}")

    def test_install_copies_exact_committed_bytes_and_keeps_service_stopped(self) -> None:
        with patch.dict(os.environ, {"PATH": "/current/cargo/bin:/current/nvm/bin:/usr/bin",
                                     "OPENAI_API_KEY": "SECRET_SENTINEL", "GH_TOKEN": "SECOND_SECRET"}):
            result = install(self.config, self.source, self.sha)
        release = Path(result["release_path"])
        self.assertEqual(result["state"], "stopped")
        self.assertEqual(release.name, result["bundle_sha256"])
        self.assertEqual(Path(result["config_path"]).read_bytes(), self.config.read_bytes())
        manifest = json.loads((release / "manifest.json").read_text())
        self.assertEqual(manifest["source_commit"], self.sha)
        for entry in manifest["files"]:
            installed = release / entry["path"]
            self.assertEqual(installed.read_bytes(), (self.source / entry["path"]).read_bytes())
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(release.stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE(Path(result["config_path"]).stat().st_mode), 0o600)
        unit = Path(result["unit_path"]).read_text()
        self.assertIn('ExecStart="/usr/bin/python3"', unit)
        self.assertIn('"--config"', unit)
        self.assertIn('"halt-children"', unit)
        self.assertIn("KillMode=control-group", unit)
        # The service must let bounded cleanup stop four model launchers and a
        # gate launcher plus its separately supervised Docker container.
        self.assertIn("TimeoutStopSec=900\n", unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("/current/cargo/bin:/current/nvm/bin:/usr/bin", unit)
        self.assertNotIn("SECRET_SENTINEL", unit)
        self.assertNotIn("SECOND_SECRET", unit)
        self.assertIn("%%n", unit)
        self.assertIn("$$name", unit)
        self.assertFalse(any("start" in call.args or "enable" in call.args for call in self.mock_systemctl.call_args_list))

    def test_repeat_install_verifies_existing_bundle_without_overwriting_it(self) -> None:
        first = install(self.config, self.source, self.sha)
        release = Path(first["release_path"])
        inode = release.stat().st_ino
        file = release / "scripts/issue_pipeline/controller.py"
        file_inode = file.stat().st_ino
        second = install(self.config, self.source, self.sha)
        self.assertEqual(first, second)
        self.assertEqual(release.stat().st_ino, inode)
        self.assertEqual(file.stat().st_ino, file_inode)

    def test_tampered_or_writable_existing_release_is_not_repaired_in_place(self) -> None:
        result = install(self.config, self.source, self.sha)
        file = Path(result["release_path"]) / "scripts/issue_pipeline/controller.py"
        file.chmod(0o600)
        with self.assertRaises(InstallError):
            install(self.config, self.source, self.sha)
        file.write_text("altered controller\n")
        file.chmod(0o400)
        with self.assertRaises(InstallError):
            install(self.config, self.source, self.sha)
        self.assertEqual(file.read_text(), "altered controller\n")

    def test_dirty_whole_source_wrong_sha_and_uncommitted_bundle_are_refused(self) -> None:
        with self.assertRaises(InstallError):
            install(self.config, self.source, "HEAD")
        with self.assertRaises(InstallError):
            install(self.config, self.source, "0" * 40)
        (self.source / "unrelated.txt").write_text("outside package but dirty\n")
        with self.assertRaises(InstallError):
            install(self.config, self.source, self.sha)
        git(self.source, "checkout", "--", "unrelated.txt")
        (self.source / "scripts/issue_pipeline/new.py").write_text("VALUE = 1\n")
        with self.assertRaises(InstallError):
            install(self.config, self.source, self.sha)
        self.mock_systemctl.assert_not_called()

    def test_symlinked_bundle_or_config_or_destination_is_refused(self) -> None:
        alias = self.parent / "config-link"
        alias.symlink_to(self.config)
        with self.assertRaises(InstallError):
            install(alias, self.source, self.sha)
        package_file = self.source / "scripts/issue_pipeline/controller.py"
        package_file.unlink()
        package_file.symlink_to(self.source / "unrelated.txt")
        git(self.source, "add", ".")
        git(self.source, "commit", "-m", "disallowed symlink")
        sha = git(self.source, "rev-parse", "HEAD")
        with self.assertRaises(InstallError):
            install(self.config, self.source, sha)
        git(self.source, "checkout", "--detach", self.sha)
        foreign = self.parent / "foreign"
        foreign.mkdir()
        self.state.symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(InstallError):
            install(self.config, self.source, self.sha)
        self.assertEqual(list(foreign.iterdir()), [])

    def test_running_service_refuses_before_unit_or_config_replacement(self) -> None:
        self.mock_systemctl.side_effect = lambda *args: "active\n"
        with self.assertRaisesRegex(InstallError, "stopped"):
            install(self.config, self.source, self.sha)
        self.assertFalse((self.state / "config.toml").exists())
        self.assertFalse((self.home / ".config/systemd/user" / SERVICE).exists())

    def test_failed_manager_reload_rolls_back_files_and_cleans_temporary_paths(self) -> None:
        self.state.mkdir()
        prior_config = self.state / "config.toml"
        prior_config.write_text("original configuration\n")
        unit = self.home / ".config/systemd/user" / SERVICE
        unit.parent.mkdir(parents=True)
        unit.write_text("original unit\n")
        def fail_reload(*args):
            if args == ("daemon-reload",):
                raise InstallError("injected manager reload failure")
            return self.systemd(*args)
        self.mock_systemctl.side_effect = fail_reload
        with self.assertRaises(InstallError):
            install(self.config, self.source, self.sha)
        self.assertEqual(prior_config.read_text(), "original configuration\n")
        self.assertEqual(unit.read_text(), "original unit\n")
        self.assertFalse(any(path.name.startswith((".pipeline-install-", ".pipeline-config-", ".pipeline-bundle-"))
                             for path in self.home.rglob("*")))

    def test_service_escaping_preserves_literal_specifiers_quotes_and_dollars(self) -> None:
        self.assertEqual(_quote('name %n "quoted" \\ $HOME', command=True),
                         '"name %%n \\"quoted\\" \\\\ $$HOME"')
        self.assertEqual(_quote("PATH=/a/$literal"), '"PATH=/a/$literal"')
        for value in ("line\nbreak", "carriage\rreturn", "zero\0byte", "delete\x7f"):
            with self.subTest(value=value), self.assertRaises(InstallError):
                _quote(value)
        with patch.dict(os.environ, {"PATH": "/usr/bin\nExecStart=/bad"}):
            with self.assertRaises(InstallError):
                install(self.config, self.source, self.sha)

    def test_invalid_python_or_incomplete_controller_bundle_is_refused(self) -> None:
        entry = self.source / "scripts/issue-pipeline.py"
        entry.write_text("def incomplete(\n")
        git(self.source, "add", ".")
        git(self.source, "commit", "-m", "syntax invalid")
        with self.assertRaises(InstallError):
            install(self.config, self.source, git(self.source, "rev-parse", "HEAD"))
        entry.unlink()
        git(self.source, "add", ".")
        git(self.source, "commit", "-m", "missing CLI")
        with self.assertRaises(InstallError):
            install(self.config, self.source, git(self.source, "rev-parse", "HEAD"))


if __name__ == "__main__":
    unittest.main()
