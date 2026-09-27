"""Configuration file and deadline resolution."""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from xpipe_to_ssh import xpipe
from xpipe_to_ssh.cli import parse_options
from xpipe_to_ssh.config import Settings, load_settings
from xpipe_to_ssh.errors import ConfigError
from xpipe_to_ssh.xpipe import DEFAULT_TIMEOUT, default_timeout, set_request_timeout


class SettingsTests(unittest.TestCase):
    def write(self, body: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "config.toml"
        path.write_text(body)
        return path

    def test_missing_file_is_not_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(load_settings(Path(directory) / "absent.toml"), Settings())

    def test_all_supported_keys_are_read(self) -> None:
        path = self.write('shell = "posix"\nagent_socket = "none"\nptb = true\napi_timeout = 2.5\n')

        self.assertEqual(
            load_settings(path),
            Settings(shell="posix", agent_socket="none", ptb=True, api_timeout=2.5),
        )

    def test_malformed_toml_names_the_file(self) -> None:
        path = self.write("shell = \n")

        with self.assertRaises(ConfigError) as caught:
            load_settings(path)
        self.assertIn(str(path), str(caught.exception))

    def test_unknown_key_is_a_reported_typo(self) -> None:
        path = self.write('shell = "posix"\nagent-socket = "none"\n')

        with self.assertRaisesRegex(ConfigError, "agent-socket"):
            load_settings(path)

    def test_wrong_type_and_out_of_range_values_are_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            load_settings(self.write('api_timeout = "soon"\n'))
        with self.assertRaises(ConfigError):
            load_settings(self.write("api_timeout = 0\n"))
        with self.assertRaises(ConfigError):
            load_settings(self.write("api_timeout = 9999\n"))
        with self.assertRaises(ConfigError):
            load_settings(self.write('shell = "fish"\n'))
        with self.assertRaises(ConfigError):
            load_settings(self.write('agent_socket = ""\n'))
        with self.assertRaises(ConfigError):
            load_settings(self.write("ptb = 1\n"))

    def test_environment_variable_selects_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "elsewhere.toml"
            path.write_text('shell = "powershell"\n')
            with mock.patch.dict(os.environ, {"XPIPE_TO_SSH_CONFIG": str(path)}):
                self.assertEqual(load_settings().shell, "powershell")

    def test_explicit_settings_excludes_unset_keys(self) -> None:
        self.assertEqual(Settings(shell="posix").explicit(), {"shell": "posix"})


class TimeoutTests(unittest.TestCase):
    def tearDown(self) -> None:
        set_request_timeout(None)
        os.environ.pop(xpipe.TIMEOUT_ENV, None)

    def test_default_applies_without_configuration(self) -> None:
        self.assertEqual(default_timeout(), DEFAULT_TIMEOUT)

    def test_environment_beats_the_configured_value(self) -> None:
        set_request_timeout(30.0)
        with mock.patch.dict(os.environ, {xpipe.TIMEOUT_ENV: "2"}):
            self.assertEqual(default_timeout(), 2.0)

    def test_configured_value_is_used_without_the_environment(self) -> None:
        set_request_timeout(30.0)
        self.assertEqual(default_timeout(), 30.0)

    def test_unparsable_environment_value_falls_back(self) -> None:
        with mock.patch.dict(os.environ, {xpipe.TIMEOUT_ENV: "soon"}):
            self.assertEqual(default_timeout(), DEFAULT_TIMEOUT)


class CliPrecedenceTests(unittest.TestCase):
    """The documented order: command line, then environment, then file."""

    def options(self, argv: list[str], *, config: str = "", env: dict[str, str] | None = None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(config)
            environment = {"XPIPE_TO_SSH_CONFIG": str(path)}
            environment.update(env or {})
            with mock.patch.dict(os.environ, environment, clear=False):
                _parser, options = parse_options(argv)
            return options

    def test_config_file_supplies_defaults(self) -> None:
        options = self.options(
            ["--list"],
            config='shell = "json"\nagent_socket = "none"\nptb = true\napi_timeout = 4\n',
        )

        self.assertEqual(options.shell, "json")
        self.assertEqual(options.agent_socket, "none")
        self.assertTrue(options.ptb)
        self.assertEqual(options.api_timeout, 4.0)

    def test_command_line_beats_environment_and_file(self) -> None:
        options = self.options(
            ["oracle", "--shell", "posix", "--agent-socket", "/tmp/from-flag.sock"],
            config='shell = "json"\nagent_socket = "none"\n',
            env={"XPIPE_TO_SSH_SHELL": "powershell", "XPIPE_TO_SSH_AGENT_SOCKET": "/tmp/env.sock"},
        )

        self.assertEqual(options.shell, "posix")
        self.assertEqual(options.agent_socket, "/tmp/from-flag.sock")

    def test_environment_beats_the_file(self) -> None:
        options = self.options(
            ["--list"],
            config='shell = "json"\napi_timeout = 4\n',
            env={"XPIPE_TO_SSH_SHELL": "powershell", "XPIPE_API_TIMEOUT": "2"},
        )

        self.assertEqual(options.shell, "powershell")
        self.assertEqual(options.api_timeout, 2.0)

    def test_defaults_apply_with_no_configuration(self) -> None:
        options = self.options(["--list"])

        self.assertEqual(options.shell, "auto")
        self.assertEqual(options.agent_socket, "auto")
        self.assertFalse(options.ptb)
        self.assertIsNone(options.api_timeout)

    def test_invalid_environment_values_are_reported(self) -> None:
        for env in ({"XPIPE_TO_SSH_SHELL": "fish"}, {"XPIPE_API_TIMEOUT": "soon"}):
            with self.subTest(env=env):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit):
                        self.options(["--list"], env=env)
                self.assertIn("error:", stderr.getvalue())

    def test_configured_agent_socket_does_not_conflict_with_list(self) -> None:
        options = self.options(["--list"], config='agent_socket = "/tmp/standing.sock"\n')

        self.assertEqual(options.agent_socket, "/tmp/standing.sock")


if __name__ == "__main__":
    unittest.main()
