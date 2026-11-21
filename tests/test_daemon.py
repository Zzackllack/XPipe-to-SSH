import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from collections.abc import Iterator
from unittest import mock

import requests

from xpipe_to_ssh.cli import AppDependencies, main
from xpipe_to_ssh.daemon import (
    Availability,
    classify,
    ensure_client,
)
from xpipe_to_ssh.errors import XPipeConnectionError
from xpipe_to_ssh.presentation import RICH_AVAILABLE, confirm_open


@contextlib.contextmanager
def fake_tty_stdin(text: str) -> Iterator[None]:
    """Pretend stdin is an interactive terminal that yields ``text`` once."""

    class Tty:
        def __init__(self) -> None:
            self.buffer = io.StringIO(text)

        def isatty(self) -> bool:
            return True

        def readline(self) -> str:
            return self.buffer.readline()

    original = sys.stdin
    sys.stdin = Tty()  # type: ignore[assignment]
    try:
        yield
    finally:
        sys.stdin = original


def direct_info(**config: object) -> dict[str, object]:
    raw = {
        "type": "ssh",
        "host": "example.test",
        "port": 22,
        "identity": {
            "type": "inPlace",
            "identityStore": {
                "type": "localIdentity",
                "username": "alice",
                "sshIdentity": {"type": "none"},
            },
        },
    }
    raw.update(config)
    return {"store": "store-id", "type": "ssh", "name": ["default", "test"], "rawData": raw}


class FlakyClient:
    """Stands in for the real client: unreachable until the opener 'starts' XPipe."""

    def __init__(self) -> None:
        self.up = False
        self.probed = 0

    def _assert_up(self) -> None:
        if not self.up:
            raise requests.ConnectionError("Connection refused by 127.0.0.1:21721")

    def daemon_version(self) -> dict[str, str]:
        self._assert_up()
        self.probed += 1
        return {"version": "24.3.0"}

    def store_query(self, **_: object) -> list[str]:
        self._assert_up()
        return ["store-id"]

    def store_info(self, refs: list[str]) -> list[dict[str, object]]:
        self._assert_up()
        return [{**direct_info(), "store": refs[0]}]


class FakeProc(subprocess.Popen[bytes]):
    """A Popen that has already exited with ``returncode``."""

    def __init__(self, returncode: int) -> None:
        self._returncode = returncode

    def poll(self) -> int:
        return self._returncode


class ClassifyTests(unittest.TestCase):
    def test_missing_beacon_auth_means_not_running(self) -> None:
        from xpipe_api.exceptions import NoTokenFoundException

        status, _ = classify(NoTokenFoundException("no auth file"))
        self.assertIs(status, Availability.NOT_RUNNING)

    def test_wrong_user_beacon_auth_is_not_offered_a_restart(self) -> None:
        from xpipe_api.exceptions import NoTokenFoundException

        status, _ = classify(NoTokenFoundException("Bad permissions on xpipe_auth"))
        self.assertIs(status, Availability.UNKNOWN)

    def test_rejected_handshake_is_unauthorized(self) -> None:
        from xpipe_api.exceptions import AuthFailedException

        status, _ = classify(AuthFailedException("401 Unauthorized"))
        self.assertIs(status, Availability.UNAUTHORIZED)

    def test_connection_refused_means_not_running(self) -> None:
        status, _ = classify(requests.ConnectionError("Connection refused"))
        self.assertIs(status, Availability.NOT_RUNNING)

    def test_connection_timeout_means_not_running(self) -> None:
        status, _ = classify(requests.ConnectTimeout("timed out"))
        self.assertIs(status, Availability.NOT_RUNNING)

    def test_wrapped_cause_is_found_through_the_chain(self) -> None:
        from xpipe_api.exceptions import NoTokenFoundException

        wrapped = XPipeConnectionError("Could not reach the XPipe daemon")
        wrapped.__cause__ = NoTokenFoundException("no auth file")
        status, _ = classify(wrapped)
        self.assertIs(status, Availability.NOT_RUNNING)

    def test_own_deadline_timeout_is_not_offered_a_restart(self) -> None:
        exc = XPipeConnectionError("XPipe request timed out after 5 seconds")
        status, _ = classify(exc)
        self.assertIs(status, Availability.UNKNOWN)

    def test_unrelated_errors_are_unknown(self) -> None:
        status, detail = classify(ValueError("boom"))
        self.assertIs(status, Availability.UNKNOWN)
        self.assertIn("boom", detail)


class TtyStderr(io.StringIO):
    """A StringIO that Rich treats as a terminal."""

    def isatty(self) -> bool:
        return True


class ConfirmOpenTests(unittest.TestCase):
    def test_empty_answer_accepts(self) -> None:
        with fake_tty_stdin("\n"), contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(confirm_open())

    def test_yes_accepts(self) -> None:
        for answer in ("y\n", "yes\n", "Y\n"):
            with (
                self.subTest(answer=answer),
                fake_tty_stdin(answer),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertTrue(confirm_open())

    def test_no_declines(self) -> None:
        with fake_tty_stdin("n\n"), contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(confirm_open())

    def test_end_of_input_declines(self) -> None:
        # EOF must not be mistaken for a default yes.
        with fake_tty_stdin(""), contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(confirm_open())

    @unittest.skipUnless(RICH_AVAILABLE, "requires Rich styling")
    def test_prompt_is_styled_on_a_tty(self) -> None:
        err = TtyStderr()
        with (
            fake_tty_stdin("y\n"),
            mock.patch("sys.stderr", err),
            mock.patch.dict(os.environ, {"TERM": "xterm-256color", "TTY_COMPATIBLE": "1"}),
        ):
            self.assertTrue(confirm_open())
        rendered = err.getvalue()
        self.assertIn("xpipe open", rendered)
        self.assertIn("\x1b[", rendered)  # ANSI styling, not the plain text line

    def test_prompt_stays_plain_on_a_pipe(self) -> None:
        err = io.StringIO()
        with fake_tty_stdin("y\n"), contextlib.redirect_stderr(err):
            self.assertTrue(confirm_open())
        self.assertNotIn("\x1b[", err.getvalue())


class EnsureClientTests(unittest.TestCase):
    def test_healthy_client_is_returned_without_prompting(self) -> None:
        client = FlakyClient()
        client.up = True
        result = ensure_client(
            ptb=False,
            client_maker=lambda _: client,
            confirm=lambda: self.fail("must not prompt for a healthy daemon"),
        )
        self.assertIs(result, client)

    def test_declining_the_offer_raises_the_friendly_error(self) -> None:
        client = FlakyClient()
        opener_called = False

        def opener() -> None:
            nonlocal opener_called
            opener_called = True
            return None

        with self.assertRaisesRegex(XPipeConnectionError, "Could not reach the XPipe daemon"):
            ensure_client(
                ptb=False, client_maker=lambda _: client, confirm=lambda: False, opener=opener
            )
        self.assertFalse(opener_called)

    def test_non_interactive_failure_raises_without_prompting(self) -> None:
        with self.assertRaisesRegex(XPipeConnectionError, "Could not reach the XPipe daemon"):
            ensure_client(ptb=False, client_maker=lambda _: FlakyClient(), confirm=None)

    def test_accepting_the_offer_launches_and_retries(self) -> None:
        client = FlakyClient()

        def opener() -> None:
            client.up = True
            return None

        with contextlib.redirect_stderr(io.StringIO()):
            result = ensure_client(
                ptb=False, client_maker=lambda _: client, confirm=lambda: True, opener=opener
            )
        self.assertIs(result, client)
        self.assertEqual(client.probed, 1)  # the failing probe raises before counting

    def test_unauthorized_is_never_offered_a_restart(self) -> None:
        from xpipe_api.exceptions import AuthFailedException

        class RejectingClient(FlakyClient):
            def daemon_version(self) -> dict[str, str]:
                raise AuthFailedException("401 Unauthorized")

        opener_called = False

        def opener() -> None:
            nonlocal opener_called
            opener_called = True
            return None

        with self.assertRaisesRegex(XPipeConnectionError, "Settings -> HTTP API"):
            ensure_client(
                ptb=False,
                client_maker=lambda _: RejectingClient(),
                confirm=lambda: True,
                opener=opener,
            )
        self.assertFalse(opener_called)

    def test_launch_that_never_becomes_reachable_times_out(self) -> None:
        client = FlakyClient()
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaisesRegex(XPipeConnectionError, "did not become reachable"),
        ):
            ensure_client(
                ptb=False,
                client_maker=lambda _: client,
                confirm=lambda: True,
                opener=lambda: None,
                timeout=0.2,
            )

    def test_failing_launcher_reports_its_exit_code(self) -> None:
        client = FlakyClient()
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaisesRegex(XPipeConnectionError, "exited with code 3"),
        ):
            ensure_client(
                ptb=False,
                client_maker=lambda _: client,
                confirm=lambda: True,
                opener=lambda: FakeProc(3),
            )

    def test_missing_xpipe_binary_is_a_clean_error(self) -> None:
        from xpipe_to_ssh import daemon

        client = FlakyClient()
        with (
            mock.patch.object(daemon.shutil, "which", return_value=None),
            self.assertRaisesRegex(XPipeConnectionError, "xpipe` command on PATH"),
        ):
            ensure_client(
                ptb=False,
                client_maker=lambda _: client,
                confirm=lambda: True,
                opener=daemon.open_xpipe,
            )


class AutoOpenEndToEndTests(unittest.TestCase):
    def test_list_offers_to_open_xpipe_and_proceeds(self) -> None:
        client = FlakyClient()
        output = io.StringIO()

        def opener() -> None:
            client.up = True
            return None

        with (
            mock.patch("xpipe_to_ssh.cli.default_client", lambda _: client),
            mock.patch("xpipe_to_ssh.cli.shutil.which", return_value="/usr/local/bin/xpipe"),
            fake_tty_stdin("y\n"),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(TtyStderr()),
        ):
            result = main(["--list"], AppDependencies(opener=opener))
        self.assertEqual(result, 0)
        self.assertIn("default/test", output.getvalue())

    def test_list_declined_offer_keeps_the_error_exit(self) -> None:
        client = FlakyClient()
        error = TtyStderr()
        with (
            mock.patch("xpipe_to_ssh.cli.default_client", lambda _: client),
            mock.patch("xpipe_to_ssh.cli.shutil.which", return_value="/usr/local/bin/xpipe"),
            fake_tty_stdin("n\n"),
            contextlib.redirect_stderr(error),
        ):
            result = main(["--list"], AppDependencies(opener=lambda: None))
        self.assertEqual(result, 1)
        self.assertIn("Could not reach the XPipe daemon", error.getvalue())
        self.assertFalse(client.up)

    def test_non_tty_stderr_means_no_offer_even_with_tty_stdin(self) -> None:
        # The prompt is written to stderr; a piped stderr would swallow it.
        client = FlakyClient()
        error = io.StringIO()
        with (
            mock.patch("xpipe_to_ssh.cli.default_client", lambda _: client),
            mock.patch("xpipe_to_ssh.cli.shutil.which", return_value="/usr/local/bin/xpipe"),
            fake_tty_stdin("y\n"),
            contextlib.redirect_stderr(error),
        ):
            result = main(["--list"], AppDependencies(opener=lambda: None))
        self.assertEqual(result, 1)
        self.assertNotIn("xpipe open", error.getvalue())
        self.assertFalse(client.up)

    def test_json_mode_never_prompts_even_on_a_tty(self) -> None:
        client = FlakyClient()
        output = io.StringIO()
        error = TtyStderr()
        with (
            mock.patch("xpipe_to_ssh.cli.default_client", lambda _: client),
            fake_tty_stdin("y\n"),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(error),
        ):
            result = main(["--list", "--shell", "json"], AppDependencies(opener=lambda: None))
        self.assertEqual(result, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["error"]["code"], "xpipe_request_failed")
        self.assertNotIn("xpipe open", error.getvalue())
        self.assertFalse(client.up)

    def test_plain_command_generation_offers_open_and_continues(self) -> None:
        client = FlakyClient()

        def opener() -> None:
            client.up = True
            return None

        output = io.StringIO()
        with (
            mock.patch("xpipe_to_ssh.cli.default_client", lambda _: client),
            mock.patch("xpipe_to_ssh.cli.shutil.which", return_value="/usr/local/bin/xpipe"),
            fake_tty_stdin("y\n"),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(TtyStderr()),
        ):
            result = main(["test", "--plain"], AppDependencies(opener=opener))
        self.assertEqual(result, 0)
        self.assertIn("example.test", output.getvalue())


if __name__ == "__main__":
    unittest.main()


class MayOfferOpenTests(unittest.TestCase):
    """The offer to launch XPipe must only happen in a truly interactive run."""

    def test_non_interactive_run_does_not_offer_to_open_xpipe(self) -> None:
        from xpipe_to_ssh.cli import may_offer_open, parse_options

        def offer(argv: list[str], env: dict[str, str] | None = None) -> bool:
            clean = {"XPIPE_TO_SSH_CONFIG": "/dev/null", **(env or {})}
            with mock.patch.dict(os.environ, clean, clear=False):
                _parser, options = parse_options(argv)
                with (
                    mock.patch(
                        "xpipe_to_ssh.cli.shutil.which", return_value="/usr/local/bin/xpipe"
                    ),
                    mock.patch("sys.stdin", TtyStderr()),
                    mock.patch("sys.stderr", TtyStderr()),
                ):
                    return may_offer_open(options)

        self.assertTrue(offer(["--list"]))

        cases = (
            (["--list", "--shell", "json"], None, "json output"),
            (["--list", "--ptb"], None, "PTB builds"),
            (["--list"], {"XPIPE_BEACON_PORT": "21729"}, "custom beacon port"),
        )
        for argv, env, label in cases:
            with self.subTest(case=label):
                self.assertFalse(offer(argv, env))

        with self.subTest(case="piped stdin"):
            with mock.patch.dict(os.environ, {"XPIPE_TO_SSH_CONFIG": "/dev/null"}, clear=False):
                _parser, options = parse_options(["--list"])
            with (
                mock.patch("xpipe_to_ssh.cli.shutil.which", return_value="/usr/local/bin/xpipe"),
                mock.patch("sys.stdin", io.StringIO("")),
                mock.patch("sys.stderr", TtyStderr()),
            ):
                self.assertFalse(may_offer_open(options))

        with self.subTest(case="piped stderr"):
            with mock.patch.dict(os.environ, {"XPIPE_TO_SSH_CONFIG": "/dev/null"}, clear=False):
                _parser, options = parse_options(["--list"])
            with (
                mock.patch("xpipe_to_ssh.cli.shutil.which", return_value="/usr/local/bin/xpipe"),
                mock.patch("sys.stdin", TtyStderr()),
                mock.patch("sys.stderr", io.StringIO("")),
            ):
                self.assertFalse(may_offer_open(options))

        with self.subTest(case="xpipe CLI missing"):
            with mock.patch.dict(os.environ, {"XPIPE_TO_SSH_CONFIG": "/dev/null"}, clear=False):
                _parser, options = parse_options(["--list"])
            with (
                mock.patch("xpipe_to_ssh.cli.shutil.which", return_value=None),
                mock.patch("sys.stdin", TtyStderr()),
                mock.patch("sys.stderr", TtyStderr()),
            ):
                self.assertFalse(may_offer_open(options))


class OpenXPipeTests(unittest.TestCase):
    def test_launch_detaches_from_the_interactive_terminal(self) -> None:
        from xpipe_to_ssh import daemon

        captured: dict[str, object] = {}

        class PopenStub:  # a stand-in the assertion can inspect
            def __init__(self, args: object, **kwargs: object) -> None:
                captured["args"] = args
                captured["kwargs"] = kwargs

        with (
            mock.patch.object(daemon.shutil, "which", return_value="/usr/local/bin/xpipe"),
            mock.patch.object(daemon.subprocess, "Popen", PopenStub),
        ):
            daemon.open_xpipe()

        import subprocess as real_subprocess

        self.assertEqual(captured["args"], ["/usr/local/bin/xpipe", "open"])
        kwargs = captured["kwargs"]
        assert isinstance(kwargs, dict)
        self.assertIs(kwargs["stdin"], real_subprocess.DEVNULL)
        self.assertIs(kwargs["stdout"], real_subprocess.DEVNULL)
        self.assertIs(kwargs["stderr"], real_subprocess.DEVNULL)
        self.assertTrue(kwargs["start_new_session"])
