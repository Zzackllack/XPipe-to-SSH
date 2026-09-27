import contextlib
import io
import json
import sys
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

from xpipe_to_ssh import agents, presentation
from xpipe_to_ssh.agents import probe_agent, resolve_agent_socket
from xpipe_to_ssh.cli import AppDependencies, default_client, main
from xpipe_to_ssh.errors import (
    AgentError,
    ExportError,
    XPipeConnectionError,
    XPipeError,
    XPipeSchemaError,
)
from xpipe_to_ssh.models import AgentProbe, AgentSocket
from xpipe_to_ssh.presentation import choose_host_interactively
from xpipe_to_ssh.rendering import address_kind, render
from xpipe_to_ssh.selection import choose_connection, decode_identity_data
from xpipe_to_ssh.ssh import (
    build_ssh_argv,
    identity_options,
    parse_bool,
    parse_port,
    validate_destination,
)
from xpipe_to_ssh.xpipe import (
    WireRecord,
    XPipeAdapter,
    connection_config,
    selected_value,
)


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


class SingleClient:
    def __init__(self, info: dict[str, object] | None = None) -> None:
        self.info = info or direct_info()

    def store_query(self, **_: object) -> list[str]:
        return ["store-id"]

    def store_info(self, refs: list[str]) -> list[dict[str, object]]:
        return [{**self.info, "store": refs[0]}]


class BehaviorTests(unittest.TestCase):
    def test_json_list_is_structured_and_contains_stable_ids(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                ["--list", "--shell", "json"],
                AppDependencies(client_factory=lambda _: SingleClient()),
            )
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["schemaVersion"], 1)
        self.assertEqual(
            payload["connections"],
            [
                {
                    "name": "default/test",
                    "id": "store-id",
                    "type": "ssh",
                    "host": "example.test",
                    "availableHosts": ["example.test"],
                    "port": 22,
                }
            ],
        )

    def test_name_lookup_filters_before_fetching_store_details(self) -> None:
        class FilteredClient(SingleClient):
            def __init__(self) -> None:
                super().__init__()
                self.query_args: list[dict[str, object]] = []

            def store_query(self, **kwargs: object) -> list[str]:
                self.query_args.append(kwargs)
                return ["store-id"]

        client = FilteredClient()
        self.assertEqual(choose_connection(client, "test")["store"], "store-id")
        self.assertEqual(
            client.query_args,
            [{"categories": "**", "stores": "**test**", "types": "ssh*"}],
        )

    def test_json_list_keeps_malformed_port_from_breaking_discovery(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                ["--list", "--shell", "json"],
                AppDependencies(
                    client_factory=lambda _: SingleClient(direct_info(port="9" * 5000))
                ),
            )
        self.assertEqual(result, 0)
        self.assertIsNone(json.loads(output.getvalue())["connections"][0]["port"])

    def test_name_lookup_retries_broadly_if_server_filter_misses(self) -> None:
        class OlderClient(SingleClient):
            def __init__(self) -> None:
                super().__init__()
                self.patterns: list[str] = []

            def store_query(self, **kwargs: object) -> list[str]:
                pattern = str(kwargs["stores"])
                self.patterns.append(pattern)
                return [] if pattern != "**" else ["store-id"]

        client = OlderClient()
        self.assertEqual(choose_connection(client, "test")["store"], "store-id")
        self.assertEqual(client.patterns, ["**test**", "**"])

    def test_json_not_found_error_has_stable_code(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                ["missing", "--shell", "json"],
                AppDependencies(client_factory=lambda _: SingleClient()),
            )
        self.assertEqual(result, 2)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], "connection_not_found")

    def test_json_client_setup_failure_has_xpipe_code(self) -> None:
        def unavailable(_ptb: bool) -> object:
            raise XPipeError("client setup failed")

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["test", "--shell", "json"], AppDependencies(client_factory=unavailable))
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], "xpipe_error")

    def test_json_ambiguity_contains_candidate_ids(self) -> None:
        class AmbiguousClient(SingleClient):
            def store_query(self, **_: object) -> list[str]:
                return ["first", "second"]

            def store_info(self, refs: list[str]) -> list[dict[str, object]]:
                return [{**direct_info(), "store": ref} for ref in refs]

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                ["test", "--shell", "json"],
                AppDependencies(client_factory=lambda _: AmbiguousClient()),
            )
        self.assertEqual(result, 2)
        error = json.loads(output.getvalue())["error"]
        self.assertEqual(error["code"], "ambiguous_connection")
        self.assertEqual([item["id"] for item in error["candidates"]], ["first", "second"])

    def test_json_argument_error_is_machine_readable(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["test", "--shell=json", "--host", "one", "--pick-host"])
        self.assertEqual(result, 2)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], "invalid_arguments")

    def test_strict_mode_stops_before_copying_on_warning(self) -> None:
        copied: list[str] = []
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                ["test", "--host", "other.example", "--strict", "--shell", "json", "--copy"],
                AppDependencies(
                    client_factory=lambda _: SingleClient(),
                    clipboard=lambda value: copied.append(value) or "test",
                ),
            )
        self.assertEqual(result, 2)
        self.assertEqual(copied, [])
        error = json.loads(output.getvalue())["error"]
        self.assertEqual(error["code"], "strict_warnings")
        self.assertEqual(len(error["warnings"]), 1)

    def test_strict_mode_allows_warning_free_command(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                ["test", "--strict", "--shell", "json"],
                AppDependencies(client_factory=lambda _: SingleClient()),
            )
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["warnings"], [])

    def test_remote_command_is_passed_as_one_ssh_argument(self) -> None:
        executed: list[list[str]] = []
        result = main(
            ["test", "--connect", "--remote-command", "printf '%s\\n' hello"],
            AppDependencies(
                client_factory=lambda _: SingleClient(),
                executor=lambda argv, _env: executed.append(argv),
            ),
        )
        self.assertEqual(result, 0)
        self.assertEqual(
            executed,
            [["ssh", "-l", "alice", "example.test", "printf '%s\\n' hello"]],
        )

    def test_remote_command_requires_connect_and_rejects_control_characters(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(main(["test", "--remote-command", "id"]), 2)
            self.assertEqual(main(["test", "--connect", "--remote-command", "id\nwhoami"]), 2)
        self.assertIn("requires --connect", stderr.getvalue())
        self.assertIn("control characters", stderr.getvalue())

    def test_mixed_gateway_agent_providers_are_reported(self) -> None:
        def with_agent(info: dict[str, object], identifier: str) -> dict[str, object]:
            raw_data = info["rawData"]
            self.assertIsInstance(raw_data, dict)
            raw = dict(raw_data) if isinstance(raw_data, dict) else {}
            raw["identity"] = {
                "type": "inPlace",
                "identityStore": {
                    "type": "localIdentity",
                    "username": "alice",
                    "sshIdentity": {"type": "passwordManagerAgent", "identifier": identifier},
                },
            }
            return {**info, "rawData": raw}

        target = with_agent(direct_info(gateway="gateway-id"), "bitwarden")
        gateway = with_agent(direct_info(host="gateway.example"), "1password")

        class GatewayClient(SingleClient):
            def __init__(self, gateway_info: dict[str, object]) -> None:
                super().__init__()
                self.gateway_info = gateway_info

            def store_info(self, refs: list[str]) -> list[dict[str, object]]:
                return [{**self.gateway_info, "store": refs[0]}]

        command = build_ssh_argv(GatewayClient(gateway), target)
        self.assertTrue(
            any("different password-manager SSH agents" in warning for warning in command.warnings)
        )

        opaque_target = with_agent(direct_info(gateway="gateway-id"), "key-one")
        opaque_gateway = with_agent(direct_info(host="gateway.example"), "key-two")
        opaque_command = build_ssh_argv(GatewayClient(opaque_gateway), opaque_target)
        self.assertFalse(
            any(
                "different password-manager SSH agents" in warning
                for warning in opaque_command.warnings
            )
        )

    def test_plain_list_carries_the_same_fields_as_the_table(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                ["--list", "--plain"], AppDependencies(client_factory=lambda _: SingleClient())
            )

        self.assertEqual(result, 0)
        row = output.getvalue().strip().split("\t")
        self.assertEqual(row, ["default/test", "example.test", "22", "ssh", "store-id"])

    def test_windows_gateway_nests_a_cmdline_quoted_proxy_command(self) -> None:
        # Windows OpenSSH parses ProxyCommand with the C runtime rules, so a
        # nested value containing a space needs double quotes, not shell quotes.
        gateway: WireRecord = {
            "store": "gateway",
            "type": "ssh",
            "name": ["default", "gateway"],
            "rawData": {
                "type": "ssh",
                "host": "gateway.example",
                "port": 22,
                "additionalOptions": "UserKnownHostsFile=my hosts",
            },
        }
        target = direct_info(gateway="gateway")

        class GatewayClient(SingleClient):
            def store_info(self, refs: list[str]) -> list[dict[str, object]]:
                return [gateway]

        windows = build_ssh_argv(GatewayClient(), target, platform_name="nt")
        posix = build_ssh_argv(GatewayClient(), target, platform_name="posix")

        windows_proxy = next(v for v in windows.argv if v.startswith("ProxyCommand="))
        posix_proxy = next(v for v in posix.argv if v.startswith("ProxyCommand="))
        self.assertIn('"UserKnownHostsFile=my hosts"', windows_proxy)
        self.assertIn("'UserKnownHostsFile=my hosts'", posix_proxy)

    def test_untrusted_input_in_errors_is_bounded(self) -> None:
        huge = "9" * 5000
        with self.assertRaises(ExportError) as caught:
            parse_port(huge)
        self.assertLess(len(str(caught.exception)), 200)
        self.assertIn("5000 chars", str(caught.exception))

    def test_port_boundaries_and_rejection(self) -> None:
        for value in (1, 22, 65535, "65535", "000022"):
            self.assertIn(parse_port(value), (1, 22, 65535, 22))
        for value in (0, -1, 65536, True, "22.0", "", "9" * 5000):
            with self.subTest(value=value), self.assertRaises(ExportError):
                parse_port(value)

    def test_boolean_values_are_not_python_truthiness(self) -> None:
        self.assertTrue(parse_bool("true", field="forwardX11"))
        self.assertFalse(parse_bool("false", field="forwardX11"))
        with self.assertRaises(ExportError):
            parse_bool("yes", field="forwardX11")

    def test_destinations_reject_option_injection_and_normalize_ipv6(self) -> None:
        self.assertEqual(validate_destination("[fe80::1]"), "fe80::1")
        self.assertEqual(address_kind("[fe80::1]"), "IPv6")
        for value in ("-oProxyCommand=x", "bad host", "bad\nvalue", "[not-ip]"):
            with self.subTest(value=value), self.assertRaises(ExportError):
                validate_destination(value)

    def test_forward_x11_false_does_not_add_flag(self) -> None:
        command = build_ssh_argv(SingleClient(), direct_info(forwardX11="false"))
        self.assertNotIn("-X", command.argv)

    def test_json_output_has_explicit_schema_version(self) -> None:
        command = build_ssh_argv(SingleClient(), direct_info())
        self.assertIn('"schemaVersion": 1', render(command, "json"))

    def test_selected_value_stops_on_cycles(self) -> None:
        value: dict[str, object] = {}
        value["value"] = value
        self.assertIs(selected_value(value), value)

    def test_malformed_xpipe_ids_are_rejected(self) -> None:
        class BadClient:
            def store_query(self, **_: object) -> list[object]:
                return ["ok", 4]

            def store_info(self, refs: list[str]) -> list[dict[str, object]]:
                return []

        with self.assertRaises(XPipeSchemaError):
            XPipeAdapter(BadClient()).query()

    def test_stalled_xpipe_requests_have_a_deadline(self) -> None:
        class SlowClient:
            def store_query(self, **_: object) -> list[str]:
                import time

                time.sleep(0.05)
                return []

            def store_info(self, refs: list[str]) -> list[dict[str, object]]:
                return []

        with self.assertRaisesRegex(RuntimeError, "timed out"):
            XPipeAdapter(SlowClient(), timeout=0.001).query()

    def test_agent_provider_is_forwarded_by_cli(self) -> None:
        info = direct_info(
            identity={
                "type": "inPlace",
                "identityStore": {
                    "type": "localIdentity",
                    "username": "alice",
                    "sshIdentity": {"type": "passwordManagerAgent", "identifier": "bitwarden"},
                },
            }
        )
        calls: list[dict[str, object]] = []

        def agent_resolver(requested: str, **kwargs: object) -> AgentSocket | None:
            calls.append({"requested": requested, **kwargs})
            return AgentSocket("/tmp/agent.sock", "Bitwarden", 1, provider="Bitwarden")

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                ["test", "--plain"],
                AppDependencies(
                    client_factory=lambda _: SingleClient(info), agent_resolver=agent_resolver
                ),
            )
        self.assertEqual(result, 0)
        self.assertEqual(calls[0]["identifier"], "bitwarden")
        self.assertIn("SSH_AUTH_SOCK=/tmp/agent.sock", output.getvalue())

    def test_cli_rejects_ambiguous_modes(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = main(["test", "--host", "one", "--pick-host"])
        self.assertEqual(result, 2)
        self.assertIn("mutually exclusive", stderr.getvalue())

    def test_explicit_regular_file_is_not_accepted_as_unix_socket(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent"
            path.touch()
            with self.assertRaises(AgentError):
                resolve_agent_socket(str(path), platform_name="posix")

    def test_probe_reports_missing_socket_without_collapsing_diagnostics(self) -> None:
        probe = probe_agent(
            Path("/definitely/missing"), ssh_add="/bin/false", platform_name="posix"
        )
        self.assertIsNone(probe.identity_count)
        self.assertIsNotNone(probe.error)


class RegressionTests(unittest.TestCase):
    """Cases that each broke a real export or misreported a real failure."""

    def test_explicit_null_port_falls_back_to_the_ssh_default(self) -> None:
        # XPipe serializes an unset port as null rather than omitting the key.
        command = build_ssh_argv(SingleClient(), direct_info(port=None))

        self.assertEqual(command.port, 22)
        self.assertNotIn("-p", command.argv)
        self.assertEqual(parse_port(None), 22)
        self.assertEqual(parse_port(None, default=2222), 2222)

    def test_one_unusable_alternative_address_does_not_fail_the_export(self) -> None:
        command = build_ssh_argv(
            SingleClient(),
            direct_info(
                host={
                    "value": "good.example",
                    "available": ["good.example", "bad host", "10.0.0.1"],
                }
            ),
        )

        self.assertEqual(command.selected_host, "good.example")
        self.assertEqual(command.argv[-1], "good.example")
        self.assertEqual(command.available_hosts, ["good.example", "10.0.0.1"])
        self.assertTrue(any("bad host" in warning for warning in command.warnings))

    def test_unusable_selected_address_is_still_a_hard_failure(self) -> None:
        with self.assertRaises(ExportError):
            build_ssh_argv(
                SingleClient(),
                direct_info(host={"value": "bad host", "available": ["bad host"]}),
            )

    def test_unreachable_daemon_is_reported_as_an_xpipe_failure(self) -> None:
        from xpipe_api.exceptions import NoTokenFoundException

        with mock.patch("xpipe_api.Client", side_effect=NoTokenFoundException("no auth file")):
            with self.assertRaisesRegex(XPipeConnectionError, "HTTP API"):
                default_client(False)

    def test_address_selection_rejects_numbers_outside_the_offered_range(self) -> None:
        available = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        with (
            mock.patch.object(presentation, "RICH_AVAILABLE", False),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            for answer in ("0", "-1", "4", "abc", ""):
                with self.subTest(answer=answer), fake_tty_stdin(f"{answer}\n"):
                    with self.assertRaises(ExportError):
                        choose_host_interactively("10.0.0.1", available, no_color=True)

    def test_address_selection_at_end_of_input_is_not_an_internal_error(self) -> None:
        available = ["10.0.0.1", "10.0.0.2"]
        with (
            mock.patch.object(presentation, "RICH_AVAILABLE", False),
            contextlib.redirect_stderr(io.StringIO()),
            fake_tty_stdin(""),
        ):
            with self.assertRaises(ExportError):
                choose_host_interactively("10.0.0.1", available, no_color=True)

    @unittest.skipUnless(presentation.RICH_AVAILABLE, "requires rich")
    def test_rich_prompt_console_writes_to_stderr(self) -> None:
        with (
            mock.patch.object(presentation, "RICH_AVAILABLE", True),
            mock.patch.object(presentation, "Prompt") as prompt,
            fake_tty_stdin("2\n"),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            prompt.ask.return_value = "2"
            chosen = choose_host_interactively("10.0.0.1", ["10.0.0.1", "10.0.0.2"], no_color=True)

        self.assertEqual(chosen, "10.0.0.2")
        self.assertTrue(prompt.ask.call_args.kwargs["console"].stderr)

    def test_interactive_pick_keeps_json_stdout_parseable(self) -> None:
        info = direct_info(host={"value": "10.0.0.1", "available": ["10.0.0.1", "10.0.0.2"]})
        output = io.StringIO()
        with (
            mock.patch.object(presentation, "RICH_AVAILABLE", False),
            fake_tty_stdin("2\n"),
            contextlib.redirect_stdout(output),
        ):
            result = main(
                ["test", "--shell", "json", "--pick-host"],
                AppDependencies(client_factory=lambda _: SingleClient(info)),
            )

        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["connection"]["host"], "10.0.0.2")


class AgentSelectionTests(unittest.TestCase):
    """Agent matching against a real XPipe `passwordManagerAgent` identity."""

    def resolve(
        self,
        requested: str,
        *,
        names: list[str],
        count: int,
        provider: str | None = None,
        identifier: str | None = None,
    ) -> AgentSocket | None:
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for name in names:
                path = Path(directory) / name
                path.touch()
                paths.append(path)
            with mock.patch.object(agents, "probe_agent", return_value=AgentProbe(count, None)):
                return resolve_agent_socket(
                    requested,
                    candidates=paths,
                    platform_name="posix",
                    provider=provider,
                    identifier=identifier,
                )

    def resolve_one(
        self,
        requested: str,
        *,
        names: list[str],
        count: int,
        provider: str | None = None,
        identifier: str | None = None,
    ) -> AgentSocket:
        agent = self.resolve(
            requested, names=names, count=count, provider=provider, identifier=identifier
        )
        if agent is None:
            self.fail("expected an agent socket to be resolved")
        return agent

    def test_xpipe_key_name_does_not_disqualify_a_working_agent(self) -> None:
        # XPipe stores the password-manager *key name* in `identifier`, and
        # `ssh-add -L` lists it as the key comment - it is not a product name.
        agent = self.resolve_one(
            "auto", names=["bitwarden-agent.sock"], count=2, identifier="MacBook Air SSH Key"
        )

        self.assertEqual(agent.provider, "bitwarden")
        self.assertEqual(agent.identity_count, 2)

    def test_named_product_still_selects_that_agent_first(self) -> None:
        agent = self.resolve_one(
            "auto",
            names=["bitwarden-agent.sock", "1password-agent.sock"],
            count=3,
            provider="1Password",
        )

        self.assertEqual(agent.provider, "1password")

    def test_unsatisfiable_product_preference_reports_no_agent(self) -> None:
        agent = self.resolve(
            "auto", names=["bitwarden-agent.sock"], count=2, identifier="1password"
        )

        self.assertIsNone(agent)

    def test_cli_sets_agent_sock_for_a_live_password_manager_identity(self) -> None:
        info = direct_info(
            identity={
                "type": "inPlace",
                "identityStore": {
                    "type": "localIdentity",
                    "username": "alice",
                    "sshIdentity": {
                        "type": "passwordManagerAgent",
                        "identifier": "MacBook Air SSH Key",
                    },
                },
            }
        )

        def agent_resolver(requested: str, **kwargs: object) -> AgentSocket:
            return AgentSocket("/tmp/agent.sock", "Bitwarden", 2, provider="bitwarden")

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                ["test", "--shell", "json"],
                AppDependencies(
                    client_factory=lambda _: SingleClient(info), agent_resolver=agent_resolver
                ),
            )

        payload = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(payload["env"], {"SSH_AUTH_SOCK": "/tmp/agent.sock"})
        self.assertEqual(payload["warnings"], [])

    def test_password_warning_is_accurate_without_key_material(self) -> None:
        keyless = identity_options(
            SingleClient(),
            connection_config(
                direct_info(
                    identity={
                        "type": "inPlace",
                        "identityStore": {
                            "username": "alice",
                            "sshIdentity": {"type": "none"},
                            "password": "secret",
                        },
                    }
                )
            ),
        )
        keyed = identity_options(
            SingleClient(),
            connection_config(
                direct_info(
                    identity={
                        "type": "inPlace",
                        "identityStore": {
                            "username": "alice",
                            "sshIdentity": {"type": "agent"},
                            "password": "secret",
                        },
                    }
                )
            ),
        )

        self.assertIn("SSH will prompt for the password", keyless.warnings[0])
        self.assertIn("if the key is rejected", keyed.warnings[0])


class AdapterAndArgumentTests(unittest.TestCase):
    """Client-generation binding and pre-parse machine-output detection."""

    def test_json_errors_survive_argparse_abbreviations(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["test", "--she", "json", "--host", "one", "--pick-host"])

        self.assertEqual(result, 2)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], "invalid_arguments")

    def test_text_errors_stay_text_without_a_json_request(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = main(["test", "--she", "posix", "--host", "one", "--pick-host"])

        self.assertEqual(result, 2)
        self.assertIn("mutually exclusive", stderr.getvalue())

    def test_incomplete_store_api_is_reported_precisely(self) -> None:
        class HalfClient:
            def store_query(self, **kwargs: object) -> list[str]:
                return []

        with self.assertRaisesRegex(XPipeSchemaError, r"found only: store_query"):
            XPipeAdapter(HalfClient()).query()

    def test_async_only_client_is_rejected_before_it_returns_a_coroutine(self) -> None:
        class AsyncLike:
            async def store_query(self, **kwargs: object) -> list[str]:
                return []

            async def store_info(self, refs: list[str]) -> list[dict]:
                return []

            async def secret_decrypt(self, value: object) -> object:
                return {}

        with self.assertRaisesRegex(XPipeSchemaError, "async"):
            XPipeAdapter(AsyncLike()).query()

    def test_decryption_failure_is_not_downgraded_to_a_warning(self) -> None:
        class FailingDecrypt:
            def secret_decrypt(self, value: object) -> object:
                raise TimeoutError("daemon stalled")

        warnings: list[str] = []
        with self.assertRaises(XPipeConnectionError):
            decode_identity_data(FailingDecrypt(), {"secrets": "ciphertext"}, warnings)
        self.assertEqual(warnings, [])

    def test_decryption_does_not_require_the_query_api(self) -> None:
        class DecryptOnly:
            def secret_decrypt(self, value: object) -> object:
                return '{"type": "none"}'

        self.assertEqual(
            decode_identity_data(DecryptOnly(), {"secrets": "x"}, []),
            {"type": "none"},
        )


if __name__ == "__main__":
    unittest.main()
