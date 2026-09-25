import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from main import ExportError, build_ssh_argv

from xpipe_to_ssh.agents import probe_agent, resolve_agent_socket
from xpipe_to_ssh.cli import AppDependencies, main
from xpipe_to_ssh.errors import AgentError, XPipeSchemaError
from xpipe_to_ssh.models import AgentSocket
from xpipe_to_ssh.rendering import address_kind, render
from xpipe_to_ssh.selection import choose_connection
from xpipe_to_ssh.ssh import parse_bool, parse_port, validate_destination
from xpipe_to_ssh.xpipe import XPipeAdapter, selected_value


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
                    "port": "22",
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
            def store_info(self, refs: list[str]) -> list[dict[str, object]]:
                return [{**gateway, "store": refs[0]}]

        command = build_ssh_argv(GatewayClient(), target)
        self.assertTrue(
            any("different password-manager SSH agents" in warning for warning in command.warnings)
        )

    def test_port_boundaries_and_rejection(self) -> None:
        for value in (1, 22, 65535, "65535"):
            self.assertIn(parse_port(value), (1, 22, 65535))
        for value in (0, -1, 65536, True, "22.0", ""):
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


if __name__ == "__main__":
    unittest.main()
