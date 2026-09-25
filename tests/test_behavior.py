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
