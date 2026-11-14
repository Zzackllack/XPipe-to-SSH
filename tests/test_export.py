"""Bulk export to SSH config, hosts YAML, JSON, and Ansible inventory."""

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from tests.test_daemon import fake_tty_stdin
from xpipe_to_ssh.cli import AppDependencies, main
from xpipe_to_ssh.errors import ExportOutputError, InternalError
from xpipe_to_ssh.export import (
    AgentResolver,
    CommandFields,
    ExportHost,
    ExportResult,
    HostPicker,
    ansible_document,
    collect_export,
    command_fields,
    hosts_document,
    render_export,
    sanitize_alias,
    unique_names,
    write_document,
)
from xpipe_to_ssh.models import AgentSocket, SSHCommand


def ssh_info(store: str, *name: str, **raw: object) -> dict[str, object]:
    """A v24 store record for an SSH connection, with sensible defaults."""
    data: dict[str, object] = {
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
    data.update(raw)
    return {"store": store, "type": data["type"], "name": list(name), "rawData": data}


def config_host_info(store: str, *name: str, alias: str) -> dict[str, object]:
    return {
        "store": store,
        "type": "sshConfigHost",
        "name": list(name),
        "rawData": {"hostEntry": {"name": alias}},
    }


class MultiClient:
    """A daemon double that serves several complete store records."""

    def __init__(self, records: list[dict[str, object]]) -> None:
        self.records = {str(record["store"]): record for record in records}
        self.order = [str(record["store"]) for record in records]
        self.query_args: list[dict[str, object]] = []

    def store_query(self, **kwargs: object) -> list[str]:
        self.query_args.append(kwargs)
        return list(self.order)

    def store_info(self, refs: list[str]) -> list[dict[str, object]]:
        return [self.records[ref] for ref in refs]


def sample_client() -> MultiClient:
    gateway = ssh_info("gw", "default", "gateway", host="gw.example")
    alpha = ssh_info("alpha", "default", "alpha", host="alpha.example")
    beta = ssh_info(
        "beta",
        "default",
        "beta",
        host="beta.example",
        port=2222,
        identity={
            "type": "inPlace",
            "identityStore": {
                "type": "localIdentity",
                "username": "bob",
                "sshIdentity": {"type": "file", "file": "/home/bob/.ssh/id_ed25519"},
            },
        },
    )
    routed = ssh_info(
        "routed",
        "default",
        "routed",
        host="routed.example",
        port=2222,
        gateway="gw",
        forwardX11=True,
        additionalOptions="UserKnownHostsFile=/tmp/known_hosts",
    )
    return MultiClient([alpha, beta, gateway, routed])


def exported_hosts(client: MultiClient) -> list[ExportHost]:
    return collect_export(client, list(client.records.values())).hosts


def run_export(argv: list[str], client: MultiClient) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        result = main(argv, AppDependencies(client_factory=lambda _: client))
    return result, out.getvalue(), err.getvalue()


class NamingTests(unittest.TestCase):
    def test_sanitize_alias_folds_whitespace_and_glob_characters(self) -> None:
        self.assertEqual(sanitize_alias("default/nas ds"), "default/nas-ds")
        self.assertEqual(sanitize_alias("**oracle*"), "oracle")
        self.assertEqual(sanitize_alias("a  b/c"), "a-b/c")
        self.assertEqual(sanitize_alias("   "), "xpipe")

    def test_inventory_names_drop_the_path_separator(self) -> None:
        self.assertEqual(sanitize_alias("default/nas ds", allow_slash=False), "default-nas-ds")
        self.assertEqual(sanitize_alias("/a/b/", allow_slash=False), "a-b")

    def test_duplicate_names_are_disambiguated_in_order(self) -> None:
        self.assertEqual(unique_names(["a", "b", "a", "a"]), ["a", "b", "a-2", "a-3"])

    def test_sanitized_collisions_get_a_suffix(self) -> None:
        client = MultiClient(
            [
                ssh_info("one", "default", "a b"),
                ssh_info("two", "default", "a-b"),
            ]
        )

        self.assertEqual(
            [host.alias for host in exported_hosts(client)], ["default/a-b", "default/a-b-2"]
        )


class CommandFieldsTests(unittest.TestCase):
    def test_every_planner_flag_is_read_back(self) -> None:
        command = SSHCommand(
            argv=[
                "ssh",
                "-p",
                "2222",
                "-l",
                "bob",
                "-i",
                "/keys/id",
                "-X",
                "-o",
                "UserKnownHostsFile=/tmp/kh",
                "-o",
                "ProxyCommand=ssh -W %h:%p gw.example",
                "host.example",
            ]
        )

        fields = command_fields(command)

        self.assertEqual(fields.hostname, "host.example")
        self.assertEqual(fields.username, "bob")
        self.assertEqual(fields.port, 2222)
        self.assertEqual(fields.identity_files, ["/keys/id"])
        self.assertTrue(fields.forward_x11)
        self.assertEqual(fields.proxy_command, "ssh -W %h:%p gw.example")
        self.assertEqual(fields.options, [("UserKnownHostsFile", "/tmp/kh")])

    def test_unknown_argument_is_a_drift_signal_not_a_silent_drop(self) -> None:
        with self.assertRaises(InternalError):
            command_fields(SSHCommand(argv=["ssh", "-Q", "ciphers", "host.example"]))

    def test_space_separated_additional_option_is_understood(self) -> None:
        fields = command_fields(SSHCommand(argv=["ssh", "-o", "ForwardAgent yes", "host.example"]))

        self.assertEqual(fields.options, [("ForwardAgent", "yes")])


class SerializerTests(unittest.TestCase):
    def test_ssh_config_blocks_carry_hostname_user_port_and_identity(self) -> None:
        client = MultiClient(
            [
                ssh_info("a", "default", "alpha", host="alpha.example"),
                ssh_info(
                    "b",
                    "default",
                    "beta",
                    host="beta.example",
                    port=2222,
                    identity={
                        "type": "inPlace",
                        "identityStore": {
                            "type": "localIdentity",
                            "username": "bob",
                            "sshIdentity": {
                                "type": "file",
                                "file": "/home/bob/.ssh/id_ed25519",
                            },
                        },
                    },
                ),
            ]
        )

        text = render_export(ExportResult(hosts=exported_hosts(client)), "ssh-config")

        self.assertIn("# Generated by xpipe-to-ssh", text)
        self.assertIn("Host default/alpha", text)
        self.assertIn("    HostName alpha.example", text)
        self.assertIn("Host default/beta", text)
        self.assertIn("    Port 2222", text)
        self.assertIn("    User bob", text)
        self.assertIn("    IdentityFile /home/bob/.ssh/id_ed25519", text)

    def test_gateway_block_matches_the_proxycommand_destination(self) -> None:
        # The inner ssh spawned by the ProxyCommand dials the gateway by its
        # hostname and re-reads the config; the gateway block must match for
        # Port, User, IdentityFile, and IdentityAgent to apply to that hop.
        text = render_export(ExportResult(hosts=exported_hosts(sample_client())), "ssh-config")

        self.assertIn("Host default/gateway gw.example\n", text)

    def test_proxy_command_destination_without_a_gateway_block_extends_nothing(self) -> None:
        hosts = [
            ExportHost(
                name="default/routed",
                alias="default/routed",
                id="routed",
                type="ssh",
                fields=CommandFields(
                    hostname="routed.example",
                    username="alice",
                    port=2222,
                    identity_files=[],
                    forward_x11=False,
                    proxy_command="ssh -l alice -W %h:%p gw.example",
                    options=[],
                ),
                available_hosts=["routed.example"],
                auth_methods=[],
                gateways=["Gateway"],
            )
        ]

        text = render_export(ExportResult(hosts=hosts), "ssh-config")

        self.assertIn("Host default/routed\n", text)
        self.assertNotIn("Host default/routed gw.example", text)

    def test_ssh_config_includes_gateway_forwarding_and_extra_options(self) -> None:
        text = render_export(ExportResult(hosts=exported_hosts(sample_client())), "ssh-config")

        self.assertIn("ProxyCommand ssh -l alice -W %h:%p gw.example", text)
        self.assertIn("    ForwardX11 yes", text)
        self.assertIn("    UserKnownHostsFile /tmp/known_hosts", text)

    def test_yaml_document_is_an_ordered_host_list_with_stable_fields(self) -> None:
        document = yaml.safe_load(
            render_export(ExportResult(hosts=exported_hosts(sample_client())), "yaml")
        )

        self.assertEqual(document["schemaVersion"], 1)
        aliases = [host["alias"] for host in document["hosts"]]
        self.assertEqual(aliases, sorted(aliases))
        routed = next(host for host in document["hosts"] if host["alias"] == "default/routed")
        self.assertEqual(routed["hostname"], "routed.example")
        self.assertEqual(routed["port"], 2222)
        self.assertEqual(routed["proxyCommand"], "ssh -l alice -W %h:%p gw.example")
        self.assertTrue(routed["forwardX11"])
        self.assertEqual(routed["options"], {"UserKnownHostsFile": "/tmp/known_hosts"})

    def test_json_document_round_trips(self) -> None:
        document = json.loads(
            render_export(ExportResult(hosts=exported_hosts(sample_client())), "json")
        )

        self.assertEqual(document["schemaVersion"], 1)
        self.assertEqual(len(document["hosts"]), 4)

    def test_ansible_inventory_has_only_the_all_group(self) -> None:
        client = MultiClient([ssh_info("a", "default", "alpha", host="alpha.example")])

        document = ansible_document(exported_hosts(client))

        self.assertEqual(list(document), ["all"])
        variables = document["all"]["hosts"]["default-alpha"]
        self.assertEqual(variables["ansible_host"], "alpha.example")
        self.assertEqual(variables["ansible_user"], "alice")
        self.assertNotIn("ansible_port", variables)

    def test_ansible_common_args_quote_a_spaced_proxy_command(self) -> None:
        document = ansible_document(exported_hosts(sample_client()))

        routed = document["all"]["hosts"]["default-routed"]
        self.assertIn(
            "'ProxyCommand=ssh -l alice -W %h:%p gw.example'", routed["ansible_ssh_common_args"]
        )

    def test_empty_export_still_produces_a_valid_document(self) -> None:
        empty = ExportResult(hosts=[])

        self.assertIn("all", render_export(empty, "ansible"))
        self.assertEqual(hosts_document([])["hosts"], [])
        self.assertNotIn("Host ", render_export(empty, "ssh-config"))


class CliExportTests(unittest.TestCase):
    def test_export_runs_without_a_connection_argument(self) -> None:
        result, out, _err = run_export(["--export", "ssh-config"], sample_client())

        self.assertEqual(result, 0)
        self.assertIn("Host default/alpha", out)

    def test_export_format_is_independent_of_shell(self) -> None:
        result, out, _err = run_export(["--export", "yaml", "--shell", "json"], sample_client())

        self.assertEqual(result, 0)
        self.assertIsInstance(yaml.safe_load(out), dict)

    def test_export_skips_ssh_config_hosts_with_a_warning(self) -> None:
        client = MultiClient([config_host_info("cfg", "default", "alias", alias="server-alias")])

        result, out, err = run_export(["--export", "ssh-config"], client)

        self.assertEqual(result, 0)
        self.assertIn("already resolves through ~/.ssh/config", err)
        self.assertNotIn("Host ", out)

    def test_one_broken_connection_is_skipped_not_fatal(self) -> None:
        broken = ssh_info("bad", "default", "bad", host="bad host")
        good = ssh_info("good", "default", "good")
        client = MultiClient([broken, good])

        result, out, err = run_export(["--export", "ssh-config"], client)

        self.assertEqual(result, 0)
        self.assertIn("# XPipe connection: default/good", out)
        self.assertNotIn("default/bad", out)
        self.assertIn("Skipped 'default/bad'", err)

    def test_strict_export_fails_and_json_error_is_machine_readable(self) -> None:
        broken = ssh_info("bad", "default", "bad", host="bad host")
        client = MultiClient([broken])

        result, out, _err = run_export(
            ["--export", "ssh-config", "--strict", "--shell", "json"], client
        )

        self.assertEqual(result, 2)
        self.assertEqual(json.loads(out)["error"]["code"], "strict_warnings")

    def test_filter_is_applied_at_the_daemon_for_export(self) -> None:
        client = sample_client()

        run_export(["--export", "yaml", "--filter", "ggl"], client)

        self.assertEqual(
            client.query_args[-1], {"categories": "**", "stores": "**ggl**", "types": "ssh*"}
        )

    def test_per_connection_warnings_are_prefixed_with_the_name(self) -> None:
        client = MultiClient(
            [
                ssh_info(
                    "a",
                    "default",
                    "alpha",
                    host={"value": "alpha.example", "available": ["alpha.example", "bad host"]},
                )
            ]
        )

        result, _out, err = run_export(["--export", "yaml"], client)

        self.assertEqual(result, 0)
        self.assertIn("default/alpha:", err)
        self.assertIn("bad host", err)

    def test_block_changing_options_are_dropped_with_a_warning(self) -> None:
        client = MultiClient(
            [
                ssh_info(
                    "a",
                    "default",
                    "alpha",
                    additionalOptions="Match host *.example\nServerAliveInterval=30",
                )
            ]
        )

        result, out, err = run_export(["--export", "ssh-config"], client)

        self.assertEqual(result, 0)
        self.assertNotIn("Match", out)
        self.assertIn("ServerAliveInterval 30", out)
        self.assertIn("split a config block", err)

    def test_export_never_writes_a_stored_password(self) -> None:
        secret = "super-secret-password"
        client = MultiClient(
            [
                ssh_info(
                    "a",
                    "default",
                    "alpha",
                    identity={
                        "type": "inPlace",
                        "identityStore": {
                            "username": "alice",
                            "sshIdentity": {"type": "none"},
                            "password": secret,
                        },
                    },
                )
            ]
        )

        for fmt in ("ssh-config", "yaml", "json", "ansible"):
            with self.subTest(fmt=fmt):
                _result, out, _err = run_export(["--export", fmt], client)
                self.assertNotIn(secret, out)


class OutputFileTests(unittest.TestCase):
    def test_export_writes_a_file_and_creates_parents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "config.d" / "xpipe.conf"

            result, out, err = run_export(
                ["--export", "ssh-config", "--output", str(target)], sample_client()
            )

            self.assertEqual(result, 0)
            self.assertEqual(out, "")
            self.assertIn("wrote", err)
            self.assertIn("Host default/alpha", target.read_text())

    @unittest.skipIf(os.name == "nt", "Windows does not enforce POSIX file modes")
    def test_export_file_is_private_on_posix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "hosts.yaml"

            run_export(["--export", "yaml", "--output", str(target)], sample_client())

            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_existing_file_is_not_clobbered_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "hosts.yaml"
            target.write_text("keep me")

            result, _out, err = run_export(
                ["--export", "yaml", "--output", str(target)], sample_client()
            )

            self.assertEqual(result, 1)
            self.assertEqual(target.read_text(), "keep me")
            self.assertIn("--force", err)

    def test_force_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "hosts.yaml"
            target.write_text("old")

            result, _out, _err = run_export(
                ["--export", "yaml", "--output", str(target), "--force"], sample_client()
            )

            self.assertEqual(result, 0)
            self.assertIn("hosts:", target.read_text())

    def test_dash_output_stays_on_stdout(self) -> None:
        result, out, _err = run_export(["--export", "json", "--output", "-"], sample_client())

        self.assertEqual(result, 0)
        self.assertEqual(len(json.loads(out)["hosts"]), 4)

    def test_write_document_leaves_no_temporary_behind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "out.yaml"

            write_document("body\n", target, force=False)

            self.assertEqual(target.read_text(), "body\n")
            self.assertEqual([path.name for path in Path(directory).iterdir()], ["out.yaml"])

    def test_write_failure_is_reported_with_a_stable_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "out.yaml"
            target.mkdir()

            with self.assertRaises(ExportOutputError) as caught:
                write_document("body\n", target, force=True)
            self.assertEqual(caught.exception.code, "export_output_failed")
            self.assertEqual(caught.exception.exit_code, 1)


class ExportArgumentTests(unittest.TestCase):
    def test_export_conflicts_are_rejected(self) -> None:
        cases = [
            (["--list", "--export", "yaml"], "--list and --export"),
            (["--export", "yaml", "--connect"], "connection-only"),
            (["--export", "yaml", "--plain"], "connection-only"),
            (["--export", "yaml", "oracle"], "connection-only"),
            (["--output", "x"], "--output requires --export"),
            (["--force"], "--force requires"),
            (["oracle", "--filter", "x"], "--filter requires"),
        ]
        for argv, needle in cases:
            with self.subTest(argv=argv):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(main(argv), 2)
                self.assertIn(needle, stderr.getvalue())

    def test_export_requires_a_known_format(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--export", "toml"]), 2)

    def test_export_allows_strict_and_shell_json(self) -> None:
        result, out, _err = run_export(
            ["--export", "json", "--strict", "--shell", "json"], sample_client()
        )

        self.assertEqual(result, 0)
        self.assertEqual(len(json.loads(out)["hosts"]), 4)


def agent_info(
    store: str, *name: str, identifier: str = "bitwarden", host: str = ""
) -> dict[str, object]:
    """A store record whose identity is a password-manager SSH agent."""
    return ssh_info(
        store,
        *name,
        host=host or f"{store}.example",
        identity={
            "type": "inPlace",
            "identityStore": {
                "type": "localIdentity",
                "username": "alice",
                "sshIdentity": {"type": "passwordManagerAgent", "identifier": identifier},
            },
        },
    )


class AgentExportTests(unittest.TestCase):
    def agent_client(self) -> MultiClient:
        return MultiClient([agent_info("a", "default", "alpha")])

    def agent_socket(self, count: int = 2, path: str = "/tmp/agent.sock") -> AgentSocket:
        return AgentSocket(path, "Bitwarden", count, provider="bitwarden")

    def collect(
        self,
        client: MultiClient,
        *,
        agent_resolver: AgentResolver | None = None,
        agent_socket: str = "auto",
        host_picker: HostPicker | None = None,
    ) -> ExportResult:
        return collect_export(
            client,
            list(client.records.values()),
            agent_resolver=agent_resolver,
            agent_socket=agent_socket,
            host_picker=host_picker,
        )

    def test_ssh_config_emits_identity_agent(self) -> None:
        result = self.collect(
            self.agent_client(), agent_resolver=lambda *_a, **_k: self.agent_socket()
        )

        text = render_export(ExportResult(hosts=result.hosts), "ssh-config")

        self.assertIn("    IdentityAgent /tmp/agent.sock", text)

    def test_yaml_and_json_records_carry_identity_agent(self) -> None:
        hosts = self.collect(
            self.agent_client(), agent_resolver=lambda *_a, **_k: self.agent_socket()
        ).hosts
        for fmt, load in (("yaml", yaml.safe_load), ("json", json.loads)):
            with self.subTest(fmt=fmt):
                document = load(render_export(ExportResult(hosts=hosts), fmt))
                host = next(h for h in document["hosts"] if h["alias"] == "default/alpha")
                self.assertEqual(host["identityAgent"], "/tmp/agent.sock")

    def test_ansible_common_args_include_identity_agent(self) -> None:
        hosts = self.collect(
            self.agent_client(), agent_resolver=lambda *_a, **_k: self.agent_socket()
        ).hosts

        document = ansible_document(hosts)
        args = document["all"]["hosts"]["default-alpha"]["ansible_ssh_common_args"]

        self.assertIn("IdentityAgent=/tmp/agent.sock", args)

    def test_missing_socket_is_a_warning_and_omits_identity_agent(self) -> None:
        result = self.collect(self.agent_client(), agent_resolver=lambda *_a, **_k: None)

        self.assertTrue(
            any("no matching usable agent socket" in warning for warning in result.warnings)
        )
        text = render_export(ExportResult(hosts=result.hosts), "ssh-config")
        self.assertNotIn("IdentityAgent", text)

    def test_zero_identity_socket_is_a_warning(self) -> None:
        result = self.collect(
            self.agent_client(), agent_resolver=lambda *_a, **_k: self.agent_socket(count=0)
        )

        self.assertTrue(any("no identities" in warning for warning in result.warnings))

    def test_without_resolver_no_identity_agent_is_emitted(self) -> None:
        result = self.collect(self.agent_client())

        self.assertEqual(result.hosts[0].identity_agent, None)

    def test_explicit_agent_socket_flag_reaches_the_resolver(self) -> None:
        client = self.agent_client()
        requested: list[str] = []

        def resolver(agent_socket: str, **_kwargs: object) -> AgentSocket:
            requested.append(agent_socket)
            return self.agent_socket(path=agent_socket)

        # run_export injects no agent_resolver, so exercise the CLI explicitly.
        out_buffer, err_buffer = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(out_buffer),
            contextlib.redirect_stderr(err_buffer),
        ):
            result = main(
                ["--export", "ssh-config", "--agent-socket", "/opt/custom.sock"],
                AppDependencies(client_factory=lambda _: client, agent_resolver=resolver),
            )
        self.assertEqual(result, 0)
        self.assertEqual(requested, ["/opt/custom.sock"])
        self.assertIn("    IdentityAgent /opt/custom.sock", out_buffer.getvalue())

    def test_strict_turns_a_missing_socket_into_a_failure(self) -> None:
        client = self.agent_client()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = main(
                ["--export", "ssh-config", "--strict", "--shell", "json"],
                AppDependencies(
                    client_factory=lambda _: client, agent_resolver=lambda *_a, **_k: None
                ),
            )

        self.assertEqual(result, 2)
        self.assertEqual(json.loads(out.getvalue())["error"]["code"], "strict_warnings")

    def test_spaced_socket_path_is_quoted_in_ssh_config(self) -> None:
        result = self.collect(
            self.agent_client(),
            agent_resolver=lambda *_a, **_k: self.agent_socket(path="/tmp/my agents/agent.sock"),
        )

        text = render_export(ExportResult(hosts=result.hosts), "ssh-config")

        self.assertIn('    IdentityAgent "/tmp/my agents/agent.sock"', text)


class TtyStderr(io.StringIO):
    """A StringIO that Rich treats as a terminal."""

    def isatty(self) -> bool:
        return True


class ExportTuiTests(unittest.TestCase):
    def test_pretty_export_renders_a_summary_on_a_tty(self) -> None:
        client = sample_client()
        out, err = io.StringIO(), TtyStderr()
        with contextlib.redirect_stdout(out), mock.patch("sys.stderr", err):
            result = main(
                ["--export", "ssh-config"],
                AppDependencies(client_factory=lambda _: client),
            )

        self.assertEqual(result, 0)
        rendered = err.getvalue()
        self.assertIn("XPipe", rendered)
        self.assertIn("Exported (4)", rendered)
        self.assertIn("default/alpha", rendered)
        self.assertIn("alpha.example", rendered)
        # Pretty mode replaces the plain warning lines with panels.
        self.assertNotIn("warning: ", rendered)
        # The document itself stays untouched on stdout.
        self.assertIn("Host default/alpha", out.getvalue())

    def test_pretty_export_lists_skipped_connections_in_their_own_panel(self) -> None:
        broken = ssh_info("bad", "default", "bad", host="bad host")
        client = MultiClient([broken, ssh_info("good", "default", "good")])
        out, err = io.StringIO(), TtyStderr()
        with contextlib.redirect_stdout(out), mock.patch("sys.stderr", err):
            result = main(
                ["--export", "ssh-config"],
                AppDependencies(client_factory=lambda _: client),
            )

        self.assertEqual(result, 0)
        rendered = err.getvalue()
        self.assertIn("Skipped (1)", rendered)
        self.assertIn("default/bad", rendered)
        self.assertIn("default/good", rendered)

    def test_pretty_export_shows_the_agent_provider_per_connection(self) -> None:
        client = MultiClient([agent_info("a", "default", "alpha")])
        out, err = io.StringIO(), TtyStderr()
        with contextlib.redirect_stdout(out), mock.patch("sys.stderr", err):
            result = main(
                ["--export", "ssh-config"],
                AppDependencies(
                    client_factory=lambda _: client,
                    agent_resolver=lambda *_a, **_k: AgentSocket(
                        "/Users/zacklack/.bitwarden-ssh-agent.sock",
                        "Bitwarden",
                        2,
                        provider="bitwarden",
                    ),
                ),
            )

        self.assertEqual(result, 0)
        self.assertIn("Bitwarden", err.getvalue())

    def test_pretty_export_with_no_color_emits_no_ansi(self) -> None:
        out, err = io.StringIO(), TtyStderr()
        with contextlib.redirect_stdout(out), mock.patch("sys.stderr", err):
            result = main(
                ["--export", "ssh-config", "--no-color"],
                AppDependencies(client_factory=lambda _: sample_client()),
            )

        self.assertEqual(result, 0)
        rendered = err.getvalue()
        # --no-color strips hues; Rich still emits bold/dim emphasis by design.
        for hue in (
            "\x1b[31m",
            "\x1b[32m",
            "\x1b[33m",
            "\x1b[34m",
            "\x1b[35m",
            "\x1b[36m",
            "\x1b[37m",
        ):
            self.assertNotIn(hue, rendered)

    def test_shell_json_export_never_renders_panels(self) -> None:
        out, err = io.StringIO(), TtyStderr()
        with contextlib.redirect_stdout(out), mock.patch("sys.stderr", err):
            result = main(
                ["--export", "json", "--shell", "json"],
                AppDependencies(client_factory=lambda _: sample_client()),
            )

        self.assertEqual(result, 0)
        self.assertNotIn("Exported", err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["schemaVersion"], 1)

    def test_json_export_alone_keeps_chrome_on_stderr_and_document_on_stdout(self) -> None:
        out, err = io.StringIO(), TtyStderr()
        with contextlib.redirect_stdout(out), mock.patch("sys.stderr", err):
            result = main(
                ["--export", "json"],
                AppDependencies(client_factory=lambda _: sample_client()),
            )

        self.assertEqual(result, 0)
        self.assertIn("Exported (4)", err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["schemaVersion"], 1)

    def test_plain_output_is_unchanged_when_stderr_is_not_a_tty(self) -> None:
        client = MultiClient([ssh_info("bad", "default", "bad", host="bad host")])
        _result, _out, err = run_export(["--export", "ssh-config"], client)

        self.assertIn("warning: ", err)
        self.assertEqual(_result, 0)


class PickHostsExportTests(unittest.TestCase):
    def multi_host_client(self) -> MultiClient:
        return MultiClient(
            [
                ssh_info(
                    "a",
                    "default",
                    "alpha",
                    host={"value": "10.0.0.1", "available": ["10.0.0.1", "10.0.0.2", "192.0.2.7"]},
                ),
                ssh_info("b", "default", "beta", host="beta.example"),
            ]
        )

    def test_selected_host_is_used_without_the_flag(self) -> None:
        text = render_export(
            ExportResult(hosts=exported_hosts(self.multi_host_client())), "ssh-config"
        )

        self.assertIn("HostName 10.0.0.1", text)

    def test_pick_hosts_exports_the_chosen_host(self) -> None:
        client = self.multi_host_client()
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch("xpipe_to_ssh.presentation.RICH_AVAILABLE", False),
            fake_tty_stdin("2\n"),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            result = main(
                ["--export", "ssh-config", "--pick-hosts"],
                AppDependencies(client_factory=lambda _: client),
            )

        self.assertEqual(result, 0)
        self.assertIn("HostName 10.0.0.2", out.getvalue())
        # A connection with a single available host is never prompted, so the
        # one queued answer was spent on alpha alone.
        self.assertIn("HostName beta.example", out.getvalue())

    def test_pick_hosts_lists_all_alternatives_before_asking(self) -> None:
        client = self.multi_host_client()
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch("xpipe_to_ssh.presentation.RICH_AVAILABLE", False),
            fake_tty_stdin("1\n"),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            main(
                ["--export", "ssh-config", "--pick-hosts"],
                AppDependencies(client_factory=lambda _: client),
            )

        self.assertIn("192.0.2.7", err.getvalue())

    def test_pick_hosts_keeps_json_output_parseable(self) -> None:
        client = self.multi_host_client()
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch("xpipe_to_ssh.presentation.RICH_AVAILABLE", False),
            fake_tty_stdin("2\n"),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            result = main(
                ["--export", "json", "--pick-hosts"],
                AppDependencies(client_factory=lambda _: client),
            )

        self.assertEqual(result, 0)
        self.assertEqual(
            next(h for h in json.loads(out.getvalue())["hosts"] if h["alias"] == "default/alpha")[
                "hostname"
            ],
            "10.0.0.2",
        )

    def test_pick_hosts_with_an_out_of_range_answer_fails_without_a_document(self) -> None:
        client = self.multi_host_client()
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch("xpipe_to_ssh.presentation.RICH_AVAILABLE", False),
            fake_tty_stdin("9\n"),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            result = main(
                ["--export", "ssh-config", "--pick-hosts"],
                AppDependencies(client_factory=lambda _: client),
            )

        self.assertEqual(result, 2)
        self.assertEqual(out.getvalue(), "")

    def test_pick_hosts_without_a_tty_fails_instead_of_skipping(self) -> None:
        client = self.multi_host_client()
        with mock.patch("sys.stdin", io.StringIO("")):
            result, out, err = run_export(["--export", "ssh-config", "--pick-hosts"], client)

        self.assertEqual(result, 2)
        self.assertIn("--pick-hosts requires an interactive terminal", err)
        self.assertEqual(out, "")

    def test_pick_hosts_requires_export(self) -> None:
        client = self.multi_host_client()
        for argv in (["--pick-hosts"], ["--pick-hosts", "--list"], ["--pick-hosts", "alpha"]):
            with self.subTest(argv=argv):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(
                        main(argv, AppDependencies(client_factory=lambda _: client)), 2
                    )
                self.assertIn("--pick-hosts requires --export", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
