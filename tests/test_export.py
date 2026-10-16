"""Bulk export to SSH config, hosts YAML, JSON, and Ansible inventory."""

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import yaml

from xpipe_to_ssh.cli import AppDependencies, main
from xpipe_to_ssh.errors import ExportOutputError, InternalError
from xpipe_to_ssh.export import (
    ExportHost,
    ExportResult,
    ansible_document,
    collect_export,
    command_fields,
    hosts_document,
    render_export,
    sanitize_alias,
    unique_names,
    write_document,
)
from xpipe_to_ssh.models import SSHCommand


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


if __name__ == "__main__":
    unittest.main()
