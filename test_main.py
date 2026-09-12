import unittest

from main import (
    ExportError,
    build_ssh_argv,
    choose_connection,
    connection_config,
    identity_options,
    info_one,
    query_all,
    ssh_config_alias,
    store_id,
)


def ssh_info(identifier_key: str, identifier: str) -> dict:
    identity = {
        "type": "inPlace",
        "identityStore": {
            "type": "localIdentity",
            "username": "alice",
            "sshIdentity": {"type": "passwordManagerAgent", "identifier": "agent"},
        },
    }
    return {
        identifier_key: identifier,
        "type": "ssh",
        "name": ["default", "alice@example"],
        "rawData": {
            "type": "ssh",
            "host": {"value": "example.test", "available": ["example.test"]},
            "port": 22,
            "gateway": None,
            "identity": identity,
        },
    }


class V24Client:
    def __init__(self) -> None:
        self.query_args = None
        self.info_args = None
        self.secret_decrypt_calls = 0

    def store_query(self, **kwargs: object) -> list[str]:
        self.query_args = kwargs
        return ["store-id"]

    def store_info(self, refs: list[str]) -> list[dict]:
        self.info_args = refs
        return [ssh_info("store", refs[0])]

    def secret_decrypt(self, value: object) -> object:
        self.secret_decrypt_calls += 1
        raise AssertionError("v24 identity descriptors must not be decrypted")


class V23Client:
    def connection_query(self, **kwargs: object) -> list[str]:
        return ["connection-id"]

    def connection_info(self, refs: list[str]) -> list[dict]:
        return [ssh_info("connection", refs[0])]


class FailingClient:
    def store_query(self, **kwargs: object) -> list[str]:
        raise RuntimeError("API request failed")


class GatewayClient:
    def store_info(self, refs: list[str]) -> list[dict]:
        records = {
            "target": {
                "store": "target",
                "type": "ssh",
                "name": ["default", "target"],
                "rawData": {
                    "type": "ssh",
                    "host": "target.example",
                    "port": 22,
                    "gateway": "gateway",
                },
            },
            "gateway": {
                "store": "gateway",
                "type": "ssh",
                "name": ["default", "gateway"],
                "rawData": {"type": "ssh", "host": "gateway.example", "port": 22},
            },
        }
        return [records[ref] for ref in refs]


class CompatibilityTests(unittest.TestCase):
    def test_v24_query_and_info_use_store_api(self) -> None:
        client = V24Client()

        infos = query_all(client)

        self.assertEqual(client.query_args, {"categories": "**", "stores": "**", "types": "*"})
        self.assertEqual(client.info_args, ["store-id"])
        self.assertEqual(store_id(infos[0]), "store-id")
        self.assertEqual(connection_config(infos[0])["type"], "ssh")

    def test_v23_client_fallback_remains_supported(self) -> None:
        infos = query_all(V23Client())

        self.assertEqual(store_id(infos[0]), "connection-id")
        self.assertEqual(info_one(V23Client(), "connection-id")["connection"], "connection-id")

    def test_direct_v24_identity_descriptor_is_not_decrypted(self) -> None:
        client = V24Client()
        result = identity_options(client, connection_config(ssh_info("store", "store-id")))

        self.assertTrue(result.needs_password_manager_agent)
        self.assertIn("Password-manager SSH agent", result.auth_methods)
        self.assertEqual(client.secret_decrypt_calls, 0)
        self.assertEqual(result.warnings, [])

    def test_v24_store_id_is_used_in_generated_command(self) -> None:
        client = V24Client()
        info = ssh_info("store", "store-id")

        command = build_ssh_argv(client, info)

        self.assertEqual(command.connection_id, "store-id")
        self.assertEqual(command.argv, ["ssh", "-l", "alice", "example.test"])

    def test_v24_gateway_uses_store_id_and_proxy_command(self) -> None:
        command = build_ssh_argv(
            GatewayClient(),
            {
                "store": "target",
                "type": "ssh",
                "name": ["default", "target"],
                "rawData": {
                    "type": "ssh",
                    "host": "target.example",
                    "port": 22,
                    "gateway": "gateway",
                },
            },
        )

        self.assertEqual(command.connection_id, "target")
        self.assertEqual(command.gateway_names, ["default/gateway"])
        self.assertIn("ProxyCommand=ssh -W %h:%p gateway.example", command.argv)

    def test_v24_ssh_config_alias_uses_host_entry_name(self) -> None:
        info = {
            "store": "config-id",
            "name": ["default", "ssh config", "server-alias"],
            "rawData": {"hostEntry": {"name": "server-alias"}},
        }

        self.assertEqual(ssh_config_alias(info, connection_config(info)), "server-alias")

    def test_api_errors_are_not_silently_converted_to_empty_results(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "API request failed"):
            query_all(FailingClient())

    def test_ambiguous_error_contains_v24_store_ids(self) -> None:
        class AmbiguousClient(V24Client):
            def store_query(self, **kwargs: object) -> list[str]:
                return ["first", "second"]

            def store_info(self, refs: list[str]) -> list[dict]:
                return [ssh_info("store", ref) for ref in refs]

        with self.assertRaisesRegex(ExportError, r"\[first\][\s\S]*\[second\]"):
            choose_connection(AmbiguousClient(), "alice@example")


if __name__ == "__main__":
    unittest.main()
