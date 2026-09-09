# XPipe 24 compatibility audit

Status: the current script is not compatible with the XPipe 24 API as shipped
in the local XPipe Community 24.1.1 installation.

This audit covers the XPipe 23.9 baseline and every published 24.x changelog
available on 2026-09-09: 24.0, 24.0.1, 24.0.2, 24.0.3, 24.0.4, 24.0.5,
24.1, and 24.1.1. The repository also contains a `24.1.2.md` file on the
XPipe `master` branch, but there is no published 24.1.2 release or tag yet;
that file only repeats an artifact-download fix and does not change this
assessment.

## Executive result

The tool currently fails before it can discover a connection:

```text
uv run python main.py --list --plain
# exit 0, no output

uv run python main.py oracle-oc1 --plain
error: No SSH connection matched 'oracle-oc1'. Use --list to see names.
```

The empty `--list` result is misleading. `query_all()` catches every query
exception and silently continues (`main.py:130-141`). XPipe 24.1.1 is
actually rejecting the old request with:

```text
500 ... /connection/query: ... storeFilter is marked non-null but is null
```

The local XPipe UI reports `XPipe Community (24.1.1)`, and its daemon API
reports version `24.1.1`. A direct call through the current locked dependency
(`xpipe-api` 0.1.33) reproduces the failure.

## Confirmed breaking changes

### 1. The connection API was renamed to the store API

XPipe 24 changed the `/connection/...` API family to `/store/...` and renamed
connection parameters to store parameters. The current script calls the old
client methods in several places:

| Current code | v23 client/API | v24 client/API |
| --- | --- | --- |
| `client.connection_query(...)` | `/connection/query` with `connectionFilter` | `client.store_query(...)`, `/store/query` with `storeFilter` |
| `client.connection_info(...)` | `/connection/info` with `connections` | `client.store_info(...)`, `/store/info` with `stores` |

Affected code paths:

- `query_all()` (`main.py:130-141`)
- `info_one()` (`main.py:116-120`)
- `resolve_identity()` when an identity is referenced (`main.py:263-273`)
- UUID selection, list mode, connection-name selection, and gateway handling

The Python API package fixed this in version 0.1.34. The project lock file
still pins 0.1.33, while `pyproject.toml` only says `xpipe-api>=0.1.33`.
That means a normal locked `uv run` continues to install the incompatible
client. Upgrading the package alone is also insufficient because the script
still calls the removed `connection_*` methods.

### 2. Store identifiers are now returned as `store`, not `connection`

The current code reads `info.get("connection")` for command metadata and
gateway-cycle detection (`main.py:380-384`, `main.py:399`, and
`main.py:473`). XPipe 24 store info uses `info["store"]`.

After the API method calls are migrated, the command may still be generated,
but its JSON `connection.id` will be empty, ambiguity messages will omit the
ID, and gateway cycle detection will no longer detect a cycle because every
store has an empty fallback ID.

### 3. v24 identity data is not always an encrypted JSON blob

The script assumes that any truthy `identityStore["sshIdentity"]` value must
be passed to `client.secret_decrypt()` (`main.py:278-291` and
`main.py:305-325`). In the running v24.1.1 store data, identity descriptors
are exposed directly. Examples observed without reading secret values include
`type: none` and `type: passwordManagerAgent` with an `identifier`.

The v24 descriptor is therefore not necessarily the encrypted payload that
the old script expects. A v24-compatible adapter must first recognize direct
descriptors and only call `secret_decrypt()` for an actual encrypted secret
object.

This is especially important for the user's password-manager identities:

- the current script fails to recognize the direct
  `passwordManagerAgent` descriptor;
- it consequently does not mark the command as needing an external agent;
- it may omit `SSH_AUTH_SOCK` and fall back to an ordinary SSH invocation;
- the current code instead records a decryption warning such as
  `Unable to parse or decrypt secret`.

The v24 vault/RBAC migration is relevant here because XPipe 24 changed the
vault encryption and identity handling at the same time as the API schema.

## Changes that are not currently breaking the parser

The following parts of the existing parser still match the v24.1.1 data
observed locally, but should be covered by regression tests because XPipe
explicitly does not promise a stable per-store configuration schema:

- connection configuration is still available under `rawData`, which the
  `connection_config()` fallback already supports (`main.py:144-155`);
- SSH stores still expose `host` with a selected `value` and an `available`
  list, which matches `selected_value()` and `selectable_texts()`;
- SSH stores still expose `port`, `gateway`, `forwardX11`,
  `additionalOptions`, and identity references;
- SSH config-host stores still have a usable name path, so the current alias
  fallback normally continues to produce an SSH config alias.

These are compatibility observations, not a guarantee. The official API
documentation says that store schemas can change and should be inspected from
the active XPipe instance.

## 24.x changelog review

| Release | Relevant change | Effect on this tool |
| --- | --- | --- |
| 23.9 | SSH key-file UX improvements | No direct break found. This is the baseline immediately before the migration. |
| 24.0 | API endpoints and parameters renamed from connection to store; vault format, encryption, and RBAC reworked; direct v24 upgrades require the v23.99 migration step | Direct, confirmed break. Also requires checking that the local vault and any Git sync were migrated successfully. |
| 24.0.1 | Fix startup error for custom hibernation settings | No script-specific break. It could prevent XPipe from starting, which would make the API unavailable. |
| 24.0.2 | Fix startup error for migrated KeePassXC vaults; fix Intel macOS architecture detection | No direct parser break. Relevant only if XPipe failed to start after migration. |
| 24.0.3 | More migrated-KeePassXC startup fixes; migration corruption fixes; synced-identity role-access fix | No new script API change, but identity/vault migration health matters to API results. |
| 24.0.4 | Fix password-manager identities not disabling external agents correctly; fix SSH terminal handling and Windows usernames with spaces | Relevant behavior change for agent handling, but the script independently chooses an agent socket and does not read XPipe's external-agent preference. Test this explicitly. |
| 24.0.5 | Fix SSH/git askpass handling; add Proton Pass listing; UI fixes | The script does not use XPipe's askpass executable, so no direct break found. Password fallback behavior should still be tested. |
| 24.1 | Portable KeePassXC support and unrelated startup/proxy/theme fixes | No direct break found. KeePassXC-backed identities should be included in regression testing. |
| 24.1.1 | Fix missing GitHub release artifacts | No direct script or API-schema change. This is the locally installed version. |
| 24.1.2 on `master` | Repeat artifact-download fix | Not a published release and no additional script impact found. |

## Recommended compatibility work

1. Pin the Python API to a v24-compatible release (`xpipe-api>=0.1.34`,
   preferably the tested current release) and regenerate `uv.lock`.
2. Replace `connection_query`/`connection_info` with `store_query`/`store_info`
   and use the v24 request/response field names.
3. Read the store identifier from `store`, with a temporary `connection`
   fallback only if v23 support is intentionally retained.
4. Make identity decoding schema-aware: handle direct `none`, `file`,
   `agent`, and `passwordManagerAgent` descriptors before attempting secret
   decryption.
5. Stop swallowing all query exceptions in `query_all()`. Surface the actual
   API error so a future XPipe schema change cannot look like “zero
   connections.”
6. Add fixture and live smoke tests for a direct SSH store, an SSH config host,
   a host with alternatives, a gateway, a file key, and a password-manager
   agent. Verify both `--plain` and `--shell json`, including the store ID and
   `SSH_AUTH_SOCK` behavior.

## Evidence and sources

- [XPipe 24.0 changelog](https://github.com/xpipe-io/xpipe/blob/master/dist/changelog/24.0.md)
- [XPipe 24.0.1 changelog](https://github.com/xpipe-io/xpipe/blob/master/dist/changelog/24.0.1.md)
- [XPipe 24.0.2 changelog](https://github.com/xpipe-io/xpipe/blob/master/dist/changelog/24.0.2.md)
- [XPipe 24.0.3 changelog](https://github.com/xpipe-io/xpipe/blob/master/dist/changelog/24.0.3.md)
- [XPipe 24.0.4 changelog](https://github.com/xpipe-io/xpipe/blob/master/dist/changelog/24.0.4.md)
- [XPipe 24.0.5 changelog](https://github.com/xpipe-io/xpipe/blob/master/dist/changelog/24.0.5.md)
- [XPipe 24.1 changelog](https://github.com/xpipe-io/xpipe/blob/master/dist/changelog/24.1.md)
- [XPipe 24.1.1 changelog](https://github.com/xpipe-io/xpipe/blob/master/dist/changelog/24.1.1.md)
- [XPipe 23.9 changelog](https://github.com/xpipe-io/xpipe/blob/master/dist/changelog/23.9.md)
- [XPipe Python API documentation](https://docs.xpipe.io/guide/python-api)
- [XPipe Python API client source](https://github.com/xpipe-io/xpipe-python-api/blob/master/xpipe_api/clients.py)
- [xpipe-api package releases](https://pypi.org/project/xpipe-api/)
- [XPipe 24.1.1 release](https://github.com/xpipe-io/xpipe/releases/tag/24.1.1)
