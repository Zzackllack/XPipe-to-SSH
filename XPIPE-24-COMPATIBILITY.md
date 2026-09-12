# XPipe compatibility

Last verified: 2026-09-09 against XPipe Community 24.1.1 and
`xpipe-api` 0.1.35. This document separates the historical migration issue
from the current implementation and its remaining operational limits.

## Historical XPipe 24 break

XPipe 24 renamed the HTTP API family from `/connection/...` to `/store/...`,
renamed request fields, and returned `store` identifiers. It also exposed
some identity metadata as direct descriptors rather than encrypted JSON.
The old script used `connection_query`/`connection_info`, read only
`connection` IDs, and attempted to decrypt every identity object. Query
errors were also hidden as an empty list.

## Current implementation

The adapter selects the complete v24 store API when available and retains a
v23 connection-API fallback for older client doubles or installations. It
validates IDs and response containers, preserves store IDs through selection
and gateway resolution, and propagates API failures. Direct `none`, `file`,
`agent`, and `passwordManagerAgent` descriptors are recognized before the
legacy decryption path.

The command planner additionally validates destinations, ports, booleans,
gateway depth/cycles, and additional SSH options. It keeps password values
out of generated argv and JSON. Provider and identifier metadata from a
password-manager identity is used when choosing an agent socket.

## Compatibility matrix

| Component | Supported policy | Verification |
| --- | --- | --- |
| XPipe HTTP API | v24 store API | Live read-only validation on 24.1.1 |
| Older API | v23 fallback retained | Unit fake client |
| Python client | `xpipe-api>=0.1.34` | Lock resolves 0.1.35 |
| SSH output | POSIX, PowerShell, JSON | Unit coverage; platform runtime still requires host testing |
| SSH agents | Common Unix sockets and explicit paths | Unit coverage; provider/platform matrix is intentionally conservative |

## Validation policy

The default test suite uses fakes and never opens an SSH session. An
environment-specific smoke test may query XPipe and generate argv/JSON, but
must remain read-only and must not invoke `--connect`. Live daemon version,
store counts, and generated-command counts should be recorded with any such
run because historical validation is not current production proof.

## Sources

- [XPipe Python API](https://docs.xpipe.io/guide/python-api)
- [XPipe 24.0 changelog](https://github.com/xpipe-io/xpipe/blob/master/dist/changelog/24.0.md)
- [XPipe Python API client](https://github.com/xpipe-io/xpipe-python-api/blob/master/xpipe_api/clients.py)
