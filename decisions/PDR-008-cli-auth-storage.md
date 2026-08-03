# PDR-008: Native credential storage for CLI sessions

## Context

WorkOS access tokens are intentionally short-lived. Keeping users signed in
requires a refresh token, but refresh tokens are long-lived credentials and
WorkOS rotates them after every successful refresh. Persisting both tokens in
`~/.pensar/config.json` exposed the refresh credential as ordinary application
configuration and made simultaneous Apex processes vulnerable to refresh-token
rotation races.

## Decision

Apex stores WorkOS refresh tokens through Bun's Secrets API, which uses the
operating system credential store: macOS Keychain, Windows Credential Manager,
or Linux Secret Service. The Node-compatible packaged CLI uses the equivalent
`@napi-rs/keyring` adapter. Access tokens remain in process memory and are
recreated from the refresh token when Apex starts.

When a native credential service is unavailable, Apex uses a dedicated
`~/.pensar/auth.json` fallback with `0600` permissions inside a `0700`
directory and records the active backend in non-secret config metadata. Legacy
tokens are migrated out of `config.json` on first use.

Refreshes are single-flighted within a process and protected by a cross-process
lock. Rotated refresh tokens are persisted before session metadata is updated.
An authenticated request may force one refresh and retry once after a `401`;
further failures are returned normally. Only WorkOS `400` and `401` refresh
responses end the local session. Network and server failures preserve the
refresh token so temporary outages do not sign the user out.

## Rationale

Native credential stores provide OS-managed encryption and access control
without asking users to manage another secret. Memory-only access tokens reduce
the value of filesystem disclosure and naturally respect their short lifetime.
Serialized refresh rotation prevents two TUI or CLI processes from consuming
the same single-use token. The restricted fallback keeps authentication usable
in headless Linux environments where Secret Service is commonly absent while
remaining separate from general configuration.

## Alternatives considered

- **Keep refresh tokens in `config.json`** — rejected because application
  configuration is routinely inspected, copied, and backed up as plain text.
- **Persist access and refresh tokens together** — rejected because access
  tokens can be recreated and do not need to survive process exit.
- **Require the native credential service with no fallback** — rejected because
  many headless Linux and SSH environments do not have an unlocked Secret
  Service session.
- **Refresh only on locally decoded JWT expiry** — rejected because tokens can
  be revoked early; a bounded `401` refresh handles server-side invalidation.

## Consequences

- ✅ Refresh credentials use the strongest storage available on each desktop
  operating system.
- ✅ Short access-token lifetimes and normal refresh rotation are hidden from
  the user.
- ✅ Concurrent Apex processes cannot race a single-use refresh token locally.
- ✅ Temporary WorkOS or network outages do not destroy a valid local session.
- ⚠️ The secure-file fallback is permission-protected rather than backed by an
  OS credential vault; Apex logs whenever it must use it.
- ⚠️ Bun currently marks its Secrets API experimental, so runtime upgrades must
  include an auth-storage regression check.
- ⚠️ Users may see an operating-system credential access prompt on first use.
