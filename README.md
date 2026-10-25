# pregresql

[![CI](https://github.com/OffworldNexus/pregresql/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/OffworldNexus/pregresql/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A mostly-transparent proxy for the PostgreSQL frontend/backend protocol, written
in pure Rust, with two hooks:

* **an authentication hook** — the proxy observes the inbound connection (Unix
  peer credentials, the tag of the listener that accepted it, the startup
  packet, TLS state, and the credentials the client presented) and the hook returns the *actual* upstream target to
  connect to (network location, TLS, role, password, database);
* **a query hook** — every statement the client tries to run goes through the
  hook, which may allow it, rewrite it, or reject it with a synthetic
  `ErrorResponse` that never reaches the server.

The protocol itself is implemented from scratch in this crate: startup
negotiation, TLS and GSSENC negotiation, trust/cleartext/MD5/SCRAM-SHA-256
authentication in *both* directions, the simple and extended query protocols,
the COPY sub-protocol, cancellation, and asynchronous notifications. There is no
dependency on `tokio-postgres`, `postgres-protocol` or libpq — the only
protocol-aware code here is this crate's own (the test suite uses
`tokio-postgres` purely as a *client*, and the regression run uses PostgreSQL's
own `psql`).

```
        ┌──────────┐        ┌───────────────┐        ┌──────────────┐
        │  client  │ ─────▶ │  pregresql    │ ─────▶ │  PostgreSQL  │
        │  (psql,  │  PG    │  AuthHook     │  PG    │  server      │
        │  driver) │ ◀───── │  QueryHook    │ ◀───── │              │
        └──────────┘  wire  └───────────────┘  wire  └──────────────┘
```

## Layout

| Path | What it is |
| --- | --- |
| `src/protocol/` | framing, typed messages, startup packets — the protocol itself |
| `src/auth/` | MD5 challenge/response and SCRAM-SHA-256 (RFC 5802/7677), client and server side |
| `src/proxy/hooks.rs` | the two hook traits and their input/output types |
| `src/proxy/session.rs` | per-connection state machine: auth, upstream setup, policy relay |
| `src/proxy/server.rs` | listeners, TLS negotiation, cancel requests |
| `src/bin/pregresql-proxy/` | the demo CLI |
| `examples/demo_client.rs` | a driver client that demonstrates the locked-down proxy |
| `docker/` | PostgreSQL + proxy + official regression suite harness |
| `scripts/validate.sh` | one command that runs the whole validation |

## Requirements

Unix-like operating system (Linux, or BSD/macOS). The proxy speaks the protocol
over TCP *and* over Unix-domain sockets, and reads peer credentials through
`SO_PEERCRED` (Linux) or `getpeereid` (BSD/macOS); `tokio`'s Unix-socket types
are not available on Windows. CI therefore runs on Linux and macOS.

On Linux (and Android) the proxy additionally collects the `SCM_CREDENTIALS`
of the client's first message (see *Listener tags and Unix credentials*); on
other platforms that field is always `None`.

Rust 1.88 or newer (the floor is set by the resolved dependency graph; it is
checked in CI).

## Library use

```rust,ignore
use std::sync::Arc;
use pregresql::proxy::{
    AuthContext, AuthError, AuthHook, Endpoint, Proxy, ProxyConfig, QueryContext,
    QueryDecision, QueryHook, UpstreamTarget, UpstreamTls,
};

struct MyAuth;

#[async_trait::async_trait]
impl AuthHook for MyAuth {
    // How should the incoming client authenticate to the proxy?
    fn client_auth_method(&self, _conn: &pregresql::InboundConnection) -> pregresql::ClientAuthMethod {
        pregresql::ClientAuthMethod::ScramSha256
    }

    // What password should the proxy verify that proof against?
    fn password_for_user(&self, _conn: &pregresql::InboundConnection, user: &str) -> Option<String> {
        lookup_password(user)
    }

    // Where does this session actually go?
    async fn resolve_upstream(&self, ctx: AuthContext<'_>) -> Result<UpstreamTarget, AuthError> {
        if !ctx.verified {
            return Err(AuthError::invalid_password("unverified credentials"));
        }
        if ctx.connection.transport.peer_uid() == Some(0) && !ctx.connection.tls.negotiated {
            return Err(AuthError::rejected("root over plaintext is not allowed"));
        }
        Ok(UpstreamTarget {
            endpoint: Endpoint::tcp("db.internal", 5432),
            tls: UpstreamTls::Require(Default::default()),
            user: ctx.user.to_string(),
            password: None,
            database: Some("app".into()),
            params: vec![],
        })
    }
}

struct MyPolicy;

#[async_trait::async_trait]
impl QueryHook for MyPolicy {
    async fn authorize(&self, ctx: QueryContext<'_>) -> QueryDecision {
        if ctx.sql.contains("pg_catalog") {
            QueryDecision::deny("catalog access is not permitted")
        } else {
            QueryDecision::Allow
        }
    }
}

# async fn run() -> pregresql::Result<()> {
let proxy = Proxy::new(ProxyConfig::default(), Arc::new(MyAuth), Arc::new(MyPolicy))?;
proxy.run().await
# }
```

### The authentication hook

`AuthHook` is consulted in three steps, which lets the proxy drive a real
challenge/response exchange instead of trusting whatever the client claims:

1. `client_auth_method(&InboundConnection) -> ClientAuthMethod` decides how the
   client proves itself: `Trust`, `Cleartext`, `Md5` or `ScramSha256`.
   `InboundConnection` carries the transport (including `SO_PEERCRED` uid/gid/pid
   and the `SCM_CREDENTIALS` of the first message for Unix sockets), the tag of
   the listener that accepted the connection, the TLS state and the client
   certificate, and the full startup packet.
2. `password_for_user(...)` supplies the expected password so the proxy can
   *verify* the proof. For `ScramSha256` the proxy acts as a genuine SCRAM
   server, so it learns nothing from the wire and only trusts the password the
   hook gives it; for `Md5` it verifies the challenge response; for `Cleartext`
   it compares the supplied password.
3. `resolve_upstream(&AuthContext) -> UpstreamTarget` is where the decision is
   made. `AuthContext` exposes the observed credentials: `user`, `method`,
   `verified` (did the proxy actually check the proof?) and `password` (the
   plaintext, and only ever a password that was proven).

`UpstreamTarget` is the "actual target": TCP or Unix endpoint, TLS mode
(`Disable`/`Prefer`/`Require`) with verification mode, CA bundle and optional
client certificate, the role and password to authenticate with upstream, the
database to request, and extra startup parameters that override the client's.

A failed `resolve_upstream` closes the connection with a `FATAL` `ErrorResponse`
carrying the hook's SQLSTATE.

### Listener tags and Unix credentials

Besides the addresses in `ProxyConfig::listen`, which the proxy binds itself,
an embedding application can hand the proxy listeners it bound on its own —
typically inherited from a privileged parent process across `execve` — each
with an opaque tag:

```rust,ignore
use std::os::fd::FromRawFd;

let mut proxy = Proxy::new(config, auth, policy)?;
// SAFETY: fd 3 is a listening Unix socket handed down by the parent.
let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
proxy.add_unix_listener(listener, "view-42");
proxy.add_tcp_listener(std::net::TcpListener::bind("127.0.0.1:0")?, "local-tcp");
proxy.run().await
```

Adopted listeners may be in blocking mode (the proxy switches them to
non-blocking when it starts), are served alongside the configured ones, and
their socket files are never unlinked. Every connection they accept exposes the
tag as `InboundConnection::listener_tag` (`None` for configured listeners), to
both hooks: `QueryContext::connection` is the same `InboundConnection` the auth
hook saw, so a query policy can key off the tag or the credentials without
keeping its own `connection_id` map.

Tags are the robust way to identify a local client: give each client identity
its own Unix socket, readable and writable only by that identity (for example
mode `0600` owned by the client's uid), and the kernel's permission check at
`connect()` decides which tag a client can reach.

For Unix sockets the proxy also records two kinds of peer credentials in
`Transport::Unix`:

* `peer_pid`/`peer_uid`/`peer_gid` (`Transport::peer_uid()`): `SO_PEERCRED` on
  Linux, `getpeereid` on BSD/macOS (no pid there). **These are wrong under
  gVisor** — on DigitalOcean App Platform, for example, `SO_PEERCRED` on an
  accepted socket returns the *listening* process's pid/uid/gid for every
  connection, whatever the client.
* `message_credentials` (`Transport::message_credentials()`,
  `Transport::message_uid()`), Linux and Android only: the proxy sets
  `SO_PASSCRED` on every Unix listener it serves and on each accepted socket,
  and performs the connection's first read with `recvmsg`, so the kernel hands
  it the `SCM_CREDENTIALS` (pid, uid, gid) of the process that wrote the first
  bytes. Clients need nothing special — an unmodified libpq works — and a
  client can only claim other credentials if it holds `CAP_SYS_ADMIN` /
  `CAP_SETUID` / `CAP_SETGID` (an unprivileged client claiming uid 0 gets
  `EPERM`). This works correctly under gVisor. It is `None` on other platforms,
  for TCP, or when `SO_PASSCRED` could not be enabled.

The `recvmsg` reads into the same buffer the startup negotiation decodes from,
and reads exactly what an ordinary read would, so it is transparent to the
protocol: the first bytes may be an `SSLRequest`, part of a startup packet, or a
`CancelRequest`, and data the client wrote before the proxy even accepted the
connection is covered too.

### The query hook

`QueryHook::authorize` is called before the proxy forwards a statement, with a
`QueryContext` describing:

* `kind`: `Simple` (`Query`), `Parse`, `Bind`, `Execute`-supporting portal
  reference, or `FunctionCall`;
* `sql`, `statement_name`, `portal_name`, `parameters`;
* `statement_known` — false when the client refers to a prepared statement the
  proxy never authorised;
* `connection` (the full `InboundConnection`, including the listener tag and
  peer credentials), `connection_id`, `user` (to the proxy), `upstream_user`,
  `transaction_status`.

The decision is `Allow`, `Rewrite(sql)` (for `Query`/`Parse`) or
`Deny { sqlstate, message }`.

The proxy tracks the client's prepared statements and portals, so authorising a
`Parse` is enough to authorise the `Bind`/`Execute` pair that follows it, and a
rejection is answered by the proxy itself — the statement never reaches the
server. Rejections are placed in the client's output stream at exactly the
position a real backend would have placed them, including when the client
pipelines several round trips into one burst (see *Fidelity* below).

## The demo binary

```
pregresql-proxy \
    --listen 0.0.0.0:6432 \
    --client-auth scram \
    --allow-user app --allow-password hunter2 \
    --upstream-host db.internal --upstream-port 5432 \
    --upstream-user app --upstream-password hunter2 --upstream-database appdb \
    --upstream-tls require --upstream-tls-ca /etc/ssl/ca.pem \
    --allow-statement 'SELECT id, name FROM items WHERE id = $1'
```

Clients authenticate to the proxy with a real SCRAM exchange against the
configured password, and the proxy authenticates to the upstream server with the
configured credentials. Only the statements listed with `--allow-statement`
(and/or `--allow-statement-file`) may run; every other query — including simple
`Query` messages, so a client cannot dodge the policy by avoiding the extended
protocol — is rejected by the proxy with SQLSTATE `42501`.

Matching is on the SQL text after trimming surrounding whitespace, dropping a
trailing semicolon and collapsing runs of whitespace, so
`"  SELECT id, name FROM items WHERE id = $1; "` matches. Exact matching is
deliberate: anything else (`SELECT 1; DROP TABLE items`) fails to match and is
rejected.

Useful flags:

| Flag | Effect |
| --- | --- |
| `--client-auth trust\|cleartext\|md5\|scram` | how the client proves itself |
| `--random-password` | generate `--allow-password` and print it |
| `--allow-statement SQL` | add one allowed statement (repeatable) |
| `--allow-statement-file FILE` | one allowed statement per line |
| `--allow-transaction-control` | also allow `BEGIN`/`COMMIT`/`ROLLBACK`/`SAVEPOINT`/`RELEASE` (whole statements only) |
| `--allow-simple-query` | allow *any* simple-protocol query (disables the policy for `Query` messages) |
| `--allow-all` | allow everything (used to validate transparency) |
| `--tls-cert/--tls-key/--require-tls` | serve TLS to clients |
| `--upstream-tls*` | `disable`/`prefer`/`require`, CA bundle, or no verification |
| `--listen-unix PATH` | also listen on a Unix socket |

## Validation

The crate is validated by running **PostgreSQL's own regression suite through the
proxy** and comparing it with a direct run, plus a driver-level demo of the
locked-down mode.

```console
$ ./scripts/validate.sh
```

That script:

1. builds `docker/Dockerfile.pgtest` — PostgreSQL 16.15 plus the regression
   suite *and* the `regress.so`/`autoinc.so`/`refint.so` support modules for the
   exact server version — and `docker/Dockerfile.proxy`;
2. starts a real PostgreSQL server (with TLS enabled by
   `docker/init/00-ssl.sh`), the proxy in `--allow-all` mode, the proxy in
   locked-down mode, a TLS-only proxy, and a tester container;
3. runs `pg_regress` twice with an identical client environment: once against
   the server directly, once through the proxy. The suite drops and recreates
   the `regression` database for each run, so the runs are independent;
4. compares the two runs test by test (only the host name, the scheduling order
   of parallel groups and per-test durations are normalised away);
5. connects with `sslmode=require` to the TLS proxy and asks the server whether
   the leg between the proxy and the server is encrypted as well;
6. runs `examples/demo_client.rs` against the locked-down proxy.

Result of the last run:

```
baseline 220 test file(s) run,  0 differed  -- # All 220 tests passed.
proxied  220 test file(s) run,  0 differed  -- # All 220 tests passed.
the direct and the proxied runs produced identical pass/fail results
psql connected with sslmode=require and the upstream leg is encrypted too
all demo expectations met
VALIDATION PASSED
```

All 220 regression test files pass identically — through `psql`'s simple
protocol, its extended protocol (`\bind`), COPY in both directions, `LISTEN`/
`NOTIFY`, large objects (the legacy function-call sub-protocol), cursors,
prepared transactions, `\c` reconnects, and the multi-connection parallel
groups.

The demo client then shows the other side of the coin, connecting as the same
`app` role that can read every column when it talks to the server directly:

```
=== 1. direct connection to the server (no proxy) ===
  the role can read everything directly: (1, alpha, classified-alpha) (2, beta, classified-beta)

=== 2. same role and password, but through the proxy ===
  PASS connect: SCRAM login on port 16433
  PASS prepare(allow-listed): accepted, as expected
  PASS execute($1 = 1): accepted, as expected
  PASS prepare(secret columns): rejected: db error
  PASS simple Query(SELECT secret): rejected: db error
  PASS BEGIN / execute / ROLLBACK: accepted
  PASS connect with a wrong password: rejected
  PASS connect as a foreign role: rejected
all demo expectations met
```

## Fidelity notes

The proxy aims to be indistinguishable from a direct connection apart from the
two hooks. Where behaviour is observable, it reproduces the backend's:

* **Startup.** `SSLRequest` is answered with `S`/`N`, `GSSENCRequest` with `N`,
  `CancelRequest` is forwarded to the real backend using the keys the proxy
  handed the client, and a request for a minor protocol version the proxy does
  not implement is answered with `NegotiateProtocolVersion` listing unknown
  `_pq_.*` options, exactly as a backend would.
* **Unix credentials.** Reading `SCM_CREDENTIALS` changes nothing on the wire:
  the first read is a `recvmsg` that returns exactly the bytes a plain read
  would, into the same buffer. Descriptors a client might pass with
  `SCM_RIGHTS` in its first message are closed immediately.
* **Identity.** The client is given the proxy's own `BackendKeyData`, so
  cancellation has to be re-issued against the upstream connection; the
  upstream's `ParameterStatus` messages are forwarded verbatim.
* **Error recovery.** After a rejection in the extended protocol the proxy
  discards the client's messages until the next `Sync`, and the rejection is
  written into the output stream at the point the backend would have written it
  — after the `ReadyForQuery` of any round trip that was already in flight, and
  before the one that closes the rejected message's round trip. This matters for
  clients whose message parser groups responses at `ReadyForQuery`.
* **Rejections look like server errors.** A rejected statement produces an
  ordinary `ErrorResponse` (SQLSTATE `42501` by default), which drivers surface
  as a database error, not as a protocol violation.

Known, deliberate limitations:

1. **A rejection does not abort the transaction.** A real backend marks the
   transaction as failed when a statement errors inside a transaction block
   (`ReadyForQuery` reports `E`), so subsequent statements are refused until
   `ROLLBACK`. The proxy answers rejections itself, so the upstream never learns
   of the error and the transaction stays usable. Statements after a rejection
   are still subject to the policy, so this is a fidelity gap, not a security
   one.
2. **SCRAM channel binding (`SCRAM-SHA-256-PLUS`) is not offered.** The proxy
   advertises `SCRAM-SHA-256`; a client that asks for channel binding (the `p=`
   gs2 flag) is rejected rather than silently downgraded.
3. **GSSAPI/SSPI/Kerberos authentication is not implemented** in either
   direction; such requests are answered with a clear error.
4. **`AuthHook::password_for_user` returning `None` for `Md5`/`ScramSha256`
   means "accept unverified"** — `AuthContext::verified` is then `false` and the
   hook is responsible for the decision. `ScramSha256` without a password is
   refused outright, because the exchange cannot be completed at all.
5. **Pipelining and flow control.** The relay is two independent pumps, so
   neither direction can stall the other. A rewriting or denying query hook adds
   latency to the message it inspects, which is the only place a slow hook can
   delay a session.

## Testing

```console
$ cargo test --all-targets --locked   # unit and integration tests
$ cargo test --doc --locked           # the doc examples
$ cargo fmt --all -- --check
$ cargo clippy --all-targets -- -D warnings
$ cargo deny check
$ ./scripts/validate.sh               # the docker end-to-end validation
```

Unit tests cover framing (including truncated prefixes), startup packet
round-trips, MD5 composition, the SCRAM client/server exchange in both
directions against the published RFC 7677 test vector, error-field encoding, and
the output-ordering rules for rejections. `tests/listeners.rs` runs the proxy
over real sockets to cover adopted listeners and their tags (Unix and TCP),
`SCM_CREDENTIALS` (including a startup packet written before the proxy
accepted, and an `SSLRequest` followed by a fragmented startup packet), early
disconnects, and the connection details the query hook receives.

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `develop` or a `feature/**`
branch and on every pull request into `develop`:

| Job | What it enforces |
| --- | --- |
| `lint` | `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo doc` with `RUSTDOCFLAGS=-D warnings` (a broken intra-doc link in a protocol crate is a defect) |
| `test` | build and test on Linux and macOS — macOS so that the non-Linux `getpeereid` credentials path is compiled and run somewhere real |
| `msrv` | the declared `rust-version` floor, `cargo check --all-targets --locked` on 1.88.0 |
| `deny` | `cargo deny check` against `deny.toml`: advisory, licence, duplicate-source and wildcard policy |
| `validation` | `scripts/validate.sh`: the official PostgreSQL regression suite run twice (direct and through the proxy) with identical environments, the TLS check, and the locked-down demo client — the project's actual guarantee |

`deny.toml` is not decorative: it is what surfaced that `rustls-pemfile` is
unmaintained (RUSTSEC-2025-0134), which is why certificate and key loading goes
through `rustls-pki-types`' own PEM support instead.
