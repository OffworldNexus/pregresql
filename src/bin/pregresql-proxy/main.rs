//! `pregresql-proxy` — a demonstration binary for the `pregresql` crate.
//!
//! It wires up the two hooks with a simple, self-contained policy:
//!
//! * clients must log in with a fixed user name and password (the password is
//!   verified with a real SCRAM-SHA-256 or MD5 exchange, or compared directly
//!   for cleartext), and
//! * only a fixed list of prepared statements may be executed: every other
//!   statement is rejected by the proxy with a synthetic `ErrorResponse`,
//!   so the connecting client has no choice but to use the allowed statements.
//!
//! ```text
//! pregresql-proxy \
//!     --listen 0.0.0.0:6432 \
//!     --allow-user app --allow-password 'hunter2' \
//!     --upstream-host postgres --upstream-port 5432 \
//!     --upstream-user app --upstream-password 'hunter2' --upstream-database appdb \
//!     --allow-statement 'SELECT id, name FROM items WHERE id = $1'
//! ```

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use clap::{Parser, ValueEnum};
use pregresql::auth::md5::constant_time_eq;
use pregresql::proxy::{
    AuthContext, AuthError, AuthHook, ClientAuthMethod, Endpoint, InboundConnection, ListenAddr,
    Proxy, ProxyConfig, QueryContext, QueryDecision, QueryHook, QueryKind, TlsClientOptions,
    UpstreamTarget, UpstreamTls, VerifyMode,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ClientAuthArg {
    /// Accept any client without credentials.
    Trust,
    /// Ask for the password in the clear.
    Cleartext,
    /// Perform an MD5 challenge/response.
    Md5,
    /// Perform a SCRAM-SHA-256 exchange (PostgreSQL's default).
    Scram,
}

impl From<ClientAuthArg> for ClientAuthMethod {
    fn from(value: ClientAuthArg) -> Self {
        match value {
            ClientAuthArg::Trust => ClientAuthMethod::Trust,
            ClientAuthArg::Cleartext => ClientAuthMethod::Cleartext,
            ClientAuthArg::Md5 => ClientAuthMethod::Md5,
            ClientAuthArg::Scram => ClientAuthMethod::ScramSha256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum UpstreamTlsArg {
    /// Never negotiate TLS with the upstream server.
    Disable,
    /// Try TLS and fall back to plaintext (libpq's `sslmode=prefer`).
    Prefer,
    /// Require TLS.
    Require,
}

#[derive(Debug, Parser)]
#[command(
    name = "pregresql-proxy",
    version,
    about = "A PostgreSQL protocol proxy with authentication and query hooks",
    long_about = None,
)]
struct Args {
    /// TCP address to listen on. May be repeated.
    #[arg(long = "listen", value_name = "ADDR", default_value = "127.0.0.1:6432")]
    listen: Vec<String>,

    /// Unix-domain socket path to listen on. May be repeated.
    #[arg(long = "listen-unix", value_name = "PATH")]
    listen_unix: Vec<PathBuf>,

    /// How clients authenticate to the proxy.
    #[arg(long, value_enum, default_value = "scram")]
    client_auth: ClientAuthArg,

    /// The only user name that may connect to the proxy.
    #[arg(long, default_value = "app")]
    allow_user: String,

    /// The password required from that user.
    #[arg(long, default_value = "secret")]
    allow_password: String,

    /// Generate a random password for the allowed user and print it.
    #[arg(long)]
    random_password: bool,

    /// Upstream PostgreSQL host.
    #[arg(long, default_value = "127.0.0.1")]
    upstream_host: String,

    /// Upstream PostgreSQL port.
    #[arg(long, default_value_t = 5432)]
    upstream_port: u16,

    /// Upstream Unix-domain socket path (overrides host/port).
    #[arg(long, value_name = "PATH")]
    upstream_unix: Option<PathBuf>,

    /// Role to authenticate as against the upstream server.
    #[arg(long)]
    upstream_user: String,

    /// Password for that role.
    #[arg(long)]
    upstream_password: Option<String>,

    /// Database to request upstream (clients may not choose).
    #[arg(long)]
    upstream_database: Option<String>,

    /// TLS mode for the upstream connection.
    #[arg(long, value_enum, default_value = "disable")]
    upstream_tls: UpstreamTlsArg,

    /// PEM bundle of CAs to verify the upstream certificate against.
    #[arg(long, value_name = "FILE")]
    upstream_tls_ca: Option<PathBuf>,

    /// Accept any upstream certificate (disables server authentication).
    #[arg(long)]
    upstream_tls_no_verify: bool,

    /// Client certificate to present to the upstream server.
    #[arg(long, value_name = "FILE", requires = "upstream_tls_client_key")]
    upstream_tls_client_cert: Option<PathBuf>,

    /// Private key for `--upstream-tls-client-cert`.
    #[arg(long, value_name = "FILE", requires = "upstream_tls_client_cert")]
    upstream_tls_client_key: Option<PathBuf>,

    /// A prepared statement allowed to be executed. May be repeated.
    ///
    /// Matching is done on the SQL text after trimming surrounding whitespace,
    /// removing trailing semicolons and collapsing runs of whitespace.
    #[arg(long = "allow-statement", value_name = "SQL")]
    allow_statement: Vec<String>,

    /// A file with one allowed statement per line (`--` comments and blank
    /// lines are ignored). May be repeated.
    #[arg(long = "allow-statement-file", value_name = "FILE")]
    allow_statement_file: Vec<PathBuf>,

    /// Allow every statement (used to validate the proxy's transparency).
    #[arg(long)]
    allow_all: bool,

    /// Allow simple-protocol queries (`Query` messages) in addition to the
    /// allowed prepared statements.
    #[arg(long)]
    allow_simple_query: bool,

    /// Allow transaction-control statements (BEGIN/COMMIT/ROLLBACK/...).
    #[arg(long)]
    allow_transaction_control: bool,

    /// PEM certificate chain to present to clients that request TLS.
    #[arg(long, value_name = "FILE", requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// PEM private key for `--tls-cert`.
    #[arg(long, value_name = "FILE", requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// Refuse clients that do not negotiate TLS.
    #[arg(long, requires = "tls_cert")]
    require_tls: bool,

    /// Maximum number of simultaneously served connections.
    #[arg(long)]
    max_connections: Option<usize>,

    /// Largest protocol message accepted, in bytes.
    #[arg(long, default_value_t = 1 << 30)]
    max_message_length: usize,

    /// Log filter, in `tracing` `EnvFilter` syntax.
    #[arg(long, default_value = "info", env = "PREGRESQL_LOG")]
    log: String,
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&args.log)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("cannot start the async runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let allow_password = if args.random_password {
        random_password()
    } else {
        args.allow_password.clone()
    };

    // ---- authentication hook ------------------------------------------------
    let target = UpstreamTarget {
        endpoint: match &args.upstream_unix {
            Some(path) => Endpoint::unix(path.clone()),
            None => Endpoint::tcp(args.upstream_host.clone(), args.upstream_port),
        },
        tls: upstream_tls(&args),
        user: args.upstream_user.clone(),
        password: args.upstream_password.clone(),
        database: args.upstream_database.clone(),
        params: Vec::new(),
    };
    let auth = Arc::new(DemoAuth {
        allow_user: args.allow_user.clone(),
        allow_password: allow_password.clone(),
        method: args.client_auth.into(),
        target: target.clone(),
        // A random password handed out for unknown users so that a failed
        // login looks exactly like a wrong password instead of leaking
        // whether the user exists.
        decoy_password: random_password(),
    });

    // ---- query hook ---------------------------------------------------------
    let mut statements = HashSet::new();
    for sql in &args.allow_statement {
        if let Some(normalized) = normalize_sql(sql) {
            statements.insert(normalized);
        }
    }
    for file in &args.allow_statement_file {
        let content = std::fs::read_to_string(file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        for (number, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("--") {
                continue;
            }
            match normalize_sql(line) {
                Some(normalized) => {
                    statements.insert(normalized);
                }
                None => {
                    return Err(format!(
                        "{}:{}: statement is empty after normalisation",
                        file.display(),
                        number + 1
                    )
                    .into())
                }
            }
        }
    }
    let policy = Arc::new(DemoPolicy {
        statements,
        allow_all: args.allow_all,
        allow_simple_query: args.allow_simple_query,
        allow_transaction_control: args.allow_transaction_control,
    });

    if !args.allow_all && policy.statements.is_empty() {
        tracing::warn!(
            "no allowed statements configured: every query will be rejected \
             (pass --allow-statement, --allow-statement-file or --allow-all)"
        );
    }

    // ---- proxy --------------------------------------------------------------
    let mut listen = Vec::new();
    for addr in &args.listen {
        let parsed: SocketAddr = addr
            .parse()
            .map_err(|e| format!("invalid --listen address {addr:?}: {e}"))?;
        listen.push(ListenAddr::Tcp(parsed));
    }
    for path in &args.listen_unix {
        listen.push(ListenAddr::Unix(path.clone()));
    }
    if listen.is_empty() {
        return Err("no listener configured".into());
    }

    let config = ProxyConfig {
        listen,
        tls: match (&args.tls_cert, &args.tls_key) {
            (Some(cert_file), Some(key_file)) => Some(pregresql::proxy::TlsServerOptions {
                cert_file: cert_file.clone(),
                key_file: key_file.clone(),
                client_ca_file: None,
            }),
            _ => None,
        },
        require_tls: args.require_tls,
        max_message_length: args.max_message_length,
        max_connections: args.max_connections,
        replace_unix_socket: true,
    };

    let proxy = Proxy::new(config, auth, policy)?;

    tracing::info!(allow_user = %args.allow_user, "pregresql-proxy starting");
    println!(
        "pregresql-proxy: clients authenticate as {:?} with password {:?} ({:?})",
        args.allow_user, allow_password, args.client_auth
    );
    if args.allow_all {
        println!("pregresql-proxy: ALL statements are allowed (--allow-all)");
    } else {
        println!(
            "pregresql-proxy: {} allowed statement(s); every other query is rejected",
            if args.allow_statement.is_empty() && args.allow_statement_file.is_empty() {
                "no".to_string()
            } else {
                "(see --allow-statement)".to_string()
            }
        );
    }

    tokio::select! {
        result = proxy.run() => result?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    Ok(())
}

fn upstream_tls(args: &Args) -> UpstreamTls {
    let options = TlsClientOptions {
        verify: if args.upstream_tls_no_verify {
            VerifyMode::None
        } else {
            VerifyMode::Full
        },
        ca_file: args.upstream_tls_ca.clone(),
        client_cert: match (
            &args.upstream_tls_client_cert,
            &args.upstream_tls_client_key,
        ) {
            (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
            _ => None,
        },
    };
    match args.upstream_tls {
        UpstreamTlsArg::Disable => UpstreamTls::Disable,
        UpstreamTlsArg::Prefer => UpstreamTls::Prefer(options),
        UpstreamTlsArg::Require => UpstreamTls::Require(options),
    }
}

fn random_password() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

// ---------------------------------------------------------------------------
// Authentication hook
// ---------------------------------------------------------------------------

struct DemoAuth {
    allow_user: String,
    allow_password: String,
    method: ClientAuthMethod,
    target: UpstreamTarget,
    decoy_password: String,
}

#[async_trait]
impl AuthHook for DemoAuth {
    fn client_auth_method(&self, _connection: &InboundConnection) -> ClientAuthMethod {
        self.method
    }

    fn password_for_user(&self, _connection: &InboundConnection, user: &str) -> Option<String> {
        if user == self.allow_user {
            Some(self.allow_password.clone())
        } else {
            // Not the allowed user: still answer a challenge so that the
            // failure is indistinguishable from a wrong password.
            Some(self.decoy_password.clone())
        }
    }

    async fn resolve_upstream(&self, ctx: AuthContext<'_>) -> Result<UpstreamTarget, AuthError> {
        if ctx.user != self.allow_user {
            return Err(AuthError::rejected(format!(
                "role {:?} is not allowed to connect through this proxy",
                ctx.user
            )));
        }
        if self.method != ClientAuthMethod::Trust && !ctx.verified {
            return Err(AuthError::invalid_password(
                "the client's credentials could not be verified",
            ));
        }
        if let Some(password) = ctx.password {
            if !constant_time_eq(password.as_bytes(), self.allow_password.as_bytes()) {
                return Err(AuthError::invalid_password(format!(
                    "password authentication failed for user {:?}",
                    ctx.user
                )));
            }
        }
        Ok(self.target.clone())
    }
}

// ---------------------------------------------------------------------------
// Query hook
// ---------------------------------------------------------------------------

struct DemoPolicy {
    statements: HashSet<String>,
    allow_all: bool,
    allow_simple_query: bool,
    allow_transaction_control: bool,
}

#[async_trait]
impl QueryHook for DemoPolicy {
    async fn authorize(&self, ctx: QueryContext<'_>) -> QueryDecision {
        if self.allow_all {
            return QueryDecision::Allow;
        }

        if ctx.kind == QueryKind::FunctionCall {
            return QueryDecision::deny(
                "the legacy function-call sub-protocol is not permitted by this proxy",
            );
        }

        if ctx.sql.is_empty() {
            // A Bind/Execute for a statement the proxy never authorised.
            return QueryDecision::deny_with(
                "26000",
                "prepared statement was not authorised by this proxy",
            );
        }

        if let Some(normalized) = normalize_sql(ctx.sql) {
            if self.statements.contains(&normalized) {
                return QueryDecision::Allow;
            }
        }

        if self.allow_transaction_control && is_transaction_control(ctx.sql) {
            return QueryDecision::Allow;
        }

        if self.allow_simple_query && ctx.kind == QueryKind::Simple {
            return QueryDecision::Allow;
        }

        QueryDecision::deny(format!(
            "statement is not in the proxy's allow-list ({}); this proxy only permits its \
             configured prepared statements",
            first_words(ctx.sql, 8)
        ))
    }
}

// ---------------------------------------------------------------------------
// Statement matching helpers
// ---------------------------------------------------------------------------

/// Trim, drop trailing semicolons and collapse whitespace runs.
fn normalize_sql(sql: &str) -> Option<String> {
    let trimmed = sql.trim().trim_end_matches(';').trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(trimmed.len());
    let mut previous_was_space = false;
    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            if !previous_was_space {
                out.push(' ');
            }
            previous_was_space = true;
        } else {
            out.push(ch);
            previous_was_space = false;
        }
    }
    Some(out.trim().to_string())
}

fn first_words(sql: &str, count: usize) -> String {
    sql.split_whitespace()
        .take(count)
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_identifier(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '"' || c == '$')
}

/// True when the *whole* statement is transaction control and nothing else.
fn is_transaction_control(sql: &str) -> bool {
    let tokens: Vec<String> = sql
        .split_whitespace()
        .map(|t| t.to_ascii_uppercase())
        .collect();
    let tokens: Vec<&str> = tokens.iter().map(String::as_str).collect();
    match tokens.as_slice() {
        [k] => matches!(*k, "BEGIN" | "COMMIT" | "END" | "ROLLBACK" | "ABORT"),
        [k, m] if matches!(*m, "WORK" | "TRANSACTION") => {
            matches!(*k, "BEGIN" | "COMMIT" | "END" | "ROLLBACK" | "START")
        }
        [k, name] if *k == "SAVEPOINT" || *k == "RELEASE" => is_identifier(name),
        [k, s, name] if *k == "RELEASE" && *s == "SAVEPOINT" => is_identifier(name),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation_is_stable() {
        assert_eq!(normalize_sql("  SELECT 1 ;  ").as_deref(), Some("SELECT 1"));
        assert_eq!(
            normalize_sql("SELECT\n  id\nFROM t\nWHERE id = $1").as_deref(),
            Some("SELECT id FROM t WHERE id = $1")
        );
        assert_eq!(normalize_sql("   ;  "), None);
    }

    #[test]
    fn transaction_control_is_narrow() {
        assert!(is_transaction_control("BEGIN"));
        assert!(is_transaction_control("begin transaction"));
        assert!(is_transaction_control("COMMIT"));
        assert!(is_transaction_control("savepoint sp1"));
        assert!(is_transaction_control("RELEASE SAVEPOINT sp1"));

        // Anything with a second statement must not qualify.
        assert!(!is_transaction_control("BEGIN; DROP TABLE t"));
        assert!(!is_transaction_control("COMMIT; SELECT 1"));
        assert!(!is_transaction_control("SAVEPOINT a; DROP TABLE t"));
        assert!(!is_transaction_control("SELECT 1"));
        assert!(!is_transaction_control("SET ROLE postgres"));
    }
}
