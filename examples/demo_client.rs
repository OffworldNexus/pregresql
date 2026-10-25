//! A demonstration client for the **locked-down** proxy.
//!
//! It shows the whole point of the crate: the `app` role has full SQL
//! privileges on `appdb`, yet when it connects through the proxy it can only
//! execute the prepared statements the proxy was configured with.
//!
//! `tokio-postgres` is used here purely as a *client*: it always drives the
//! extended query protocol (Parse/Bind/Execute/Sync), which is exactly what we
//! want to exercise. The library itself has no dependency on it.
//!
//! ```text
//! cargo run --example demo_client -- 16433
//! ```

use std::process::ExitCode;

use tokio_postgres::{Client, NoTls};

/// The one statement the proxy is configured to allow.
const ALLOWED: &str = "SELECT id, name FROM items WHERE id = $1";

/// A statement the proxy must reject, even though the role may run it.
const FORBIDDEN: &str = "SELECT id, name, secret FROM items WHERE id = $1";

struct Checks {
    failures: Vec<String>,
}

impl Checks {
    fn new() -> Self {
        Self {
            failures: Vec::new(),
        }
    }

    fn pass(&self, what: &str, detail: impl std::fmt::Display) {
        println!("  \x1b[32mPASS\x1b[0m {what}: {detail}");
    }

    fn fail(&mut self, what: &str, detail: impl std::fmt::Display) {
        println!("  \x1b[31mFAIL\x1b[0m {what}: {detail}");
        self.failures.push(format!("{what}: {detail}"));
    }

    fn expect_ok<T, E: std::fmt::Display>(
        &mut self,
        what: &str,
        result: Result<T, E>,
    ) -> Option<T> {
        match result {
            Ok(value) => {
                self.pass(what, "accepted, as expected");
                Some(value)
            }
            Err(e) => {
                self.fail(
                    what,
                    format!("was rejected but should have been accepted ({e})"),
                );
                None
            }
        }
    }

    fn expect_err<T, E: std::fmt::Display>(&mut self, what: &str, result: Result<T, E>) {
        match result {
            Ok(_) => self.fail(what, "was accepted but should have been rejected"),
            Err(e) => {
                let text = e.to_string().replace('\n', " | ");
                self.pass(what, format!("rejected: {text}"));
            }
        }
    }
}

async fn connect(port: u16) -> Result<Client, Box<dyn std::error::Error>> {
    let config = format!(
        "host=127.0.0.1 port={port} user=app password=hunter2 dbname=appdb \
         application_name=pregresql-demo connect_timeout=15"
    );
    let (client, connection) = tokio_postgres::connect(&config, NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {e}");
        }
    });
    Ok(client)
}

#[tokio::main]
async fn main() -> ExitCode {
    // 0 = upstream server, 1 = proxy port (defaults match docker-compose.yml).
    let upstream_port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(15432);
    let proxy_port: u16 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(16433);

    let mut checks = Checks::new();

    println!("\n=== 1. direct connection to the server (no proxy) ===");
    match connect(upstream_port).await {
        Ok(client) => {
            let rows = client
                .simple_query("SELECT id, name, secret FROM items ORDER BY id")
                .await;
            match rows {
                Ok(rows) => {
                    let rendered: Vec<String> = rows
                        .iter()
                        .filter_map(|row| match row {
                            tokio_postgres::SimpleQueryMessage::Row(r) => Some(format!(
                                "({}, {}, {})",
                                r.get(0).unwrap_or("?"),
                                r.get(1).unwrap_or("?"),
                                r.get(2).unwrap_or("?")
                            )),
                            _ => None,
                        })
                        .collect();
                    println!(
                        "  the role can read everything directly: {}",
                        rendered.join(" ")
                    );
                }
                Err(e) => println!("  direct query failed: {e}"),
            }
        }
        Err(e) => println!("  could not connect directly to 127.0.0.1:{upstream_port}: {e}"),
    }

    println!("\n=== 2. same role and password, but through the proxy ===");
    let client = match connect(proxy_port).await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("could not connect through the proxy on 127.0.0.1:{proxy_port}: {e}");
            return ExitCode::FAILURE;
        }
    };
    checks.pass("connect", format!("SCRAM login on port {proxy_port}"));

    // The allowed prepared statement, used exactly as a driver would.
    if let Some(statement) =
        checks.expect_ok("prepare(allow-listed)", client.prepare(ALLOWED).await)
    {
        if let Some(rows) =
            checks.expect_ok("execute($1 = 1)", client.query(&statement, &[&1i32]).await)
        {
            let rendered: Vec<String> = rows
                .iter()
                .map(|row| format!("({}, {})", row.get::<_, i32>(0), row.get::<_, String>(1)))
                .collect();
            println!("      rows: {}", rendered.join(" "));
            if rendered == ["(1, alpha)"] {
                checks.pass("result", "row 1 rendered as expected");
            } else {
                checks.fail("result", format!("unexpected rows: {rendered:?}"));
            }
        }
        checks.expect_ok("execute($1 = 2)", client.query(&statement, &[&2i32]).await);
    }

    // The proxy must refuse to even parse the statement the operator did not
    // allow, even though the role has the SQL privilege to run it.
    checks.expect_err("prepare(secret columns)", client.prepare(FORBIDDEN).await);

    // Nor may the client fall back to the simple protocol.
    checks.expect_err(
        "simple Query(SELECT 1)",
        client.simple_query("SELECT 1").await,
    );
    checks.expect_err(
        "simple Query(SELECT secret)",
        client.simple_query("SELECT secret FROM items").await,
    );

    // Transaction control is explicitly allowed by this proxy's configuration.
    checks.expect_ok("BEGIN", client.batch_execute("BEGIN").await);
    match client.prepare(ALLOWED).await {
        Ok(statement) => {
            checks.expect_ok(
                "execute inside the transaction",
                client.query(&statement, &[&1i32]).await,
            );
        }
        Err(e) => checks.fail("prepare inside the transaction", e),
    }
    checks.expect_ok("ROLLBACK", client.batch_execute("ROLLBACK").await);

    // The session must still be usable after all those rejections.
    match client.prepare(ALLOWED).await {
        Ok(statement) => {
            checks.expect_ok(
                "execute after recoveries",
                client.query(&statement, &[&1i32]).await,
            );
        }
        Err(e) => checks.fail("prepare after recoveries", e),
    }

    // A wrong password must not get in.
    let bad = format!(
        "host=127.0.0.1 port={proxy_port} user=app password=wrong dbname=appdb connect_timeout=15"
    );
    checks.expect_err(
        "connect with a wrong password",
        tokio_postgres::connect(&bad, NoTls).await,
    );

    // Neither may an unknown role.
    let unknown = format!(
        "host=127.0.0.1 port={proxy_port} user=root password=hunter2 dbname=appdb connect_timeout=15"
    );
    checks.expect_err(
        "connect as a foreign role",
        tokio_postgres::connect(&unknown, NoTls).await,
    );

    println!();
    if checks.failures.is_empty() {
        println!("\x1b[32mall demo expectations met\x1b[0m");
        ExitCode::SUCCESS
    } else {
        println!(
            "\x1b[31m{} demo expectation(s) not met\x1b[0m",
            checks.failures.len()
        );
        for failure in &checks.failures {
            println!("  - {failure}");
        }
        ExitCode::FAILURE
    }
}
