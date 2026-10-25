//! Per-connection proxy session: startup, authentication on both sides, and the
//! bidirectional relay with query-policy enforcement.
//!
//! The relay runs as two independent pumps (client→upstream and
//! upstream→client) so that neither direction can stall the other: a client
//! that keeps sending while the upstream is streaming a large result cannot
//! deadlock the connection.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex as AsyncMutex;

use crate::auth::{md5, scram, ScramClient, ScramServer};
use crate::error::{Error, Result};
use crate::protocol::codec::{decode_frame, encode_frame, Frame};
use crate::protocol::message::{
    error_response, fatal_response, parse_ready_for_query, ready_for_query, Authentication,
    BackendKeyData, BindMessage, CloseMessage, ErrorFields, NegotiateProtocolVersion,
    ParameterStatus, ParseMessage, PasswordResponse, QueryMessage, TransactionStatus,
};
use crate::protocol::startup::StartupParams;
use crate::proxy::cancel::{CancelRegistry, CancelTarget};
use crate::proxy::config::{Endpoint, UpstreamTls};
use crate::proxy::hooks::{
    AuthContext, ClientAuthMethod, InboundConnection, QueryContext, QueryDecision, QueryHook,
    QueryKind, TlsInfo, Transport, UpstreamTarget,
};
use crate::proxy::stream::{BoxedStream, RawStream};

/// SQLSTATE used when a query hook rejects a statement without naming one.
const DEFAULT_DENIED_SQLSTATE: &str = "42501";

/// Upper bound on the number of prepared statements and portals the proxy
/// tracks per session, so that a client cannot make the bookkeeping grow
/// without bound. Statements beyond the cap are still relayed; the proxy simply
/// stops remembering them, which makes a policy that relies on
/// [`QueryContext::statement_known`](crate::proxy::QueryContext::statement_known)
/// reject the corresponding `Bind`/`Execute`.
const MAX_TRACKED_OBJECTS: usize = 65_536;

/// A rejection the proxy generated, waiting for its place in the output stream.
#[derive(Debug)]
struct PendingRejection {
    frame: Frame,
    /// Value of [`OutputOrder::cycles_forwarded`] at the moment the rejection
    /// was generated. See [`OutputOrder`] for why this is the right anchor.
    after_cycles: u64,
}

/// Keeps proxy-generated messages in the right place in the client's output
/// stream.
///
/// A real backend processes the client's messages one at a time, so a rejection
/// it generates lands exactly between the responses to the messages the client
/// sent before it and the responses to the messages it sent afterwards. The
/// proxy answers rejections itself, so it has to place them in that same slot
/// even though the upstream server's responses are relayed by a separate pump.
///
/// The anchor is the number of *round trips* the client has started:
/// `Query`, `FunctionCall` and `Sync` each produce exactly one `ReadyForQuery`,
/// and every other message produces none. So a rejection generated while
/// `cycles_forwarded == n` has to be written to the client after the `n`-th
/// `ReadyForQuery` (if any) and before the `(n+1)`-th.
#[derive(Debug, Default)]
struct OutputOrder {
    cycles_forwarded: u64,
    rfqs_relayed: u64,
    pending: std::collections::VecDeque<PendingRejection>,
}

impl OutputOrder {
    /// Record that a client message producing one `ReadyForQuery` went upstream.
    fn note_cycle_forwarded(&mut self) {
        self.cycles_forwarded += 1;
    }

    /// Record the client message that *creates* a round trip (look at its tag).
    fn note_client_message(&mut self, tag: u8) {
        if matches!(tag, b'Q' | b'F' | b'S') {
            self.note_cycle_forwarded();
        }
    }

    /// Hold a rejection until its position in the stream is reached.
    fn queue(&mut self, frame: Frame) {
        self.pending.push_back(PendingRejection {
            frame,
            after_cycles: self.cycles_forwarded,
        });
    }

    /// Record that a `ReadyForQuery` has just been relayed.
    fn note_rfq_relayed(&mut self) {
        self.rfqs_relayed += 1;
    }

    /// Remove every rejection whose position has been reached.
    fn take_due(&mut self) -> Vec<Frame> {
        let mut due = Vec::new();
        while let Some(front) = self.pending.front() {
            if front.after_cycles > self.rfqs_relayed {
                break;
            }
            due.push(self.pending.pop_front().expect("front exists").frame);
        }
        due
    }
}

/// Relay state shared between the two pump directions.
#[derive(Debug, Default)]
struct Shared {
    /// Named prepared statements known to the proxy: name -> SQL.
    prepared: HashMap<String, String>,
    /// The unnamed prepared statement, when the client has parsed one.
    unnamed: Option<String>,
    /// Portals known to the proxy: portal name -> source statement name.
    portals: HashMap<String, String>,
    /// Transaction status reported by the most recent `ReadyForQuery`.
    txn: TransactionStatus,
    /// Set after the proxy rejected a message in the extended protocol: the
    /// client's messages are then dropped until the next `Sync`, exactly as a
    /// PostgreSQL backend discards them after an error.
    skip_until_sync: bool,
    /// Placement of proxy-generated rejections in the output stream.
    order: OutputOrder,
}

impl Shared {
    /// Take the rejections that are due to be written to the client.
    fn take_due_rejections(&mut self) -> Vec<Frame> {
        self.order.take_due()
    }
}

impl Shared {
    fn statement_sql(&self, name: &str) -> Option<&str> {
        if name.is_empty() {
            self.unnamed.as_deref()
        } else {
            self.prepared.get(name).map(String::as_str)
        }
    }

    fn remember_statement(&mut self, name: &str, sql: &str) {
        if name.is_empty() {
            self.unnamed = Some(sql.to_string());
        } else if self.prepared.len() < MAX_TRACKED_OBJECTS || self.prepared.contains_key(name) {
            self.prepared.insert(name.to_string(), sql.to_string());
        } else {
            tracing::debug!("not tracking prepared statement {name:?}: session limit reached");
        }
    }

    fn remember_portal(&mut self, portal: &str, statement: &str) {
        if self.portals.len() < MAX_TRACKED_OBJECTS || self.portals.contains_key(portal) {
            self.portals
                .insert(portal.to_string(), statement.to_string());
        } else {
            tracing::debug!("not tracking portal {portal:?}: session limit reached");
        }
    }
}

/// Static context for the client-side pump.
struct ClientPump {
    connection_id: u64,
    user: String,
    upstream_user: String,
    hook: Arc<dyn QueryHook>,
}

/// What the client-side pump should do with one message.
enum ClientAction {
    /// Pass the message through unchanged.
    Forward(Frame),
    /// Pass the message through and then end the relay (client said goodbye).
    ForwardAndStop(Frame),
    /// Send these synthesized messages to the client and drop the original.
    Reply(Vec<Frame>),
    /// Hold this synthesized message back and deliver it together with the next
    /// message relayed from the upstream server.
    Queue(Frame),
    /// Drop the message.
    Drop,
}

/// The identity the client proved during authentication.
struct ClientIdentity {
    verified: bool,
    password: Option<String>,
}

impl ClientIdentity {
    /// Nothing was proven.
    fn trusted() -> Self {
        Self {
            verified: false,
            password: None,
        }
    }

    /// The proxy verified the client's proof against its expected password.
    fn verified(password: String) -> Self {
        Self {
            verified: true,
            password: Some(password),
        }
    }

    /// The client sent a password the proxy had nothing to compare it with.
    fn unverified_password(password: String) -> Self {
        Self {
            verified: false,
            password: Some(password),
        }
    }

    /// The client proved knowledge of a password the proxy cannot check.
    fn unverifiable() -> Self {
        Self {
            verified: false,
            password: None,
        }
    }
}

/// Messages buffered while the upstream completes its startup.
struct Pending {
    parameter_frames: Vec<Frame>,
    status: TransactionStatus,
    upstream_pid: i32,
    upstream_secret: i32,
}

/// Setup state and long-lived resources for one proxied connection.
pub struct Session {
    /// Connection number, unique within the process.
    pub id: u64,
    /// Socket towards the client.
    pub client: BoxedStream,
    /// Bytes read from the client but not yet consumed.
    pub client_buf: BytesMut,
    /// The client's startup parameters.
    pub startup: StartupParams,
    /// Where the client connected from.
    pub transport: Transport,
    /// TLS properties of the inbound connection.
    pub tls: TlsInfo,
    /// The authentication hook.
    pub auth: Arc<dyn crate::proxy::hooks::AuthHook>,
    /// The query hook.
    pub query: Arc<dyn QueryHook>,
    /// Cancellation registry shared by the whole proxy.
    pub cancels: Arc<CancelRegistry>,
    /// Largest message this connection accepts.
    pub max_message_length: usize,
    /// Backend key handed to the client.
    pub our_pid: i32,
    /// Backend secret handed to the client.
    pub our_secret: i32,
    /// Bytes read from the upstream server but not yet consumed.
    upstream_buf: BytesMut,
    /// The upstream socket, once connected.
    upstream: Option<BoxedStream>,
    /// SCRAM state while authenticating to the upstream server.
    scram: Option<Box<ScramClient>>,
    /// The role the proxy uses towards the upstream server.
    upstream_user: String,
}

impl Session {
    /// Create a session from an accepted connection and a parsed startup packet.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        client: BoxedStream,
        client_buf: BytesMut,
        startup: StartupParams,
        transport: Transport,
        tls: TlsInfo,
        auth: Arc<dyn crate::proxy::hooks::AuthHook>,
        query: Arc<dyn QueryHook>,
        cancels: Arc<CancelRegistry>,
        max_message_length: usize,
        our_pid: i32,
        our_secret: i32,
    ) -> Self {
        Self {
            id,
            client,
            client_buf,
            startup,
            transport,
            tls,
            auth,
            query,
            cancels,
            max_message_length,
            our_pid,
            our_secret,
            upstream_buf: BytesMut::with_capacity(16 * 1024),
            upstream: None,
            scram: None,
            upstream_user: String::new(),
        }
    }

    /// Run the session to completion, always clearing the cancel registration.
    pub async fn run(mut self) -> Result<()> {
        let outcome = match self.setup().await {
            Ok(()) => self.relay().await,
            Err(e) => Err(e),
        };
        self.cancels.unregister(self.our_pid, self.our_secret);
        outcome
    }

    // -- setup ---------------------------------------------------------------

    async fn setup(&mut self) -> Result<()> {
        // 1. Protocol version negotiation: the backend answers a minor version
        //    it does not implement, and lists unknown `_pq_.` options.
        let minor = self.startup.minor_version();
        let unknown: Vec<String> = self
            .startup
            .unrecognized_options()
            .into_iter()
            .map(str::to_string)
            .collect();
        if minor > 0 || !unknown.is_empty() {
            let negotiate = NegotiateProtocolVersion {
                newest_minor: 0,
                unrecognized_options: unknown,
            };
            self.write_client(negotiate.to_frame()).await?;
        }

        // 2. Authenticate the client against the proxy.
        let method = self.auth.client_auth_method(&self.inbound());
        let identity = self.authenticate_client(method).await?;

        // 3. Ask the hook where this session should go.
        let user = self.user().to_string();
        let inbound = self.inbound();
        let ctx = AuthContext {
            connection: &inbound,
            user: &user,
            method,
            verified: identity.verified,
            password: identity.password.as_deref(),
        };
        let target = match self.auth.resolve_upstream(ctx).await {
            Ok(target) => target,
            Err(e) => {
                self.write_client(fatal_response(&e.sqlstate, &e.message))
                    .await?;
                return Err(Error::auth(e.message));
            }
        };
        tracing::debug!(
            connection = self.id,
            user = %user,
            upstream_user = %target.user,
            "resolved upstream target"
        );
        self.upstream_user = target.user.clone();

        // 4. Connect and authenticate to the upstream server.
        let pending = match self.connect_upstream(&target).await {
            Ok(pending) => pending,
            Err(e) => {
                self.write_client(fatal_response(
                    "08006",
                    format!("proxy could not establish the upstream session: {e}"),
                ))
                .await?;
                return Err(e);
            }
        };

        // 5. Hand the client the upstream's session parameters, our own
        //    cancellation key, and the freshly-observed transaction status.
        for frame in pending.parameter_frames {
            self.write_client(frame).await?;
        }
        self.write_client(
            BackendKeyData {
                pid: self.our_pid,
                secret: self.our_secret,
            }
            .to_frame(),
        )
        .await?;
        self.write_client(ready_for_query(pending.status)).await?;

        // 6. Remember how to cancel this session.
        self.cancels.register(
            self.our_pid,
            self.our_secret,
            CancelTarget {
                endpoint: target.endpoint.clone(),
                tls: target.tls.clone(),
                pid: pending.upstream_pid,
                secret: pending.upstream_secret,
            },
        );

        Ok(())
    }

    fn inbound(&self) -> InboundConnection {
        InboundConnection {
            id: self.id,
            transport: self.transport.clone(),
            tls: self.tls.clone(),
            protocol_version: self.startup.version,
            params: self.startup.params.clone(),
        }
    }

    fn user(&self) -> &str {
        self.startup.user().unwrap_or_default()
    }

    async fn write_client(&mut self, frame: Frame) -> Result<()> {
        self.client.write_all(&frame.encode()).await?;
        self.client.flush().await?;
        Ok(())
    }

    async fn read_client_frame(&mut self) -> Result<Frame> {
        loop {
            let decoded = { decode_frame(&mut self.client_buf, self.max_message_length)? };
            if let Some(frame) = decoded {
                return Ok(frame);
            }
            self.client_buf.reserve(16 * 1024);
            let n = self.client.read_buf(&mut self.client_buf).await?;
            if n == 0 {
                return Err(Error::ConnectionClosed);
            }
        }
    }

    async fn read_upstream_frame(&mut self) -> Result<Frame> {
        let max = self.max_message_length;
        let buf = &mut self.upstream_buf;
        let upstream = self
            .upstream
            .as_mut()
            .ok_or_else(|| Error::other("upstream is not connected"))?;
        loop {
            let decoded = { decode_frame(buf, max)? };
            if let Some(frame) = decoded {
                return Ok(frame);
            }
            buf.reserve(16 * 1024);
            let n = upstream.read_buf(buf).await?;
            if n == 0 {
                return Err(Error::ConnectionClosed);
            }
        }
    }

    async fn reject<T>(&mut self, sqlstate: &str, message: &str) -> Result<T> {
        self.write_client(fatal_response(sqlstate, message)).await?;
        Err(Error::auth(message.to_string()))
    }

    async fn authenticate_client(&mut self, method: ClientAuthMethod) -> Result<ClientIdentity> {
        let user = self.user().to_string();
        let inbound = self.inbound();
        let expected = self.auth.password_for_user(&inbound, &user);

        match method {
            ClientAuthMethod::Trust => {
                self.write_client(Authentication::Ok.to_frame()).await?;
                Ok(ClientIdentity::trusted())
            }

            ClientAuthMethod::Cleartext => {
                self.write_client(Authentication::CleartextPassword.to_frame())
                    .await?;
                let frame = self.read_client_frame().await?;
                if frame.tag != b'p' {
                    return self
                        .reject("08P01", "expected a password message during authentication")
                        .await;
                }
                let password = PasswordResponse::parse_password(&frame.body)?;
                let identity = match &expected {
                    Some(expect) => {
                        if !md5::constant_time_eq(expect.as_bytes(), password.as_bytes()) {
                            return self
                                .reject(
                                    "28P01",
                                    &format!("password authentication failed for user {user:?}"),
                                )
                                .await;
                        }
                        ClientIdentity::verified(expect.clone())
                    }
                    None => ClientIdentity::unverified_password(password),
                };
                self.write_client(Authentication::Ok.to_frame()).await?;
                Ok(identity)
            }

            ClientAuthMethod::Md5 => {
                let mut salt = [0u8; 4];
                rand::thread_rng().fill(&mut salt);
                self.write_client(Authentication::Md5Password(salt).to_frame())
                    .await?;
                let frame = self.read_client_frame().await?;
                if frame.tag != b'p' {
                    return self
                        .reject("08P01", "expected a password message during authentication")
                        .await;
                }
                let response = PasswordResponse::parse_password(&frame.body)?;
                let identity = match &expected {
                    Some(expect) => {
                        if !md5::verify_md5_response(&user, expect, &salt, &response) {
                            return self
                                .reject(
                                    "28P01",
                                    &format!("password authentication failed for user {user:?}"),
                                )
                                .await;
                        }
                        ClientIdentity::verified(expect.clone())
                    }
                    None => ClientIdentity::unverifiable(),
                };
                self.write_client(Authentication::Ok.to_frame()).await?;
                Ok(identity)
            }

            ClientAuthMethod::ScramSha256 => self.authenticate_client_scram(&user, expected).await,
        }
    }

    async fn authenticate_client_scram(
        &mut self,
        user: &str,
        expected: Option<String>,
    ) -> Result<ClientIdentity> {
        let Some(password) = expected else {
            return self
                .reject(
                    "28000",
                    "SCRAM authentication requires the auth hook to supply the expected password \
                     (AuthHook::password_for_user returned None)",
                )
                .await;
        };

        self.write_client(Authentication::Sasl(vec![scram::SCRAM_SHA_256.to_string()]).to_frame())
            .await?;

        let first = self.read_client_frame().await?;
        if first.tag != b'p' {
            return self
                .reject("08P01", "expected a SASL initial response")
                .await;
        }
        let (mechanism, data) = match PasswordResponse::parse_sasl_initial(&first.body)? {
            PasswordResponse::SaslInitial { mechanism, data } => (mechanism, data),
            _ => unreachable!("parse_sasl_initial always builds SaslInitial"),
        };
        if mechanism != scram::SCRAM_SHA_256 {
            return self
                .reject(
                    "28000",
                    &format!("unsupported SASL mechanism {mechanism:?}"),
                )
                .await;
        }
        let data = data.ok_or_else(|| Error::protocol("missing SASL initial response payload"))?;
        let client_first = std::str::from_utf8(&data)
            .map_err(|e| Error::protocol(format!("invalid SCRAM client-first-message: {e}")))?;

        let server = ScramServer::start(
            client_first,
            ScramServer::random_salt(),
            scram::DEFAULT_ITERATIONS,
            scram::server_nonce(),
        )?;
        self.write_client(
            Authentication::SaslContinue(Bytes::from(server.server_first_message())).to_frame(),
        )
        .await?;

        let second = self.read_client_frame().await?;
        if second.tag != b'p' {
            return self.reject("08P01", "expected a SASL response").await;
        }
        let client_final = std::str::from_utf8(&second.body)
            .map_err(|e| Error::protocol(format!("invalid SCRAM client-final-message: {e}")))?;
        let server_final = match server.verify_client_final(client_final, &password) {
            Ok(final_message) => final_message,
            Err(_) => {
                return self
                    .reject(
                        "28P01",
                        &format!("password authentication failed for user {user:?}"),
                    )
                    .await
            }
        };
        self.write_client(Authentication::SaslFinal(Bytes::from(server_final)).to_frame())
            .await?;
        self.write_client(Authentication::Ok.to_frame()).await?;
        Ok(ClientIdentity::verified(password))
    }

    // -- upstream ------------------------------------------------------------

    async fn connect_upstream(&mut self, target: &UpstreamTarget) -> Result<Pending> {
        let stream = RawStream::connect(&target.endpoint).await?;
        let host = match &target.endpoint {
            Endpoint::Tcp { host, .. } => host.clone(),
            Endpoint::Unix { .. } => "localhost".to_string(),
        };

        let upstream: BoxedStream = match &target.tls {
            UpstreamTls::Disable => Box::new(stream),
            UpstreamTls::Prefer(options) => {
                let mut stream = stream;
                if stream.ssl_request().await? {
                    stream.start_tls_client(&host, options).await?
                } else {
                    Box::new(stream)
                }
            }
            UpstreamTls::Require(options) => {
                let mut stream = stream;
                if !stream.ssl_request().await? {
                    return Err(Error::tls(
                        "upstream server does not support TLS but TLS was required",
                    ));
                }
                stream.start_tls_client(&host, options).await?
            }
        };
        self.upstream = Some(upstream);

        let startup = self.build_upstream_startup(target);
        self.write_upstream(&startup.to_bytes()).await?;
        self.authenticate_upstream(target).await?;
        self.collect_startup_complete().await
    }

    fn build_upstream_startup(&self, target: &UpstreamTarget) -> StartupParams {
        let mut params: Vec<(String, String)> = Vec::new();
        params.push(("user".to_string(), target.user.clone()));

        let database = target
            .database
            .clone()
            .or_else(|| self.startup.database().map(str::to_string))
            .unwrap_or_else(|| target.user.clone());
        params.push(("database".to_string(), database));

        for (key, value) in &self.startup.params {
            if key == "user" || key == "database" || key.starts_with("_pq_.") {
                continue;
            }
            if params.iter().any(|(k, _)| k == key) {
                continue;
            }
            params.push((key.clone(), value.clone()));
        }

        // Hook-supplied overrides win over anything the client asked for.
        for (key, value) in &target.params {
            match params.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = value.clone(),
                None => params.push((key.clone(), value.clone())),
            }
        }

        StartupParams::new(params)
    }

    async fn write_upstream(&mut self, bytes: &[u8]) -> Result<()> {
        let upstream = self
            .upstream
            .as_mut()
            .ok_or_else(|| Error::other("upstream is not connected"))?;
        upstream.write_all(bytes).await?;
        upstream.flush().await?;
        Ok(())
    }

    async fn authenticate_upstream(&mut self, target: &UpstreamTarget) -> Result<()> {
        loop {
            let frame = self.read_upstream_frame().await?;
            match frame.tag {
                b'R' => match Authentication::parse(&frame.body)? {
                    Authentication::Ok => return Ok(()),
                    Authentication::CleartextPassword => {
                        let password = target.password.as_deref().ok_or_else(|| {
                            Error::auth(
                                "upstream requested a cleartext password but none is configured",
                            )
                        })?;
                        let response = PasswordResponse::password_frame(password);
                        self.write_upstream(&response.encode()).await?;
                    }
                    Authentication::Md5Password(salt) => {
                        let password = target.password.as_deref().ok_or_else(|| {
                            Error::auth("upstream requested an MD5 password but none is configured")
                        })?;
                        let digest = md5::md5_password_response(&target.user, password, &salt);
                        let response = PasswordResponse::password_frame(&digest);
                        self.write_upstream(&response.encode()).await?;
                    }
                    Authentication::Sasl(mechanisms) => {
                        if !mechanisms.iter().any(|m| m == scram::SCRAM_SHA_256) {
                            return Err(Error::auth(format!(
                                "upstream offered unsupported SASL mechanisms: {mechanisms:?}"
                            )));
                        }
                        let client = ScramClient::new();
                        let first = client.client_first_message();
                        let response = PasswordResponse::sasl_initial_frame(
                            scram::SCRAM_SHA_256,
                            first.as_bytes(),
                        );
                        self.write_upstream(&response.encode()).await?;
                        self.scram = Some(Box::new(client));
                    }
                    Authentication::SaslContinue(data) => {
                        let password = target.password.as_deref().ok_or_else(|| {
                            Error::auth("upstream requested SCRAM but no password is configured")
                        })?;
                        let client = self
                            .scram
                            .as_mut()
                            .ok_or_else(|| Error::protocol("unexpected SASL continue message"))?;
                        let message = std::str::from_utf8(&data).map_err(|e| {
                            Error::protocol(format!("invalid SCRAM server-first-message: {e}"))
                        })?;
                        client.handle_server_first(message, password)?;
                        let final_message = client.client_final_message(None);
                        let response =
                            PasswordResponse::sasl_response_frame(final_message.as_bytes());
                        self.write_upstream(&response.encode()).await?;
                    }
                    Authentication::SaslFinal(data) => {
                        let client = self
                            .scram
                            .as_mut()
                            .ok_or_else(|| Error::protocol("unexpected SASL final message"))?;
                        let message = std::str::from_utf8(&data).map_err(|e| {
                            Error::protocol(format!("invalid SCRAM server-final-message: {e}"))
                        })?;
                        client.verify_server_final(message)?;
                    }
                    other => {
                        return Err(Error::auth(format!(
                            "upstream requested an unsupported authentication method: {other:?}"
                        )))
                    }
                },
                b'E' => {
                    let fields = ErrorFields::parse(&frame.body)?;
                    return Err(Error::auth(format!(
                        "upstream rejected the connection: {}",
                        fields.message().unwrap_or("unknown error")
                    )));
                }
                b'N' => {}
                other => {
                    return Err(Error::protocol(format!(
                        "unexpected message '{}' during upstream authentication",
                        other as char
                    )));
                }
            }
        }
    }

    async fn collect_startup_complete(&mut self) -> Result<Pending> {
        let mut parameter_frames = Vec::new();
        let mut upstream_pid = 0;
        let mut upstream_secret = 0;
        loop {
            let frame = self.read_upstream_frame().await?;
            match frame.tag {
                b'S' => {
                    ParameterStatus::parse(&frame.body)?;
                    parameter_frames.push(frame);
                }
                b'N' | b'v' => parameter_frames.push(frame),
                b'K' => {
                    let key = BackendKeyData::parse(&frame.body)?;
                    upstream_pid = key.pid;
                    upstream_secret = key.secret;
                }
                b'Z' => {
                    let status = parse_ready_for_query(&frame.body)?;
                    return Ok(Pending {
                        parameter_frames,
                        status,
                        upstream_pid,
                        upstream_secret,
                    });
                }
                b'E' => {
                    let fields = ErrorFields::parse(&frame.body)?;
                    return Err(Error::auth(format!(
                        "upstream refused the session: {}",
                        fields.message().unwrap_or("unknown error")
                    )));
                }
                other => {
                    return Err(Error::protocol(format!(
                        "unexpected message '{}' while completing the upstream startup",
                        other as char
                    )));
                }
            }
        }
    }

    // -- relay ---------------------------------------------------------------

    async fn relay(&mut self) -> Result<()> {
        let client = std::mem::replace(&mut self.client, Box::new(tokio::io::empty()));
        let upstream = self
            .upstream
            .take()
            .ok_or_else(|| Error::other("upstream is not connected"))?;

        let (client_rd, client_wr) = tokio::io::split(client);
        let (up_rd, up_wr) = tokio::io::split(upstream);
        let client_wr = Arc::new(AsyncMutex::new(client_wr));
        let up_wr = Arc::new(AsyncMutex::new(up_wr));

        let shared = Arc::new(Mutex::new(Shared::default()));
        let max_len = self.max_message_length;
        let pump = ClientPump {
            connection_id: self.id,
            user: self.user().to_string(),
            upstream_user: self.upstream_user.clone(),
            hook: self.query.clone(),
        };

        let mut client_buf = std::mem::take(&mut self.client_buf);
        let mut upstream_buf = std::mem::take(&mut self.upstream_buf);

        let outcome = tokio::select! {
            r = pump_client(
                client_rd,
                &mut client_buf,
                Arc::clone(&client_wr),
                Arc::clone(&up_wr),
                Arc::clone(&shared),
                pump,
                max_len,
            ) => r,
            r = pump_upstream(
                up_rd,
                &mut upstream_buf,
                Arc::clone(&client_wr),
                Arc::clone(&shared),
                max_len,
            ) => r,
        };

        // Best effort: tell the backend to roll back rather than wait for us.
        let terminate = encode_frame(b'X', &[]);
        {
            let mut writer = up_wr.lock().await;
            let _ = writer.write_all(&terminate).await;
            let _ = writer.flush().await;
        }

        match &outcome {
            Ok(()) => tracing::debug!(connection = self.id, "connection finished"),
            Err(e) => tracing::debug!(connection = self.id, error = %e, "connection ended"),
        }
        outcome
    }
}

/// Read one complete protocol message, blocking until it arrives.
async fn next_frame(
    rd: &mut ReadHalf<BoxedStream>,
    buf: &mut BytesMut,
    max_len: usize,
) -> Result<Frame> {
    loop {
        let decoded = { decode_frame(buf, max_len)? };
        if let Some(frame) = decoded {
            return Ok(frame);
        }
        buf.reserve(16 * 1024);
        let n = rd.read_buf(buf).await?;
        if n == 0 {
            return Err(Error::ConnectionClosed);
        }
    }
}

/// Forward client messages to the upstream server, applying query policy.
async fn pump_client(
    mut rd: ReadHalf<BoxedStream>,
    buf: &mut BytesMut,
    client_wr: Arc<AsyncMutex<WriteHalf<BoxedStream>>>,
    up_wr: Arc<AsyncMutex<WriteHalf<BoxedStream>>>,
    shared: Arc<Mutex<Shared>>,
    ctx: ClientPump,
    max_len: usize,
) -> Result<()> {
    loop {
        let frame = match next_frame(&mut rd, buf, max_len).await {
            Ok(frame) => frame,
            Err(Error::ConnectionClosed) => return Ok(()),
            Err(e) => return Err(e),
        };

        let action = decide_client_frame(frame, &shared, &ctx).await?;
        match action {
            ClientAction::Forward(frame) => {
                if let Ok(mut state) = shared.lock() {
                    state.order.note_client_message(frame.tag);
                }
                let encoded = frame.encode();
                let mut writer = up_wr.lock().await;
                writer.write_all(&encoded).await?;
                writer.flush().await?;
            }
            ClientAction::ForwardAndStop(frame) => {
                if let Ok(mut state) = shared.lock() {
                    state.order.note_client_message(frame.tag);
                }
                let encoded = frame.encode();
                let mut writer = up_wr.lock().await;
                writer.write_all(&encoded).await?;
                writer.flush().await?;
                return Ok(());
            }
            ClientAction::Reply(frames) => {
                let mut writer = client_wr.lock().await;
                for frame in frames {
                    writer.write_all(&frame.encode()).await?;
                }
                writer.flush().await?;
            }
            ClientAction::Queue(frame) => {
                if let Ok(mut state) = shared.lock() {
                    state.order.queue(frame);
                }
            }
            ClientAction::Drop => {}
        }

        // A rejection queued by this iteration may already be due (a plain
        // simple-protocol or function-call rejection never has to wait).
        let due = shared
            .lock()
            .map(|mut state| state.take_due_rejections())
            .unwrap_or_default();
        if !due.is_empty() {
            let mut writer = client_wr.lock().await;
            for frame in due {
                writer.write_all(&frame.encode()).await?;
            }
            writer.flush().await?;
        }
    }
}

/// Forward upstream messages to the client, tracking the transaction status.
async fn pump_upstream(
    mut rd: ReadHalf<BoxedStream>,
    buf: &mut BytesMut,
    client_wr: Arc<AsyncMutex<WriteHalf<BoxedStream>>>,
    shared: Arc<Mutex<Shared>>,
    max_len: usize,
) -> Result<()> {
    loop {
        let frame = match next_frame(&mut rd, buf, max_len).await {
            Ok(frame) => frame,
            Err(Error::ConnectionClosed) => return Ok(()),
            Err(e) => return Err(e),
        };

        if frame.tag == b'Z' {
            if let Ok(status) = parse_ready_for_query(&frame.body) {
                if let Ok(mut state) = shared.lock() {
                    state.txn = status;
                }
            }
        }

        // A queued rejection whose position has been reached goes out before
        // this message, in the same flush, exactly as a backend would write an
        // error it had already buffered.
        let before = shared
            .lock()
            .map(|mut state| state.take_due_rejections())
            .unwrap_or_default();

        let mut out = BytesMut::new();
        for frame in &before {
            out.extend_from_slice(&frame.encode());
        }
        out.extend_from_slice(&frame.encode());
        {
            let mut writer = client_wr.lock().await;
            writer.write_all(&out).await?;
            writer.flush().await?;
        }

        // A rejection may only become due *after* the `ReadyForQuery` that
        // closes the round trip it belongs to.
        if frame.tag == b'Z' {
            let after = shared
                .lock()
                .map(|mut state| {
                    state.order.note_rfq_relayed();
                    state.take_due_rejections()
                })
                .unwrap_or_default();
            if !after.is_empty() {
                let mut writer = client_wr.lock().await;
                for frame in after {
                    writer.write_all(&frame.encode()).await?;
                }
                writer.flush().await?;
            }
        }
    }
}

/// Decide what to do with one client message.
async fn decide_client_frame(
    frame: Frame,
    shared: &Arc<Mutex<Shared>>,
    ctx: &ClientPump,
) -> Result<ClientAction> {
    // `Terminate` is always honoured, even while skipping.
    if frame.tag == b'X' {
        if let Ok(mut state) = shared.lock() {
            state.skip_until_sync = false;
        }
        return Ok(ClientAction::ForwardAndStop(frame));
    }

    // While recovering from a rejected extended-protocol message, everything
    // except `Sync` is discarded, exactly as a PostgreSQL backend does.
    let skipping = shared.lock().map(|s| s.skip_until_sync).unwrap_or(false);
    if skipping {
        match frame.tag {
            b'S' => {
                if let Ok(mut state) = shared.lock() {
                    state.skip_until_sync = false;
                }
                // The `ReadyForQuery` this produces is what carries our
                // buffered rejection out to the client.
                return Ok(ClientAction::Forward(frame));
            }
            b'H' => {
                // A backend discards `Flush` while skipping, but it also flushes
                // whatever is already in its output buffer before blocking for
                // more input, so any rejection that is due goes out now.
                let due = shared
                    .lock()
                    .map(|mut state| state.take_due_rejections())
                    .unwrap_or_default();
                if due.is_empty() {
                    return Ok(ClientAction::Drop);
                }
                return Ok(ClientAction::Reply(due));
            }
            _ => return Ok(ClientAction::Drop),
        }
    }

    match frame.tag {
        b'Q' => {
            let message = QueryMessage::parse(&frame.body)?;
            if let Ok(mut state) = shared.lock() {
                // A simple Query destroys the unnamed statement and portal.
                state.unnamed = None;
                state.portals.clear();
            }
            let decision = authorize(
                ctx,
                shared,
                QueryKind::Simple,
                &message.sql,
                None,
                None,
                true,
                None,
            )
            .await;
            match decision {
                QueryDecision::Allow => Ok(ClientAction::Forward(frame)),
                QueryDecision::Rewrite(sql) => {
                    Ok(ClientAction::Forward(QueryMessage { sql }.to_frame()))
                }
                QueryDecision::Deny { sqlstate, message } => {
                    let status = current_status(shared);
                    queue_messages(
                        shared,
                        [
                            error_response(
                                sqlstate.as_deref().unwrap_or(DEFAULT_DENIED_SQLSTATE),
                                message,
                            ),
                            ready_for_query(status),
                        ],
                    );
                    Ok(ClientAction::Drop)
                }
            }
        }

        b'P' => {
            let message = ParseMessage::parse(&frame.body)?;
            let decision = authorize(
                ctx,
                shared,
                QueryKind::Parse,
                &message.sql,
                Some(&message.name),
                None,
                true,
                None,
            )
            .await;
            match decision {
                QueryDecision::Allow => {
                    if let Ok(mut state) = shared.lock() {
                        state.remember_statement(&message.name, &message.sql);
                    }
                    Ok(ClientAction::Forward(frame))
                }
                QueryDecision::Rewrite(sql) => {
                    if let Ok(mut state) = shared.lock() {
                        state.remember_statement(&message.name, &sql);
                    }
                    Ok(ClientAction::Forward(
                        ParseMessage {
                            name: message.name,
                            sql,
                            param_types: message.param_types,
                        }
                        .to_frame(),
                    ))
                }
                QueryDecision::Deny {
                    sqlstate,
                    message: reason,
                } => reject_extended(shared, sqlstate, reason),
            }
        }

        b'B' => {
            let message = BindMessage::parse(&frame.body)?;
            let known_sql = shared
                .lock()
                .ok()
                .and_then(|state| state.statement_sql(&message.statement).map(str::to_string));
            let known = known_sql.is_some();
            let sql = known_sql.unwrap_or_default();
            let decision = authorize(
                ctx,
                shared,
                QueryKind::Bind,
                &sql,
                Some(&message.statement),
                Some(&message.portal),
                known,
                Some(&message.params),
            )
            .await;
            match decision {
                QueryDecision::Allow => {
                    if let Ok(mut state) = shared.lock() {
                        state.remember_portal(&message.portal, &message.statement);
                    }
                    Ok(ClientAction::Forward(frame))
                }
                QueryDecision::Rewrite(_) => reject_extended(
                    shared,
                    None,
                    "proxy policy returned Rewrite for a Bind message".to_string(),
                ),
                QueryDecision::Deny {
                    sqlstate,
                    message: reason,
                } => reject_extended(shared, sqlstate, reason),
            }
        }

        b'C' => {
            let message = CloseMessage::parse(&frame.body)?;
            if let Ok(mut state) = shared.lock() {
                match message.kind {
                    b'S' => {
                        if message.name.is_empty() {
                            state.unnamed = None;
                        } else {
                            state.prepared.remove(&message.name);
                        }
                    }
                    b'P' => {
                        state.portals.remove(&message.name);
                    }
                    _ => {}
                }
            }
            Ok(ClientAction::Forward(frame))
        }

        b'F' => {
            // Legacy function-call sub-protocol: an unnamed RPC. Policies get a
            // chance to reject it, but cannot inspect it.
            let decision = authorize(
                ctx,
                shared,
                QueryKind::FunctionCall,
                "",
                None,
                None,
                false,
                None,
            )
            .await;
            match decision {
                QueryDecision::Allow => Ok(ClientAction::Forward(frame)),
                QueryDecision::Deny { sqlstate, message } => {
                    let status = current_status(shared);
                    queue_messages(
                        shared,
                        [
                            error_response(
                                sqlstate.as_deref().unwrap_or(DEFAULT_DENIED_SQLSTATE),
                                message,
                            ),
                            ready_for_query(status),
                        ],
                    );
                    Ok(ClientAction::Drop)
                }
                QueryDecision::Rewrite(_) => {
                    let status = current_status(shared);
                    queue_messages(
                        shared,
                        [
                            error_response(
                                DEFAULT_DENIED_SQLSTATE,
                                "proxy policy rewrote a FunctionCall message",
                            ),
                            ready_for_query(status),
                        ],
                    );
                    Ok(ClientAction::Drop)
                }
            }
        }

        // Flush, Sync, Describe, Execute, COPY data and anything unknown are
        // relayed verbatim.
        _ => Ok(ClientAction::Forward(frame)),
    }
}

fn current_status(shared: &Arc<Mutex<Shared>>) -> TransactionStatus {
    shared
        .lock()
        .map(|state| state.txn)
        .unwrap_or(TransactionStatus::Idle)
}

/// Queue synthesized messages so that they are written to the client in the
/// position a real backend would have written them.
fn queue_messages(shared: &Arc<Mutex<Shared>>, frames: impl IntoIterator<Item = Frame>) {
    if let Ok(mut state) = shared.lock() {
        for frame in frames {
            state.order.queue(frame);
        }
    }
}

/// Build a rejection for a message inside an extended-protocol cycle.
///
/// The proxy answers with an `ErrorResponse` and then drops the client's
/// messages until the next `Sync`, which mirrors how a backend recovers from an
/// error. The response itself is queued (see [`OutputOrder`]) so that it is
/// delivered in the position a backend would have delivered it.
///
/// See the README for the one behavioural difference: the transaction is *not*
/// marked as failed.
fn reject_extended(
    shared: &Arc<Mutex<Shared>>,
    sqlstate: Option<String>,
    message: String,
) -> Result<ClientAction> {
    if let Ok(mut state) = shared.lock() {
        state.skip_until_sync = true;
    }
    Ok(ClientAction::Queue(error_response(
        sqlstate.as_deref().unwrap_or(DEFAULT_DENIED_SQLSTATE),
        message,
    )))
}

/// Consult the query hook.
#[allow(clippy::too_many_arguments)]
async fn authorize(
    ctx: &ClientPump,
    shared: &Arc<Mutex<Shared>>,
    kind: QueryKind,
    sql: &str,
    statement_name: Option<&str>,
    portal_name: Option<&str>,
    statement_known: bool,
    parameters: Option<&[Option<Bytes>]>,
) -> QueryDecision {
    let transaction_status = current_status(shared);
    let query_ctx = QueryContext {
        connection_id: ctx.connection_id,
        user: &ctx.user,
        upstream_user: &ctx.upstream_user,
        transaction_status,
        kind,
        sql,
        statement_name,
        portal_name,
        statement_known,
        parameters,
    };
    ctx.hook.authorize(query_ctx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::TransactionStatus;

    fn error(tag: u8) -> Frame {
        error_response("42501", format!("rejected {tag}"))
    }

    fn tag_of(frame: &Frame) -> u8 {
        frame.tag
    }

    #[test]
    fn rejection_with_no_pending_round_trip_is_immediate() {
        let mut order = OutputOrder::default();
        order.queue(error(b'A'));
        let due = order.take_due();
        assert_eq!(due.len(), 1);
        assert_eq!(tag_of(&due[0]), b'E');
        assert!(order.take_due().is_empty());
    }

    #[test]
    fn only_round_trip_messages_advance_the_anchor() {
        let mut order = OutputOrder::default();
        // Parse/Bind/Describe/Execute/Close/Flush do not end a round trip.
        for tag in *b"PBDECHdcf" {
            order.note_client_message(tag);
        }
        assert_eq!(order.cycles_forwarded, 0);
        for tag in *b"QFS" {
            order.note_client_message(tag);
        }
        assert_eq!(order.cycles_forwarded, 3);
    }

    /// The backend order for
    /// `Close + Sync + Parse(denied) + Describe + Sync` is
    /// `CloseComplete, ReadyForQuery, ErrorResponse, ReadyForQuery`.
    #[test]
    fn rejection_waits_for_the_round_trip_that_precedes_it() {
        let mut order = OutputOrder::default();

        // Close and Sync are forwarded; the rejection follows them.
        order.note_client_message(b'C');
        order.note_client_message(b'S');
        order.queue(error(b'A'));

        // Nothing may be emitted before the first ReadyForQuery is relayed.
        assert!(order.take_due().is_empty(), "must follow the first RfQ");

        // CloseComplete is relayed: still nothing.
        assert!(order.take_due().is_empty());

        // ReadyForQuery #1 is relayed: now the rejection is due.
        order.note_rfq_relayed();
        let due = order.take_due();
        assert_eq!(due.len(), 1);
        assert_eq!(tag_of(&due[0]), b'E');
    }

    /// The simplest case: `Parse(denied) + Describe + Sync` with nothing in
    /// flight must be answered before the `ReadyForQuery` of that `Sync`.
    #[test]
    fn rejection_with_nothing_in_flight_precedes_the_next_ready_for_query() {
        let mut order = OutputOrder::default();
        order.queue(error(b'A'));
        // Sync is forwarded after the rejection was queued...
        order.note_client_message(b'S');
        // ...and the rejection is already due before the RfQ is relayed.
        assert_eq!(order.take_due().len(), 1);
    }

    #[test]
    fn queued_rejections_keep_their_order() {
        let mut order = OutputOrder::default();
        order.queue(error(b'1'));
        order.queue(error(b'2'));
        order.queue(error(b'3'));
        let due = order.take_due();
        assert_eq!(due.len(), 3);
        assert_eq!(tag_of(&due[0]), b'E');
        assert!(order.take_due().is_empty());
    }

    #[test]
    fn a_later_rejection_waits_for_its_own_round_trip() {
        let mut order = OutputOrder::default();

        // Round trip #1 in flight.
        order.note_client_message(b'S');
        order.queue(error(b'1'));
        assert!(order.take_due().is_empty());

        // The client pipelines a second rejection in the next round trip.
        order.note_client_message(b'S');
        order.queue(error(b'2'));

        // First ReadyForQuery releases only the first rejection.
        order.note_rfq_relayed();
        assert_eq!(order.take_due().len(), 1);

        // Second ReadyForQuery releases the second.
        order.note_rfq_relayed();
        assert_eq!(order.take_due().len(), 1);
        assert!(order.take_due().is_empty());
    }

    #[test]
    fn transaction_status_byte_round_trips() {
        assert_eq!(
            parse_ready_for_query(&ready_for_query(TransactionStatus::InTransaction).body).unwrap(),
            TransactionStatus::InTransaction
        );
    }
}
