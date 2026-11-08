pub mod ws;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::LazyConfigAcceptor;

use crate::ca::CertAuthority;
use crate::http::rewrite::{fix_content_length, parse_absolute_target, parse_authority, prepare_forward};
use crate::http::{
    parse_request_head, parse_response_head, request_framing, response_framing, BodyFraming, BodyState, Header,
    MessageReader, RequestHead, ResponseHead,
};
use crate::intercept::{Direction, Intercept, Pending, Verdict};
use crate::match_replace::{RuleSet, Rewritten};
use crate::model::{Flow, IdGen, Source, Target, WsFrame};
use crate::scope::{glob_match, Scope};
use crate::upstream::{connect, BoxIo, Connection};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait for a client to speak after CONNECT before assuming the
/// tunnel carries a protocol where the server talks first.
const CLIENT_HELLO_WAIT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
pub enum Event {
    Flow(Box<Flow>),
    WsFrame(WsFrame),
    InterceptQueued(Pending),
    InterceptCleared(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    pub body_cap: usize,
    /// Host patterns tunnelled without TLS interception.
    pub tls_passthrough: Vec<String>,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            body_cap: 32 * 1024 * 1024,
            tls_passthrough: Vec::new(),
        }
    }
}

pub struct ProxyCtx {
    pub ca: Arc<CertAuthority>,
    pub scope: Arc<RwLock<Scope>>,
    pub intercept: Arc<Intercept>,
    pub settings: Arc<RwLock<ProxySettings>>,
    pub rules: Arc<RwLock<RuleSet>>,
    pub ids: Arc<IdGen>,
    pub events: mpsc::Sender<Event>,
}

impl ProxyCtx {
    async fn emit_flow(&self, flow: &Flow) {
        let _ = self.events.send(Event::Flow(Box::new(flow.clone()))).await;
    }

    fn body_cap(&self) -> usize {
        self.settings.read().expect("settings lock").body_cap
    }

    fn rewrite(&self, direction: Direction, message: &[u8], body_complete: bool) -> Option<Rewritten> {
        self.rules.read().expect("rules lock").rewrite(direction, message, body_complete)
    }

    fn rewrites_bodies(&self, direction: Direction) -> bool {
        self.rules.read().expect("rules lock").rewrites_bodies(direction)
    }

    fn is_passthrough(&self, host: &str) -> bool {
        let settings = self.settings.read().expect("settings lock");
        settings.tls_passthrough.iter().any(|p| glob_match(p, host))
    }
}

/// A running listener. Dropping it stops the proxy and all its connections.
pub struct ProxyHandle {
    pub local_addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn start(ctx: Arc<ProxyCtx>, addr: SocketAddr) -> io::Result<ProxyHandle> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((tcp, _)) = accepted else { continue };
                    let _ = tcp.set_nodelay(true);
                    let ctx = ctx.clone();
                    connections.spawn(async move {
                        if let Err(e) = handle_connection(ctx, tcp, local_addr).await {
                            tracing::debug!("connection ended: {e}");
                        }
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    Ok(ProxyHandle { local_addr, task })
}

fn is_own_listener(host: &str, port: u16, local: SocketAddr) -> bool {
    if port != local.port() {
        return false;
    }
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback() || ip == local.ip() || (local.ip().is_unspecified()))
}

fn simple_response(status: &str, message: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}",
        message.len()
    )
    .into_bytes()
}

async fn handle_connection(ctx: Arc<ProxyCtx>, tcp: TcpStream, local: SocketAddr) -> io::Result<()> {
    let mut reader = MessageReader::new(tcp);
    let Some(raw_head) = reader.read_head().await? else {
        return Ok(());
    };
    let head = match parse_request_head(&raw_head) {
        Ok(head) => head,
        Err(e) => {
            let body = simple_response("400 Bad Request", &e.to_string());
            return reader.stream_mut().write_all(&body).await;
        }
    };
    if head.method.eq_ignore_ascii_case("CONNECT") {
        return handle_connect(ctx, reader, &head, local).await;
    }
    let (tcp, buffered) = reader.into_parts();
    let mut client = MessageReader::new(Box::new(tcp) as BoxIo);
    client.restore(buffered);
    let session = Session {
        ctx,
        local,
        fixed: None,
        sni: None,
    };
    session.run(&mut client, Some(raw_head)).await
}

async fn handle_connect(
    ctx: Arc<ProxyCtx>,
    mut reader: MessageReader<TcpStream>,
    head: &RequestHead,
    local: SocketAddr,
) -> io::Result<()> {
    let Some((host, port)) = parse_authority(&head.target, 443) else {
        let body = simple_response("400 Bad Request", "invalid CONNECT target");
        return reader.stream_mut().write_all(&body).await;
    };
    if is_own_listener(&host, port, local) {
        let body = simple_response("400 Bad Request", "refusing to connect the proxy to itself");
        return reader.stream_mut().write_all(&body).await;
    }
    reader
        .stream_mut()
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    let (mut tcp, _) = reader.into_parts();

    let mut first = [0u8; 1];
    let is_tls = match timeout(CLIENT_HELLO_WAIT, tcp.peek(&mut first)).await {
        Ok(Ok(0)) | Ok(Err(_)) => return Ok(()),
        Ok(Ok(_)) => first[0] == 0x16,
        Err(_) => false,
    };
    if !is_tls || ctx.is_passthrough(&host) {
        let mut upstream = TcpStream::connect((host.as_str(), port)).await?;
        copy_bidirectional(&mut tcp, &mut upstream).await?;
        return Ok(());
    }

    let start = LazyConfigAcceptor::new(Acceptor::default(), tcp).await?;
    let sni = start.client_hello().server_name().map(str::to_owned);
    let config = ctx
        .ca
        .server_config(sni.as_deref().unwrap_or(&host))
        .map_err(io::Error::other)?;
    let tls = start.into_stream(config).await?;
    let mut client = MessageReader::new(Box::new(tls) as BoxIo);
    let session = Session {
        ctx,
        local,
        fixed: Some(Target { host, port, tls: true }),
        sni,
    };
    session.run(&mut client, None).await
}

/// Who should end the connection after an exchange.
#[derive(PartialEq, Eq)]
enum After {
    KeepAlive,
    Close,
}

fn has_token(headers: &[Header], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .filter_map(|h| std::str::from_utf8(&h.value).ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

fn client_wants_close(head: &RequestHead) -> bool {
    has_token(&head.headers, "connection", "close")
        || (head.minor_version == 0 && !has_token(&head.headers, "connection", "keep-alive"))
}

fn server_wants_close(head: &ResponseHead) -> bool {
    has_token(&head.headers, "connection", "close")
        || (head.minor_version == 0 && !has_token(&head.headers, "connection", "keep-alive"))
}

fn request_path(target: &str) -> String {
    match parse_absolute_target(target) {
        Some(absolute) => absolute.origin_form,
        None => target.to_string(),
    }
}

fn first_token(raw: &[u8]) -> String {
    let token = raw.split(|b| *b == b' ').next().unwrap_or_default();
    String::from_utf8_lossy(token).into_owned()
}

/// Waits for the user's decision. Returns `None` if the client went away.
async fn await_verdict(
    ctx: &ProxyCtx,
    client: &mut MessageReader<BoxIo>,
    flow_id: u64,
    direction: Direction,
    target: &Target,
    raw: Vec<u8>,
) -> Option<Verdict> {
    let Some(mut waiter) = ctx.intercept.submit(flow_id, direction, target.clone(), raw) else {
        return Some(Verdict::Forward);
    };
    let id = waiter.pending.id;
    let _ = ctx.events.send(Event::InterceptQueued(waiter.pending.clone())).await;
    let outcome = loop {
        tokio::select! {
            verdict = &mut waiter.verdict => break Some(verdict.unwrap_or(Verdict::Forward)),
            read = client.fill() => match read {
                Ok(0) | Err(_) => break None,
                Ok(_) => continue,
            },
        }
    };
    drop(waiter);
    let _ = ctx.events.send(Event::InterceptCleared(id)).await;
    outcome
}

struct Session {
    ctx: Arc<ProxyCtx>,
    local: SocketAddr,
    /// Set inside a CONNECT tunnel, where every request has the same target.
    fixed: Option<Target>,
    sni: Option<String>,
}

struct Upstream {
    target: Target,
    conn: Connection,
}

impl Session {
    async fn run(self, client: &mut MessageReader<BoxIo>, mut first: Option<Vec<u8>>) -> io::Result<()> {
        let mut upstream = None;
        loop {
            let raw_head = match first.take() {
                Some(head) => head,
                None => match client.read_head().await? {
                    Some(head) => head,
                    None => return Ok(()),
                },
            };
            if self.exchange(client, raw_head, &mut upstream).await? == After::Close {
                let _ = client.stream_mut().shutdown().await;
                return Ok(());
            }
        }
    }

    fn resolve_target(&self, head: &RequestHead) -> Option<Target> {
        if let Some(fixed) = &self.fixed {
            return Some(fixed.clone());
        }
        if let Some(absolute) = parse_absolute_target(&head.target) {
            return Some(Target {
                host: absolute.host,
                port: absolute.port,
                tls: absolute.tls,
            });
        }
        let host = std::str::from_utf8(head.header("host")?).ok()?;
        let (host, port) = parse_authority(host.trim(), 80)?;
        Some(Target { host, port, tls: false })
    }

    async fn exchange(
        &self,
        client: &mut MessageReader<BoxIo>,
        raw_head: Vec<u8>,
        upstream: &mut Option<Upstream>,
    ) -> io::Result<After> {
        let ctx = &self.ctx;
        let head = match parse_request_head(&raw_head) {
            Ok(head) => head,
            Err(e) => {
                let body = simple_response("400 Bad Request", &e.to_string());
                client.stream_mut().write_all(&body).await?;
                return Ok(After::Close);
            }
        };
        let Some(target) = self.resolve_target(&head) else {
            let body = simple_response("400 Bad Request", "could not determine the target host");
            client.stream_mut().write_all(&body).await?;
            return Ok(After::Close);
        };
        if self.fixed.is_none() && is_own_listener(&target.host, target.port, self.local) {
            let body = simple_response("400 Bad Request", "refusing to send the request back to the proxy");
            client.stream_mut().write_all(&body).await?;
            return Ok(After::Close);
        }
        if has_token(&head.headers, "expect", "100-continue") {
            client.stream_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            client.stream_mut().flush().await?;
        }

        let cap = ctx.body_cap();
        let mut request = prepare_forward(&raw_head);
        let mut body_state = BodyState::new(request_framing(&head));
        let mut body_complete = false;
        while request.len() <= cap {
            match client.next_body_chunk(&mut body_state).await? {
                Some(chunk) => request.extend_from_slice(&chunk),
                None => {
                    body_complete = true;
                    break;
                }
            }
        }

        let mut flow = Flow::new(ctx.ids.next(), Source::Proxy, target.clone(), request.clone());
        flow.truncated = !body_complete;
        let in_scope = ctx
            .scope
            .read()
            .expect("scope lock")
            .allows(&target.host, &request_path(&head.target));

        if in_scope {
            if let Some(rewritten) = ctx.rewrite(Direction::Request, &request, body_complete) {
                request = rewritten.message;
                flow.request = request.clone();
                flow.edited = true;
            }
        }

        if body_complete && in_scope {
            let verdict = await_verdict(ctx, client, flow.id, Direction::Request, &target, request.clone()).await;
            match verdict {
                None => return self.abandon(&mut flow, "client disconnected while intercepted").await,
                Some(Verdict::Drop) => {
                    let body = simple_response("403 Forbidden", "Request dropped in Sluice");
                    let _ = client.stream_mut().write_all(&body).await;
                    return self.abandon(&mut flow, "dropped by user").await;
                }
                Some(Verdict::Edited(edited)) => {
                    request = fix_content_length(&edited);
                    flow.request = request.clone();
                    flow.edited = true;
                }
                Some(Verdict::Forward) => {}
            }
        }
        ctx.emit_flow(&flow).await;

        let method = first_token(&request);
        let replayable = body_complete;
        let mut reused = matches!(upstream, Some(u) if u.target == target);
        let (raw_response, response_head) = loop {
            if !reused {
                *upstream = None;
                match connect(&target, self.sni.as_deref()).await {
                    Ok(conn) => {
                        *upstream = Some(Upstream {
                            target: target.clone(),
                            conn,
                        })
                    }
                    Err(e) => return self.bad_gateway(client, &mut flow, e).await,
                }
            }
            let up = upstream.as_mut().expect("upstream just connected");
            flow.tls_error = up.conn.tls_error.clone();
            let attempt = self
                .send_and_read_head(client, &mut up.conn, &request, &mut body_state, body_complete)
                .await;
            match attempt {
                Ok(Some(found)) => break found,
                // A reused connection may have been closed by the server
                // while idle, so one retry on a new connection is safe.
                Ok(None) | Err(_) if reused && replayable => reused = false,
                Ok(None) => {
                    let e = io::Error::new(io::ErrorKind::UnexpectedEof, "server closed without responding");
                    return self.bad_gateway(client, &mut flow, e).await;
                }
                Err(e) => return self.bad_gateway(client, &mut flow, e).await,
            }
        };

        let response_head = match response_head {
            Ok(head) => head,
            Err(message) => {
                flow.response = Some(raw_response);
                *upstream = None;
                return self.bad_gateway(client, &mut flow, io::Error::other(message)).await;
            }
        };

        let up = upstream.take().expect("upstream present after response");
        self.deliver_response(client, up, upstream, flow, target, &head, raw_response, response_head, &method, in_scope)
            .await
    }

    async fn abandon(&self, flow: &mut Flow, reason: &str) -> io::Result<After> {
        flow.error = Some(reason.to_string());
        flow.finish();
        self.ctx.emit_flow(flow).await;
        Ok(After::Close)
    }

    async fn bad_gateway(
        &self,
        client: &mut MessageReader<BoxIo>,
        flow: &mut Flow,
        error: io::Error,
    ) -> io::Result<After> {
        let message = format!("Sluice could not complete the request: {error}");
        let _ = client
            .stream_mut()
            .write_all(&simple_response("502 Bad Gateway", &message))
            .await;
        self.abandon(flow, &error.to_string()).await
    }

    /// Writes the request and returns the final response head. `Ok(None)`
    /// means the server closed before sending anything.
    #[allow(clippy::type_complexity)]
    async fn send_and_read_head(
        &self,
        client: &mut MessageReader<BoxIo>,
        conn: &mut Connection,
        request: &[u8],
        body_state: &mut BodyState,
        body_complete: bool,
    ) -> io::Result<Option<(Vec<u8>, Result<ResponseHead, String>)>> {
        conn.reader.stream_mut().write_all(request).await?;
        if !body_complete {
            while let Some(chunk) = client.next_body_chunk(body_state).await? {
                conn.reader.stream_mut().write_all(&chunk).await?;
            }
        }
        conn.reader.stream_mut().flush().await?;
        loop {
            let read = timeout(RESPONSE_TIMEOUT, conn.reader.read_head())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for the response"))??;
            let Some(raw) = read else {
                return Ok(None);
            };
            let head = match parse_response_head(&raw) {
                Ok(head) => head,
                Err(e) => return Ok(Some((raw, Err(e.to_string())))),
            };
            match head.status {
                // The client already received a 100 from the proxy if it asked.
                100 => continue,
                101 => return Ok(Some((raw, Ok(head)))),
                102..=199 => {
                    client.stream_mut().write_all(&raw).await?;
                    client.stream_mut().flush().await?;
                }
                _ => return Ok(Some((raw, Ok(head)))),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn deliver_response(
        &self,
        client: &mut MessageReader<BoxIo>,
        mut up: Upstream,
        upstream_slot: &mut Option<Upstream>,
        mut flow: Flow,
        target: Target,
        request_head: &RequestHead,
        raw_head: Vec<u8>,
        head: ResponseHead,
        method: &str,
        in_scope: bool,
    ) -> io::Result<After> {
        let ctx = &self.ctx;
        if head.status == 101 {
            client.stream_mut().write_all(&raw_head).await?;
            client.stream_mut().flush().await?;
            flow.response = Some(raw_head);
            flow.finish();
            ctx.emit_flow(&flow).await;
            return self.relay_upgrade(client, up, &head, flow.id).await;
        }

        let cap = ctx.body_cap();
        let framing = response_framing(&head, method);
        let mut must_close =
            framing == BodyFraming::UntilClose || server_wants_close(&head) || client_wants_close(request_head);
        let mut reusable = framing != BodyFraming::UntilClose && !server_wants_close(&head);
        let mut state = BodyState::new(framing);
        let head_len = raw_head.len();
        let mut recorded = raw_head;
        let mut sent = 0usize;

        let is_event_stream = head
            .header("content-type")
            .is_some_and(|v| v.to_ascii_lowercase().starts_with(b"text/event-stream"));
        let must_buffer = ctx.intercept.is_enabled(Direction::Response) || ctx.rewrites_bodies(Direction::Response);
        let mut complete = false;
        if in_scope && !is_event_stream && must_buffer {
            while recorded.len() <= cap + head_len {
                match up.conn.reader.next_body_chunk(&mut state).await {
                    Ok(Some(chunk)) => recorded.extend_from_slice(&chunk),
                    Ok(None) => {
                        complete = true;
                        break;
                    }
                    Err(e) => return self.bad_gateway(client, &mut flow, e).await,
                }
            }
        }
        if in_scope {
            if let Some(rewritten) = ctx.rewrite(Direction::Response, &recorded, complete) {
                recorded = rewritten.message;
                flow.edited = true;
                // A new body brings a matching length. A header rule that
                // alters the framing leaves the client unable to reuse this.
                let same_framing =
                    parse_response_head(&recorded).is_ok_and(|new| response_framing(&new, method) == framing);
                must_close |= !rewritten.body_changed && !same_framing;
            }
        }
        if complete {
            let verdict = await_verdict(ctx, client, flow.id, Direction::Response, &target, recorded.clone()).await;
            match verdict {
                None => return self.abandon(&mut flow, "client disconnected while intercepted").await,
                Some(Verdict::Drop) => {
                    let body = simple_response("403 Forbidden", "Response dropped in Sluice");
                    let _ = client.stream_mut().write_all(&body).await;
                    flow.response = Some(recorded);
                    return self.abandon(&mut flow, "dropped by user").await;
                }
                Some(Verdict::Edited(edited)) => {
                    recorded = fix_content_length(&edited);
                    flow.edited = true;
                    // The edit may have changed the framing the client
                    // would rely on, so end the connection after it.
                    must_close = true;
                }
                Some(Verdict::Forward) => {}
            }
        }
        client.stream_mut().write_all(&recorded).await?;
        client.stream_mut().flush().await?;
        sent += recorded.len();

        loop {
            let chunk = match up.conn.reader.next_body_chunk(&mut state).await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(e) => {
                    flow.error = Some(e.to_string());
                    must_close = true;
                    reusable = false;
                    break;
                }
            };
            if let Err(e) = client.stream_mut().write_all(&chunk).await {
                flow.error = Some(format!("client disconnected: {e}"));
                must_close = true;
                reusable = false;
                break;
            }
            client.stream_mut().flush().await?;
            sent += chunk.len();
            let room = (cap + head_len).saturating_sub(recorded.len());
            if chunk.len() > room {
                flow.truncated = true;
            }
            recorded.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
        tracing::trace!(flow = flow.id, sent, "response delivered");
        flow.response = Some(recorded);
        flow.finish();
        ctx.emit_flow(&flow).await;
        if reusable {
            *upstream_slot = Some(up);
        }
        Ok(if must_close { After::Close } else { After::KeepAlive })
    }

    async fn relay_upgrade(
        &self,
        client: &mut MessageReader<BoxIo>,
        up: Upstream,
        head: &ResponseHead,
        flow_id: u64,
    ) -> io::Result<After> {
        let client_buffered = client.take_buffered();
        let (mut upstream, upstream_buffered) = up.conn.reader.into_parts();
        if has_token(&head.headers, "upgrade", "websocket") {
            ws::relay(
                client.stream_mut(),
                client_buffered,
                upstream,
                upstream_buffered,
                flow_id,
                self.ctx.events.clone(),
            )
            .await;
        } else {
            upstream.write_all(&client_buffered).await?;
            client.stream_mut().write_all(&upstream_buffered).await?;
            let _ = copy_bidirectional(client.stream_mut(), &mut upstream).await;
        }
        Ok(After::Close)
    }
}
