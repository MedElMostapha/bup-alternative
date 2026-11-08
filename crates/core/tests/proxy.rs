//! Drives a real proxy instance against local HTTP, TLS and WebSocket servers.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use sluice_core::ca::CertAuthority;
use sluice_core::http::{parse_request_head, parse_response_head, request_framing, response_framing, BodyState, MessageReader};
use sluice_core::intercept::{Intercept, Verdict};
use sluice_core::model::{IdGen, Target};
use sluice_core::proxy::{self, Event, ProxyCtx, ProxyHandle, ProxySettings};
use sluice_core::scope::Scope;
use sluice_core::upstream::{send_raw, SendOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const BIG_SIZE: usize = 2 * 1024 * 1024;

#[derive(Clone, Default)]
struct Origin {
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    connections: Arc<AtomicU64>,
}

impl Origin {
    fn last_request(&self) -> Vec<u8> {
        self.received.lock().unwrap().last().cloned().expect("origin saw a request")
    }

    fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }

    async fn serve<S: AsyncRead + AsyncWrite + Unpin>(self, stream: S) {
        let connection = self.connections.fetch_add(1, Ordering::SeqCst) + 1;
        let mut reader = MessageReader::new(stream);
        while let Ok(Some(raw_head)) = reader.read_head().await {
            let head = parse_request_head(&raw_head).unwrap();
            let mut raw = raw_head.clone();
            let mut state = BodyState::new(request_framing(&head));
            while let Some(chunk) = reader.next_body_chunk(&mut state).await.unwrap() {
                raw.extend(chunk);
            }
            self.received.lock().unwrap().push(raw.clone());
            let stream = reader.stream_mut();
            match head.target.as_str() {
                "/big" => {
                    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {BIG_SIZE}\r\n\r\n");
                    stream.write_all(head.as_bytes()).await.unwrap();
                    stream.write_all(&vec![b'x'; BIG_SIZE]).await.unwrap();
                }
                "/until-close" => {
                    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nthe whole body").await.unwrap();
                    stream.shutdown().await.unwrap();
                    return;
                }
                "/chunked" => {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
                        .await
                        .unwrap();
                }
                "/ws" => {
                    stream
                        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                        .await
                        .unwrap();
                    // Replies with one unmasked text frame per masked frame.
                    let mut frame = [0u8; 8];
                    stream.read_exact(&mut frame).await.unwrap();
                    stream.write_all(&[0x81, 0x04, b'p', b'o', b'n', b'g']).await.unwrap();
                    stream.flush().await.unwrap();
                    let mut rest = Vec::new();
                    let _ = stream.read_to_end(&mut rest).await;
                    return;
                }
                _ => {
                    let body = format!("connection={connection}");
                    let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                    stream.write_all(reply.as_bytes()).await.unwrap();
                }
            }
            stream.flush().await.unwrap();
        }
    }
}

async fn spawn_plain_origin() -> (SocketAddr, Origin) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = Origin::default();
    let shared = origin.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(shared.clone().serve(tcp));
        }
    });
    (addr, origin)
}

async fn spawn_tls_origin(dir: &std::path::Path) -> (SocketAddr, Origin) {
    // A separate CA, so the proxy has no reason to trust this server.
    let ca = CertAuthority::load_or_create(&dir.join("origin")).unwrap();
    let acceptor = TlsAcceptor::from(ca.server_config("localhost").unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = Origin::default();
    let shared = origin.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let shared = shared.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    shared.serve(tls).await;
                }
            });
        }
    });
    (addr, origin)
}

struct Harness {
    _dir: tempfile::TempDir,
    ca: Arc<CertAuthority>,
    intercept: Arc<Intercept>,
    settings: Arc<RwLock<ProxySettings>>,
    events: Arc<Mutex<Vec<Event>>>,
    handle: ProxyHandle,
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(CertAuthority::load_or_create(&dir.path().join("proxy")).unwrap());
        let intercept = Arc::new(Intercept::default());
        let settings = Arc::new(RwLock::new(ProxySettings::default()));
        let (tx, mut rx) = mpsc::channel(1024);
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                sink.lock().unwrap().push(event);
            }
        });
        let ctx = Arc::new(ProxyCtx {
            ca: ca.clone(),
            scope: Arc::new(RwLock::new(Scope::default())),
            intercept: intercept.clone(),
            settings: settings.clone(),
            ids: Arc::new(IdGen::default()),
            events: tx,
        });
        let handle = proxy::start(ctx, "127.0.0.1:0".parse().unwrap()).await.unwrap();
        Self {
            _dir: dir,
            ca,
            intercept,
            settings,
            events,
            handle,
        }
    }

    async fn connect(&self) -> MessageReader<TcpStream> {
        MessageReader::new(TcpStream::connect(self.handle.local_addr).await.unwrap())
    }

    fn tls_connector(&self) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(self.ca.cert_pem().as_bytes()).unwrap())
            .unwrap();
        let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    /// Waits until a recorded event satisfies `pick`.
    async fn wait_for<T>(&self, pick: impl Fn(&Event) -> Option<T>) -> T {
        for _ in 0..500 {
            if let Some(found) = self.events.lock().unwrap().iter().find_map(&pick) {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("event did not arrive; saw {:#?}", self.events.lock().unwrap().len());
    }

    async fn finished_flow(&self, id: u64) -> sluice_core::model::Flow {
        self.wait_for(|event| match event {
            Event::Flow(flow) if flow.id == id && flow.complete => Some((**flow).clone()),
            _ => None,
        })
        .await
    }
}

async fn read_response<S: AsyncRead + Unpin>(reader: &mut MessageReader<S>, method: &str) -> (u16, Vec<u8>) {
    let raw = reader.read_head().await.unwrap().expect("response head");
    let head = parse_response_head(&raw).unwrap();
    let mut state = BodyState::new(response_framing(&head, method));
    let mut body = Vec::new();
    while let Some(chunk) = reader.next_body_chunk(&mut state).await.unwrap() {
        body.extend(chunk);
    }
    (head.status, body)
}

#[tokio::test]
async fn forwards_http_and_records_the_flow() {
    let harness = Harness::start().await;
    let (addr, origin) = spawn_plain_origin().await;
    let mut client = harness.connect().await;
    let request = format!(
        "POST http://{addr}/path?a=1 HTTP/1.1\r\nhOsT: {addr}\r\nProxy-Connection: keep-alive\r\nX-oDD:   spaced \r\nContent-Length: 3\r\n\r\nabc"
    );
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    let (status, _) = read_response(&mut client, "POST").await;
    assert_eq!(status, 200);

    let expected = format!("POST /path?a=1 HTTP/1.1\r\nhOsT: {addr}\r\nX-oDD:   spaced \r\nContent-Length: 3\r\n\r\nabc");
    assert_eq!(origin.last_request(), expected.as_bytes());

    let flow = harness.finished_flow(1).await;
    assert_eq!(flow.request, expected.as_bytes());
    assert!(flow.response.unwrap().starts_with(b"HTTP/1.1 200 OK"));
    assert!(flow.duration_ms.is_some());
}

#[tokio::test]
async fn intercepts_tls_and_records_certificate_problems() {
    let harness = Harness::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (addr, origin) = spawn_tls_origin(dir.path()).await;

    let mut client = harness.connect().await;
    let port = addr.port();
    let connect = format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n");
    client.stream_mut().write_all(connect.as_bytes()).await.unwrap();
    let head = client.read_head().await.unwrap().unwrap();
    assert_eq!(parse_response_head(&head).unwrap().status, 200);

    // Fails unless the leaf really chains to the proxy's CA and names the host.
    let (tcp, _) = client.into_parts();
    let name = ServerName::try_from("localhost").unwrap();
    let tls = harness.tls_connector().connect(name, tcp).await.unwrap();
    let mut client = MessageReader::new(tls);
    let request = format!("GET /secure HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n");
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    let (status, _) = read_response(&mut client, "GET").await;
    assert_eq!(status, 200);

    assert_eq!(origin.last_request(), request.as_bytes());
    let flow = harness.finished_flow(1).await;
    assert!(flow.target.tls);
    assert!(flow.tls_error.is_some(), "untrusted origin should be noted");
}

#[tokio::test]
async fn reuses_the_upstream_connection_for_keep_alive() {
    let harness = Harness::start().await;
    let (addr, origin) = spawn_plain_origin().await;
    let mut client = harness.connect().await;
    for path in ["/one", "/two"] {
        let request = format!("GET http://{addr}{path} HTTP/1.1\r\nHost: {addr}\r\n\r\n");
        client.stream_mut().write_all(request.as_bytes()).await.unwrap();
        let (_, body) = read_response(&mut client, "GET").await;
        assert_eq!(body, b"connection=1");
    }
    assert_eq!(origin.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn streams_past_the_record_cap_and_marks_truncation() {
    let harness = Harness::start().await;
    harness.settings.write().unwrap().body_cap = 1024;
    let (addr, _) = spawn_plain_origin().await;
    let mut client = harness.connect().await;
    let request = format!("GET http://{addr}/big HTTP/1.1\r\nHost: {addr}\r\n\r\n");
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    let (_, body) = read_response(&mut client, "GET").await;
    assert_eq!(body.len(), BIG_SIZE, "the client still gets everything");

    let flow = harness.finished_flow(1).await;
    assert!(flow.truncated);
    assert!(flow.response.unwrap().len() < 2048);
}

#[tokio::test]
async fn relays_chunked_and_close_delimited_bodies() {
    let harness = Harness::start().await;
    let (addr, _) = spawn_plain_origin().await;

    let mut client = harness.connect().await;
    let request = format!("GET http://{addr}/chunked HTTP/1.1\r\nHost: {addr}\r\n\r\n");
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    let (_, body) = read_response(&mut client, "GET").await;
    assert_eq!(body, b"3\r\nabc\r\n0\r\n\r\n");

    let mut client = harness.connect().await;
    let request = format!("GET http://{addr}/until-close HTTP/1.1\r\nHost: {addr}\r\n\r\n");
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    let (_, body) = read_response(&mut client, "GET").await;
    assert_eq!(body, b"the whole body");
}

#[tokio::test]
async fn intercept_can_edit_a_request() {
    let harness = Harness::start().await;
    harness.intercept.configure(true, false);
    let (addr, origin) = spawn_plain_origin().await;
    let mut client = harness.connect().await;
    let request = format!("POST http://{addr}/ HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 3\r\n\r\nold");
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();

    let pending = harness
        .wait_for(|event| match event {
            Event::InterceptQueued(p) => Some(p.clone()),
            _ => None,
        })
        .await;
    assert_eq!(origin.count(), 0, "nothing is sent while paused");

    let edited = format!("POST /changed HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 3\r\n\r\nnew body");
    assert!(harness.intercept.resolve(pending.id, Verdict::Edited(edited.into_bytes())));
    let (status, _) = read_response(&mut client, "POST").await;
    assert_eq!(status, 200);

    let expected = format!("POST /changed HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 8\r\n\r\nnew body");
    assert_eq!(origin.last_request(), expected.as_bytes());
    assert!(harness.finished_flow(1).await.edited);
}

#[tokio::test]
async fn intercept_can_drop_a_request() {
    let harness = Harness::start().await;
    harness.intercept.configure(true, false);
    let (addr, origin) = spawn_plain_origin().await;
    let mut client = harness.connect().await;
    let request = format!("GET http://{addr}/ HTTP/1.1\r\nHost: {addr}\r\n\r\n");
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    let pending = harness
        .wait_for(|event| match event {
            Event::InterceptQueued(p) => Some(p.clone()),
            _ => None,
        })
        .await;
    assert!(harness.intercept.resolve(pending.id, Verdict::Drop));
    let (status, _) = read_response(&mut client, "GET").await;
    assert_eq!(status, 403);
    assert_eq!(origin.count(), 0);
    assert_eq!(harness.finished_flow(1).await.error.as_deref(), Some("dropped by user"));
}

#[tokio::test]
async fn intercept_entry_clears_when_the_client_leaves() {
    let harness = Harness::start().await;
    harness.intercept.configure(true, false);
    let (addr, _) = spawn_plain_origin().await;
    let mut client = harness.connect().await;
    let request = format!("GET http://{addr}/ HTTP/1.1\r\nHost: {addr}\r\n\r\n");
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    let pending = harness
        .wait_for(|event| match event {
            Event::InterceptQueued(p) => Some(p.clone()),
            _ => None,
        })
        .await;
    drop(client);
    harness
        .wait_for(|event| match event {
            Event::InterceptCleared(id) if *id == pending.id => Some(()),
            _ => None,
        })
        .await;
    assert!(harness.intercept.queued().is_empty());
}

#[tokio::test]
async fn intercept_can_edit_a_response() {
    let harness = Harness::start().await;
    harness.intercept.configure(false, true);
    let (addr, _) = spawn_plain_origin().await;
    let mut client = harness.connect().await;
    let request = format!("GET http://{addr}/ HTTP/1.1\r\nHost: {addr}\r\n\r\n");
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    let pending = harness
        .wait_for(|event| match event {
            Event::InterceptQueued(p) => Some(p.clone()),
            _ => None,
        })
        .await;
    let edited = b"HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nedited".to_vec();
    assert!(harness.intercept.resolve(pending.id, Verdict::Edited(edited)));
    let (status, body) = read_response(&mut client, "GET").await;
    assert_eq!((status, body.as_slice()), (201, &b"edited"[..]));
}

#[tokio::test]
async fn captures_websocket_frames_both_ways() {
    let harness = Harness::start().await;
    let (addr, origin) = spawn_plain_origin().await;
    let mut client = harness.connect().await;
    let request = format!(
        "GET http://{addr}/ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
    );
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    let head = client.read_head().await.unwrap().unwrap();
    assert_eq!(parse_response_head(&head).unwrap().status, 101);
    assert!(!String::from_utf8_lossy(&origin.last_request()).contains("permessage-deflate"));

    let mask = [9u8, 8, 7, 6];
    let mut frame = vec![0x81, 0x82];
    frame.extend(mask);
    frame.extend(b"hi".iter().enumerate().map(|(i, b)| b ^ mask[i]));
    client.stream_mut().write_all(&frame).await.unwrap();

    let mut reply = [0u8; 6];
    client.stream_mut().read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[2..], b"pong");

    let from_client = harness
        .wait_for(|event| match event {
            Event::WsFrame(f) if f.from_client => Some(f.clone()),
            _ => None,
        })
        .await;
    assert_eq!(from_client.payload, b"hi");
    let from_server = harness
        .wait_for(|event| match event {
            Event::WsFrame(f) if !f.from_client => Some(f.clone()),
            _ => None,
        })
        .await;
    assert_eq!(from_server.payload, b"pong");
}

#[tokio::test]
async fn refuses_to_proxy_to_itself() {
    let harness = Harness::start().await;
    let own = harness.handle.local_addr;
    let mut client = harness.connect().await;
    let request = format!("GET http://{own}/ HTTP/1.1\r\nHost: {own}\r\n\r\n");
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    assert_eq!(read_response(&mut client, "GET").await.0, 400);
}

#[tokio::test]
async fn upstream_failure_becomes_a_bad_gateway() {
    let harness = Harness::start().await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let mut client = harness.connect().await;
    let request = format!("GET http://{closed}/ HTTP/1.1\r\nHost: {closed}\r\n\r\n");
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    assert_eq!(read_response(&mut client, "GET").await.0, 502);
    assert!(harness.finished_flow(1).await.error.is_some());
}

#[tokio::test]
async fn send_raw_delivers_exact_bytes() {
    let (addr, origin) = spawn_plain_origin().await;
    let target = Target {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls: false,
    };
    let request = b"GET /x HTTP/1.1\r\nhOST:   odd\r\nx-Y: 1\r\n\r\n";
    let exchange = send_raw(&target, request, &SendOptions::default()).await.unwrap();
    assert_eq!(origin.last_request(), request);
    assert!(exchange.response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(exchange.response.ends_with(b"connection=1"));
}
