//! Connections to origin servers. The proxy, repeater and fuzzer all send
//! through here so they behave the same way on the wire.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::http::{parse_response_head, response_framing, BodyState, MessageReader};
use crate::model::Target;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Accepts every certificate, because a testing tool must reach servers with
/// broken ones, but remembers what proper validation would have said.
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    failure: Arc<Mutex<Option<String>>>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if let Err(e) = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            *self.failure.lock().expect("verifier lock") = Some(e.to_string());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn tls_connector(failure: Arc<Mutex<Option<String>>>) -> io::Result<TlsConnector> {
    let provider = Arc::new(default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(io::Error::other)?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RecordingVerifier { inner, failure }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}

pub struct Connection {
    pub reader: MessageReader<BoxIo>,
    pub tls_error: Option<String>,
}

/// Connects to `target`. `sni` overrides the name sent during the handshake.
pub async fn connect(target: &Target, sni: Option<&str>) -> io::Result<Connection> {
    let addr = (target.host.as_str(), target.port);
    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
    let _ = tcp.set_nodelay(true);
    if !target.tls {
        return Ok(Connection {
            reader: MessageReader::new(Box::new(tcp)),
            tls_error: None,
        });
    }
    let failure = Arc::new(Mutex::new(None));
    let connector = tls_connector(failure.clone())?;
    let name = ServerName::try_from(sni.unwrap_or(&target.host).to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let tls = timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
    let tls_error = failure.lock().expect("verifier lock").take();
    Ok(Connection {
        reader: MessageReader::new(Box::new(tls)),
        tls_error,
    })
}

#[derive(Debug, Clone)]
pub struct SendOptions {
    pub timeout: Duration,
    pub body_cap: usize,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            body_cap: 32 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RawExchange {
    pub response: Vec<u8>,
    pub elapsed: Duration,
    pub truncated: bool,
    pub tls_error: Option<String>,
}

/// Sends exactly `request` on a new connection and reads one response.
pub async fn send_raw(target: &Target, request: &[u8], options: &SendOptions) -> io::Result<RawExchange> {
    timeout(options.timeout, send_inner(target, request, options))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timed out"))?
}

async fn send_inner(target: &Target, request: &[u8], options: &SendOptions) -> io::Result<RawExchange> {
    let started = Instant::now();
    let mut conn = connect(target, None).await?;
    conn.reader.stream_mut().write_all(request).await?;
    conn.reader.stream_mut().flush().await?;
    let method = request
        .split(|b| *b == b' ')
        .next()
        .and_then(|m| std::str::from_utf8(m).ok())
        .unwrap_or("GET");
    loop {
        let raw_head = conn
            .reader
            .read_head()
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "server closed without responding"))?;
        let head = parse_response_head(&raw_head).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if (100..200).contains(&head.status) && head.status != 101 {
            continue;
        }
        let mut response = raw_head;
        let head_len = response.len();
        let mut truncated = false;
        let mut state = BodyState::new(response_framing(&head, method));
        while let Some(chunk) = conn.reader.next_body_chunk(&mut state).await? {
            let room = (options.body_cap + head_len).saturating_sub(response.len());
            if chunk.len() > room {
                truncated = true;
            }
            response.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
        return Ok(RawExchange {
            response,
            elapsed: started.elapsed(),
            truncated,
            tls_error: conn.tls_error,
        });
    }
}
