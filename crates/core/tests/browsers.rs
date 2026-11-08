//! Drives the real installed browsers through the proxy. Ignored by default
//! because they need Chrome and Firefox; run with `cargo test -- --ignored`.
//!
//! A browser that rejects Sluice's certificate closes the connection before
//! sending anything, so a recorded request proves the certificate was trusted.

use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use sluice_core::browser::{chrome_args, detect, prepare_firefox, BrowserKind};
use sluice_core::ca::CertAuthority;
use sluice_core::engine::Engine;
use sluice_core::http::{parse_request_head, MessageReader};
use sluice_core::store::{FlowFilter, FlowSummary};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio_rustls::TlsAcceptor;

const PATH: &str = "/sluice-browser-check";
const SECOND_PATH: &str = "/sluice-second-host";

async fn spawn_tls_origin(dir: &Path) -> SocketAddr {
    let ca = CertAuthority::load_or_create(&dir.join("origin")).unwrap();
    let acceptor = TlsAcceptor::from(ca.server_config("localhost").unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let mut reader = MessageReader::new(tls);
                while let Ok(Some(head)) = reader.read_head().await {
                    // The frame makes the browser accept a second host's
                    // certificate in the same session.
                    let body = if parse_request_head(&head).unwrap().target == PATH {
                        format!("<html><title>ok</title><iframe src=\"https://127.0.0.1:{}{SECOND_PATH}\"></iframe></html>", addr.port())
                    } else {
                        "<html><title>second</title>checked</html>".to_string()
                    };
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = reader.stream_mut().write_all(reply.as_bytes()).await;
                }
            });
        }
    });
    addr
}

fn executable(kind: BrowserKind) -> std::path::PathBuf {
    detect().into_iter().find(|b| b.kind == kind).expect("browser installed").path
}

async fn wait_for(engine: &Arc<Engine>, path: &str) -> FlowSummary {
    for _ in 0..100 {
        let rows = engine.list_flows(&FlowFilter::default()).unwrap();
        if let Some(found) = rows.into_iter().find(|r| r.path == path && r.complete) {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the browser never requested {path} through the proxy");
}

async fn assert_both_hosts_loaded(engine: &Arc<Engine>) {
    let first = wait_for(engine, PATH).await;
    assert_eq!((first.status, first.tls), (Some(200), true));
    let second = wait_for(engine, SECOND_PATH).await;
    assert_eq!((second.status, second.host.as_str()), (Some(200), "127.0.0.1"));
}

async fn run_for_a_while(command: &mut Command) {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(40), child.wait()).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Chrome installed"]
async fn chrome_trusts_sluice_through_the_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let origin = spawn_tls_origin(dir.path()).await;
    let (engine, _rx) = Engine::open(&dir.path().join("p.sluice"), dir.path()).unwrap();
    let status = engine.start_proxy("127.0.0.1:0".parse().unwrap(), false).await.unwrap();
    let ca = CertAuthority::load_or_create(dir.path()).unwrap();

    let args = chrome_args(&dir.path().join("chrome"), status.address.parse().unwrap(), &ca.leaf_spki_base64());
    let mut command = Command::new(executable(BrowserKind::Chrome));
    command
        .args(args)
        .args(["--headless=new", "--dump-dom"])
        .arg(format!("https://localhost:{}{PATH}", origin.port()));
    run_for_a_while(&mut command).await;

    assert_both_hosts_loaded(&engine).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Firefox installed"]
async fn firefox_trusts_sluice_through_the_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let origin = spawn_tls_origin(dir.path()).await;
    let (engine, _rx) = Engine::open(&dir.path().join("p.sluice"), dir.path()).unwrap();
    let status = engine.start_proxy("127.0.0.1:0".parse().unwrap(), false).await.unwrap();
    let proxy: SocketAddr = status.address.parse().unwrap();
    let profile = dir.path().join("firefox");
    let firefox = executable(BrowserKind::Firefox);

    let (exe, prof, data) = (firefox.clone(), profile.clone(), dir.path().to_path_buf());
    tokio::task::spawn_blocking(move || {
        let ca = CertAuthority::load_or_create(&data).unwrap();
        prepare_firefox(&exe, &prof, proxy, &ca).unwrap();
    })
    .await
    .unwrap();

    let mut command = Command::new(firefox);
    command
        .args(["--headless", "--new-instance", "--profile"])
        .arg(&profile)
        .arg("--screenshot")
        .arg(dir.path().join("shot.png"))
        .arg(format!("https://localhost:{}{PATH}", origin.port()));
    run_for_a_while(&mut command).await;

    assert_both_hosts_loaded(&engine).await;
}
