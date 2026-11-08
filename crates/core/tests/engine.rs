//! End-to-end behaviour of a whole project: capture, storage, repeater,
//! fuzzer limits and passive findings.

use std::collections::HashSet;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use sluice_core::browser::BrowserKind;
use sluice_core::engine::{Engine, EngineError, SendRequest, UiEvent};
use sluice_core::fuzzer::{AttackMode, FuzzConfig, FuzzError, PayloadSource, RunState};
use sluice_core::http::{parse_request_head, request_framing, BodyState, MessageReader};
use sluice_core::intercept::{Direction, Verdict};
use sluice_core::match_replace::{MatchRule, RuleKind};
use sluice_core::model::Target;
use sluice_core::repeater::RepeaterTab;
use sluice_core::scope::{Scope, ScopeRule};
use sluice_core::store::{FlowFilter, Store};
use sluice_core::text::{Encoding, RawText};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[derive(Default)]
struct Stats {
    seen: Mutex<Vec<Vec<u8>>>,
    active: AtomicUsize,
    peak: AtomicUsize,
}

async fn spawn_origin(delay: Duration) -> (SocketAddr, Arc<Stats>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(Stats::default());
    let shared = stats.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let stats = shared.clone();
            tokio::spawn(async move {
                let mut reader = MessageReader::new(tcp);
                while let Ok(Some(head)) = reader.read_head().await {
                    let parsed = parse_request_head(&head).unwrap();
                    let mut raw = head;
                    let mut state = BodyState::new(request_framing(&parsed));
                    while let Some(chunk) = reader.next_body_chunk(&mut state).await.unwrap() {
                        raw.extend(chunk);
                    }
                    let now = stats.active.fetch_add(1, Ordering::SeqCst) + 1;
                    stats.peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    stats.active.fetch_sub(1, Ordering::SeqCst);
                    stats.seen.lock().unwrap().push(raw);
                    let body = if parsed.target.contains("hit") { "MATCHME" } else { "nothing" };
                    let (coding, body) = if parsed.target.contains("gzip") {
                        ("Content-Encoding: gzip\r\n", gzip(body.as_bytes()))
                    } else {
                        ("", body.as_bytes().to_vec())
                    };
                    let mut reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=abc\r\n{coding}Content-Length: {}\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    reply.extend(body);
                    reader.stream_mut().write_all(&reply).await.unwrap();
                }
            });
        }
    });
    (addr, stats)
}

fn open() -> (tempfile::TempDir, Arc<Engine>, mpsc::UnboundedReceiver<UiEvent>) {
    let dir = tempfile::tempdir().unwrap();
    let (engine, rx) = Engine::open(&dir.path().join("p.sluice"), dir.path()).unwrap();
    (dir, engine, rx)
}

fn target(addr: SocketAddr) -> Target {
    Target {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls: false,
    }
}

fn allow(engine: &Engine, addr: SocketAddr) {
    engine
        .set_scope(Scope {
            include: vec![ScopeRule {
                host: addr.ip().to_string(),
                path_prefix: String::new(),
            }],
            exclude: vec![],
        })
        .unwrap();
}

fn fuzz_config(addr: SocketAddr, payloads: &[&str], concurrency: usize, delay_ms: u64) -> FuzzConfig {
    FuzzConfig {
        target: target(addr),
        template: format!("GET /§x§ HTTP/1.1\r\nHost: {addr}\r\n\r\n"),
        encoding: Encoding::Utf8,
        mode: AttackMode::Single,
        payloads: vec![PayloadSource::List(payloads.iter().map(|s| s.to_string()).collect())],
        processing: vec![],
        concurrency,
        delay_ms,
        grep: Some("MATCHME".into()),
        normalize: true,
        timeout_ms: 5000,
    }
}

async fn wait_finished(rx: &mut mpsc::UnboundedReceiver<UiEvent>) -> RunState {
    loop {
        let event = tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .expect("the run should end")
            .expect("channel open");
        if let UiEvent::FuzzState { state, .. } = event {
            if matches!(state, RunState::Finished | RunState::Stopped) {
                return state;
            }
        }
    }
}

async fn proxied_get(proxy: &str, addr: SocketAddr, path: &str) {
    let tcp = TcpStream::connect(proxy).await.unwrap();
    let mut client = MessageReader::new(tcp);
    let request = format!("GET http://{addr}{path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    client.stream_mut().write_all(request.as_bytes()).await.unwrap();
    while client.fill().await.unwrap() > 0 {}
}

#[tokio::test]
async fn captured_traffic_is_stored_and_scanned_once() {
    let (_dir, engine, mut rx) = open();
    let (addr, _) = spawn_origin(Duration::ZERO).await;
    let status = engine.start_proxy("127.0.0.1:0".parse().unwrap(), false).await.unwrap();
    for path in ["/a", "/b"] {
        proxied_get(&status.address, addr, path).await;
    }

    let mut cookie_findings = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut flows_done = 0;
    while flows_done < 2 || cookie_findings == 0 {
        assert!(Instant::now() < deadline, "events did not arrive");
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap() {
            UiEvent::Flow(summary) if summary.complete => flows_done += 1,
            UiEvent::Finding(f) if f.rule == "cookie-no-httponly" => cookie_findings += 1,
            _ => {}
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    while let Ok(event) = rx.try_recv() {
        if matches!(&event, UiEvent::Finding(f) if f.rule == "cookie-no-httponly") {
            cookie_findings += 1;
        }
    }
    assert_eq!(cookie_findings, 1, "the same cookie is reported once");

    let rows = engine.list_flows(&FlowFilter::default()).unwrap();
    assert_eq!(rows.len(), 2);
    let detail = engine.flow_detail(rows[0].id).unwrap();
    assert!(detail.response.unwrap().text.ends_with("nothing"));
    assert!(!engine.list_findings().unwrap().is_empty());
}

#[tokio::test]
async fn proxy_refuses_external_interface_without_confirmation() {
    let (_dir, engine, _rx) = open();
    let result = engine.start_proxy("0.0.0.0:0".parse().unwrap(), false).await;
    assert!(matches!(result, Err(EngineError::NonLoopback(_))));
}

#[tokio::test]
async fn proxy_restarts_on_the_same_port() {
    let (_dir, engine, _rx) = open();
    let first = engine.start_proxy("127.0.0.1:0".parse().unwrap(), false).await.unwrap();
    let addr: SocketAddr = first.address.parse().unwrap();
    let again = engine.start_proxy(addr, false).await.unwrap();
    assert_eq!(again.address, first.address);
    engine.stop_proxy().await;
    assert!(!engine.proxy_status().await.unwrap().running);
}

#[tokio::test]
async fn scope_limits_intercept_findings_and_the_history_filter() {
    let (_dir, engine, _rx) = open();
    let (addr, _) = spawn_origin(Duration::ZERO).await;
    let status = engine.start_proxy("127.0.0.1:0".parse().unwrap(), false).await.unwrap();
    let set_include = |host: &str| {
        engine
            .set_scope(Scope {
                include: vec![ScopeRule {
                    host: host.into(),
                    path_prefix: String::new(),
                }],
                exclude: vec![],
            })
            .unwrap();
    };
    let in_scope = FlowFilter {
        in_scope_only: true,
        ..Default::default()
    };
    engine.configure_intercept(true, false);

    // Out of scope: passes straight through, but is still recorded.
    set_include("*.example.test");
    tokio::time::timeout(Duration::from_secs(5), proxied_get(&status.address, addr, "/out"))
        .await
        .expect("out-of-scope traffic must not be paused");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(engine.queued_intercepts().is_empty());
    assert!(engine.list_findings().unwrap().is_empty());
    assert_eq!(engine.list_flows(&FlowFilter::default()).unwrap().len(), 1);
    assert!(engine.list_flows(&in_scope).unwrap().is_empty());

    // In scope through a wildcard: paused, scanned and shown by the filter.
    set_include("127.*");
    assert_eq!(engine.list_flows(&in_scope).unwrap().len(), 1);
    let address = status.address.clone();
    let request = tokio::spawn(async move { proxied_get(&address, addr, "/in").await });
    let deadline = Instant::now() + Duration::from_secs(5);
    let pending = loop {
        if let Some(pending) = engine.queued_intercepts().pop() {
            break pending;
        }
        assert!(Instant::now() < deadline, "in-scope traffic should be paused");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert!(engine.resolve_intercept(pending.id, Verdict::Forward));
    tokio::time::timeout(Duration::from_secs(5), request).await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!engine.list_findings().unwrap().is_empty());
    assert_eq!(engine.list_flows(&in_scope).unwrap().len(), 2);
}

#[tokio::test]
async fn browsers_cannot_open_while_the_proxy_is_stopped() {
    let (_dir, engine, _rx) = open();
    let result = engine.launch_browser(BrowserKind::Chrome).await;
    assert!(matches!(result, Err(EngineError::ProxyStopped)));
}

#[tokio::test]
async fn occupied_port_is_reported_in_the_status() {
    let (_dir, engine, _rx) = open();
    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = taken.local_addr().unwrap();
    assert!(engine.start_proxy(addr, false).await.is_err());
    let status = engine.proxy_status().await.unwrap();
    assert!(!status.running);
    assert!(status.error.unwrap().contains(&addr.to_string()));
}

#[tokio::test]
async fn project_state_survives_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.sluice");
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    {
        let (engine, _rx) = Engine::open(&path, dir.path()).unwrap();
        allow(&engine, addr);
        engine
            .create_tab("saved".into(), target(addr), RawText::from_bytes(b"GET / HTTP/1.1\r\n\r\n"))
            .unwrap();
        engine.list_tabs().unwrap();
    }
    let (engine, _rx) = Engine::open(&path, dir.path()).unwrap();
    assert_eq!(engine.scope().include.len(), 1);
    let tabs: Vec<RepeaterTab> = engine.list_tabs().unwrap();
    assert_eq!(tabs[0].name, "saved");
}

#[tokio::test]
async fn repeater_sends_and_keeps_history() {
    let (_dir, engine, _rx) = open();
    let (addr, stats) = spawn_origin(Duration::ZERO).await;
    let tab = engine
        .create_tab("t".into(), target(addr), RawText::from_bytes(b""))
        .unwrap();
    let send = |text: &str, normalize| SendRequest {
        tab_id: tab.id,
        target: target(addr),
        request: RawText::from_bytes(text.as_bytes()),
        normalize,
        timeout_ms: Some(5000),
    };

    let detail = engine
        .repeater_send(send("POST /n HTTP/1.1\nHost: x\nContent-Length: 0\n\nbody", true))
        .await
        .unwrap();
    assert_eq!(detail.summary.status, Some(200));
    assert_eq!(
        stats.seen.lock().unwrap().last().unwrap().as_slice(),
        b"POST /n HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody"
    );

    let exact = "GET /exact HTTP/1.1\r\nhOST:   x\r\n\r\n";
    engine.repeater_send(send(exact, false)).await.unwrap();
    assert_eq!(stats.seen.lock().unwrap().last().unwrap().as_slice(), exact.as_bytes());
    assert_eq!(engine.tab_sends(tab.id).unwrap().len(), 2);
}

#[tokio::test]
async fn repeater_send_can_be_cancelled() {
    let (_dir, engine, _rx) = open();
    let (addr, _) = spawn_origin(Duration::from_secs(10)).await;
    let tab = engine.create_tab("t".into(), target(addr), RawText::from_bytes(b"")).unwrap();
    let task = tokio::spawn({
        let engine = engine.clone();
        let send = SendRequest {
            tab_id: tab.id,
            target: target(addr),
            request: RawText::from_bytes(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            normalize: false,
            timeout_ms: None,
        };
        async move { engine.repeater_send(send).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    engine.repeater_cancel(tab.id);
    let detail = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap().unwrap();
    assert_eq!(detail.summary.error.as_deref(), Some("cancelled"));
}

#[tokio::test]
async fn fuzzer_refuses_targets_outside_scope() {
    let (_dir, engine, _rx) = open();
    let (addr, stats) = spawn_origin(Duration::ZERO).await;
    let result = engine.fuzz_start(fuzz_config(addr, &["1"], 1, 0));
    assert!(matches!(result, Err(EngineError::Fuzz(FuzzError::OutOfScope(_)))));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(stats.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn fuzzer_marks_matches_and_respects_concurrency() {
    let (_dir, engine, mut rx) = open();
    let (addr, stats) = spawn_origin(Duration::from_millis(30)).await;
    allow(&engine, addr);
    let payloads: Vec<String> = (0..11).map(|i| if i == 5 { "hit".into() } else { format!("p{i}") }).collect();
    let refs: Vec<&str> = payloads.iter().map(String::as_str).collect();
    let config = fuzz_config(addr, &refs, 3, 0);
    assert_eq!(engine.fuzz_preview(&config).unwrap(), 11);

    let run = engine.fuzz_start(config).unwrap();
    assert_eq!(wait_finished(&mut rx).await, RunState::Finished);
    let results = engine.fuzz_results(run.id).unwrap();
    assert_eq!(results.len(), 11);
    assert_eq!(results.iter().filter(|r| r.matched).map(|r| r.payloads[0].as_str()).collect::<Vec<_>>(), ["hit"]);
    assert!(results.iter().all(|r| r.status == Some(200)));
    let peak = stats.peak.load(Ordering::SeqCst);
    assert!((2..=3).contains(&peak), "peak concurrency was {peak}");
    let runs = engine.list_fuzz_runs().unwrap();
    assert_eq!(runs[0].state, RunState::Finished);
}

#[tokio::test]
async fn fuzzer_honours_the_delay() {
    let (_dir, engine, mut rx) = open();
    let (addr, _) = spawn_origin(Duration::ZERO).await;
    allow(&engine, addr);
    let started = Instant::now();
    engine.fuzz_start(fuzz_config(addr, &["a", "b", "c", "d"], 4, 60)).unwrap();
    wait_finished(&mut rx).await;
    assert!(started.elapsed() >= Duration::from_millis(180));
}

#[tokio::test]
async fn fuzzer_can_pause_and_stop() {
    let (_dir, engine, mut rx) = open();
    let (addr, stats) = spawn_origin(Duration::ZERO).await;
    allow(&engine, addr);
    let payloads: Vec<String> = (0..500).map(|i| format!("p{i}")).collect();
    let refs: Vec<&str> = payloads.iter().map(String::as_str).collect();
    let run = engine.fuzz_start(fuzz_config(addr, &refs, 1, 20)).unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    engine.fuzz_control(run.id, RunState::Paused).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let paused_at = stats.seen.lock().unwrap().len();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(stats.seen.lock().unwrap().len(), paused_at, "paused runs send nothing");

    engine.fuzz_control(run.id, RunState::Running).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(stats.seen.lock().unwrap().len() > paused_at, "resumed runs continue");

    engine.fuzz_control(run.id, RunState::Stopped).unwrap();
    assert_eq!(wait_finished(&mut rx).await, RunState::Stopped);
    assert!(stats.seen.lock().unwrap().len() < 500);
}

#[tokio::test]
async fn fuzzer_matches_inside_compressed_responses_and_history_finds_them() {
    let (_dir, engine, mut rx) = open();
    let (addr, _) = spawn_origin(Duration::ZERO).await;
    allow(&engine, addr);
    let run = engine.fuzz_start(fuzz_config(addr, &["gzip-hit", "gzip-miss"], 1, 0)).unwrap();
    assert_eq!(wait_finished(&mut rx).await, RunState::Finished);
    let results = engine.fuzz_results(run.id).unwrap();
    assert_eq!(results.iter().map(|r| r.matched).collect::<Vec<_>>(), [true, false]);
    let search = FlowFilter {
        text: Some("MATCHME".into()),
        ..Default::default()
    };
    assert_eq!(engine.list_flows(&search).unwrap().len(), 1);
}

#[tokio::test]
async fn resuming_sends_only_what_is_missing_and_rechecks_old_matches() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("p.sluice");
    let (engine, mut rx) = Engine::open(&project, dir.path()).unwrap();
    let (addr, stats) = spawn_origin(Duration::ZERO).await;
    allow(&engine, addr);
    let payloads: Vec<String> = (0..40).map(|i| if i == 0 { "gzip-hit".into() } else { format!("p{i}") }).collect();
    let refs: Vec<&str> = payloads.iter().map(String::as_str).collect();
    let run = engine.fuzz_start(fuzz_config(addr, &refs, 1, 10)).unwrap();
    assert!(matches!(
        engine.fuzz_resume(run.id),
        Err(EngineError::Fuzz(FuzzError::NotStopped))
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;
    engine.fuzz_control(run.id, RunState::Stopped).unwrap();
    assert_eq!(wait_finished(&mut rx).await, RunState::Stopped);
    let mut earlier = engine.fuzz_results(run.id).unwrap();
    assert!(!earlier.is_empty() && earlier.len() < 40, "stopped after {}", earlier.len());

    // A result recorded before matching could read compressed bodies.
    earlier[0].matched = false;
    let store = Store::open(&project, Arc::new(RwLock::new(Scope::default()))).unwrap();
    store.save_fuzz_result(&earlier[0]).unwrap();
    store.flush();

    let sent_before = stats.seen.lock().unwrap().len();
    assert_eq!(engine.fuzz_resume(run.id).unwrap().state, RunState::Running);
    assert_eq!(wait_finished(&mut rx).await, RunState::Finished);

    let results = engine.fuzz_results(run.id).unwrap();
    assert_eq!(results.iter().map(|r| r.index).collect::<HashSet<_>>().len(), 40);
    assert!(results[0].matched, "old results are matched again");
    let sent_after = stats.seen.lock().unwrap().len() - sent_before;
    // The one request in flight at the stop has no result, so it goes again.
    let missing = 40 - earlier.len();
    assert!((missing..=missing + 1).contains(&sent_after), "sent {sent_after} for {missing} missing");
    assert_eq!(engine.list_fuzz_runs().unwrap()[0].state, RunState::Finished);
    assert!(matches!(
        engine.fuzz_resume(run.id),
        Err(EngineError::Fuzz(FuzzError::NotStopped))
    ));
}

#[tokio::test]
async fn runs_left_active_by_a_previous_session_reopen_as_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("p.sluice");
    let (engine, _rx) = Engine::open(&project, dir.path()).unwrap();
    let (addr, _) = spawn_origin(Duration::ZERO).await;
    allow(&engine, addr);
    let run = engine.fuzz_start(fuzz_config(addr, &["a", "b", "c"], 1, 2000)).unwrap();
    assert_eq!(engine.list_fuzz_runs().unwrap()[0].state, RunState::Running);

    let (reopened, _rx) = Engine::open(&project, dir.path()).unwrap();
    assert_eq!(reopened.list_fuzz_runs().unwrap()[0].state, RunState::Stopped);
    engine.fuzz_control(run.id, RunState::Stopped).unwrap();
}

#[tokio::test]
async fn stop_does_not_wait_out_the_delay() {
    let (_dir, engine, mut rx) = open();
    let (addr, _) = spawn_origin(Duration::ZERO).await;
    allow(&engine, addr);
    let run = engine.fuzz_start(fuzz_config(addr, &["a", "b"], 1, 60_000)).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    engine.fuzz_control(run.id, RunState::Stopped).unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(2), wait_finished(&mut rx)).await;
    assert_eq!(ended.expect("stop should not wait for the delay"), RunState::Stopped);
    engine.fuzz_resume(run.id).unwrap();
    engine.fuzz_control(run.id, RunState::Stopped).unwrap();
}

#[tokio::test]
async fn match_rules_persist_with_their_problems_reported() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("p.sluice");
    let rule = |pattern: &str| MatchRule {
        enabled: true,
        direction: Direction::Request,
        kind: RuleKind::SetHeader,
        pattern: pattern.into(),
        replacement: "1".into(),
        regex: false,
    };
    let (engine, _rx) = Engine::open(&project, dir.path()).unwrap();
    let saved = engine.set_match_rules(vec![rule("X-Good"), rule("not valid")]).unwrap();
    assert_eq!(saved.errors[0], None);
    assert!(saved.errors[1].is_some());
    engine.list_flows(&FlowFilter::default()).unwrap();

    let (reopened, _rx) = Engine::open(&project, dir.path()).unwrap();
    let loaded = reopened.match_rules();
    assert_eq!(loaded.rules, [rule("X-Good"), rule("not valid")]);
    assert!(loaded.errors[1].is_some());
}
