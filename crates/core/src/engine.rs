//! Owns every service for one open project. The UI layer only talks to this.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;

use crate::browser::{self, BrowserError, BrowserInfo, BrowserKind};
use crate::ca::{CaError, CertAuthority};
use crate::fuzzer::{self, FuzzConfig, FuzzDeps, FuzzError, FuzzResult, FuzzRunInfo, RunState};
use crate::http::decode::decode_body;
use crate::http::{find_head_end, parse_response_head};
use crate::intercept::{Direction, Intercept, Pending, Verdict};
use crate::model::{Flow, IdGen, Source, Target, WsFrame};
use crate::proxy::{self, Event, ProxyCtx, ProxyHandle, ProxySettings};
use crate::repeater::{normalize_message, RepeaterTab};
use crate::scanner::{scan_flow, Finding};
use crate::scope::Scope;
use crate::store::{FlowFilter, FlowSummary, Store, StoreError};
use crate::text::RawText;
use crate::upstream::{send_raw, SendOptions};

const EVENT_QUEUE: usize = 4096;
const SCAN_QUEUE: usize = 1024;
const SCOPE_KEY: &str = "scope";
const SETTINGS_KEY: &str = "proxy_settings";
const LISTEN_KEY: &str = "listen_addr";
const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Ca(#[from] CaError),
    #[error(transparent)]
    Fuzz(#[from] FuzzError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("binding {0} exposes the proxy to other machines; confirm this to continue")]
    NonLoopback(SocketAddr),
    #[error("not found")]
    NotFound,
    #[error(transparent)]
    Browser(#[from] BrowserError),
    #[error("the proxy is stopped; start it in Settings first")]
    ProxyStopped,
}

/// What the UI hears about as it happens. Bodies are fetched on demand.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UiEvent {
    Flow(FlowSummary),
    WsFrame { flow_id: u64 },
    InterceptQueued(PendingView),
    InterceptCleared { id: u64 },
    Finding(Finding),
    FuzzResult(FuzzResult),
    FuzzState { run_id: u64, state: RunState },
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingView {
    pub id: u64,
    pub flow_id: u64,
    pub direction: Direction,
    pub target: Target,
    pub raw: RawText,
}

impl From<Pending> for PendingView {
    fn from(pending: Pending) -> Self {
        Self {
            id: pending.id,
            flow_id: pending.flow_id,
            direction: pending.direction,
            target: pending.target,
            raw: RawText::from_bytes(&pending.raw),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowDetail {
    pub summary: FlowSummary,
    pub target: Target,
    pub request: RawText,
    pub response: Option<RawText>,
    /// Head plus decompressed body, present only when that differs.
    pub decoded_response: Option<RawText>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub address: String,
    /// Why the most recent attempt to start the listener failed.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SendRequest {
    pub tab_id: u64,
    pub target: Target,
    pub request: RawText,
    pub normalize: bool,
    pub timeout_ms: Option<u64>,
}

struct FuzzHandle {
    control: watch::Sender<RunState>,
}

pub struct Engine {
    data_dir: PathBuf,
    store: Arc<Store>,
    ca: Arc<CertAuthority>,
    scope: Arc<RwLock<Scope>>,
    settings: Arc<RwLock<ProxySettings>>,
    intercept: Arc<Intercept>,
    ids: Arc<IdGen>,
    ui: mpsc::UnboundedSender<UiEvent>,
    events: mpsc::Sender<Event>,
    proxy: tokio::sync::Mutex<Option<ProxyHandle>>,
    proxy_error: Mutex<Option<String>>,
    fuzz_runs: Mutex<HashMap<u64, FuzzHandle>>,
    repeater_sends: Mutex<HashMap<u64, AbortHandle>>,
    next_id: IdGen,
}

impl Engine {
    /// Opens a project file. Must be called from within a Tokio runtime.
    pub fn open(
        project: &Path,
        data_dir: &Path,
    ) -> Result<(Arc<Self>, mpsc::UnboundedReceiver<UiEvent>), EngineError> {
        let ca = Arc::new(CertAuthority::load_or_create(data_dir)?);
        let scope = Arc::new(RwLock::new(Scope::default()));
        let store = Arc::new(Store::open(project, scope.clone())?);
        if let Some(saved) = store.get_value(SCOPE_KEY)? {
            *scope.write().expect("scope lock") = saved;
        }
        let settings = store.get_value::<ProxySettings>(SETTINGS_KEY)?.unwrap_or_default();
        let last_tab = store.list_tabs()?.iter().map(|t| t.id).max().unwrap_or(0);
        let last_run = store.list_fuzz_runs()?.first().map_or(0, |r| r.id);
        let ids = Arc::new(IdGen::starting_after(store.last_flow_id()?));
        let (ui, ui_rx) = mpsc::unbounded_channel();
        let (events, events_rx) = mpsc::channel(EVENT_QUEUE);
        let (scan_tx, scan_rx) = std::sync::mpsc::sync_channel(SCAN_QUEUE);

        let engine = Arc::new(Self {
            data_dir: data_dir.to_path_buf(),
            store: store.clone(),
            ca,
            scope: scope.clone(),
            settings: Arc::new(RwLock::new(settings)),
            intercept: Arc::new(Intercept::default()),
            ids,
            ui: ui.clone(),
            events,
            proxy: tokio::sync::Mutex::new(None),
            proxy_error: Mutex::new(None),
            fuzz_runs: Mutex::new(HashMap::new()),
            repeater_sends: Mutex::new(HashMap::new()),
            next_id: IdGen::starting_after(last_tab.max(last_run)),
        });

        let known = store
            .list_findings()?
            .into_iter()
            .map(|f| (f.rule, f.host, f.dedupe))
            .collect();
        std::thread::spawn({
            let (store, ui) = (store.clone(), ui.clone());
            move || scan_worker(scan_rx, store, ui, known)
        });
        tokio::spawn(pump_events(events_rx, store, ui, scope, scan_tx));
        Ok((engine, ui_rx))
    }

    pub fn ca_pem(&self) -> String {
        self.ca.cert_pem().to_string()
    }

    pub fn listen_address(&self) -> Result<String, EngineError> {
        Ok(self
            .store
            .get_value::<String>(LISTEN_KEY)?
            .unwrap_or_else(|| DEFAULT_LISTEN.to_string()))
    }

    pub async fn start_proxy(&self, addr: SocketAddr, allow_non_loopback: bool) -> Result<ProxyStatus, EngineError> {
        let result = self.bind_proxy(addr, allow_non_loopback).await;
        *self.proxy_error.lock().expect("error lock") = result.as_ref().err().map(|e| format!("{addr}: {e}"));
        result
    }

    async fn bind_proxy(&self, addr: SocketAddr, allow_non_loopback: bool) -> Result<ProxyStatus, EngineError> {
        if !addr.ip().is_loopback() && !allow_non_loopback {
            return Err(EngineError::NonLoopback(addr));
        }
        let mut slot = self.proxy.lock().await;
        // The old listener must be gone before a restart on the same port.
        *slot = None;
        let ctx = Arc::new(ProxyCtx {
            ca: self.ca.clone(),
            scope: self.scope.clone(),
            intercept: self.intercept.clone(),
            settings: self.settings.clone(),
            ids: self.ids.clone(),
            events: self.events.clone(),
        });
        let mut last_error = None;
        for _ in 0..20 {
            match proxy::start(ctx.clone(), addr).await {
                Ok(handle) => {
                    let address = handle.local_addr.to_string();
                    *slot = Some(handle);
                    self.store.set_value(LISTEN_KEY, &addr.to_string())?;
                    return Ok(ProxyStatus {
                        running: true,
                        address,
                        error: None,
                    });
                }
                // Aborted listeners release their socket asynchronously.
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    last_error = Some(e);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(last_error.expect("loop ran at least once").into())
    }

    pub async fn stop_proxy(&self) {
        *self.proxy.lock().await = None;
    }

    pub async fn proxy_status(&self) -> Result<ProxyStatus, EngineError> {
        let slot = self.proxy.lock().await;
        Ok(match slot.as_ref() {
            Some(handle) => ProxyStatus {
                running: true,
                address: handle.local_addr.to_string(),
                error: None,
            },
            None => ProxyStatus {
                running: false,
                address: self.listen_address()?,
                error: self.proxy_error.lock().expect("error lock").clone(),
            },
        })
    }

    pub fn available_browsers(&self) -> Vec<BrowserInfo> {
        browser::detect()
    }

    /// Opens a browser preconfigured to use the running proxy.
    pub async fn launch_browser(&self, kind: BrowserKind) -> Result<(), EngineError> {
        let status = self.proxy_status().await?;
        if !status.running {
            return Err(EngineError::ProxyStopped);
        }
        let proxy: SocketAddr = status.address.parse().map_err(std::io::Error::other)?;
        let (ca, data_dir) = (self.ca.clone(), self.data_dir.clone());
        tokio::task::spawn_blocking(move || browser::launch(kind, proxy, &data_dir, &ca))
            .await
            .map_err(std::io::Error::other)??;
        Ok(())
    }

    pub fn scope(&self) -> Scope {
        self.scope.read().expect("scope lock").clone()
    }

    pub fn set_scope(&self, scope: Scope) -> Result<(), EngineError> {
        self.store.set_value(SCOPE_KEY, &scope)?;
        *self.scope.write().expect("scope lock") = scope;
        Ok(())
    }

    pub fn settings(&self) -> ProxySettings {
        self.settings.read().expect("settings lock").clone()
    }

    pub fn set_settings(&self, settings: ProxySettings) -> Result<(), EngineError> {
        self.store.set_value(SETTINGS_KEY, &settings)?;
        *self.settings.write().expect("settings lock") = settings;
        Ok(())
    }

    pub fn list_flows(&self, filter: &FlowFilter) -> Result<Vec<FlowSummary>, EngineError> {
        self.store.flush();
        Ok(self.store.list_flows(filter)?)
    }

    pub fn flow_detail(&self, id: u64) -> Result<FlowDetail, EngineError> {
        self.store.flush();
        let flow = self.store.get_flow(id)?.ok_or(EngineError::NotFound)?;
        Ok(detail_of(&flow))
    }

    pub fn ws_frames(&self, flow_id: u64) -> Result<Vec<WsFrame>, EngineError> {
        self.store.flush();
        Ok(self.store.ws_frames(flow_id)?)
    }

    pub fn clear_history(&self) {
        self.store.clear_history();
        self.store.flush();
    }

    pub fn configure_intercept(&self, requests: bool, responses: bool) {
        self.intercept.configure(requests, responses);
    }

    pub fn queued_intercepts(&self) -> Vec<PendingView> {
        self.intercept.queued().into_iter().map(PendingView::from).collect()
    }

    pub fn resolve_intercept(&self, id: u64, verdict: Verdict) -> bool {
        self.intercept.resolve(id, verdict)
    }

    pub fn list_tabs(&self) -> Result<Vec<RepeaterTab>, EngineError> {
        self.store.flush();
        Ok(self.store.list_tabs()?)
    }

    pub fn create_tab(&self, name: String, target: Target, request: RawText) -> Result<RepeaterTab, EngineError> {
        let tab = RepeaterTab {
            id: self.next_id.next(),
            name,
            target,
            request,
        };
        self.store.save_tab(&tab)?;
        Ok(tab)
    }

    pub fn update_tab(&self, tab: RepeaterTab) -> Result<(), EngineError> {
        Ok(self.store.save_tab(&tab)?)
    }

    pub fn delete_tab(&self, id: u64) {
        self.store.delete_tab(id);
    }

    pub fn tab_sends(&self, tab_id: u64) -> Result<Vec<FlowSummary>, EngineError> {
        self.store.flush();
        Ok(self.store.tab_sends(tab_id)?)
    }

    /// Sends a request and waits for the response, unless cancelled first.
    pub async fn repeater_send(self: &Arc<Self>, send: SendRequest) -> Result<FlowDetail, EngineError> {
        let bytes = send.request.to_bytes();
        let bytes = if send.normalize { normalize_message(&bytes) } else { bytes };
        let mut flow = Flow::new(self.ids.next(), Source::Repeater, send.target.clone(), bytes);
        let options = SendOptions {
            timeout: Duration::from_millis(send.timeout_ms.unwrap_or(30_000)),
            ..SendOptions::default()
        };
        let task = tokio::spawn({
            let (target, request) = (send.target, flow.request.clone());
            async move { send_raw(&target, &request, &options).await }
        });
        self.repeater_sends
            .lock()
            .expect("sends lock")
            .insert(send.tab_id, task.abort_handle());
        let outcome = task.await;
        self.repeater_sends.lock().expect("sends lock").remove(&send.tab_id);
        match outcome {
            Ok(Ok(exchange)) => {
                flow.response = Some(exchange.response);
                flow.truncated = exchange.truncated;
                flow.tls_error = exchange.tls_error;
            }
            Ok(Err(e)) => flow.error = Some(e.to_string()),
            Err(_) => flow.error = Some("cancelled".to_string()),
        }
        flow.finish();
        let detail = detail_of(&flow);
        self.store.link_send(send.tab_id, flow.id);
        self.store.save_flow(flow);
        Ok(detail)
    }

    pub fn repeater_cancel(&self, tab_id: u64) {
        if let Some(handle) = self.repeater_sends.lock().expect("sends lock").get(&tab_id) {
            handle.abort();
        }
    }

    /// How many requests a configuration would send, without sending any.
    pub fn fuzz_preview(&self, config: &FuzzConfig) -> Result<u64, EngineError> {
        let (plan, _) = fuzzer::prepare(config, &self.scope())?;
        Ok(plan.total())
    }

    pub fn fuzz_start(self: &Arc<Self>, config: FuzzConfig) -> Result<FuzzRunInfo, EngineError> {
        let (plan, grep) = fuzzer::prepare(&config, &self.scope())?;
        let info = fuzzer::new_run_info(self.next_id.next(), config, plan.total());
        self.store.save_fuzz_run(&info)?;
        let (control, control_rx) = watch::channel(RunState::Running);
        self.fuzz_runs
            .lock()
            .expect("runs lock")
            .insert(info.id, FuzzHandle { control });
        let deps = Arc::new(FuzzDeps {
            store: self.store.clone(),
            ids: self.ids.clone(),
            scope: self.scope.clone(),
            ui: self.ui.clone(),
        });
        let engine = self.clone();
        let run_info = info.clone();
        tokio::spawn(async move {
            let id = run_info.id;
            fuzzer::run(run_info, plan, grep, control_rx, deps).await;
            engine.fuzz_runs.lock().expect("runs lock").remove(&id);
        });
        Ok(info)
    }

    /// Asks a running attack to pause, resume or stop.
    pub fn fuzz_control(&self, run_id: u64, state: RunState) -> Result<(), EngineError> {
        let runs = self.fuzz_runs.lock().expect("runs lock");
        let handle = runs.get(&run_id).ok_or(EngineError::NotFound)?;
        let _ = handle.control.send(state);
        let _ = self.ui.send(UiEvent::FuzzState { run_id, state });
        Ok(())
    }

    pub fn list_fuzz_runs(&self) -> Result<Vec<FuzzRunInfo>, EngineError> {
        self.store.flush();
        Ok(self.store.list_fuzz_runs()?)
    }

    pub fn fuzz_results(&self, run_id: u64) -> Result<Vec<FuzzResult>, EngineError> {
        self.store.flush();
        Ok(self.store.fuzz_results(run_id)?)
    }

    pub fn list_findings(&self) -> Result<Vec<Finding>, EngineError> {
        self.store.flush();
        Ok(self.store.list_findings()?)
    }
}

fn detail_of(flow: &Flow) -> FlowDetail {
    let decoded_response = flow.response.as_deref().and_then(|raw| {
        let head = parse_response_head(raw).ok()?;
        let end = find_head_end(raw)?;
        let decoded = decode_body(&head.headers, &raw[end..]);
        (decoded != raw[end..]).then(|| RawText::from_bytes(&[&raw[..end], decoded.as_slice()].concat()))
    });
    FlowDetail {
        summary: FlowSummary::of(flow),
        target: flow.target.clone(),
        request: RawText::from_bytes(&flow.request),
        response: flow.response.as_deref().map(RawText::from_bytes),
        decoded_response,
    }
}

async fn pump_events(
    mut events: mpsc::Receiver<Event>,
    store: Arc<Store>,
    ui: mpsc::UnboundedSender<UiEvent>,
    scope: Arc<RwLock<Scope>>,
    scan: std::sync::mpsc::SyncSender<Flow>,
) {
    while let Some(event) = events.recv().await {
        match event {
            Event::Flow(flow) => {
                let summary = FlowSummary::of(&flow);
                let scannable = flow.complete
                    && flow.response.is_some()
                    && scope.read().expect("scope lock").allows(&summary.host, &summary.path);
                if scannable && scan.try_send((*flow).clone()).is_err() {
                    tracing::warn!(flow = flow.id, "scanner queue is full; skipping flow");
                }
                store.save_flow(*flow);
                let _ = ui.send(UiEvent::Flow(summary));
            }
            Event::WsFrame(frame) => {
                let flow_id = frame.flow_id;
                store.save_ws_frame(frame);
                let _ = ui.send(UiEvent::WsFrame { flow_id });
            }
            Event::InterceptQueued(pending) => {
                let _ = ui.send(UiEvent::InterceptQueued(pending.into()));
            }
            Event::InterceptCleared(id) => {
                let _ = ui.send(UiEvent::InterceptCleared { id });
            }
        }
    }
}

fn scan_worker(
    flows: std::sync::mpsc::Receiver<Flow>,
    store: Arc<Store>,
    ui: mpsc::UnboundedSender<UiEvent>,
    mut known: HashSet<(String, String, String)>,
) {
    while let Ok(flow) = flows.recv() {
        for finding in scan_flow(&flow) {
            let key = (finding.rule.clone(), finding.host.clone(), finding.dedupe.clone());
            if known.insert(key) {
                let _ = store.save_finding(&finding);
                let _ = ui.send(UiEvent::Finding(finding));
            }
        }
    }
}
