#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sluice_core::browser::{BrowserInfo, BrowserKind};
use sluice_core::engine::{Engine, EngineError, FlowDetail, PendingView, ProxyStatus, SendRequest, UiEvent};
use sluice_core::fuzzer::{FuzzConfig, FuzzResult, FuzzRunInfo, RunState};
use sluice_core::intercept::Verdict;
use sluice_core::model::Target;
use sluice_core::proxy::ProxySettings;
use sluice_core::repeater::{normalize_message, RepeaterTab};
use sluice_core::scanner::Finding;
use sluice_core::scope::Scope;
use sluice_core::store::{FlowFilter, FlowSummary};
use sluice_core::text::RawText;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::mpsc::UnboundedReceiver;

const EVENT_BATCH_INTERVAL: Duration = Duration::from_millis(100);
const DEFAULT_PROJECT: &str = "default.sluice";

struct AppState {
    engine: RwLock<Arc<Engine>>,
    project: RwLock<PathBuf>,
    data_dir: PathBuf,
}

impl AppState {
    fn engine(&self) -> Arc<Engine> {
        self.engine.read().expect("engine lock").clone()
    }
}

type CommandResult<T> = Result<T, String>;

fn text_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Runs a database-backed call away from the threads serving the UI.
async fn blocking<T: Send + 'static>(
    state: State<'_, AppState>,
    call: impl FnOnce(Arc<Engine>) -> Result<T, EngineError> + Send + 'static,
) -> CommandResult<T> {
    let engine = state.engine();
    tauri::async_runtime::spawn_blocking(move || call(engine))
        .await
        .map_err(text_error)?
        .map_err(text_error)
}

/// Forwards engine events to the window in batches of about 100 ms.
fn spawn_bridge(app: AppHandle, mut events: UnboundedReceiver<UiEvent>) {
    tauri::async_runtime::spawn(async move {
        while let Some(first) = events.recv().await {
            let mut batch = vec![first];
            tokio::time::sleep(EVENT_BATCH_INTERVAL).await;
            while let Ok(event) = events.try_recv() {
                batch.push(event);
            }
            let _ = app.emit("sluice-events", &batch);
        }
    });
}

async fn start_saved_listener(engine: &Engine) {
    let Some(addr) = engine.listen_address().ok().and_then(|a| a.parse::<SocketAddr>().ok()) else {
        return;
    };
    // An address outside loopback needs confirming again in Settings.
    let _ = engine.start_proxy(addr, false).await;
}

fn open_engine(app: &AppHandle, project: &Path, data_dir: &Path) -> Result<Arc<Engine>, EngineError> {
    let (engine, events) = Engine::open(project, data_dir)?;
    spawn_bridge(app.clone(), events);
    Ok(engine)
}

#[tauri::command]
async fn open_project(app: AppHandle, state: State<'_, AppState>, path: String) -> CommandResult<()> {
    let path = PathBuf::from(path);
    let engine = open_engine(&app, &path, &state.data_dir).map_err(text_error)?;
    *state.engine.write().expect("engine lock") = engine.clone();
    *state.project.write().expect("project lock") = path;
    start_saved_listener(&engine).await;
    Ok(())
}

#[tauri::command]
fn project_path(state: State<'_, AppState>) -> String {
    state.project.read().expect("project lock").display().to_string()
}

#[tauri::command]
async fn proxy_status(state: State<'_, AppState>) -> CommandResult<ProxyStatus> {
    state.engine().proxy_status().await.map_err(text_error)
}

#[tauri::command]
async fn start_proxy(state: State<'_, AppState>, address: String, allow_external: bool) -> CommandResult<ProxyStatus> {
    let addr: SocketAddr = address.parse().map_err(|_| format!("{address} is not a valid address and port"))?;
    state.engine().start_proxy(addr, allow_external).await.map_err(text_error)
}

#[tauri::command]
async fn stop_proxy(state: State<'_, AppState>) -> CommandResult<()> {
    state.engine().stop_proxy().await;
    Ok(())
}

#[tauri::command]
fn available_browsers(state: State<'_, AppState>) -> Vec<BrowserInfo> {
    state.engine().available_browsers()
}

#[tauri::command]
async fn launch_browser(state: State<'_, AppState>, kind: BrowserKind) -> CommandResult<()> {
    state.engine().launch_browser(kind).await.map_err(text_error)
}

#[tauri::command]
fn get_scope(state: State<'_, AppState>) -> Scope {
    state.engine().scope()
}

#[tauri::command]
fn set_scope(state: State<'_, AppState>, scope: Scope) -> CommandResult<()> {
    state.engine().set_scope(scope).map_err(text_error)
}

#[tauri::command]
fn get_settings(state: State<'_, AppState>) -> ProxySettings {
    state.engine().settings()
}

#[tauri::command]
fn set_settings(state: State<'_, AppState>, settings: ProxySettings) -> CommandResult<()> {
    state.engine().set_settings(settings).map_err(text_error)
}

#[tauri::command]
fn ca_pem(state: State<'_, AppState>) -> String {
    state.engine().ca_pem()
}

#[tauri::command]
fn export_ca(state: State<'_, AppState>, path: String) -> CommandResult<()> {
    std::fs::write(path, state.engine().ca_pem()).map_err(text_error)
}

#[tauri::command]
async fn list_flows(state: State<'_, AppState>, filter: FlowFilter) -> CommandResult<Vec<FlowSummary>> {
    blocking(state, move |engine| engine.list_flows(&filter)).await
}

#[tauri::command]
async fn flow_detail(state: State<'_, AppState>, id: u64) -> CommandResult<FlowDetail> {
    blocking(state, move |engine| engine.flow_detail(id)).await
}

#[derive(Serialize)]
struct WsFrameView {
    from_client: bool,
    opcode: u8,
    payload: RawText,
    truncated: bool,
    at_ms: i64,
}

#[tauri::command]
async fn ws_frames(state: State<'_, AppState>, flow_id: u64) -> CommandResult<Vec<WsFrameView>> {
    blocking(state, move |engine| {
        Ok(engine
            .ws_frames(flow_id)?
            .into_iter()
            .map(|frame| WsFrameView {
                from_client: frame.from_client,
                opcode: frame.opcode,
                payload: RawText::from_bytes(&frame.payload),
                truncated: frame.truncated,
                at_ms: frame.at_ms,
            })
            .collect())
    })
    .await
}

#[tauri::command]
async fn clear_history(state: State<'_, AppState>) -> CommandResult<()> {
    blocking(state, |engine| {
        engine.clear_history();
        Ok(())
    })
    .await
}

#[tauri::command]
fn configure_intercept(state: State<'_, AppState>, requests: bool, responses: bool) {
    state.engine().configure_intercept(requests, responses);
}

#[tauri::command]
fn queued_intercepts(state: State<'_, AppState>) -> Vec<PendingView> {
    state.engine().queued_intercepts()
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
enum Decision {
    Forward,
    Drop,
    Edited { raw: RawText },
}

#[tauri::command]
fn resolve_intercept(state: State<'_, AppState>, id: u64, decision: Decision) -> bool {
    let verdict = match decision {
        Decision::Forward => Verdict::Forward,
        Decision::Drop => Verdict::Drop,
        Decision::Edited { raw } => Verdict::Edited(normalize_message(&raw.to_bytes())),
    };
    state.engine().resolve_intercept(id, verdict)
}

#[tauri::command]
async fn list_tabs(state: State<'_, AppState>) -> CommandResult<Vec<RepeaterTab>> {
    blocking(state, |engine| engine.list_tabs()).await
}

#[tauri::command]
fn create_tab(state: State<'_, AppState>, name: String, target: Target, request: RawText) -> CommandResult<RepeaterTab> {
    state.engine().create_tab(name, target, request).map_err(text_error)
}

#[tauri::command]
fn update_tab(state: State<'_, AppState>, tab: RepeaterTab) -> CommandResult<()> {
    state.engine().update_tab(tab).map_err(text_error)
}

#[tauri::command]
fn delete_tab(state: State<'_, AppState>, id: u64) {
    state.engine().delete_tab(id);
}

#[tauri::command]
async fn tab_sends(state: State<'_, AppState>, tab_id: u64) -> CommandResult<Vec<FlowSummary>> {
    blocking(state, move |engine| engine.tab_sends(tab_id)).await
}

#[tauri::command]
async fn repeater_send(state: State<'_, AppState>, send: SendRequest) -> CommandResult<FlowDetail> {
    state.engine().repeater_send(send).await.map_err(text_error)
}

#[tauri::command]
fn repeater_cancel(state: State<'_, AppState>, tab_id: u64) {
    state.engine().repeater_cancel(tab_id);
}

#[tauri::command]
async fn fuzz_preview(state: State<'_, AppState>, config: FuzzConfig) -> CommandResult<u64> {
    blocking(state, move |engine| engine.fuzz_preview(&config)).await
}

#[tauri::command]
async fn fuzz_start(state: State<'_, AppState>, config: FuzzConfig) -> CommandResult<FuzzRunInfo> {
    state.engine().fuzz_start(config).map_err(text_error)
}

#[tauri::command]
fn fuzz_control(state: State<'_, AppState>, run_id: u64, run_state: RunState) -> CommandResult<()> {
    state.engine().fuzz_control(run_id, run_state).map_err(text_error)
}

#[tauri::command]
async fn list_fuzz_runs(state: State<'_, AppState>) -> CommandResult<Vec<FuzzRunInfo>> {
    blocking(state, |engine| engine.list_fuzz_runs()).await
}

#[tauri::command]
async fn fuzz_results(state: State<'_, AppState>, run_id: u64) -> CommandResult<Vec<FuzzResult>> {
    blocking(state, move |engine| engine.fuzz_results(run_id)).await
}

#[tauri::command]
async fn list_findings(state: State<'_, AppState>) -> CommandResult<Vec<Finding>> {
    blocking(state, |engine| engine.list_findings()).await
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = match std::env::var_os("SLUICE_DATA_DIR") {
                Some(dir) => PathBuf::from(dir),
                None => app.path().app_data_dir()?,
            };
            std::fs::create_dir_all(&data_dir)?;
            let project = data_dir.join(DEFAULT_PROJECT);
            let handle = app.handle().clone();
            let engine = tauri::async_runtime::block_on(async {
                let engine = open_engine(&handle, &project, &data_dir)?;
                start_saved_listener(&engine).await;
                Ok::<_, EngineError>(engine)
            })?;
            app.manage(AppState {
                engine: RwLock::new(engine),
                project: RwLock::new(project),
                data_dir,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            open_project,
            project_path,
            proxy_status,
            start_proxy,
            stop_proxy,
            available_browsers,
            launch_browser,
            get_scope,
            set_scope,
            get_settings,
            set_settings,
            ca_pem,
            export_ca,
            list_flows,
            flow_detail,
            ws_frames,
            clear_history,
            configure_intercept,
            queued_intercepts,
            resolve_intercept,
            list_tabs,
            create_tab,
            update_tab,
            delete_tab,
            tab_sends,
            repeater_send,
            repeater_cancel,
            fuzz_preview,
            fuzz_start,
            fuzz_control,
            list_fuzz_runs,
            fuzz_results,
            list_findings,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Sluice");
}
