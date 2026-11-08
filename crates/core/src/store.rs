//! The project file: one SQLite database. All writes go through one thread
//! that batches them into transactions, so capture never waits on disk.

use std::path::Path;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex, RwLock};

use rusqlite::functions::FunctionFlags;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::fuzzer::{FuzzResult, FuzzRunInfo};
use crate::http::decode::decode_response;
use crate::http::{parse_request_head, parse_response_head};
use crate::model::{Flow, Source, Target, WsFrame};
use crate::repeater::RepeaterTab;
use crate::scanner::Finding;
use crate::scope::Scope;
use crate::site_map::{SitePlace, SiteRow};

const MAX_BATCH: usize = 500;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS flows (
  id INTEGER PRIMARY KEY, source TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
  tls INTEGER NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, status INTEGER,
  request_len INTEGER NOT NULL, response_len INTEGER NOT NULL, mime TEXT NOT NULL,
  started_ms INTEGER NOT NULL, duration_ms INTEGER, edited INTEGER NOT NULL,
  truncated INTEGER NOT NULL, tls_error TEXT, error TEXT, complete INTEGER NOT NULL,
  request BLOB NOT NULL, response BLOB
);
CREATE INDEX IF NOT EXISTS flows_host ON flows(host);
CREATE TABLE IF NOT EXISTS ws_frames (
  id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id INTEGER NOT NULL, from_client INTEGER NOT NULL,
  opcode INTEGER NOT NULL, payload BLOB NOT NULL, truncated INTEGER NOT NULL, at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ws_frames_flow ON ws_frames(flow_id);
CREATE TABLE IF NOT EXISTS repeater_tabs (id INTEGER PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS repeater_sends (tab_id INTEGER NOT NULL, flow_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fuzz_runs (id INTEGER PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS fuzz_results (
  run_id INTEGER NOT NULL, idx INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY (run_id, idx)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, host TEXT NOT NULL, dedupe TEXT NOT NULL,
  data TEXT NOT NULL, UNIQUE (rule, host, dedupe)
);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("stored data is invalid: {0}")]
    Json(#[from] serde_json::Error),
}

/// The fields a history row needs, without the message bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummary {
    pub id: u64,
    pub source: Source,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    pub request_len: u64,
    pub response_len: u64,
    pub mime: String,
    pub started_ms: i64,
    pub duration_ms: Option<u64>,
    pub edited: bool,
    pub truncated: bool,
    pub tls_error: Option<String>,
    pub error: Option<String>,
    pub complete: bool,
}

impl FlowSummary {
    pub fn of(flow: &Flow) -> Self {
        let request = parse_request_head(&flow.request).ok();
        let response = flow.response.as_deref().and_then(|r| parse_response_head(r).ok());
        let mime = response
            .as_ref()
            .and_then(|h| h.header("content-type"))
            .map(|v| String::from_utf8_lossy(v).split(';').next().unwrap_or("").trim().to_ascii_lowercase())
            .unwrap_or_default();
        Self {
            id: flow.id,
            source: flow.source,
            host: flow.target.host.clone(),
            port: flow.target.port,
            tls: flow.target.tls,
            method: request.as_ref().map(|h| h.method.clone()).unwrap_or_default(),
            path: request.as_ref().map(|h| h.target.clone()).unwrap_or_default(),
            status: response.as_ref().map(|h| h.status),
            request_len: flow.request.len() as u64,
            response_len: flow.response.as_ref().map_or(0, |r| r.len() as u64),
            mime,
            started_ms: flow.started_ms,
            duration_ms: flow.duration_ms,
            edited: flow.edited,
            truncated: flow.truncated,
            tls_error: flow.tls_error.clone(),
            error: flow.error.clone(),
            complete: flow.complete,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortColumn {
    Id,
    StartedMs,
    Method,
    Host,
    Path,
    Status,
    ResponseLen,
    DurationMs,
    Mime,
}

impl SortColumn {
    fn order_by(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::StartedMs => "started_ms",
            Self::Method => "method COLLATE NOCASE",
            Self::Host => "host COLLATE NOCASE",
            Self::Path => "path COLLATE NOCASE",
            Self::Status => "status",
            Self::ResponseLen => "response_len",
            Self::DurationMs => "duration_ms",
            Self::Mime => "mime COLLATE NOCASE",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FlowFilter {
    pub source: Option<Source>,
    pub host: Option<String>,
    pub method: Option<String>,
    /// 2 means 2xx, and so on.
    pub status_class: Option<u16>,
    pub mime: Option<String>,
    pub text: Option<String>,
    pub in_scope_only: bool,
    pub before_id: Option<u64>,
    pub limit: Option<u32>,
    /// Newest first when unset.
    pub sort: Option<SortColumn>,
    pub ascending: bool,
    /// How to page through a sorted list, where `before_id` means nothing.
    pub offset: Option<u32>,
    /// Only requests at or below this node of the site map.
    pub site: Option<SitePlace>,
}

fn source_name(source: Source) -> &'static str {
    match source {
        Source::Proxy => "proxy",
        Source::Repeater => "repeater",
        Source::Fuzzer => "fuzzer",
    }
}

fn source_from(name: &str) -> Source {
    match name {
        "repeater" => Source::Repeater,
        "fuzzer" => Source::Fuzzer,
        _ => Source::Proxy,
    }
}

const SUMMARY_COLUMNS: &str = "id, source, host, port, tls, method, path, status, request_len, response_len, \
                               mime, started_ms, duration_ms, edited, truncated, tls_error, error, complete";

fn summary_from_row(row: &Row<'_>) -> rusqlite::Result<FlowSummary> {
    Ok(FlowSummary {
        id: row.get(0)?,
        source: source_from(&row.get::<_, String>(1)?),
        host: row.get(2)?,
        port: row.get(3)?,
        tls: row.get(4)?,
        method: row.get(5)?,
        path: row.get(6)?,
        status: row.get(7)?,
        request_len: row.get(8)?,
        response_len: row.get(9)?,
        mime: row.get(10)?,
        started_ms: row.get(11)?,
        duration_ms: row.get(12)?,
        edited: row.get(13)?,
        truncated: row.get(14)?,
        tls_error: row.get(15)?,
        error: row.get(16)?,
        complete: row.get(17)?,
    })
}

fn write_flow(conn: &Connection, flow: &Flow) -> rusqlite::Result<()> {
    let s = FlowSummary::of(flow);
    conn.prepare_cached(
        "INSERT OR REPLACE INTO flows VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
    )?
    .execute(params![
        s.id,
        source_name(s.source),
        s.host,
        s.port,
        s.tls,
        s.method,
        s.path,
        s.status,
        s.request_len,
        s.response_len,
        s.mime,
        s.started_ms,
        s.duration_ms,
        s.edited,
        s.truncated,
        s.tls_error,
        s.error,
        s.complete,
        flow.request,
        flow.response,
    ])?;
    Ok(())
}

type WriteOp = Box<dyn FnOnce(&Connection) -> rusqlite::Result<()> + Send>;

enum Message {
    Write(WriteOp),
    Barrier(std_mpsc::Sender<()>),
}

fn writer_loop(mut conn: Connection, rx: std_mpsc::Receiver<Message>) {
    while let Ok(first) = rx.recv() {
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(message) => batch.push(message),
                Err(_) => break,
            }
        }
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                tracing::error!("could not begin transaction: {e}");
                continue;
            }
        };
        let mut barriers = Vec::new();
        for message in batch {
            match message {
                Message::Write(op) => {
                    if let Err(e) = op(&tx) {
                        tracing::error!("write failed: {e}");
                    }
                }
                Message::Barrier(done) => barriers.push(done),
            }
        }
        if let Err(e) = tx.commit() {
            tracing::error!("commit failed: {e}");
        }
        for done in barriers {
            let _ = done.send(());
        }
    }
}

pub struct Store {
    writer: std_mpsc::Sender<Message>,
    reader: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path, scope: Arc<RwLock<Scope>>) -> Result<Self, StoreError> {
        let write_conn = Connection::open(path)?;
        write_conn.pragma_update(None, "journal_mode", "WAL")?;
        write_conn.pragma_update(None, "synchronous", "NORMAL")?;
        write_conn.execute_batch(SCHEMA)?;
        let reader = Connection::open(path)?;
        reader.create_scalar_function("in_scope", 2, FunctionFlags::SQLITE_UTF8, move |ctx| {
            let host: String = ctx.get(0)?;
            let path: String = ctx.get(1)?;
            Ok(scope.read().expect("scope lock").allows(&host, &path))
        })?;
        reader.create_scalar_function("decoded_response", 1, FunctionFlags::SQLITE_UTF8, |ctx| {
            let raw: Option<Vec<u8>> = ctx.get(0)?;
            Ok(raw.and_then(|r| decode_response(&r)))
        })?;
        let (writer, rx) = std_mpsc::channel();
        std::thread::spawn(move || writer_loop(write_conn, rx));
        Ok(Self {
            writer,
            reader: Mutex::new(reader),
        })
    }

    fn write(&self, op: impl FnOnce(&Connection) -> rusqlite::Result<()> + Send + 'static) {
        let _ = self.writer.send(Message::Write(Box::new(op)));
    }

    /// Blocks until every write queued so far is committed.
    pub fn flush(&self) {
        let (done, wait) = std_mpsc::channel();
        if self.writer.send(Message::Barrier(done)).is_ok() {
            let _ = wait.recv();
        }
    }

    pub fn save_flow(&self, flow: Flow) {
        self.write(move |conn| write_flow(conn, &flow));
    }

    pub fn save_ws_frame(&self, frame: WsFrame) {
        self.write(move |conn| {
            conn.prepare_cached(
                "INSERT INTO ws_frames (flow_id, from_client, opcode, payload, truncated, at_ms) VALUES (?1,?2,?3,?4,?5,?6)",
            )?
            .execute(params![
                frame.flow_id,
                frame.from_client,
                frame.opcode,
                frame.payload,
                frame.truncated,
                frame.at_ms
            ])?;
            Ok(())
        });
    }

    pub fn last_flow_id(&self) -> Result<u64, StoreError> {
        self.flush();
        let conn = self.reader.lock().expect("reader lock");
        Ok(conn.query_row("SELECT COALESCE(MAX(id), 0) FROM flows", [], |r| r.get(0))?)
    }

    pub fn list_flows(&self, filter: &FlowFilter) -> Result<Vec<FlowSummary>, StoreError> {
        let mut clauses = vec!["1=1".to_string()];
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        use rusqlite::types::Value;
        if let Some(source) = filter.source {
            clauses.push("source = ?".into());
            args.push(Value::Text(source_name(source).into()));
        }
        if let Some(host) = &filter.host {
            clauses.push("instr(lower(host), lower(?)) > 0".into());
            args.push(Value::Text(host.clone()));
        }
        if let Some(method) = &filter.method {
            clauses.push("method = ? COLLATE NOCASE".into());
            args.push(Value::Text(method.clone()));
        }
        if let Some(class) = filter.status_class {
            clauses.push("status / 100 = ?".into());
            args.push(Value::Integer(class as i64));
        }
        if let Some(mime) = &filter.mime {
            clauses.push("instr(mime, lower(?)) > 0".into());
            args.push(Value::Text(mime.clone()));
        }
        if let Some(text) = &filter.text {
            clauses.push(
                "(instr(request, ?) > 0 OR instr(COALESCE(response, x''), ?) > 0 \
                 OR instr(decoded_response(response), ?) > 0)"
                    .into(),
            );
            args.push(Value::Blob(text.clone().into_bytes()));
            args.push(Value::Blob(text.clone().into_bytes()));
            args.push(Value::Blob(text.clone().into_bytes()));
        }
        if filter.in_scope_only {
            clauses.push("in_scope(host, path)".into());
        }
        if let Some(SitePlace { target, path }) = &filter.site {
            clauses.push("host = ? AND port = ? AND tls = ?".into());
            args.push(Value::Text(target.host.clone()));
            args.push(Value::Integer(target.port as i64));
            args.push(Value::Integer(target.tls as i64));
            if !path.is_empty() {
                // `/a` must not take in `/ab`, but does take in `/a/b` and `/a?x`.
                let (folder, query) = (format!("{path}/"), format!("{path}?"));
                clauses.push("(path = ? OR substr(path, 1, ?) = ? OR substr(path, 1, ?) = ?)".into());
                args.push(Value::Text(path.clone()));
                args.push(Value::Integer(folder.chars().count() as i64));
                args.push(Value::Text(folder));
                args.push(Value::Integer(query.chars().count() as i64));
                args.push(Value::Text(query));
            }
        }
        if let Some(before) = filter.before_id {
            clauses.push("id < ?".into());
            args.push(Value::Integer(before as i64));
        }
        args.push(Value::Integer(filter.limit.unwrap_or(1000).min(10_000) as i64));
        args.push(Value::Integer(filter.offset.unwrap_or(0) as i64));
        let order = match filter.sort {
            Some(column) => format!("{} {}, id DESC", column.order_by(), if filter.ascending { "ASC" } else { "DESC" }),
            None => "id DESC".to_string(),
        };
        let sql = format!(
            "SELECT {SUMMARY_COLUMNS} FROM flows WHERE {} ORDER BY {order} LIMIT ? OFFSET ?",
            clauses.join(" AND ")
        );
        let conn = self.reader.lock().expect("reader lock");
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(args), summary_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Proxy traffic grouped for the site map, without reading any message.
    pub fn site_rows(&self, in_scope_only: bool) -> Result<Vec<SiteRow>, StoreError> {
        let scope = if in_scope_only { "AND in_scope(host, path)" } else { "" };
        let sql = format!(
            "SELECT host, port, tls, path, status, COUNT(*), MAX(id) FROM flows \
             WHERE source = 'proxy' {scope} GROUP BY host, port, tls, path, status"
        );
        let conn = self.reader.lock().expect("reader lock");
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map([], |row| {
            Ok(SiteRow {
                target: Target {
                    host: row.get(0)?,
                    port: row.get(1)?,
                    tls: row.get(2)?,
                },
                path: row.get(3)?,
                status: row.get(4)?,
                requests: row.get(5)?,
                latest_id: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn get_flow(&self, id: u64) -> Result<Option<Flow>, StoreError> {
        let conn = self.reader.lock().expect("reader lock");
        let flow = conn
            .query_row(
                &format!("SELECT {SUMMARY_COLUMNS}, request, response FROM flows WHERE id = ?1"),
                [id],
                |row| {
                    let s = summary_from_row(row)?;
                    Ok(Flow {
                        id: s.id,
                        source: s.source,
                        target: Target {
                            host: s.host,
                            port: s.port,
                            tls: s.tls,
                        },
                        request: row.get(18)?,
                        response: row.get(19)?,
                        started_ms: s.started_ms,
                        duration_ms: s.duration_ms,
                        edited: s.edited,
                        truncated: s.truncated,
                        tls_error: s.tls_error,
                        error: s.error,
                        complete: s.complete,
                    })
                },
            )
            .optional()?;
        Ok(flow)
    }

    pub fn ws_frames(&self, flow_id: u64) -> Result<Vec<WsFrame>, StoreError> {
        let conn = self.reader.lock().expect("reader lock");
        let mut statement = conn.prepare(
            "SELECT flow_id, from_client, opcode, payload, truncated, at_ms FROM ws_frames WHERE flow_id = ?1 ORDER BY id",
        )?;
        let rows = statement.query_map([flow_id], |row| {
            Ok(WsFrame {
                flow_id: row.get(0)?,
                from_client: row.get(1)?,
                opcode: row.get(2)?,
                payload: row.get(3)?,
                truncated: row.get(4)?,
                at_ms: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn clear_history(&self) {
        self.write(|conn| {
            conn.execute_batch("DELETE FROM flows WHERE source = 'proxy'; DELETE FROM ws_frames;")
        });
    }

    pub fn set_value<T: Serialize>(&self, key: &str, value: &T) -> Result<(), StoreError> {
        let key = key.to_string();
        let json = serde_json::to_string(value)?;
        self.write(move |conn| {
            conn.execute("INSERT OR REPLACE INTO kv VALUES (?1, ?2)", params![key, json])?;
            Ok(())
        });
        Ok(())
    }

    pub fn get_value<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, StoreError> {
        let conn = self.reader.lock().expect("reader lock");
        let json: Option<String> = conn
            .query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0))
            .optional()?;
        Ok(json.map(|j| serde_json::from_str(&j)).transpose()?)
    }

    pub fn save_tab(&self, tab: &RepeaterTab) -> Result<(), StoreError> {
        let id = tab.id;
        let json = serde_json::to_string(tab)?;
        self.write(move |conn| {
            conn.execute("INSERT OR REPLACE INTO repeater_tabs VALUES (?1, ?2)", params![id, json])?;
            Ok(())
        });
        Ok(())
    }

    pub fn delete_tab(&self, id: u64) {
        self.write(move |conn| {
            conn.execute("DELETE FROM repeater_tabs WHERE id = ?1", [id])?;
            conn.execute("DELETE FROM repeater_sends WHERE tab_id = ?1", [id])?;
            Ok(())
        });
    }

    pub fn list_tabs(&self) -> Result<Vec<RepeaterTab>, StoreError> {
        self.json_rows("SELECT data FROM repeater_tabs ORDER BY id", [])
    }

    pub fn link_send(&self, tab_id: u64, flow_id: u64) {
        self.write(move |conn| {
            conn.execute("INSERT INTO repeater_sends VALUES (?1, ?2)", [tab_id, flow_id])?;
            Ok(())
        });
    }

    pub fn tab_sends(&self, tab_id: u64) -> Result<Vec<FlowSummary>, StoreError> {
        let conn = self.reader.lock().expect("reader lock");
        let mut statement = conn.prepare(&format!(
            "SELECT {SUMMARY_COLUMNS} FROM flows WHERE id IN \
             (SELECT flow_id FROM repeater_sends WHERE tab_id = ?1) ORDER BY id DESC"
        ))?;
        let rows = statement.query_map([tab_id], summary_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn save_fuzz_run(&self, run: &FuzzRunInfo) -> Result<(), StoreError> {
        let id = run.id;
        let json = serde_json::to_string(run)?;
        self.write(move |conn| {
            conn.execute("INSERT OR REPLACE INTO fuzz_runs VALUES (?1, ?2)", params![id, json])?;
            Ok(())
        });
        Ok(())
    }

    pub fn list_fuzz_runs(&self) -> Result<Vec<FuzzRunInfo>, StoreError> {
        self.json_rows("SELECT data FROM fuzz_runs ORDER BY id DESC", [])
    }

    pub fn save_fuzz_result(&self, result: &FuzzResult) -> Result<(), StoreError> {
        let (run, index) = (result.run_id, result.index);
        let json = serde_json::to_string(result)?;
        self.write(move |conn| {
            conn.prepare_cached("INSERT OR REPLACE INTO fuzz_results VALUES (?1, ?2, ?3)")?
                .execute(params![run, index, json])?;
            Ok(())
        });
        Ok(())
    }

    pub fn fuzz_results(&self, run_id: u64) -> Result<Vec<FuzzResult>, StoreError> {
        self.json_rows("SELECT data FROM fuzz_results WHERE run_id = ?1 ORDER BY idx", [run_id])
    }

    pub fn save_finding(&self, finding: &Finding) -> Result<(), StoreError> {
        let (rule, host, dedupe) = (finding.rule.clone(), finding.host.clone(), finding.dedupe.clone());
        let json = serde_json::to_string(finding)?;
        self.write(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO findings (rule, host, dedupe, data) VALUES (?1,?2,?3,?4)",
                params![rule, host, dedupe, json],
            )?;
            Ok(())
        });
        Ok(())
    }

    pub fn list_findings(&self) -> Result<Vec<Finding>, StoreError> {
        self.json_rows("SELECT data FROM findings ORDER BY id DESC", [])
    }

    fn json_rows<T: DeserializeOwned, P: rusqlite::Params>(&self, sql: &str, args: P) -> Result<Vec<T>, StoreError> {
        let conn = self.reader.lock().expect("reader lock");
        let mut statement = conn.prepare(sql)?;
        let texts = statement.query_map(args, |row| row.get::<_, String>(0))?;
        let mut items = Vec::new();
        for text in texts {
            items.push(serde_json::from_str(&text?)?);
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(id: u64, host: &str, path: &str, status: u16) -> Flow {
        let target = Target {
            host: host.into(),
            port: 80,
            tls: false,
        };
        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes();
        let mut flow = Flow::new(id, Source::Proxy, target, request);
        flow.response = Some(format!("HTTP/1.1 {status} X\r\nContent-Type: text/HTML; charset=x\r\n\r\nneedle").into_bytes());
        flow.finish();
        flow
    }

    fn open() -> (tempfile::TempDir, Store, Arc<RwLock<Scope>>) {
        let dir = tempfile::tempdir().unwrap();
        let scope = Arc::new(RwLock::new(Scope::default()));
        let store = Store::open(&dir.path().join("p.sluice"), scope.clone()).unwrap();
        (dir, store, scope)
    }

    #[test]
    fn flow_round_trips_with_derived_columns() {
        let (_dir, store, _) = open();
        store.save_flow(flow(7, "a.test", "/x", 404));
        store.flush();
        let rows = store.list_flows(&FlowFilter::default()).unwrap();
        assert_eq!(rows[0].method, "GET");
        assert_eq!(rows[0].path, "/x");
        assert_eq!(rows[0].status, Some(404));
        assert_eq!(rows[0].mime, "text/html");
        assert_eq!(store.get_flow(7).unwrap().unwrap().request, flow(7, "a.test", "/x", 404).request);
        assert_eq!(store.last_flow_id().unwrap(), 7);
    }

    #[test]
    fn site_rows_group_proxy_traffic_only() {
        let (_dir, store, scope) = open();
        store.save_flow(flow(1, "a.test", "/x", 200));
        store.save_flow(flow(2, "a.test", "/x", 200));
        store.save_flow(flow(3, "a.test", "/x", 500));
        store.save_flow(flow(4, "b.test", "/y", 200));
        let mut sent = flow(5, "a.test", "/repeated", 200);
        sent.source = Source::Repeater;
        store.save_flow(sent);
        store.flush();

        let mut rows = store.site_rows(false).unwrap();
        rows.sort_by_key(|row| row.latest_id);
        let got: Vec<_> = rows.iter().map(|r| (r.target.host.as_str(), r.path.as_str(), r.status, r.requests, r.latest_id)).collect();
        assert_eq!(
            got,
            [("a.test", "/x", Some(200), 2, 2), ("a.test", "/x", Some(500), 1, 3), ("b.test", "/y", Some(200), 1, 4)]
        );

        scope.write().unwrap().include.push(crate::scope::ScopeRule {
            host: "b.test".into(),
            path_prefix: String::new(),
        });
        let rows = store.site_rows(true).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target.host, "b.test");
    }

    #[test]
    fn a_site_place_takes_in_what_is_below_it_only() {
        let (_dir, store, _) = open();
        for (id, path) in [(1, "/a"), (2, "/a/"), (3, "/a/b"), (4, "/a?x=1"), (5, "/ab"), (6, "/")] {
            store.save_flow(flow(id, "a.test", path, 200));
        }
        store.save_flow(flow(7, "b.test", "/a", 200));
        store.flush();
        let ids = |path: &str| -> Vec<u64> {
            let site = SitePlace {
                target: Target {
                    host: "a.test".into(),
                    port: 80,
                    tls: false,
                },
                path: path.into(),
            };
            let filter = FlowFilter {
                site: Some(site),
                ..Default::default()
            };
            store.list_flows(&filter).unwrap().iter().map(|f| f.id).collect()
        };
        assert_eq!(ids("/a"), [4, 3, 2, 1]);
        assert_eq!(ids("/a/b"), [3]);
        assert_eq!(ids(""), [6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn saving_again_updates_the_row() {
        let (_dir, store, _) = open();
        store.save_flow(flow(1, "a.test", "/", 200));
        store.save_flow(flow(1, "a.test", "/", 500));
        store.flush();
        let rows = store.list_flows(&FlowFilter::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, Some(500));
    }

    #[test]
    fn filters_combine() {
        let (_dir, store, scope) = open();
        store.save_flow(flow(1, "a.test", "/one", 200));
        store.save_flow(flow(2, "b.test", "/two", 404));
        store.flush();
        let ids = |filter: FlowFilter| -> Vec<u64> {
            store.list_flows(&filter).unwrap().iter().map(|r| r.id).collect()
        };
        assert_eq!(ids(FlowFilter { host: Some("A.T".into()), ..Default::default() }), [1]);
        assert_eq!(ids(FlowFilter { status_class: Some(4), ..Default::default() }), [2]);
        assert_eq!(ids(FlowFilter { text: Some("/two".into()), ..Default::default() }), [2]);
        assert_eq!(ids(FlowFilter { text: Some("needle".into()), ..Default::default() }), [2, 1]);
        assert_eq!(ids(FlowFilter { before_id: Some(2), ..Default::default() }), [1]);
        scope.write().unwrap().include.push(crate::scope::ScopeRule {
            host: "b.test".into(),
            path_prefix: String::new(),
        });
        assert_eq!(ids(FlowFilter { in_scope_only: true, ..Default::default() }), [2]);
    }

    #[test]
    fn flows_sort_by_any_column_and_page_with_offset() {
        let (_dir, store, _) = open();
        store.save_flow(flow(1, "b.test", "/x", 404));
        store.save_flow(flow(2, "A.test", "/z", 200));
        store.save_flow(flow(3, "c.test", "/y", 500));
        store.flush();
        let ids = |sort: Option<SortColumn>, ascending: bool, offset: Option<u32>| -> Vec<u64> {
            let filter = FlowFilter { sort, ascending, offset, limit: Some(2), ..Default::default() };
            store.list_flows(&filter).unwrap().iter().map(|r| r.id).collect()
        };
        assert_eq!(ids(None, false, None), [3, 2]);
        assert_eq!(ids(Some(SortColumn::Host), true, None), [2, 1], "text ignores case");
        assert_eq!(ids(Some(SortColumn::Status), false, None), [3, 1]);
        assert_eq!(ids(Some(SortColumn::Status), false, Some(2)), [2]);
        assert_eq!(ids(Some(SortColumn::Path), true, Some(1)), [3, 2]);
    }

    #[test]
    fn equal_sort_values_are_newest_first_and_sort_names_match_the_interface() {
        let (_dir, store, _) = open();
        store.save_flow(flow(1, "a.test", "/", 200));
        store.save_flow(flow(2, "a.test", "/", 200));
        store.flush();
        let filter: FlowFilter = serde_json::from_str(r#"{"sort":"response_len","ascending":true}"#).unwrap();
        assert_eq!(store.list_flows(&filter).unwrap().iter().map(|r| r.id).collect::<Vec<_>>(), [2, 1]);
    }

    #[test]
    fn text_search_reads_compressed_responses() {
        use std::io::Write;
        let (_dir, store, _) = open();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"hidden needle").unwrap();
        let mut compressed = flow(1, "a.test", "/", 200);
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        response.extend(encoder.finish().unwrap());
        compressed.response = Some(response);
        store.save_flow(compressed);
        store.flush();
        let found = |text: &str| {
            let filter = FlowFilter { text: Some(text.into()), ..Default::default() };
            store.list_flows(&filter).unwrap().len()
        };
        assert_eq!(found("hidden needle"), 1);
        assert_eq!(found("Content-Encoding"), 1);
        assert_eq!(found("absent"), 0);
    }

    #[test]
    fn values_persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.sluice");
        let scope = Arc::new(RwLock::new(Scope::default()));
        {
            let store = Store::open(&path, scope.clone()).unwrap();
            store.set_value("answer", &42u32).unwrap();
            store.flush();
        }
        let store = Store::open(&path, scope).unwrap();
        assert_eq!(store.get_value::<u32>("answer").unwrap(), Some(42));
        assert_eq!(store.get_value::<u32>("missing").unwrap(), None);
    }
}
