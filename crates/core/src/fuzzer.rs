//! Sends a template request many times with payloads substituted at marked
//! positions, within limits the user can see before anything is sent.

use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;

use crate::engine::UiEvent;
use crate::http::parse_request_head;
use crate::model::{now_ms, Flow, IdGen, Source, Target};
use crate::repeater::normalize_message;
use crate::scope::Scope;
use crate::store::Store;
use crate::text::{encode, Encoding};
use crate::upstream::{send_raw, SendOptions};

pub const MARKER: char = '§';
const MAX_REQUESTS: u64 = 1_000_000;
const MAX_CONCURRENCY: usize = 100;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FuzzError {
    #[error("the template has no payload positions; mark them with § on both sides")]
    NoPositions,
    #[error("the template has an unmatched § marker")]
    UnmatchedMarker,
    #[error("this attack needs {needed} payload list(s) but {given} were provided")]
    WrongListCount { needed: usize, given: usize },
    #[error("a payload list is empty")]
    EmptyList,
    #[error("this attack would send {0} requests, more than the limit of {MAX_REQUESTS}")]
    TooManyRequests(u128),
    #[error("{0} is not in scope; add it under Settings before fuzzing")]
    OutOfScope(String),
    #[error("the template is not a valid HTTP request: {0}")]
    BadTemplate(String),
    #[error("invalid match pattern: {0}")]
    BadPattern(String),
    #[error("could not read payload file: {0}")]
    PayloadFile(String),
    #[error("concurrency must be between 1 and {MAX_CONCURRENCY}")]
    BadConcurrency,
    #[error("number range is invalid")]
    BadRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttackMode {
    /// One position at a time; the others keep their default values.
    Single,
    /// The same payload in every position.
    Same,
    /// The nth payload of each list together.
    Parallel,
    /// Every combination across the lists.
    Combinations,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadSource {
    List(Vec<String>),
    File(String),
    Numbers { from: i64, to: i64, step: i64 },
}

impl PayloadSource {
    fn load(&self, encoding: Encoding) -> Result<Vec<Vec<u8>>, FuzzError> {
        match self {
            Self::List(items) => Ok(items.iter().map(|s| encode(s, encoding)).collect()),
            Self::File(path) => {
                let bytes = std::fs::read(Path::new(path)).map_err(|e| FuzzError::PayloadFile(e.to_string()))?;
                Ok(bytes
                    .split(|b| *b == b'\n')
                    .map(|line| line.strip_suffix(b"\r").unwrap_or(line).to_vec())
                    .filter(|line| !line.is_empty())
                    .collect())
            }
            Self::Numbers { from, to, step } => {
                if *step == 0 || (to > from && *step < 0) || (to < from && *step > 0) {
                    return Err(FuzzError::BadRange);
                }
                let count = ((*to as i128 - *from as i128) / *step as i128) as u128 + 1;
                if count > MAX_REQUESTS as u128 {
                    return Err(FuzzError::TooManyRequests(count));
                }
                Ok((0..count as i64).map(|i| (from + i * step).to_string().into_bytes()).collect())
            }
        }
    }
}

fn default_concurrency() -> usize {
    2
}

fn default_delay() -> u64 {
    100
}

fn default_timeout() -> u64 {
    30_000
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzConfig {
    pub target: Target,
    pub template: String,
    pub encoding: Encoding,
    pub mode: AttackMode,
    pub payloads: Vec<PayloadSource>,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// Minimum gap between starting one request and the next.
    #[serde(default = "default_delay")]
    pub delay_ms: u64,
    #[serde(default)]
    pub grep: Option<String>,
    #[serde(default = "default_true")]
    pub normalize: bool,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

/// A template split around its positions, with the payloads to use.
#[derive(Debug)]
pub struct AttackPlan {
    /// Alternates literal text and position defaults, starting with a literal.
    segments: Vec<Vec<u8>>,
    mode: AttackMode,
    lists: Vec<Vec<Vec<u8>>>,
    total: u64,
    normalize: bool,
}

impl AttackPlan {
    pub fn new(config: &FuzzConfig) -> Result<Self, FuzzError> {
        let parts: Vec<&str> = config.template.split(MARKER).collect();
        if parts.len() == 1 {
            return Err(FuzzError::NoPositions);
        }
        if parts.len().is_multiple_of(2) {
            return Err(FuzzError::UnmatchedMarker);
        }
        let positions = parts.len() / 2;
        let needed = match config.mode {
            AttackMode::Single | AttackMode::Same => 1,
            AttackMode::Parallel | AttackMode::Combinations => positions,
        };
        if config.payloads.len() != needed {
            return Err(FuzzError::WrongListCount {
                needed,
                given: config.payloads.len(),
            });
        }
        let lists = config
            .payloads
            .iter()
            .map(|p| p.load(config.encoding))
            .collect::<Result<Vec<_>, _>>()?;
        if lists.iter().any(|l| l.is_empty()) {
            return Err(FuzzError::EmptyList);
        }
        let total: u128 = match config.mode {
            AttackMode::Single => positions as u128 * lists[0].len() as u128,
            AttackMode::Same => lists[0].len() as u128,
            AttackMode::Parallel => lists.iter().map(|l| l.len() as u128).min().unwrap_or(0),
            AttackMode::Combinations => lists
                .iter()
                .try_fold(1u128, |acc, l| acc.checked_mul(l.len() as u128))
                .unwrap_or(u128::MAX),
        };
        if total > MAX_REQUESTS as u128 {
            return Err(FuzzError::TooManyRequests(total));
        }
        Ok(Self {
            segments: parts.iter().map(|s| encode(s, config.encoding)).collect(),
            mode: config.mode,
            lists,
            total: total as u64,
            normalize: config.normalize,
        })
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    fn positions(&self) -> usize {
        self.segments.len() / 2
    }

    /// The payload for each position at `index`; `None` keeps the default.
    fn choose(&self, index: u64) -> Vec<Option<&[u8]>> {
        let positions = self.positions();
        let index = index as usize;
        match self.mode {
            AttackMode::Single => {
                let list = &self.lists[0];
                let (position, item) = (index / list.len(), index % list.len());
                (0..positions)
                    .map(|p| (p == position).then(|| list[item].as_slice()))
                    .collect()
            }
            AttackMode::Same => vec![Some(self.lists[0][index].as_slice()); positions],
            AttackMode::Parallel => self.lists.iter().map(|l| Some(l[index].as_slice())).collect(),
            AttackMode::Combinations => {
                let mut remaining = index;
                let mut chosen = vec![None; positions];
                // The last position varies fastest.
                for (slot, list) in chosen.iter_mut().zip(&self.lists).rev() {
                    *slot = Some(list[remaining % list.len()].as_slice());
                    remaining /= list.len();
                }
                chosen
            }
        }
    }

    fn render(&self, chosen: &[Option<&[u8]>]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, segment) in self.segments.iter().enumerate() {
            match (i % 2 == 1).then(|| chosen[i / 2]).flatten() {
                Some(payload) => out.extend_from_slice(payload),
                None => out.extend_from_slice(segment),
            }
        }
        if self.normalize {
            normalize_message(&out)
        } else {
            out
        }
    }

    /// The request as it would be sent, plus readable payload labels.
    pub fn build(&self, index: u64) -> (Vec<u8>, Vec<String>) {
        let chosen = self.choose(index);
        let labels = chosen
            .iter()
            .flatten()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        (self.render(&chosen), labels)
    }

    /// The template with every position left at its default value.
    pub fn baseline(&self) -> Vec<u8> {
        self.render(&vec![None; self.positions()])
    }
}

fn path_of(request: &[u8]) -> Result<String, FuzzError> {
    parse_request_head(request)
        .map(|h| h.target)
        .map_err(|e| FuzzError::BadTemplate(e.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunState {
    Running,
    Paused,
    Stopped,
    Finished,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzRunInfo {
    pub id: u64,
    pub config: FuzzConfig,
    pub total: u64,
    pub state: RunState,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub run_id: u64,
    pub index: u64,
    pub payloads: Vec<String>,
    pub flow_id: u64,
    pub status: Option<u16>,
    pub length: u64,
    pub duration_ms: u64,
    pub matched: bool,
    pub error: Option<String>,
}

pub struct FuzzDeps {
    pub store: Arc<Store>,
    pub ids: Arc<IdGen>,
    pub scope: Arc<RwLock<Scope>>,
    pub ui: mpsc::UnboundedSender<UiEvent>,
}

/// Checks everything that can be known before sending, and returns the plan.
pub fn prepare(config: &FuzzConfig, scope: &Scope) -> Result<(AttackPlan, Option<Regex>), FuzzError> {
    if !(1..=MAX_CONCURRENCY).contains(&config.concurrency) {
        return Err(FuzzError::BadConcurrency);
    }
    let plan = AttackPlan::new(config)?;
    let grep = match config.grep.as_deref().filter(|g| !g.is_empty()) {
        Some(pattern) => Some(Regex::new(pattern).map_err(|e| FuzzError::BadPattern(e.to_string()))?),
        None => None,
    };
    let path = path_of(&plan.baseline())?;
    if !scope.contains(&config.target.host, &path) {
        return Err(FuzzError::OutOfScope(format!("{}{}", config.target.host, path)));
    }
    Ok((plan, grep))
}

async fn send_one(
    run_id: u64,
    index: u64,
    request: Vec<u8>,
    labels: Vec<String>,
    config: Arc<FuzzConfig>,
    grep: Option<Regex>,
    deps: Arc<FuzzDeps>,
) {
    let mut flow = Flow::new(deps.ids.next(), Source::Fuzzer, config.target.clone(), request);
    let options = SendOptions {
        timeout: Duration::from_millis(config.timeout_ms),
        ..SendOptions::default()
    };
    // A payload in the path could otherwise step outside the allowed prefix.
    let allowed = path_of(&flow.request)
        .map(|path| deps.scope.read().expect("scope lock").contains(&config.target.host, &path))
        .unwrap_or(true);
    let outcome = if allowed {
        send_raw(&config.target, &flow.request, &options).await.map_err(|e| e.to_string())
    } else {
        Err("request path is out of scope; not sent".to_string())
    };
    match outcome {
        Ok(exchange) => {
            flow.response = Some(exchange.response);
            flow.truncated = exchange.truncated;
            flow.tls_error = exchange.tls_error;
        }
        Err(e) => flow.error = Some(e),
    }
    flow.finish();
    let response = flow.response.as_deref();
    let result = FuzzResult {
        run_id,
        index,
        payloads: labels,
        flow_id: flow.id,
        status: response.and_then(|r| crate::http::parse_response_head(r).ok()).map(|h| h.status),
        length: response.map_or(0, |r| r.len() as u64),
        duration_ms: flow.duration_ms.unwrap_or(0),
        matched: grep.zip(response).is_some_and(|(g, r)| g.is_match(r)),
        error: flow.error.clone(),
    };
    deps.store.save_flow(flow);
    let _ = deps.store.save_fuzz_result(&result);
    let _ = deps.ui.send(UiEvent::FuzzResult(result));
}

/// Runs an attack to completion. `control` pauses or stops it.
pub async fn run(
    mut info: FuzzRunInfo,
    plan: AttackPlan,
    grep: Option<Regex>,
    mut control: watch::Receiver<RunState>,
    deps: Arc<FuzzDeps>,
) {
    let config = Arc::new(info.config.clone());
    let delay = Duration::from_millis(config.delay_ms);
    let permits = Arc::new(Semaphore::new(config.concurrency));
    let mut tasks = JoinSet::new();
    let mut final_state = RunState::Finished;

    'dispatch: for index in 0..plan.total() {
        loop {
            let state = *control.borrow_and_update();
            match state {
                RunState::Stopped => {
                    final_state = RunState::Stopped;
                    break 'dispatch;
                }
                RunState::Paused => {
                    if control.changed().await.is_err() {
                        final_state = RunState::Stopped;
                        break 'dispatch;
                    }
                }
                _ => break,
            }
        }
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit.expect("semaphore stays open"),
            _ = control.wait_for(|s| *s == RunState::Stopped) => {
                final_state = RunState::Stopped;
                break 'dispatch;
            }
        };
        let (request, labels) = plan.build(index);
        let (config, grep, deps) = (config.clone(), grep.clone(), deps.clone());
        let run_id = info.id;
        tasks.spawn(async move {
            send_one(run_id, index, request, labels, config, grep, deps).await;
            drop(permit);
        });
        while tasks.try_join_next().is_some() {}
        if !delay.is_zero() && index + 1 < plan.total() {
            tokio::time::sleep(delay).await;
        }
    }

    if final_state == RunState::Stopped {
        tasks.shutdown().await;
    } else {
        while tasks.join_next().await.is_some() {}
    }
    info.state = final_state;
    let _ = deps.store.save_fuzz_run(&info);
    let _ = deps.ui.send(UiEvent::FuzzState {
        run_id: info.id,
        state: final_state,
    });
}

pub fn new_run_info(id: u64, config: FuzzConfig, total: u64) -> FuzzRunInfo {
    FuzzRunInfo {
        id,
        config,
        total,
        state: RunState::Running,
        created_ms: now_ms(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeRule;

    fn config(template: &str, mode: AttackMode, payloads: Vec<PayloadSource>) -> FuzzConfig {
        FuzzConfig {
            target: Target {
                host: "a.test".into(),
                port: 80,
                tls: false,
            },
            template: template.into(),
            encoding: Encoding::Utf8,
            mode,
            payloads,
            concurrency: 2,
            delay_ms: 0,
            grep: None,
            normalize: false,
            timeout_ms: 1000,
        }
    }

    fn list(items: &[&str]) -> PayloadSource {
        PayloadSource::List(items.iter().map(|s| s.to_string()).collect())
    }

    fn all(plan: &AttackPlan) -> Vec<String> {
        (0..plan.total())
            .map(|i| String::from_utf8(plan.build(i).0).unwrap())
            .collect()
    }

    #[test]
    fn single_varies_one_position_at_a_time() {
        let plan = AttackPlan::new(&config("§a§-§b§", AttackMode::Single, vec![list(&["1", "2"])])).unwrap();
        assert_eq!(all(&plan), ["1-b", "2-b", "a-1", "a-2"]);
    }

    #[test]
    fn same_fills_every_position() {
        let plan = AttackPlan::new(&config("§a§-§b§", AttackMode::Same, vec![list(&["1", "2"])])).unwrap();
        assert_eq!(all(&plan), ["1-1", "2-2"]);
    }

    #[test]
    fn parallel_stops_at_the_shortest_list() {
        let lists = vec![list(&["1", "2", "3"]), list(&["x", "y"])];
        let plan = AttackPlan::new(&config("§a§-§b§", AttackMode::Parallel, lists)).unwrap();
        assert_eq!(all(&plan), ["1-x", "2-y"]);
    }

    #[test]
    fn combinations_cover_the_product() {
        let lists = vec![list(&["1", "2"]), list(&["x", "y"])];
        let plan = AttackPlan::new(&config("§a§-§b§", AttackMode::Combinations, lists)).unwrap();
        assert_eq!(all(&plan), ["1-x", "1-y", "2-x", "2-y"]);
    }

    #[test]
    fn numbers_expand_in_both_directions() {
        let up = PayloadSource::Numbers { from: 1, to: 5, step: 2 };
        assert_eq!(up.load(Encoding::Utf8).unwrap(), [b"1", b"3", b"5"]);
        let down = PayloadSource::Numbers { from: 2, to: 0, step: -1 };
        assert_eq!(down.load(Encoding::Utf8).unwrap(), [b"2", b"1", b"0"]);
        let bad = PayloadSource::Numbers { from: 0, to: 5, step: -1 };
        assert_eq!(bad.load(Encoding::Utf8), Err(FuzzError::BadRange));
    }

    #[test]
    fn invalid_templates_are_rejected() {
        let one = vec![list(&["1"])];
        assert_eq!(
            AttackPlan::new(&config("none", AttackMode::Single, one.clone())).unwrap_err(),
            FuzzError::NoPositions
        );
        assert_eq!(
            AttackPlan::new(&config("§a", AttackMode::Single, one)).unwrap_err(),
            FuzzError::UnmatchedMarker
        );
        assert_eq!(
            AttackPlan::new(&config("§a§§b§", AttackMode::Combinations, vec![list(&["1"])])).unwrap_err(),
            FuzzError::WrongListCount { needed: 2, given: 1 }
        );
    }

    #[test]
    fn enormous_attacks_are_refused() {
        let big = || PayloadSource::Numbers { from: 1, to: 100_000, step: 1 };
        let err = AttackPlan::new(&config("§a§§b§", AttackMode::Combinations, vec![big(), big()])).unwrap_err();
        assert_eq!(err, FuzzError::TooManyRequests(10_000_000_000));
    }

    #[test]
    fn target_must_be_in_scope() {
        let template = "GET /§a§ HTTP/1.1\r\nHost: a.test\r\n\r\n";
        let cfg = config(template, AttackMode::Single, vec![list(&["1"])]);
        let empty = Scope::default();
        assert!(matches!(prepare(&cfg, &empty), Err(FuzzError::OutOfScope(_))));
        let scope = Scope {
            include: vec![ScopeRule {
                host: "a.test".into(),
                path_prefix: String::new(),
            }],
            exclude: vec![],
        };
        assert!(prepare(&cfg, &scope).is_ok());
    }
}
