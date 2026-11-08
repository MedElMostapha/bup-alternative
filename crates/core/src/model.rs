use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Proxy,
    Repeater,
    Fuzzer,
}

/// One request and its response, as raw bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub id: u64,
    pub source: Source,
    pub target: Target,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub started_ms: i64,
    pub duration_ms: Option<u64>,
    pub edited: bool,
    pub truncated: bool,
    /// Why the upstream certificate failed validation, if it did.
    pub tls_error: Option<String>,
    pub error: Option<String>,
    pub complete: bool,
}

impl Flow {
    pub fn new(id: u64, source: Source, target: Target, request: Vec<u8>) -> Self {
        Self {
            id,
            source,
            target,
            request,
            response: None,
            started_ms: now_ms(),
            duration_ms: None,
            edited: false,
            truncated: false,
            tls_error: None,
            error: None,
            complete: false,
        }
    }

    pub fn finish(&mut self) {
        self.duration_ms = Some((now_ms() - self.started_ms).max(0) as u64);
        self.complete = true;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsFrame {
    pub flow_id: u64,
    pub from_client: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
    pub truncated: bool,
    pub at_ms: i64,
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Default)]
pub struct IdGen(AtomicU64);

impl IdGen {
    /// The first id handed out will be `last + 1`.
    pub fn starting_after(last: u64) -> Self {
        Self(AtomicU64::new(last))
    }

    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed) + 1
    }
}
