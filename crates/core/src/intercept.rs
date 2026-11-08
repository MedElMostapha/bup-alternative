use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::model::Target;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Request,
    Response,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub id: u64,
    pub flow_id: u64,
    pub direction: Direction,
    pub target: Target,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Forward,
    Edited(Vec<u8>),
    Drop,
}

#[derive(Default)]
struct State {
    requests: bool,
    responses: bool,
    next_id: u64,
    queue: HashMap<u64, (Pending, oneshot::Sender<Verdict>)>,
}

/// Holds messages until the user decides what happens to them.
#[derive(Default)]
pub struct Intercept {
    state: Arc<Mutex<State>>,
}

/// A queued message. Dropping it removes the message from the queue, which
/// is how a disconnected client's entry gets cleared.
pub struct Waiter {
    pub pending: Pending,
    pub verdict: oneshot::Receiver<Verdict>,
    state: Arc<Mutex<State>>,
}

impl Drop for Waiter {
    fn drop(&mut self) {
        self.state.lock().expect("intercept lock").queue.remove(&self.pending.id);
    }
}

impl Intercept {
    /// Sets what gets paused. Anything no longer covered is released.
    pub fn configure(&self, requests: bool, responses: bool) -> Vec<u64> {
        let mut state = self.state.lock().expect("intercept lock");
        state.requests = requests;
        state.responses = responses;
        let released: Vec<u64> = state
            .queue
            .iter()
            .filter(|(_, (p, _))| match p.direction {
                Direction::Request => !requests,
                Direction::Response => !responses,
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &released {
            if let Some((_, tx)) = state.queue.remove(id) {
                let _ = tx.send(Verdict::Forward);
            }
        }
        released
    }

    pub fn is_enabled(&self, direction: Direction) -> bool {
        let state = self.state.lock().expect("intercept lock");
        match direction {
            Direction::Request => state.requests,
            Direction::Response => state.responses,
        }
    }

    /// Queues a message, or returns `None` if that direction is not paused.
    pub fn submit(&self, flow_id: u64, direction: Direction, target: Target, raw: Vec<u8>) -> Option<Waiter> {
        let mut state = self.state.lock().expect("intercept lock");
        let enabled = match direction {
            Direction::Request => state.requests,
            Direction::Response => state.responses,
        };
        if !enabled {
            return None;
        }
        state.next_id += 1;
        let pending = Pending {
            id: state.next_id,
            flow_id,
            direction,
            target,
            raw,
        };
        let (tx, verdict) = oneshot::channel();
        state.queue.insert(pending.id, (pending.clone(), tx));
        Some(Waiter {
            pending,
            verdict,
            state: self.state.clone(),
        })
    }

    /// Applies a decision. Returns false if the message is no longer queued.
    pub fn resolve(&self, id: u64, verdict: Verdict) -> bool {
        match self.state.lock().expect("intercept lock").queue.remove(&id) {
            Some((_, tx)) => tx.send(verdict).is_ok(),
            None => false,
        }
    }

    pub fn queued(&self) -> Vec<Pending> {
        let state = self.state.lock().expect("intercept lock");
        let mut items: Vec<Pending> = state.queue.values().map(|(p, _)| p.clone()).collect();
        items.sort_by_key(|p| p.id);
        items
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            host: "a.test".into(),
            port: 80,
            tls: false,
        }
    }

    #[test]
    fn disabled_direction_is_not_queued() {
        let gate = Intercept::default();
        assert!(gate.submit(1, Direction::Request, target(), vec![]).is_none());
    }

    #[tokio::test]
    async fn resolve_delivers_the_verdict() {
        let gate = Intercept::default();
        gate.configure(true, false);
        let mut waiter = gate.submit(1, Direction::Request, target(), vec![]).unwrap();
        assert!(gate.resolve(waiter.pending.id, Verdict::Drop));
        assert_eq!((&mut waiter.verdict).await.unwrap(), Verdict::Drop);
    }

    #[tokio::test]
    async fn turning_off_releases_the_queue() {
        let gate = Intercept::default();
        gate.configure(true, true);
        let mut request = gate.submit(1, Direction::Request, target(), vec![]).unwrap();
        let response = gate.submit(1, Direction::Response, target(), vec![]).unwrap();
        assert_eq!(gate.configure(false, true), vec![request.pending.id]);
        assert_eq!((&mut request.verdict).await.unwrap(), Verdict::Forward);
        assert_eq!(gate.queued().len(), 1);
        drop(response);
    }

    #[test]
    fn dropping_a_waiter_clears_its_entry() {
        let gate = Intercept::default();
        gate.configure(true, false);
        let waiter = gate.submit(1, Direction::Request, target(), vec![]).unwrap();
        assert_eq!(gate.queued().len(), 1);
        drop(waiter);
        assert!(gate.queued().is_empty());
    }
}
