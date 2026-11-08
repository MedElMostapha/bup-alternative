//! Relays an upgraded WebSocket connection byte-for-byte while parsing a copy
//! of each direction for the record.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::model::{now_ms, WsFrame};
use crate::proxy::Event;

/// Payload bytes kept per frame. The relay itself is never limited.
const FRAME_RECORD_CAP: usize = 1024 * 1024;
const CLOSE_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedFrame {
    pub opcode: u8,
    pub payload: Vec<u8>,
    pub truncated: bool,
}

enum Phase {
    Header,
    Payload {
        opcode: u8,
        mask: Option<[u8; 4]>,
        remaining: u64,
        offset: u64,
        payload: Vec<u8>,
        truncated: bool,
    },
}

/// Incremental frame parser that tolerates any split of the input.
pub struct FrameParser {
    buf: Vec<u8>,
    phase: Phase,
}

impl Default for FrameParser {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            phase: Phase::Header,
        }
    }
}

impl FrameParser {
    pub fn feed(&mut self, data: &[u8]) -> Vec<ParsedFrame> {
        self.buf.extend_from_slice(data);
        let mut frames = Vec::new();
        loop {
            match &mut self.phase {
                Phase::Header => {
                    let Some((phase, used)) = parse_header(&self.buf) else {
                        return frames;
                    };
                    self.buf.drain(..used);
                    self.phase = phase;
                }
                Phase::Payload {
                    opcode,
                    mask,
                    remaining,
                    offset,
                    payload,
                    truncated,
                } => {
                    let take = (*remaining).min(self.buf.len() as u64) as usize;
                    for byte in self.buf.drain(..take) {
                        if payload.len() < FRAME_RECORD_CAP {
                            let key = mask.map_or(0, |m| m[(*offset % 4) as usize]);
                            payload.push(byte ^ key);
                        } else {
                            *truncated = true;
                        }
                        *offset += 1;
                    }
                    *remaining -= take as u64;
                    if *remaining > 0 {
                        return frames;
                    }
                    frames.push(ParsedFrame {
                        opcode: *opcode,
                        payload: std::mem::take(payload),
                        truncated: *truncated,
                    });
                    self.phase = Phase::Header;
                }
            }
        }
    }
}

fn parse_header(buf: &[u8]) -> Option<(Phase, usize)> {
    let [first, second, ..] = *buf else {
        return None;
    };
    let masked = second & 0x80 != 0;
    let (length, mut pos) = match second & 0x7f {
        126 => (u16::from_be_bytes(buf.get(2..4)?.try_into().ok()?) as u64, 4),
        127 => (u64::from_be_bytes(buf.get(2..10)?.try_into().ok()?), 10),
        n => (n as u64, 2),
    };
    let mask = if masked {
        let key: [u8; 4] = buf.get(pos..pos + 4)?.try_into().ok()?;
        pos += 4;
        Some(key)
    } else {
        None
    };
    let phase = Phase::Payload {
        opcode: first & 0x0f,
        mask,
        remaining: length,
        offset: 0,
        payload: Vec::new(),
        truncated: false,
    };
    Some((phase, pos))
}

async fn record(events: &mpsc::Sender<Event>, flow_id: u64, from_client: bool, frames: Vec<ParsedFrame>) {
    for frame in frames {
        let _ = events
            .send(Event::WsFrame(WsFrame {
                flow_id,
                from_client,
                opcode: frame.opcode,
                payload: frame.payload,
                truncated: frame.truncated,
                at_ms: now_ms(),
            }))
            .await;
    }
}

async fn pump<R, W>(
    mut from: R,
    mut to: W,
    initial: Vec<u8>,
    flow_id: u64,
    from_client: bool,
    events: mpsc::Sender<Event>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut parser = FrameParser::default();
    if !initial.is_empty() {
        if to.write_all(&initial).await.is_err() {
            return;
        }
        record(&events, flow_id, from_client, parser.feed(&initial)).await;
    }
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if to.write_all(&chunk[..n]).await.is_err() || to.flush().await.is_err() {
            break;
        }
        record(&events, flow_id, from_client, parser.feed(&chunk[..n])).await;
    }
    let _ = to.shutdown().await;
}

/// Relays until either side closes, allowing the other a moment to finish.
pub async fn relay<C, U>(
    client: C,
    client_buffered: Vec<u8>,
    upstream: U,
    upstream_buffered: Vec<u8>,
    flow_id: u64,
    events: mpsc::Sender<Event>,
) where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let outbound = pump(client_read, upstream_write, client_buffered, flow_id, true, events.clone());
    let inbound = pump(upstream_read, client_write, upstream_buffered, flow_id, false, events);
    tokio::pin!(outbound, inbound);
    tokio::select! {
        _ = &mut outbound => { let _ = tokio::time::timeout(CLOSE_GRACE, inbound).await; }
        _ = &mut inbound => { let _ = tokio::time::timeout(CLOSE_GRACE, outbound).await; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_masked_frame_split_at_every_byte() {
        let mask = [1u8, 2, 3, 4];
        let mut raw = vec![0x81, 0x85];
        raw.extend(mask);
        raw.extend(b"hello".iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        let mut parser = FrameParser::default();
        let mut frames = Vec::new();
        for byte in &raw {
            frames.extend(parser.feed(std::slice::from_ref(byte)));
        }
        assert_eq!(
            frames,
            vec![ParsedFrame {
                opcode: 1,
                payload: b"hello".to_vec(),
                truncated: false
            }]
        );
    }

    #[test]
    fn parses_extended_length_and_consecutive_frames() {
        let mut raw = vec![0x82, 126, 0x01, 0x00];
        raw.extend(vec![7u8; 256]);
        raw.extend([0x89, 0x00]);
        let frames = FrameParser::default().feed(&raw);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].payload.len(), 256);
        assert_eq!(frames[1].opcode, 9);
        assert!(frames[1].payload.is_empty());
    }

    #[test]
    fn oversized_payload_is_truncated_in_the_record() {
        let size = FRAME_RECORD_CAP as u64 + 10;
        let mut raw = vec![0x82, 127];
        raw.extend(size.to_be_bytes());
        raw.extend(vec![1u8; size as usize]);
        let frames = FrameParser::default().feed(&raw);
        assert_eq!(frames[0].payload.len(), FRAME_RECORD_CAP);
        assert!(frames[0].truncated);
    }
}
