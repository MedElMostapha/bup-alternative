use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::framing::{BodyFraming, ChunkedScanner};
use super::head::find_head_end;

const MAX_HEAD: usize = 1024 * 1024;
const READ_SIZE: usize = 64 * 1024;

/// Progress through one message body.
#[derive(Debug)]
pub enum BodyState {
    Empty,
    Length(u64),
    Chunked(ChunkedScanner),
    UntilClose,
}

impl BodyState {
    pub fn new(framing: BodyFraming) -> Self {
        match framing {
            BodyFraming::None | BodyFraming::Length(0) => Self::Empty,
            BodyFraming::Length(n) => Self::Length(n),
            BodyFraming::Chunked => Self::Chunked(ChunkedScanner::default()),
            BodyFraming::UntilClose => Self::UntilClose,
        }
    }
}

/// Buffered reader yielding message heads and body chunks as raw bytes.
pub struct MessageReader<S> {
    stream: S,
    buf: Vec<u8>,
}

impl<S> MessageReader<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Vec::new(),
        }
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Puts back bytes taken from another reader over the same stream.
    pub fn restore(&mut self, bytes: Vec<u8>) {
        self.buf = bytes;
    }

    pub fn take_buffered(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    pub fn into_parts(self) -> (S, Vec<u8>) {
        (self.stream, self.buf)
    }
}

impl<S: AsyncRead + Unpin> MessageReader<S> {
    /// Reads more bytes into the buffer and returns how many arrived.
    pub async fn fill(&mut self) -> io::Result<usize> {
        let mut chunk = vec![0u8; READ_SIZE];
        let n = self.stream.read(&mut chunk).await?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    /// Returns the raw head, or `None` on a clean close between messages.
    pub async fn read_head(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            while self.buf.starts_with(b"\r\n") {
                self.buf.drain(..2);
            }
            if let Some(end) = find_head_end(&self.buf) {
                return Ok(Some(self.buf.drain(..end).collect()));
            }
            if self.buf.len() > MAX_HEAD {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "message head too large"));
            }
            if self.fill().await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
        }
    }

    /// Returns the next raw piece of the body, or `None` when it has ended.
    pub async fn next_body_chunk(&mut self, state: &mut BodyState) -> io::Result<Option<Vec<u8>>> {
        match state {
            BodyState::Empty => Ok(None),
            BodyState::Length(remaining) => {
                if *remaining == 0 {
                    return Ok(None);
                }
                if self.buf.is_empty() && self.fill().await? == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                let take = (*remaining).min(self.buf.len() as u64) as usize;
                *remaining -= take as u64;
                Ok(Some(self.buf.drain(..take).collect()))
            }
            BodyState::Chunked(scanner) => {
                if scanner.is_done() {
                    return Ok(None);
                }
                if self.buf.is_empty() && self.fill().await? == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                let used = scanner
                    .feed(&self.buf)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(Some(self.buf.drain(..used).collect()))
            }
            BodyState::UntilClose => {
                if self.buf.is_empty() && self.fill().await? == 0 {
                    return Ok(None);
                }
                Ok(Some(std::mem::take(&mut self.buf)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_all(raw: &'static [u8], framing: BodyFraming) -> (Vec<u8>, Vec<u8>) {
        let mut reader = MessageReader::new(raw);
        let mut state = BodyState::new(framing);
        let mut body = Vec::new();
        while let Some(chunk) = reader.next_body_chunk(&mut state).await.unwrap() {
            body.extend(chunk);
        }
        (body, reader.take_buffered())
    }

    #[tokio::test]
    async fn head_then_length_body_keeps_pipelined_bytes() {
        let mut reader = MessageReader::new(&b"\r\nGET / HTTP/1.1\r\n\r\nabcNEXT"[..]);
        assert_eq!(reader.read_head().await.unwrap().unwrap(), b"GET / HTTP/1.1\r\n\r\n");
        let mut state = BodyState::new(BodyFraming::Length(3));
        let mut body = Vec::new();
        while let Some(chunk) = reader.next_body_chunk(&mut state).await.unwrap() {
            body.extend(chunk);
        }
        assert_eq!(body, b"abc");
        assert_eq!(reader.take_buffered(), b"NEXT");
    }

    #[tokio::test]
    async fn chunked_body_is_returned_unchanged() {
        let (body, rest) = read_all(b"3\r\nabc\r\n0\r\n\r\nNEXT", BodyFraming::Chunked).await;
        assert_eq!(body, b"3\r\nabc\r\n0\r\n\r\n");
        assert_eq!(rest, b"NEXT");
    }

    #[tokio::test]
    async fn until_close_reads_everything() {
        let (body, _) = read_all(b"all of it", BodyFraming::UntilClose).await;
        assert_eq!(body, b"all of it");
    }

    #[tokio::test]
    async fn truncated_length_body_is_an_error() {
        let mut reader = MessageReader::new(&b"ab"[..]);
        let mut state = BodyState::new(BodyFraming::Length(5));
        reader.next_body_chunk(&mut state).await.unwrap();
        assert!(reader.next_body_chunk(&mut state).await.is_err());
    }

    #[tokio::test]
    async fn eof_between_messages_is_clean() {
        let mut reader = MessageReader::new(&b""[..]);
        assert_eq!(reader.read_head().await.unwrap(), None);
    }
}
