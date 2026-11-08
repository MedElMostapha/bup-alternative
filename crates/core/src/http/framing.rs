use super::head::{RequestHead, ResponseHead};
use super::ParseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    None,
    Length(u64),
    Chunked,
    /// Body runs until the server closes the connection.
    UntilClose,
}

fn is_chunked(value: Option<&[u8]>) -> bool {
    value
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|v| v.rsplit(',').next())
        .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"))
}

fn content_length(value: Option<&[u8]>) -> Option<u64> {
    std::str::from_utf8(value?).ok()?.trim().parse().ok()
}

pub fn request_framing(head: &RequestHead) -> BodyFraming {
    if is_chunked(head.header("transfer-encoding")) {
        return BodyFraming::Chunked;
    }
    match content_length(head.header("content-length")) {
        Some(0) | None => BodyFraming::None,
        Some(n) => BodyFraming::Length(n),
    }
}

/// `request_method` matters because HEAD and CONNECT responses have no body
/// regardless of what their headers advertise.
pub fn response_framing(head: &ResponseHead, request_method: &str) -> BodyFraming {
    let no_body = request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&head.status)
        || head.status == 204
        || head.status == 304
        || (request_method.eq_ignore_ascii_case("CONNECT") && (200..300).contains(&head.status));
    if no_body {
        return BodyFraming::None;
    }
    if is_chunked(head.header("transfer-encoding")) {
        return BodyFraming::Chunked;
    }
    match content_length(head.header("content-length")) {
        Some(0) => BodyFraming::None,
        Some(n) => BodyFraming::Length(n),
        None => BodyFraming::UntilClose,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    Size,
    Data(u64),
    DataCrlf,
    Trailers,
    Done,
}

/// Incrementally finds where a chunked body ends without altering its bytes.
#[derive(Debug)]
pub struct ChunkedScanner {
    state: ChunkState,
    line: Vec<u8>,
}

impl Default for ChunkedScanner {
    fn default() -> Self {
        Self {
            state: ChunkState::Size,
            line: Vec::new(),
        }
    }
}

impl ChunkedScanner {
    pub fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }

    /// Consumes bytes and returns how many belong to the body. A return value
    /// smaller than `input.len()` means the body ended inside `input`.
    pub fn feed(&mut self, input: &[u8]) -> Result<usize, ParseError> {
        let mut pos = 0;
        while pos < input.len() && self.state != ChunkState::Done {
            match self.state {
                ChunkState::Data(remaining) => {
                    let take = remaining.min((input.len() - pos) as u64);
                    pos += take as usize;
                    self.state = if remaining == take {
                        ChunkState::DataCrlf
                    } else {
                        ChunkState::Data(remaining - take)
                    };
                }
                ChunkState::Size | ChunkState::DataCrlf | ChunkState::Trailers => {
                    let byte = input[pos];
                    pos += 1;
                    self.line.push(byte);
                    if self.line.len() > 16 * 1024 {
                        return Err(ParseError::BadChunk);
                    }
                    if byte == b'\n' {
                        self.finish_line()?;
                    }
                }
                ChunkState::Done => unreachable!(),
            }
        }
        Ok(pos)
    }

    fn finish_line(&mut self) -> Result<(), ParseError> {
        let line = std::mem::take(&mut self.line);
        let text = line.strip_suffix(b"\n").unwrap_or(&line);
        let text = text.strip_suffix(b"\r").unwrap_or(text);
        self.state = match self.state {
            ChunkState::Size => {
                let size = text.split(|b| *b == b';').next().unwrap_or_default();
                let size = std::str::from_utf8(size).map_err(|_| ParseError::BadChunk)?;
                match u64::from_str_radix(size.trim(), 16).map_err(|_| ParseError::BadChunk)? {
                    0 => ChunkState::Trailers,
                    n => ChunkState::Data(n),
                }
            }
            ChunkState::DataCrlf if text.is_empty() => ChunkState::Size,
            ChunkState::DataCrlf => return Err(ParseError::BadChunk),
            ChunkState::Trailers if text.is_empty() => ChunkState::Done,
            ChunkState::Trailers => ChunkState::Trailers,
            other => other,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::head::{parse_request_head, parse_response_head};
    use super::*;

    #[test]
    fn scanner_stops_at_body_end() {
        let raw = b"4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\nX-T: 1\r\n\r\nNEXT";
        let mut scanner = ChunkedScanner::default();
        let used = scanner.feed(raw).unwrap();
        assert!(scanner.is_done());
        assert_eq!(&raw[used..], b"NEXT");
    }

    #[test]
    fn scanner_handles_one_byte_reads() {
        let raw = b"4\r\nWiki\r\n0\r\n\r\n";
        let mut scanner = ChunkedScanner::default();
        for byte in raw {
            assert_eq!(scanner.feed(std::slice::from_ref(byte)).unwrap(), 1);
        }
        assert!(scanner.is_done());
    }

    #[test]
    fn scanner_rejects_bad_size() {
        let mut scanner = ChunkedScanner::default();
        assert_eq!(scanner.feed(b"zz\r\n"), Err(ParseError::BadChunk));
    }

    #[test]
    fn request_framing_prefers_chunked() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(request_framing(&parse_request_head(raw).unwrap()), BodyFraming::Chunked);
    }

    #[test]
    fn response_framing_cases() {
        let ok = parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n").unwrap();
        assert_eq!(response_framing(&ok, "GET"), BodyFraming::Length(7));
        assert_eq!(response_framing(&ok, "HEAD"), BodyFraming::None);
        let open = parse_response_head(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
        assert_eq!(response_framing(&open, "GET"), BodyFraming::UntilClose);
        let empty = parse_response_head(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!(response_framing(&empty, "GET"), BodyFraming::None);
    }
}
