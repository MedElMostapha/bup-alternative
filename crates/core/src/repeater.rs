use serde::{Deserialize, Serialize};

use crate::http::find_head_end;
use crate::http::rewrite::fix_content_length;
use crate::model::Target;
use crate::text::RawText;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeaterTab {
    pub id: u64,
    pub name: String,
    pub target: Target,
    pub request: RawText,
}

/// Turns bare LFs in the head into CRLF, since the editor inserts LF when the
/// user presses Enter, then corrects `Content-Length`. The body is untouched.
pub fn normalize_message(raw: &[u8]) -> Vec<u8> {
    let head_end = find_lenient_head_end(raw);
    let (head, body) = raw.split_at(head_end);
    let mut out = Vec::with_capacity(raw.len() + 16);
    for (i, byte) in head.iter().enumerate() {
        if *byte == b'\n' && (i == 0 || head[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(*byte);
    }
    if find_head_end(&out).is_none() {
        // The head had no blank line at all, so give it one.
        while !out.ends_with(b"\r\n\r\n") {
            out.extend_from_slice(if out.ends_with(b"\r\n") { b"\r\n" } else { b"\r\n\r\n" });
        }
    }
    out.extend_from_slice(body);
    fix_content_length(&out)
}

/// Offset just past the first blank line, accepting LF or CRLF.
fn find_lenient_head_end(raw: &[u8]) -> usize {
    let mut i = 0;
    while let Some(offset) = raw[i..].iter().position(|b| *b == b'\n') {
        let after = i + offset + 1;
        match raw.get(after) {
            Some(b'\n') => return after + 1,
            Some(b'\r') if raw.get(after + 1) == Some(&b'\n') => return after + 2,
            _ => i = after,
        }
    }
    raw.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_newlines_become_crlf_in_the_head_only() {
        let raw = b"POST / HTTP/1.1\nHost: a\nContent-Length: 1\n\nline1\nline2";
        assert_eq!(
            normalize_message(raw),
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 11\r\n\r\nline1\nline2"
        );
    }

    #[test]
    fn correct_messages_are_unchanged() {
        let raw = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(normalize_message(raw), raw);
    }

    #[test]
    fn missing_blank_line_is_added() {
        assert_eq!(normalize_message(b"GET / HTTP/1.1\nHost: a"), b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    }
}
