//! The few byte-level edits the proxy itself makes. Everything not named here
//! is forwarded untouched.

use super::find_head_end;

/// Splits an authority into host and port. IPv6 brackets are removed.
pub fn parse_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if tail.is_empty() => default_port,
            None => return None,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Some((host.to_string(), port.parse().ok()?)),
        Some(_) => None,
        None if authority.is_empty() => None,
        None => Some((authority.to_string(), default_port)),
    }
}

/// An absolute-form request target, split into its parts.
#[derive(Debug, PartialEq, Eq)]
pub struct AbsoluteTarget {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub origin_form: String,
}

pub fn parse_absolute_target(target: &str) -> Option<AbsoluteTarget> {
    let lower = target.get(..8)?.to_ascii_lowercase();
    let (tls, rest) = if lower.starts_with("http://") {
        (false, &target[7..])
    } else if lower.starts_with("https://") {
        (true, &target[8..])
    } else {
        return None;
    };
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (host, port) = parse_authority(authority, if tls { 443 } else { 80 })?;
    let origin_form = match tail.chars().next() {
        Some('/') => tail.to_string(),
        _ => format!("/{tail}"),
    };
    Some(AbsoluteTarget {
        tls,
        host,
        port,
        origin_form,
    })
}

fn line_name_is(line: &[u8], name: &str) -> bool {
    line.iter()
        .position(|b| *b == b':')
        .is_some_and(|i| line[..i].eq_ignore_ascii_case(name.as_bytes()))
}

/// Prepares a client's head for the origin server: absolute-form targets become
/// origin-form, `Proxy-Connection` goes, and WebSocket compression is declined
/// so captured frames stay readable.
pub fn prepare_forward(raw_head: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw_head.len());
    let mut lines = raw_head.split_inclusive(|b| *b == b'\n');
    if let Some(first) = lines.next() {
        out.extend_from_slice(&origin_form_line(first));
    }
    for line in lines {
        if !line_name_is(line, "proxy-connection") && !line_name_is(line, "sec-websocket-extensions") {
            out.extend_from_slice(line);
        }
    }
    out
}

fn origin_form_line(line: &[u8]) -> Vec<u8> {
    let parts: Vec<&[u8]> = line.splitn(3, |b| *b == b' ').collect();
    let [method, target, rest] = parts[..] else {
        return line.to_vec();
    };
    let Some(absolute) = std::str::from_utf8(target).ok().and_then(parse_absolute_target) else {
        return line.to_vec();
    };
    [method, b" ", absolute.origin_form.as_bytes(), b" ", rest].concat()
}

/// Sets `Content-Length` to the real body size if the header is present.
/// Used for hand-edited messages, where the old value is usually stale.
pub fn fix_content_length(raw: &[u8]) -> Vec<u8> {
    let Some(end) = find_head_end(raw) else {
        return raw.to_vec();
    };
    let (head, body) = raw.split_at(end);
    let mut out = Vec::with_capacity(raw.len());
    for line in head.split_inclusive(|b| *b == b'\n') {
        if line_name_is(line, "content-length") {
            let name_end = line.iter().position(|b| *b == b':').unwrap_or(0);
            out.extend_from_slice(&line[..name_end]);
            out.extend_from_slice(format!(": {}\r\n", body.len()).as_bytes());
        } else {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_forms() {
        assert_eq!(parse_authority("a.test:8443", 443), Some(("a.test".into(), 8443)));
        assert_eq!(parse_authority("a.test", 80), Some(("a.test".into(), 80)));
        assert_eq!(parse_authority("[::1]:9000", 80), Some(("::1".into(), 9000)));
        assert_eq!(parse_authority("[::1]", 80), Some(("::1".into(), 80)));
        assert_eq!(parse_authority("", 80), None);
        assert_eq!(parse_authority("a.test:nope", 80), None);
    }

    #[test]
    fn absolute_targets() {
        let t = parse_absolute_target("http://a.test:81/x?y=1").unwrap();
        assert_eq!((t.host.as_str(), t.port, t.tls), ("a.test", 81, false));
        assert_eq!(t.origin_form, "/x?y=1");
        assert_eq!(parse_absolute_target("http://a.test").unwrap().origin_form, "/");
        assert_eq!(parse_absolute_target("http://a.test?q").unwrap().origin_form, "/?q");
        assert!(parse_absolute_target("/relative/path").is_none());
    }

    #[test]
    fn forward_rewrites_only_what_it_must() {
        let raw = b"GET http://a.test/p HTTP/1.1\r\nhOsT: a.test\r\nProxy-Connection: keep-alive\r\nX-Odd:  v \r\n\r\n";
        assert_eq!(
            prepare_forward(raw),
            b"GET /p HTTP/1.1\r\nhOsT: a.test\r\nX-Odd:  v \r\n\r\n"
        );
    }

    #[test]
    fn forward_leaves_origin_form_alone() {
        let raw = b"GET /p HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(prepare_forward(raw), raw);
    }

    #[test]
    fn content_length_is_corrected() {
        let raw = b"POST / HTTP/1.1\r\ncontent-LENGTH: 1\r\n\r\nabcd";
        assert_eq!(
            fix_content_length(raw),
            b"POST / HTTP/1.1\r\ncontent-LENGTH: 4\r\n\r\nabcd"
        );
    }
}
