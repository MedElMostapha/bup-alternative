use super::ParseError;

const MAX_HEADERS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub minor_version: u8,
    pub headers: Vec<Header>,
    /// Length of the head in the original buffer, including the blank line.
    pub head_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub minor_version: u8,
    pub headers: Vec<Header>,
    pub head_len: usize,
}

/// Case-insensitive lookup of the first header with this name.
pub(super) fn header_value<'a>(headers: &'a [Header], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_slice())
}

impl RequestHead {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_value(&self.headers, name)
    }
}

impl ResponseHead {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_value(&self.headers, name)
    }
}

/// Returns the offset just past the blank line ending the head, if present.
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn collect_headers(raw: &[httparse::Header<'_>]) -> Vec<Header> {
    raw.iter()
        .map(|h| Header {
            name: h.name.to_string(),
            value: h.value.to_vec(),
        })
        .collect()
}

pub fn parse_request_head(buf: &[u8]) -> Result<RequestHead, ParseError> {
    let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut storage);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(head_len)) => Ok(RequestHead {
            method: req.method.unwrap_or_default().to_string(),
            target: req.path.unwrap_or_default().to_string(),
            minor_version: req.version.unwrap_or(1),
            headers: collect_headers(req.headers),
            head_len,
        }),
        Ok(httparse::Status::Partial) => Err(ParseError::Incomplete),
        Err(e) => Err(ParseError::Malformed(e.to_string())),
    }
}

pub fn parse_response_head(buf: &[u8]) -> Result<ResponseHead, ParseError> {
    let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut res = httparse::Response::new(&mut storage);
    match res.parse(buf) {
        Ok(httparse::Status::Complete(head_len)) => Ok(ResponseHead {
            status: res.code.unwrap_or(0),
            reason: res.reason.unwrap_or_default().to_string(),
            minor_version: res.version.unwrap_or(1),
            headers: collect_headers(res.headers),
            head_len,
        }),
        Ok(httparse::Status::Partial) => Err(ParseError::Incomplete),
        Err(e) => Err(ParseError::Malformed(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_header_case_and_order() {
        let raw = b"GET /a?b=1 HTTP/1.1\r\nhOsT: x.test\r\nX-b: 2\r\nX-A: 1\r\n\r\nrest";
        let head = parse_request_head(raw).unwrap();
        assert_eq!(head.method, "GET");
        assert_eq!(head.target, "/a?b=1");
        let names: Vec<_> = head.headers.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["hOsT", "X-b", "X-A"]);
        assert_eq!(head.header("HOST"), Some(&b"x.test"[..]));
        assert_eq!(&raw[head.head_len..], b"rest");
    }

    #[test]
    fn partial_head_is_incomplete() {
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1\r\nHost: x"),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn garbage_is_malformed() {
        assert!(matches!(
            parse_response_head(b"\x00\x01nonsense\r\n\r\n"),
            Err(ParseError::Malformed(_))
        ));
    }

    #[test]
    fn finds_head_end() {
        assert_eq!(find_head_end(b"a\r\n\r\nb"), Some(5));
        assert_eq!(find_head_end(b"a\r\n"), None);
    }
}
