//! Display-only body decoding. Nothing here affects what goes on the wire.

use std::io::Read;

use super::head::{find_head_end, parse_response_head, Header};

/// Limit on decoded output, so a compression bomb cannot exhaust memory.
pub const MAX_DECODED: u64 = 64 * 1024 * 1024;

fn header_text<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(&h.value).ok())
}

/// Removes chunked framing. Returns `None` if the body is not validly chunked.
pub fn dechunk(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    loop {
        let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&rest[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(rest.get(..size)?);
        rest = rest.get(size + 2..)?;
    }
}

fn read_limited(reader: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(MAX_DECODED).read_to_end(&mut out).ok()?;
    Some(out)
}

pub fn inflate(body: &[u8], coding: &str) -> Option<Vec<u8>> {
    match coding {
        "gzip" | "x-gzip" => read_limited(flate2::read::MultiGzDecoder::new(body)),
        "deflate" => read_limited(flate2::read::ZlibDecoder::new(body))
            .or_else(|| read_limited(flate2::read::DeflateDecoder::new(body))),
        "br" => read_limited(brotli::Decompressor::new(body, 4096)),
        "zstd" => read_limited(zstd::stream::read::Decoder::new(body).ok()?),
        "identity" | "" => Some(body.to_vec()),
        _ => None,
    }
}

/// Removes transfer framing, leaving the body as is if it is not valid.
pub fn unframe(headers: &[Header], body: &[u8]) -> Vec<u8> {
    let chunked = header_text(headers, "transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        dechunk(body).unwrap_or_else(|| body.to_vec())
    } else {
        body.to_vec()
    }
}

/// Undoes `Content-Encoding`, or returns `None` if the body cannot be decoded.
pub fn decompress(headers: &[Header], unframed: &[u8]) -> Option<Vec<u8>> {
    let mut current = unframed.to_vec();
    if let Some(codings) = header_text(headers, "content-encoding") {
        // Codings are listed in the order they were applied.
        for coding in codings.rsplit(',') {
            current = inflate(&current, coding.trim().to_ascii_lowercase().as_str())?;
        }
    }
    Some(current)
}

/// Returns the readable form of a body, or the input if it cannot be decoded.
pub fn decode_body(headers: &[Header], body: &[u8]) -> Vec<u8> {
    let unframed = unframe(headers, body);
    decompress(headers, &unframed).unwrap_or(unframed)
}

/// A whole response with its body made readable, or `None` if that changes nothing.
pub fn decode_response(raw: &[u8]) -> Option<Vec<u8>> {
    let head = parse_response_head(raw).ok()?;
    let end = find_head_end(raw)?;
    let decoded = decode_body(&head.headers, &raw[end..]);
    (decoded != raw[end..]).then(|| [&raw[..end], decoded.as_slice()].concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn header(name: &str, value: &str) -> Header {
        Header {
            name: name.into(),
            value: value.as_bytes().to_vec(),
        }
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn dechunks() {
        assert_eq!(dechunk(b"3\r\nabc\r\n2;x\r\nde\r\n0\r\n\r\n").unwrap(), b"abcde");
        assert!(dechunk(b"zz\r\n").is_none());
    }

    #[test]
    fn decodes_gzip() {
        let headers = [header("Content-Encoding", "gzip")];
        assert_eq!(decode_body(&headers, &gzip(b"hello")), b"hello");
    }

    #[test]
    fn decodes_zstd_and_brotli() {
        let z = zstd::encode_all(&b"hello"[..], 1).unwrap();
        assert_eq!(decode_body(&[header("content-encoding", "zstd")], &z), b"hello");
        let mut br = Vec::new();
        brotli::CompressorWriter::new(&mut br, 4096, 5, 22).write_all(b"hello").unwrap();
        assert_eq!(decode_body(&[header("content-encoding", "br")], &br), b"hello");
    }

    #[test]
    fn decodes_whole_responses_only_when_it_helps() {
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        raw.extend(gzip(b"hello"));
        assert_eq!(
            decode_response(&raw).unwrap(),
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nhello"
        );
        assert_eq!(decode_response(b"HTTP/1.1 200 OK\r\n\r\nhello"), None);
    }

    #[test]
    fn broken_compression_falls_back_to_raw_bytes() {
        let headers = [header("Content-Encoding", "gzip")];
        assert_eq!(decode_body(&headers, b"not gzip"), b"not gzip");
    }
}
