//! Converts text between the encodings found in web traffic. Nothing here
//! touches the project or the network.

use std::io::Write;

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD, URL_SAFE_NO_PAD};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::http::decode::inflate;
use crate::text::RawText;

const MAX_ENTITY: usize = 12;
const MAX_SMART_STEPS: usize = 8;
const MIN_SMART_BASE64: usize = 8;
const MIN_SMART_HEX: usize = 4;
const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];

/// Real traffic often drops padding or leaves stray bits in the last character.
const TOLERANT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecoderError {
    #[error("not valid Base64: {0}")]
    Base64(String),
    #[error("not valid hex: {0}")]
    Hex(&'static str),
    #[error("not valid gzip data")]
    Gzip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    UrlDecode,
    /// Also turns `+` into a space, as HTML form bodies and queries use it.
    FormDecode,
    HtmlDecode,
    /// Accepts both alphabets, with or without padding.
    Base64Decode,
    HexDecode,
    GzipDecode,
    /// Leaves only unreserved characters as they are.
    UrlEncode,
    UrlEncodeAll,
    HtmlEncode,
    Base64Encode,
    Base64UrlEncode,
    HexEncode,
    GzipEncode,
    Sha256,
}

fn hex_digit(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|d| d as u8)
}

fn hex_pair(pair: &[u8]) -> Option<u8> {
    Some(hex_digit(pair[0])? << 4 | hex_digit(pair[1])?)
}

fn url_decode(input: &[u8], plus_is_space: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let escaped = (input[i] == b'%').then(|| input.get(i + 1..i + 3)).flatten().and_then(hex_pair);
        match (escaped, input[i]) {
            (Some(byte), _) => {
                out.push(byte);
                i += 3;
                continue;
            }
            (None, b'+') if plus_is_space => out.push(b' '),
            (None, byte) => out.push(byte),
        }
        i += 1;
    }
    out
}

fn percent_encode(input: &[u8], keep: impl Fn(u8) -> bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for byte in input {
        if keep(*byte) {
            out.push(*byte);
        } else {
            out.extend_from_slice(format!("%{byte:02X}").as_bytes());
        }
    }
    out
}

fn entity(name: &[u8]) -> Option<char> {
    let name = std::str::from_utf8(name).ok()?;
    if let Some(number) = name.strip_prefix('#') {
        let code = match number.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => number.parse().ok()?,
        };
        return char::from_u32(code);
    }
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{a0}'),
        _ => None,
    }
}

/// One pass only, so `&amp;lt;` becomes `&lt;` as a browser would show it.
fn html_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut rest = input;
    while let Some((&first, tail)) = rest.split_first() {
        if first == b'&' {
            let end = tail.iter().take(MAX_ENTITY).position(|b| *b == b';');
            if let Some((end, c)) = end.and_then(|end| Some((end, entity(&tail[..end])?))) {
                out.extend_from_slice(c.encode_utf8(&mut [0u8; 4]).as_bytes());
                rest = &tail[end + 1..];
                continue;
            }
        }
        out.push(first);
        rest = tail;
    }
    out
}

fn html_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for byte in input {
        match byte {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\'' => out.extend_from_slice(b"&#39;"),
            other => out.push(*other),
        }
    }
    out
}

fn base64_decode(input: &[u8]) -> Result<Vec<u8>, DecoderError> {
    let standard: Vec<u8> = input
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'-' => b'+',
            b'_' => b'/',
            other => *other,
        })
        .collect();
    TOLERANT_BASE64
        .decode(standard)
        .map_err(|e| DecoderError::Base64(e.to_string()))
}

fn hex_decode(input: &[u8]) -> Result<Vec<u8>, DecoderError> {
    let digits: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace() && *b != b':')
        .collect();
    let digits = digits.strip_prefix(b"0x").unwrap_or(&digits);
    if !digits.len().is_multiple_of(2) {
        return Err(DecoderError::Hex("it has an odd number of digits"));
    }
    digits
        .chunks(2)
        .map(|pair| hex_pair(pair).ok_or(DecoderError::Hex("it contains a character that is not a hex digit")))
        .collect()
}

fn hex_encode(input: &[u8]) -> Vec<u8> {
    input.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect()
}

fn gzip_encode(input: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(input)
        .and_then(|_| encoder.try_finish())
        .expect("writing to memory cannot fail");
    encoder.finish().expect("writing to memory cannot fail")
}

impl Transform {
    pub fn apply(self, input: &[u8]) -> Result<Vec<u8>, DecoderError> {
        Ok(match self {
            Self::UrlDecode => url_decode(input, false),
            Self::FormDecode => url_decode(input, true),
            Self::HtmlDecode => html_decode(input),
            Self::Base64Decode => base64_decode(input)?,
            Self::HexDecode => hex_decode(input)?,
            Self::GzipDecode => inflate(input, "gzip").ok_or(DecoderError::Gzip)?,
            Self::UrlEncode => percent_encode(input, |b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)),
            Self::UrlEncodeAll => percent_encode(input, |_| false),
            Self::HtmlEncode => html_encode(input),
            Self::Base64Encode => STANDARD.encode(input).into_bytes(),
            Self::Base64UrlEncode => URL_SAFE_NO_PAD.encode(input).into_bytes(),
            Self::HexEncode => hex_encode(input),
            Self::GzipEncode => gzip_encode(input),
            Self::Sha256 => hex_encode(&Sha256::digest(input)),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StepOutput {
    pub raw: RawText,
    pub length: u64,
}

/// One output per step, stopping at the first step that fails.
#[derive(Debug, Clone, Serialize)]
pub struct DecoderRun {
    pub outputs: Vec<StepOutput>,
    pub error: Option<String>,
}

pub fn run(input: &[u8], steps: &[Transform]) -> DecoderRun {
    let mut outputs = Vec::with_capacity(steps.len());
    let mut current = input.to_vec();
    for step in steps {
        match step.apply(&current) {
            Ok(next) => {
                outputs.push(StepOutput {
                    raw: RawText::from_bytes(&next),
                    length: next.len() as u64,
                });
                current = next;
            }
            Err(e) => {
                return DecoderRun {
                    outputs,
                    error: Some(e.to_string()),
                }
            }
        }
    }
    DecoderRun { outputs, error: None }
}

fn is_readable(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| !text.chars().any(|c| c.is_control() && !c.is_ascii_whitespace()))
}

/// Short strings of letters are valid Base64 and hex by accident, so those two
/// only count when the result is something a person or gzip could read.
fn guess(input: &[u8]) -> Option<Transform> {
    if input.starts_with(GZIP_MAGIC) {
        return Some(Transform::GzipDecode);
    }
    let text = std::str::from_utf8(input).ok()?.trim().as_bytes();
    let plausible = |decoded: Vec<u8>| !decoded.is_empty() && (is_readable(&decoded) || decoded.starts_with(GZIP_MAGIC));
    if text.windows(3).any(|w| w[0] == b'%' && hex_pair(&w[1..]).is_some()) {
        Some(Transform::UrlDecode)
    } else if html_decode(text) != text {
        Some(Transform::HtmlDecode)
    } else if text.len() >= MIN_SMART_HEX && hex_decode(text).is_ok_and(plausible) {
        Some(Transform::HexDecode)
    } else if text.len() >= MIN_SMART_BASE64
        && text.iter().all(|b| b.is_ascii_alphanumeric() || b"+/-_=".contains(b))
        && base64_decode(text).is_ok_and(plausible)
    {
        Some(Transform::Base64Decode)
    } else {
        None
    }
}

/// The decoding steps that seem to apply to `input`, outermost first.
pub fn smart_steps(input: &[u8]) -> Vec<Transform> {
    let mut steps = Vec::new();
    let mut current = input.to_vec();
    while steps.len() < MAX_SMART_STEPS {
        let Some(step) = guess(&current) else { break };
        match step.apply(&current) {
            Ok(next) if next != current => current = next,
            _ => break,
        }
        steps.push(step);
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(step: Transform, input: &str) -> String {
        String::from_utf8_lossy(&step.apply(input.as_bytes()).unwrap()).into_owned()
    }

    #[test]
    fn step_names_match_the_interface() {
        assert_eq!(serde_json::to_string(&Transform::Base64UrlEncode).unwrap(), "\"base64_url_encode\"");
        assert_eq!(serde_json::to_string(&Transform::Sha256).unwrap(), "\"sha256\"");
    }

    #[test]
    fn url_decoding_keeps_what_it_cannot_read() {
        assert_eq!(apply(Transform::UrlDecode, "a%20b%2Fc+d"), "a b/c+d");
        assert_eq!(apply(Transform::FormDecode, "a%20b+c"), "a b c");
        assert_eq!(apply(Transform::UrlDecode, "100%zz%4"), "100%zz%4");
        assert_eq!(Transform::UrlDecode.apply(b"%FF").unwrap(), [0xff]);
    }

    #[test]
    fn url_encoding_has_two_strengths() {
        assert_eq!(apply(Transform::UrlEncode, "a b/~-"), "a%20b%2F~-");
        assert_eq!(apply(Transform::UrlEncodeAll, "a/"), "%61%2F");
    }

    #[test]
    fn html_entities() {
        assert_eq!(apply(Transform::HtmlDecode, "&lt;a&gt; &#65;&#x42; &amp;lt; &bogus; & x"), "<a> AB &lt; &bogus; & x");
        assert_eq!(apply(Transform::HtmlEncode, "<a href=\"x\">&'"), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    }

    #[test]
    fn base64_accepts_either_alphabet_and_missing_padding() {
        assert_eq!(apply(Transform::Base64Decode, "aGk/Pw=="), "hi??");
        assert_eq!(apply(Transform::Base64Decode, "aGk_Pw"), "hi??");
        assert_eq!(apply(Transform::Base64Decode, " aGk/\r\nPw== "), "hi??");
        assert_eq!(apply(Transform::Base64Encode, "hi??"), "aGk/Pw==");
        assert_eq!(apply(Transform::Base64UrlEncode, "hi??"), "aGk_Pw");
        assert!(matches!(Transform::Base64Decode.apply(b"a!b"), Err(DecoderError::Base64(_))));
    }

    #[test]
    fn hex_round_trips_and_explains_failures() {
        assert_eq!(apply(Transform::HexEncode, "AZ"), "415a");
        assert_eq!(apply(Transform::HexDecode, "0x41 5A"), "AZ");
        assert_eq!(apply(Transform::HexDecode, "41:5a"), "AZ");
        assert!(Transform::HexDecode.apply(b"414").is_err());
        assert!(Transform::HexDecode.apply(b"zz").is_err());
    }

    #[test]
    fn gzip_round_trips_and_rejects_other_data() {
        let compressed = Transform::GzipEncode.apply(b"hello").unwrap();
        assert_eq!(Transform::GzipDecode.apply(&compressed).unwrap(), b"hello");
        assert_eq!(Transform::GzipDecode.apply(b"not gzip"), Err(DecoderError::Gzip));
    }

    #[test]
    fn sha256_is_lowercase_hex() {
        assert_eq!(
            apply(Transform::Sha256, "abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_chain_stops_at_the_first_failure() {
        let done = run(b"YWJj", &[Transform::Base64Decode, Transform::HexEncode]);
        assert_eq!(done.outputs[1].raw.text, "616263");
        assert_eq!(done.outputs[1].length, 6);
        assert_eq!(done.error, None);

        let failed = run(b"YWJj", &[Transform::Base64Decode, Transform::HexDecode, Transform::Sha256]);
        assert_eq!(failed.outputs.len(), 1);
        assert!(failed.error.unwrap().contains("hex"));
    }

    #[test]
    fn binary_output_survives_the_chain() {
        let done = run(b"/w==", &[Transform::Base64Decode, Transform::HexEncode]);
        assert_eq!(done.outputs[0].length, 1);
        assert_eq!(done.outputs[1].raw.text, "ff");
    }

    #[test]
    fn smart_decoding_peels_nested_layers() {
        // The Base64 of "<b>-mark", then URL-encoded.
        assert_eq!(
            smart_steps(b"PGI%2BLW1hcms%3D"),
            [Transform::UrlDecode, Transform::Base64Decode]
        );
        assert_eq!(smart_steps(b"&lt;b&gt;"), [Transform::HtmlDecode]);
        assert_eq!(smart_steps(b"68656c6c6f"), [Transform::HexDecode]);
        let compressed = Transform::GzipEncode.apply(b"hello").unwrap();
        let wrapped = Transform::Base64Encode.apply(&compressed).unwrap();
        assert_eq!(smart_steps(&wrapped), [Transform::Base64Decode, Transform::GzipDecode]);
    }

    #[test]
    fn smart_decoding_leaves_plain_text_alone() {
        for plain in ["", "hello", "password", "deadbeef", "administrator", "GET / HTTP/1.1"] {
            assert_eq!(smart_steps(plain.as_bytes()), [], "{plain}");
        }
    }
}
