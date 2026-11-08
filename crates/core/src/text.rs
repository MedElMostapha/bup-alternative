//! Moves raw bytes through the text-only UI without losing any of them.
//! Valid UTF-8 is shown as is; anything else maps each byte to one character.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Utf8,
    Latin1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawText {
    pub text: String,
    pub encoding: Encoding,
}

impl RawText {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(text) => Self {
                text: text.to_string(),
                encoding: Encoding::Utf8,
            },
            Err(_) => Self {
                text: bytes.iter().map(|b| *b as char).collect(),
                encoding: Encoding::Latin1,
            },
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        encode(&self.text, self.encoding)
    }
}

/// Characters a user typed outside the byte range are kept as UTF-8.
pub fn encode(text: &str, encoding: Encoding) -> Vec<u8> {
    match encoding {
        Encoding::Utf8 => text.as_bytes().to_vec(),
        Encoding::Latin1 => {
            let mut out = Vec::with_capacity(text.len());
            let mut utf8 = [0u8; 4];
            for c in text.chars() {
                match u8::try_from(c as u32) {
                    Ok(byte) => out.push(byte),
                    Err(_) => out.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes()),
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips() {
        let raw = RawText::from_bytes("héllo\r\n".as_bytes());
        assert_eq!(raw.encoding, Encoding::Utf8);
        assert_eq!(raw.to_bytes(), "héllo\r\n".as_bytes());
    }

    #[test]
    fn every_byte_value_round_trips() {
        let bytes: Vec<u8> = (0..=255).collect();
        let raw = RawText::from_bytes(&bytes);
        assert_eq!(raw.encoding, Encoding::Latin1);
        assert_eq!(raw.to_bytes(), bytes);
    }
}
