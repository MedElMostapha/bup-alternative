//! Raw HTTP/1.1 parsing. Messages stay as the exact bytes seen on the wire;
//! parsed views only borrow offsets into them, so header case, order and odd
//! formatting survive a round trip.

pub mod decode;
mod framing;
mod head;
mod reader;
pub mod rewrite;

pub use framing::{request_framing, response_framing, BodyFraming, ChunkedScanner};
pub use head::{find_head_end, parse_request_head, parse_response_head, Header, RequestHead, ResponseHead};
pub use reader::{BodyState, MessageReader};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("message head is incomplete")]
    Incomplete,
    #[error("malformed message head: {0}")]
    Malformed(String),
    #[error("malformed chunked body")]
    BadChunk,
}
