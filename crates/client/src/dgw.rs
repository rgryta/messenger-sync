//! Meta's gateway ("DGW") framing: what `wss://gateway.facebook.com/ws/lightspeed` carries.
//!
//! One websocket message holds one or more frames, each a type byte and, for most, a
//! little-endian stream id and a 24-bit little-endian length. Streams multiplex requests over
//! the one socket: a stream opens with `EstablishStream` (JSON parameters), carries `Data`
//! (optionally acknowledged), and ends with `EndOfData`. Ported from mautrix-meta's
//! `pkg/messagix/dgw/frames.go`; `tests/dgw.rs` decodes and re-encodes what that code made.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Ping,
    Pong,
    /// The session is no longer authorised.
    Deauth,
    /// The server wants the client to move to a new connection.
    Drain {
        reason: u8,
    },
    Ack {
        stream: u16,
        ack: u16,
    },
    Data {
        stream: u16,
        /// 15 bits; meaningful when `requires_ack` is set.
        ack_id: u16,
        requires_ack: bool,
        /// Present on extended data frames.
        content_type: Option<u8>,
        payload: Vec<u8>,
    },
    EndOfData {
        stream: u16,
        reason: Option<u8>,
    },
    Establish {
        stream: u16,
        parameters: Vec<u8>,
    },
    /// A type this client does not read, kept whole; it ends the message, since its length
    /// is unknown.
    Unsupported(Vec<u8>),
}

const DRAIN: u8 = 3;
const DEAUTH: u8 = 4;
const PING: u8 = 9;
const PONG: u8 = 10;
const ACK: u8 = 12;
const DATA: u8 = 13;
const END_OF_DATA: u8 = 14;
const ESTABLISH: u8 = 15;
const END_OF_DATA_WITH_REASON: u8 = 16;
const EXTENDED_DATA: u8 = 17;

const REQUIRES_ACK: u16 = 0x8000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DgwError {
    #[error("a {0} frame was cut short")]
    Short(&'static str),
    #[error("a {0} frame has an impossible length")]
    Length(&'static str),
}

fn u24(b: &[u8]) -> usize {
    usize::from(b[0]) | usize::from(b[1]) << 8 | usize::from(b[2]) << 16
}

fn push_u24(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u32).to_le_bytes()[..3]);
}

fn stream(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[1], b[2]])
}

impl Frame {
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Ping => out.push(PING),
            Frame::Pong => out.push(PONG),
            Frame::Deauth => out.push(DEAUTH),
            Frame::Drain { reason } => {
                out.push(DRAIN);
                push_u24(out, 1);
                out.push(*reason);
            }
            Frame::Ack { stream, ack } => {
                out.push(ACK);
                out.extend_from_slice(&stream.to_le_bytes());
                push_u24(out, 2);
                out.extend_from_slice(&ack.to_le_bytes());
            }
            Frame::Data {
                stream,
                ack_id,
                requires_ack,
                content_type,
                payload,
            } => {
                out.push(if content_type.is_some() {
                    EXTENDED_DATA
                } else {
                    DATA
                });
                out.extend_from_slice(&stream.to_le_bytes());
                push_u24(out, 2 + usize::from(content_type.is_some()) + payload.len());
                let id = (ack_id & !REQUIRES_ACK) | if *requires_ack { REQUIRES_ACK } else { 0 };
                out.extend_from_slice(&id.to_le_bytes());
                out.extend(content_type);
                out.extend_from_slice(payload);
            }
            Frame::EndOfData { stream, reason } => match reason {
                None => {
                    out.push(END_OF_DATA);
                    out.extend_from_slice(&stream.to_le_bytes());
                }
                Some(reason) => {
                    out.push(END_OF_DATA_WITH_REASON);
                    out.extend_from_slice(&stream.to_le_bytes());
                    push_u24(out, 1);
                    out.push(*reason);
                }
            },
            Frame::Establish { stream, parameters } => {
                out.push(ESTABLISH);
                out.extend_from_slice(&stream.to_le_bytes());
                push_u24(out, parameters.len());
                out.extend_from_slice(parameters);
            }
            Frame::Unsupported(raw) => out.extend_from_slice(raw),
        }
    }

    /// Every frame in one websocket message, in order.
    pub fn decode_all(mut message: &[u8]) -> Result<Vec<Frame>, DgwError> {
        let mut frames = Vec::new();
        while !message.is_empty() {
            let (frame, rest) = Frame::decode(message)?;
            frames.push(frame);
            message = rest;
        }
        Ok(frames)
    }

    fn decode(b: &[u8]) -> Result<(Frame, &[u8]), DgwError> {
        // Frames with a stream id and a 24-bit length: (header, body) split out once.
        let sized = |name: &'static str, min: usize| -> Result<(usize, &[u8], &[u8]), DgwError> {
            if b.len() < 6 {
                return Err(DgwError::Short(name));
            }
            let length = u24(&b[3..6]);
            if length < min {
                return Err(DgwError::Length(name));
            }
            let end = 6 + length;
            if b.len() < end {
                return Err(DgwError::Short(name));
            }
            Ok((length, &b[6..end], &b[end..]))
        };
        Ok(match b[0] {
            PING => (Frame::Ping, &b[1..]),
            PONG => (Frame::Pong, &b[1..]),
            DEAUTH => (Frame::Deauth, &b[1..]),
            DRAIN => {
                // The length sits right after the type byte here: there is no stream.
                if b.len() < 5 {
                    return Err(DgwError::Short("drain"));
                }
                if u24(&b[1..4]) != 1 {
                    return Err(DgwError::Length("drain"));
                }
                (Frame::Drain { reason: b[4] }, &b[5..])
            }
            ACK => {
                let (length, body, rest) = sized("ack", 2)?;
                if length != 2 {
                    return Err(DgwError::Length("ack"));
                }
                let ack = u16::from_le_bytes([body[0], body[1]]);
                (
                    Frame::Ack {
                        stream: stream(b),
                        ack,
                    },
                    rest,
                )
            }
            DATA | EXTENDED_DATA => {
                let extended = b[0] == EXTENDED_DATA;
                let (_, body, rest) = sized("data", if extended { 3 } else { 2 })?;
                let id = u16::from_le_bytes([body[0], body[1]]);
                let (content_type, payload) = if extended {
                    (Some(body[2]), &body[3..])
                } else {
                    (None, &body[2..])
                };
                (
                    Frame::Data {
                        stream: stream(b),
                        ack_id: id & !REQUIRES_ACK,
                        requires_ack: id & REQUIRES_ACK != 0,
                        content_type,
                        payload: payload.to_vec(),
                    },
                    rest,
                )
            }
            END_OF_DATA => {
                if b.len() < 3 {
                    return Err(DgwError::Short("end of data"));
                }
                (
                    Frame::EndOfData {
                        stream: stream(b),
                        reason: None,
                    },
                    &b[3..],
                )
            }
            END_OF_DATA_WITH_REASON => {
                let (_, body, rest) = sized("end of data", 1)?;
                (
                    Frame::EndOfData {
                        stream: stream(b),
                        reason: Some(body[0]),
                    },
                    rest,
                )
            }
            ESTABLISH => {
                let (_, body, rest) = sized("establish", 0)?;
                (
                    Frame::Establish {
                        stream: stream(b),
                        parameters: body.to_vec(),
                    },
                    rest,
                )
            }
            // Including `Empty` (2), which mautrix reads as unsupported too.
            _ => (Frame::Unsupported(b.to_vec()), &[][..]),
        })
    }
}
