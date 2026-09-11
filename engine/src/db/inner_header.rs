//! KDBX 4.x inner header (inside the decrypted, decompressed payload).
//!
//! The inner header holds the inner random stream ID/key and binary
//! attachments, and is stored immediately before the XML. Layout is the same
//! TLV scheme as the outer header: field ID (1 byte), size (u32 LE), value.

use crate::error::{Error, Result};

const FIELD_END: u8 = 0;
const FIELD_INNER_RANDOM_STREAM_ID: u8 = 1;
const FIELD_INNER_RANDOM_STREAM_KEY: u8 = 2;
const FIELD_BINARY: u8 = 3;

const BINARY_FLAG_PROTECTED: u8 = 1;

/// A binary attachment stored in the inner header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerBinary {
    pub protected: bool,
    pub data: Vec<u8>,
}

/// Parsed KDBX 4 inner header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerHeader {
    /// Inner random stream ID: 2 = Salsa20, 3 = ChaCha20.
    pub inner_random_stream_id: u32,
    /// Inner random stream key (32 bytes for Salsa20, 64 for ChaCha20).
    pub inner_random_stream_key: Vec<u8>,
    /// Binary attachments.
    pub binaries: Vec<InnerBinary>,
}

impl InnerHeader {
    /// Parses the inner header. Returns the header and bytes consumed (the XML
    /// starts at that offset).
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        let mut pos = 0usize;
        let mut stream_id = 0u32;
        let mut stream_key = Vec::new();
        let mut binaries = Vec::new();

        loop {
            let field_id = read_u8(data, &mut pos)?;
            let size = read_u32(data, &mut pos)? as usize;
            if field_id == FIELD_END {
                break;
            }
            let value = read_bytes(data, &mut pos, size)?;
            match field_id {
                FIELD_INNER_RANDOM_STREAM_ID => {
                    stream_id = read_u32_slice(value)?;
                }
                FIELD_INNER_RANDOM_STREAM_KEY => stream_key = value.to_vec(),
                FIELD_BINARY => {
                    if value.is_empty() {
                        return Err(Error::Encoding("empty inner header binary".to_string()));
                    }
                    binaries.push(InnerBinary {
                        protected: value[0] & BINARY_FLAG_PROTECTED != 0,
                        data: value[1..].to_vec(),
                    });
                }
                _ => {}
            }
        }

        Ok((
            InnerHeader {
                inner_random_stream_id: stream_id,
                inner_random_stream_key: stream_key,
                binaries,
            },
            pos,
        ))
    }

    /// Serializes the inner header.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        push_field(
            &mut out,
            FIELD_INNER_RANDOM_STREAM_ID,
            &self.inner_random_stream_id.to_le_bytes(),
        );
        push_field(
            &mut out,
            FIELD_INNER_RANDOM_STREAM_KEY,
            &self.inner_random_stream_key,
        );
        for b in &self.binaries {
            let mut value = Vec::with_capacity(b.data.len() + 1);
            value.push(if b.protected {
                BINARY_FLAG_PROTECTED
            } else {
                0
            });
            value.extend_from_slice(&b.data);
            push_field(&mut out, FIELD_BINARY, &value);
        }
        out.push(FIELD_END);
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }
}

fn push_field(out: &mut Vec<u8>, id: u8, value: &[u8]) {
    out.push(id);
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8> {
    let b = *data
        .get(*pos)
        .ok_or_else(|| Error::Encoding("truncated inner header".to_string()))?;
    *pos += 1;
    Ok(b)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    let b = read_bytes(data, pos, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u32_slice(data: &[u8]) -> Result<u32> {
    let b: [u8; 4] = data
        .try_into()
        .map_err(|_| Error::Encoding("inner stream id must be 4 bytes".to_string()))?;
    Ok(u32::from_le_bytes(b))
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    // saturating_sub instead of `pos + len`: a hostile u32 field size must
    // never overflow the bounds check.
    if len > data.len().saturating_sub(*pos) {
        return Err(Error::Encoding("truncated inner header".to_string()));
    }
    let s = &data[*pos..*pos + len];
    *pos += len;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let h = InnerHeader {
            inner_random_stream_id: 3,
            inner_random_stream_key: vec![0xAB; 64],
            binaries: vec![
                InnerBinary {
                    protected: true,
                    data: vec![1, 2, 3],
                },
                InnerBinary {
                    protected: false,
                    data: b"plain".to_vec(),
                },
            ],
        };
        let ser = h.serialize();
        let (parsed, consumed) = InnerHeader::parse(&ser).unwrap();
        assert_eq!(consumed, ser.len());
        assert_eq!(parsed, h);
    }

    #[test]
    fn empty_roundtrip() {
        let h = InnerHeader {
            inner_random_stream_id: 3,
            inner_random_stream_key: vec![0x11; 64],
            binaries: vec![],
        };
        let ser = h.serialize();
        assert_eq!(InnerHeader::parse(&ser).unwrap().0, h);
    }
}
