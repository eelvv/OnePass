//! KDBX 3.1 hashed block stream.
//!
//! Layout: for each block — 4-byte index (u32 LE), 32-byte SHA-256 hash,
//! 4-byte size (u32 LE), data. The terminating block has size 0 and an
//! all-zero hash.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

const DEFAULT_BLOCK_SIZE: usize = 1024 * 1024;

/// Encodes data into a hashed-block stream (including the terminating block).
pub fn encode(data: &[u8], block_size: usize) -> Vec<u8> {
    let bs = if block_size == 0 { DEFAULT_BLOCK_SIZE } else { block_size };
    let mut out = Vec::new();
    let mut index = 0u32;
    if data.is_empty() {
        write_block(&mut out, index, &[]);
    } else {
        for chunk in data.chunks(bs) {
            write_block(&mut out, index, chunk);
            index += 1;
        }
        write_block(&mut out, index, &[]);
    }
    out
}

/// Decodes a hashed-block stream, verifying each block's hash.
pub fn decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut index = 0u32;

    loop {
        let block_index = read_u32(data, &mut pos)?;
        if block_index != index {
            return Err(Error::Encoding("hashed block index mismatch".to_string()));
        }
        let stored_hash = read_bytes(data, &mut pos, 32)?;
        let size = read_u32(data, &mut pos)? as usize;
        let block = read_bytes(data, &mut pos, size)?;

        if size == 0 {
            if stored_hash.iter().any(|&b| b != 0) {
                return Err(Error::Encoding("hashed block terminator hash not zero".to_string()));
            }
            break;
        }
        let computed = Sha256::digest(block);
        if computed.as_slice() != stored_hash {
            return Err(Error::Encoding("hashed block hash mismatch".to_string()));
        }

        index += 1;
        out.extend_from_slice(block);
    }
    Ok(out)
}

fn write_block(out: &mut Vec<u8>, index: u32, data: &[u8]) {
    out.extend_from_slice(&index.to_le_bytes());
    if data.is_empty() {
        out.extend_from_slice(&[0u8; 32]);
    } else {
        out.extend_from_slice(&Sha256::digest(data));
    }
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    let b = read_bytes(data, pos, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    if *pos + len > data.len() {
        return Err(Error::Encoding("truncated hashed block stream".to_string()));
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
        for len in [0usize, 1, 100, 1024, 1024 * 1024 + 7] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let enc = encode(&data, 1024);
            assert_eq!(decode(&enc).unwrap(), data, "len={len}");
        }
    }

    #[test]
    fn tamper_detected() {
        let mut enc = encode(b"some data", 16);
        let n = enc.len();
        enc[n - 3] ^= 0xFF;
        assert!(decode(&enc).is_err());
    }
}
