//! Payload compression (GZip), as used by KDBX.

use std::io::{Read, Write};

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::error::{Error, Result};

/// GZip-compresses data.
pub fn gzip_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)
        .map_err(|e| Error::Encoding(format!("gzip compress: {e}")))?;
    enc.finish()
        .map_err(|e| Error::Encoding(format!("gzip finish: {e}")))
}

/// GZip-decompresses data.
pub fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut dec = GzDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| Error::Encoding(format!("gzip decompress: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"KeePass XML payload ".repeat(1000);
        let compressed = gzip_compress(&data).unwrap();
        assert!(compressed.len() < data.len());
        assert_eq!(gzip_decompress(&compressed).unwrap(), data);
    }

    #[test]
    fn gzip_header_magic() {
        // gzip files start with 1f 8b
        let compressed = gzip_compress(b"hello").unwrap();
        assert_eq!(&compressed[0..2], &[0x1f, 0x8b]);
    }
}
