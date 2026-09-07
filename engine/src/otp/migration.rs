//! Google Authenticator migration format (`otpauth-migration://offline?data=…`).
//!
//! The `data` query parameter carries a Base64-encoded protobuf
//! `MigrationPayload` containing repeated `OtpParameters`. The wire format is
//! implemented here from the publicly known schema (protobuf field numbers as
//! used by Google Authenticator) — no generated code, no GPL code.

use crate::error::{Error, Result};
use crate::otp::types::{HashAlgorithm, OtpKind};
use base64::Engine;
use percent_encoding::percent_decode_str;

/// One OTP entry extracted from (or written to) a migration payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationEntry {
    pub secret: Vec<u8>,
    /// Account name.
    pub name: String,
    pub issuer: String,
    pub algorithm: HashAlgorithm,
    pub digits: u32,
    /// Only HOTP and TOTP exist in this format.
    pub kind: OtpKind,
    /// HOTP counter (ignored for TOTP).
    pub counter: u64,
}

// protobuf field numbers
const F_OTP_PARAMETERS: u32 = 1;
const F_VERSION: u32 = 2;
const F_BATCH_SIZE: u32 = 3;
const F_BATCH_INDEX: u32 = 4;
const F_BATCH_ID: u32 = 5;

const F_SECRET: u32 = 1;
const F_NAME: u32 = 2;
const F_ISSUER: u32 = 3;
const F_ALGORITHM: u32 = 4;
const F_DIGITS: u32 = 5;
const F_TYPE: u32 = 6;
const F_COUNTER: u32 = 7;

const WIRE_VARINT: u8 = 0;
const WIRE_LEN: u8 = 2;

/// Parses an `otpauth-migration://offline?data=…` URI into its entries.
pub fn parse_migration_uri(uri: &str) -> Result<Vec<MigrationEntry>> {
    let (scheme, rest) = uri
        .split_once(':')
        .ok_or_else(|| Error::InvalidUri("missing scheme".to_string()))?;
    if !scheme.eq_ignore_ascii_case("otpauth-migration") {
        return Err(Error::InvalidUri(format!("unsupported scheme: {scheme}")));
    }
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
    let data = query_param(query, "data")
        .ok_or_else(|| Error::InvalidUri("missing data parameter".to_string()))?;

    // The value may be raw or percent-encoded Base64; try both.
    let decoded = percent_decode_str(&data).decode_utf8_lossy().into_owned();
    let bytes = decode_base64_lenient(&data)
        .or_else(|| decode_base64_lenient(&decoded))
        .ok_or_else(|| Error::InvalidUri("data is not valid base64".to_string()))?;

    parse_payload(&bytes)
}

/// Builds an `otpauth-migration://offline?data=…` URI (single batch) holding
/// all entries.
pub fn build_migration_uri(entries: &[MigrationEntry]) -> Result<String> {
    let payload = encode_payload(entries)?;
    let data = base64::engine::general_purpose::STANDARD.encode(&payload);
    // Percent-encode the Base64 so the URI stays well-formed.
    let encoded = percent_encoding::utf8_percent_encode(&data, percent_encoding::NON_ALPHANUMERIC);
    Ok(format!("otpauth-migration://offline?data={encoded}"))
}

/// Decodes a `MigrationPayload` protobuf message.
pub fn parse_payload(bytes: &[u8]) -> Result<Vec<MigrationEntry>> {
    let mut r = PbReader::new(bytes);
    let mut out = Vec::new();
    while r.has_more() {
        let (field, wire) = r.read_tag()?;
        match (field, wire) {
            (F_OTP_PARAMETERS, WIRE_LEN) => {
                let len = r.read_varint()? as usize;
                let msg = r.read_bytes(len)?;
                out.push(parse_otp_parameters(msg)?);
            }
            (_, w) => r.skip(w)?, // version/batch fields and unknowns
        }
    }
    Ok(out)
}

fn parse_otp_parameters(data: &[u8]) -> Result<MigrationEntry> {
    let mut r = PbReader::new(data);
    let mut secret = Vec::new();
    let mut name = String::new();
    let mut issuer = String::new();
    let mut algorithm = 0u64;
    let mut digits = 0u64;
    let mut kind = 0u64;
    let mut counter = 0u64;

    while r.has_more() {
        let (field, wire) = r.read_tag()?;
        match (field, wire) {
            (F_SECRET, WIRE_LEN) => {
                let len = r.read_varint()? as usize;
                secret = r.read_bytes(len)?.to_vec();
            }
            (F_NAME, WIRE_LEN) => {
                let len = r.read_varint()? as usize;
                name = String::from_utf8_lossy(r.read_bytes(len)?).into_owned();
            }
            (F_ISSUER, WIRE_LEN) => {
                let len = r.read_varint()? as usize;
                issuer = String::from_utf8_lossy(r.read_bytes(len)?).into_owned();
            }
            (F_ALGORITHM, WIRE_VARINT) => algorithm = r.read_varint()?,
            (F_DIGITS, WIRE_VARINT) => digits = r.read_varint()?,
            (F_TYPE, WIRE_VARINT) => kind = r.read_varint()?,
            (F_COUNTER, WIRE_VARINT) => counter = r.read_varint()?,
            (_, w) => r.skip(w)?,
        }
    }

    if secret.is_empty() {
        return Err(Error::InvalidUri(
            "migration entry has empty secret".to_string(),
        ));
    }

    let algorithm = match algorithm {
        0 | 1 => HashAlgorithm::Sha1,
        2 => HashAlgorithm::Sha256,
        3 => HashAlgorithm::Sha512,
        4 => HashAlgorithm::Md5,
        other => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "migration algorithm {other}"
            )))
        }
    };
    let digits = match digits {
        0 | 1 => 6,
        2 => 8,
        other => return Err(Error::InvalidUri(format!("migration digit count {other}"))),
    };
    let otp_kind = match kind {
        0 | 2 => OtpKind::Totp,
        1 => OtpKind::Hotp,
        other => return Err(Error::UnsupportedType(format!("migration type {other}"))),
    };

    Ok(MigrationEntry {
        secret,
        name,
        issuer,
        algorithm,
        digits,
        kind: otp_kind,
        counter,
    })
}

/// Encodes a `MigrationPayload` protobuf message (single batch).
pub fn encode_payload(entries: &[MigrationEntry]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    for e in entries {
        let msg = encode_otp_parameters(e)?;
        write_len_delimited(&mut buf, F_OTP_PARAMETERS, &msg);
    }
    write_varint_field(&mut buf, F_VERSION, 1);
    write_varint_field(&mut buf, F_BATCH_SIZE, 1);
    write_varint_field(&mut buf, F_BATCH_INDEX, 0);
    write_varint_field(&mut buf, F_BATCH_ID, 0);
    Ok(buf)
}

fn encode_otp_parameters(e: &MigrationEntry) -> Result<Vec<u8>> {
    let algorithm = match e.algorithm {
        HashAlgorithm::Sha1 => 1u64,
        HashAlgorithm::Sha256 => 2,
        HashAlgorithm::Sha512 => 3,
        HashAlgorithm::Md5 => 4,
    };
    let digits = match e.digits {
        8 => 2u64,
        _ => 1, // six (also the default)
    };
    let kind = match e.kind {
        OtpKind::Hotp => 1u64,
        _ => 2, // TOTP
    };

    let mut buf = Vec::new();
    write_len_delimited(&mut buf, F_SECRET, &e.secret);
    write_len_delimited(&mut buf, F_NAME, e.name.as_bytes());
    write_len_delimited(&mut buf, F_ISSUER, e.issuer.as_bytes());
    write_varint_field(&mut buf, F_ALGORITHM, algorithm);
    write_varint_field(&mut buf, F_DIGITS, digits);
    write_varint_field(&mut buf, F_TYPE, kind);
    write_varint_field(&mut buf, F_COUNTER, e.counter);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// minimal protobuf wire-format reader/writer

struct PbReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> PbReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn has_more(&self) -> bool {
        self.pos < self.data.len()
    }

    fn read_varint(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            let b = *self
                .data
                .get(self.pos)
                .ok_or_else(|| Error::Encoding("truncated protobuf".to_string()))?;
            self.pos += 1;
            result |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err(Error::Encoding("varint too long".to_string()));
            }
        }
        Ok(result)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return Err(Error::Encoding("truncated protobuf".to_string()));
        }
        let s = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }

    fn read_tag(&mut self) -> Result<(u32, u8)> {
        let tag = self.read_varint()?;
        Ok(((tag >> 3) as u32, (tag & 0x7) as u8))
    }

    fn skip(&mut self, wire_type: u8) -> Result<()> {
        match wire_type {
            WIRE_VARINT => {
                self.read_varint()?;
            }
            1 => {
                self.read_bytes(8)?;
            }
            WIRE_LEN => {
                let len = self.read_varint()? as usize;
                self.read_bytes(len)?;
            }
            5 => {
                self.read_bytes(4)?;
            }
            other => {
                return Err(Error::Encoding(format!(
                    "unsupported protobuf wire type {other}"
                )))
            }
        }
        Ok(())
    }
}

fn write_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(b);
            break;
        }
        buf.push(b | 0x80);
    }
}

fn write_tag(buf: &mut Vec<u8>, field: u32, wire_type: u8) {
    write_varint(buf, (u64::from(field) << 3) | u64::from(wire_type));
}

fn write_varint_field(buf: &mut Vec<u8>, field: u32, value: u64) {
    write_tag(buf, field, WIRE_VARINT);
    write_varint(buf, value);
}

fn write_len_delimited(buf: &mut Vec<u8>, field: u32, data: &[u8]) {
    write_tag(buf, field, WIRE_LEN);
    write_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

// ---------------------------------------------------------------------------
// helpers

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if k.eq_ignore_ascii_case(key) {
            return Some(v.to_string());
        }
    }
    None
}

fn decode_base64_lenient(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(v) = engine.decode(cleaned.as_bytes()) {
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::base32;

    #[test]
    fn payload_roundtrip() {
        let entries = vec![
            MigrationEntry {
                secret: b"12345678901234567890".to_vec(),
                name: "alice@example.com".to_string(),
                issuer: "GitHub".to_string(),
                algorithm: HashAlgorithm::Sha1,
                digits: 6,
                kind: OtpKind::Totp,
                counter: 0,
            },
            MigrationEntry {
                secret: base32::decode_tolerant("JBSWY3DPEHPK3PXP").unwrap(),
                name: "bob".to_string(),
                issuer: String::new(),
                algorithm: HashAlgorithm::Sha256,
                digits: 8,
                kind: OtpKind::Hotp,
                counter: 42,
            },
        ];

        let uri = build_migration_uri(&entries).unwrap();
        let parsed = parse_migration_uri(&uri).unwrap();
        assert_eq!(parsed, entries);
    }

    #[test]
    fn uri_shape() {
        let entries = vec![MigrationEntry {
            secret: vec![1, 2, 3],
            name: "alice".to_string(),
            issuer: "Issuer".to_string(),
            algorithm: HashAlgorithm::Sha1,
            digits: 6,
            kind: OtpKind::Totp,
            counter: 0,
        }];
        let uri = build_migration_uri(&entries).unwrap();
        assert!(uri.starts_with("otpauth-migration://offline?data="));
    }
}
