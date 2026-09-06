//! KeePass VariantDictionary — the serialization used for KDF parameters and
//! public/custom data in the KDBX header.
//!
//! Format (independent implementation, matches KeePass 2.x / KeePassDX):
//! - u16 LE version (0x0100)
//! - repeated entries: type (1 byte), name length (u32 LE), name (UTF-8),
//!   value length (u32 LE), value
//! - a single 0x00 terminator byte

use std::collections::BTreeMap;

use crate::error::{Error, Result};

const VERSION: u16 = 0x0100;
const VDM_CRITICAL_MASK: u16 = 0xFF00;

/// Typed values supported by a VariantDictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VdValue {
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    ByteArray(Vec<u8>),
}

impl VdValue {
    fn type_byte(&self) -> u8 {
        match self {
            VdValue::UInt32(_) => 0x04,
            VdValue::UInt64(_) => 0x05,
            VdValue::Bool(_) => 0x08,
            VdValue::Int32(_) => 0x0C,
            VdValue::Int64(_) => 0x0D,
            VdValue::String(_) => 0x18,
            VdValue::ByteArray(_) => 0x42,
        }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            VdValue::UInt32(v) => v.to_le_bytes().to_vec(),
            VdValue::UInt64(v) => v.to_le_bytes().to_vec(),
            VdValue::Bool(b) => vec![u8::from(*b)],
            VdValue::Int32(v) => v.to_le_bytes().to_vec(),
            VdValue::Int64(v) => v.to_le_bytes().to_vec(),
            VdValue::String(s) => s.as_bytes().to_vec(),
            VdValue::ByteArray(b) => b.clone(),
        }
    }
}

/// A KeePass VariantDictionary. Uses a `BTreeMap` for deterministic output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VariantDictionary {
    map: BTreeMap<String, VdValue>,
}

impl VariantDictionary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, name: impl Into<String>, value: VdValue) {
        self.map.insert(name.into(), value);
    }

    pub fn get(&self, name: &str) -> Option<&VdValue> {
        self.map.get(name)
    }

    pub fn get_u32(&self, name: &str) -> Option<u32> {
        match self.map.get(name)? {
            VdValue::UInt32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_u64(&self, name: &str) -> Option<u64> {
        match self.map.get(name)? {
            VdValue::UInt64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_bool(&self, name: &str) -> Option<bool> {
        match self.map.get(name)? {
            VdValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_byte_array(&self, name: &str) -> Option<&[u8]> {
        match self.map.get(name)? {
            VdValue::ByteArray(v) => Some(v),
            _ => None,
        }
    }

    pub fn get_string(&self, name: &str) -> Option<&str> {
        match self.map.get(name)? {
            VdValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Serializes the dictionary.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&VERSION.to_le_bytes());
        for (name, vd) in &self.map {
            let name_bytes = name.as_bytes();
            let value_bytes = vd.encode();
            out.push(vd.type_byte());
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&value_bytes);
        }
        out.push(0x00);
        out
    }

    /// Deserializes a VariantDictionary.
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let mut pos = 0usize;
        let version = read_u16(data, &mut pos)?;
        if (version & VDM_CRITICAL_MASK) > (VERSION & VDM_CRITICAL_MASK) {
            return Err(Error::Encoding(format!(
                "unsupported variant dictionary version 0x{version:04x}"
            )));
        }

        let mut dict = VariantDictionary::new();
        loop {
            let type_byte = read_u8(data, &mut pos)?;
            if type_byte == 0x00 {
                break;
            }
            let name_len = read_u32(data, &mut pos)? as usize;
            let name = String::from_utf8(read_bytes(data, &mut pos, name_len)?.to_vec())
                .map_err(|_| Error::Encoding("invalid variant dict name utf-8".to_string()))?;
            let value_len = read_u32(data, &mut pos)? as usize;
            let value = read_bytes(data, &mut pos, value_len)?;

            let vd = match type_byte {
                0x04 if value.len() == 4 => {
                    VdValue::UInt32(u32::from_le_bytes(value.try_into().unwrap()))
                }
                0x05 if value.len() == 8 => {
                    VdValue::UInt64(u64::from_le_bytes(value.try_into().unwrap()))
                }
                0x08 if value.len() == 1 => VdValue::Bool(value[0] != 0),
                0x0C if value.len() == 4 => {
                    VdValue::Int32(i32::from_le_bytes(value.try_into().unwrap()))
                }
                0x0D if value.len() == 8 => {
                    VdValue::Int64(i64::from_le_bytes(value.try_into().unwrap()))
                }
                0x18 => VdValue::String(
                    String::from_utf8(value.to_vec())
                        .map_err(|_| Error::Encoding("invalid variant dict value utf-8".to_string()))?,
                ),
                0x42 => VdValue::ByteArray(value.to_vec()),
                _ => continue, // unknown type: skip
            };
            dict.map.insert(name, vd);
        }
        Ok(dict)
    }
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8> {
    let b = *data.get(*pos).ok_or_else(|| Error::Encoding("truncated".to_string()))?;
    *pos += 1;
    Ok(b)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16> {
    let b = read_bytes(data, pos, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    let b = read_bytes(data, pos, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    if *pos + len > data.len() {
        return Err(Error::Encoding("truncated variant dictionary".to_string()));
    }
    let s = &data[*pos..*pos + len];
    *pos += len;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_types() {
        let mut d = VariantDictionary::new();
        d.set("u32", VdValue::UInt32(0xDEAD_BEEF));
        d.set("u64", VdValue::UInt64(0x0102_0304_0506_0708));
        d.set("b", VdValue::Bool(true));
        d.set("i32", VdValue::Int32(-123));
        d.set("i64", VdValue::Int64(-9_000_000_000));
        d.set("s", VdValue::String("héllo".to_string()));
        d.set("bytes", VdValue::ByteArray(vec![1, 2, 3, 4, 5]));

        let ser = d.serialize();
        let d2 = VariantDictionary::deserialize(&ser).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn exact_byte_format() {
        // {"$UUID": ByteArray([0xEF,0x63,...,0x0C])} (Argon2d KDF UUID)
        let mut d = VariantDictionary::new();
        d.set(
            "$UUID",
            VdValue::ByteArray(vec![
                0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03,
                0xE3, 0x0A, 0x0C,
            ]),
        );

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x00, 0x01]); // version 0x0100 LE
        expected.push(0x42); // ByteArray
        expected.extend_from_slice(&5u32.to_le_bytes()); // name len "$UUID"
        expected.extend_from_slice(b"$UUID");
        expected.extend_from_slice(&16u32.to_le_bytes()); // value len
        expected.extend_from_slice(&[
            0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3,
            0x0A, 0x0C,
        ]);
        expected.push(0x00); // terminator

        assert_eq!(d.serialize(), expected);
        assert_eq!(VariantDictionary::deserialize(&expected).unwrap(), d);
    }

    #[test]
    fn rejects_bad_version() {
        // version 0x0200 -> high byte 0x02 > 0x01
        let bad = [0x00, 0x02, 0x00];
        assert!(VariantDictionary::deserialize(&bad).is_err());
    }
}
