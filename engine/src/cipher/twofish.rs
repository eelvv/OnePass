//! Twofish-256-CBC (PKCS#7 padding), KeePass KDBX.

use cbc::{Decryptor, Encryptor};
use cipher::block_padding::Pkcs7;
use cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use twofish::Twofish;

use crate::cipher::unpad_pkcs7_ct;
use crate::error::{Error, Result};

type TwofishCbcEnc = Encryptor<Twofish>;
type TwofishCbcDec = Decryptor<Twofish>;

pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = TwofishCbcEnc::new_from_slices(key, iv).map_err(|_| Error::InvalidSecret)?;
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ct = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|_| Error::Encoding("twofish-cbc encrypt failed".to_string()))?;
    Ok(ct.to_vec())
}

pub fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = TwofishCbcDec::new_from_slices(key, iv).map_err(|_| Error::InvalidSecret)?;
    let mut buf = ciphertext.to_vec();
    // CBC-decrypt block by block, then unpad in constant time.
    for chunk in buf.as_chunks_mut::<16>().0 {
        let mut block = Block::<Twofish>::clone_from_slice(chunk);
        cipher.decrypt_block_mut(&mut block);
        chunk.copy_from_slice(&block);
    }
    let end = unpad_pkcs7_ct(&buf, 16)?;
    buf.truncate(end);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let iv = [1u8; 16];
        for len in [0usize, 1, 15, 16, 17, 31, 32, 100] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 13 + 5) as u8).collect();
            let ct = encrypt(&key, &iv, &pt).unwrap();
            assert_eq!(decrypt(&key, &iv, &ct).unwrap(), pt, "len={len}");
        }
    }

    #[test]
    fn deterministic() {
        let key = [3u8; 32];
        let iv = [9u8; 16];
        let pt = b"twofish test data";
        assert_eq!(
            encrypt(&key, &iv, pt).unwrap(),
            encrypt(&key, &iv, pt).unwrap()
        );
    }
}
