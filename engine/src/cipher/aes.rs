//! AES-256-CBC (PKCS#7 padding), KeePass KDBX.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::error::{Error, Result};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256CbcEnc::new_from_slices(key, iv).map_err(|_| Error::InvalidSecret)?;
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ct = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|_| Error::Encoding("aes-cbc encrypt failed".to_string()))?;
    Ok(ct.to_vec())
}

pub fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256CbcDec::new_from_slices(key, iv).map_err(|_| Error::InvalidSecret)?;
    let mut buf = ciphertext.to_vec();
    let pt = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| Error::Encoding("aes-cbc decrypt failed (bad key or padding)".to_string()))?;
    Ok(pt.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;

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

    // NIST SP 800-38A F.2.5 (CBC-AES256) known-answer test.
    #[test]
    fn nist_cbc_aes256() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = hex::decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        )
        .unwrap();
        // NIST vector is raw CBC (no padding); the plaintext is exactly 4
        // blocks. KeePass adds a PKCS#7 padding block, so the raw ciphertext
        // is the first 64 bytes of our (80-byte) padded output.
        let expected_raw = hex::decode(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
             39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
        )
        .unwrap();

        let ct = encrypt(&key, &iv, &pt).unwrap();
        assert_eq!(ct.len(), 80); // 64 + 16-byte padding block
        assert_eq!(&ct[..64], &expected_raw[..]);
        assert_eq!(decrypt(&key, &iv, &ct).unwrap(), pt);
    }
}
