//! ChaCha20 stream cipher (RFC 8439, 12-byte nonce), KeePass KDBX 4.x.

use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};

use crate::error::{Error, Result};

pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = ChaCha20::new_from_slices(key, iv).map_err(|_| Error::InvalidSecret)?;
    let mut buf = plaintext.to_vec();
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}

// ChaCha20 is a stream cipher: encryption == decryption.
pub fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    encrypt(key, iv, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;
    use cipher::StreamCipherSeek;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        for len in [0usize, 1, 16, 63, 64, 65, 100] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 13 + 5) as u8).collect();
            let ct = encrypt(&key, &nonce, &pt).unwrap();
            assert_eq!(decrypt(&key, &nonce, &ct).unwrap(), pt, "len={len}");
        }
    }

    // RFC 8439 §2.4.2 ChaCha20 encryption (initial counter = 1). We seek the
    // keystream forward by one 64-byte block to match the RFC's counter.
    #[test]
    fn rfc8439_242() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let nonce = hex::decode("000000000000004a00000000").unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = hex::decode(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        )
        .unwrap();

        let mut cipher = ChaCha20::new_from_slices(&key, &nonce).unwrap();
        cipher.seek(64u64); // advance one block -> counter 1
        let mut buf = plaintext.to_vec();
        cipher.apply_keystream(&mut buf);
        assert_eq!(buf, expected);
    }
}
