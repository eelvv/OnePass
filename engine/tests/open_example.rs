//! Temporary end-to-end decryption probe against a real KeePass .kdbx file.
//!
//! Run with: cargo test --test open_example -- --nocapture

use onepass_engine::db::compress::gzip_decompress;
use onepass_engine::db::keys;
use onepass_engine::db::stream::hmac_block;
use onepass_engine::db::{Argon2Variant, Compression, InnerHeader, KdbxHeader, KdfParams};
use onepass_engine::kdf::{transform_aes_kdf, transform_argon2, Argon2Kind};

fn derive_final_key(header: &KdbxHeader, composite: &[u8; 32]) -> ([u8; 32], [u8; 64]) {
    let transformed: [u8; 32] = match &header.kdf {
        KdfParams::Aes { rounds, seed } => transform_aes_kdf(seed, composite, *rounds).unwrap(),
        KdfParams::Argon2 {
            id,
            salt,
            parallelism,
            memory,
            iterations,
            version,
        } => {
            let kind = match id {
                Argon2Variant::Argon2d => Argon2Kind::Argon2d,
                Argon2Variant::Argon2id => Argon2Kind::Argon2id,
            };
            transform_argon2(
                kind,
                composite,
                salt,
                (memory / 1024) as u32,
                *iterations as u32,
                *parallelism,
                *version,
            )
            .unwrap()
        }
    };
    let final_key = keys::final_key(&header.master_seed, &transformed);
    let hmac_key = keys::hmac_key(&header.master_seed, &transformed);
    (final_key, hmac_key)
}

#[test]
fn open_example() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../examples/example1.kdbx");
    let data = std::fs::read(path).expect("example file not found");

    let (header, header_len) = KdbxHeader::parse(&data).expect("header parse");
    println!("version: 0x{:08x}", header.version);
    println!("cipher: {:?}", header.cipher);
    println!("compression: {:?}", header.compression);
    println!("kdf: {:?}", header.kdf);
    println!("header_len: {header_len}");

    let password = b"example1";
    let composite = keys::composite_key(&[&keys::password_key(password)]);
    let (final_key, hmac_key) = derive_final_key(&header, &composite);

    let encrypted = &data[header_len..];

    // KDBX 4: after the header come a 32-byte SHA-256 of the header bytes and
    // a 32-byte header HMAC (block key = SHA-512(0xFF..FF || hmac_key)).
    let stored_hash = &encrypted[..32];
    let stored_hmac = &encrypted[32..64];
    let header_bytes = &data[..header_len];

    use sha2::{Digest, Sha256, Sha512};
    let computed_hash = Sha256::digest(header_bytes);
    assert_eq!(computed_hash.as_slice(), stored_hash, "header sha256 mismatch");

    let mut bk = Sha512::new();
    bk.update([0xFFu8; 8]);
    bk.update(hmac_key);
    let block_key = bk.finalize();
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(&block_key).unwrap();
    mac.update(header_bytes);
    assert_eq!(mac.finalize().into_bytes().as_slice(), stored_hmac, "header hmac mismatch");
    println!("header sha256 + hmac OK");

    let ciphertext =
        hmac_block::decode(&encrypted[64..], &hmac_key).expect("hmac blocks");
    println!("ciphertext len: {}", ciphertext.len());

    let compressed = header
        .cipher
        .decrypt(&final_key, &header.encryption_iv, &ciphertext)
        .expect("decrypt");

    // KDBX 4 has no stream-start-bytes check (that is a 3.1 feature); the
    // header SHA-256 + HMAC above already authenticated the key.
    let payload = match header.compression {
        Compression::Gzip => gzip_decompress(&compressed).expect("gzip"),
        Compression::None => compressed,
    };

    if header.version >= onepass_engine::db::header::VERSION_40 {
        let (inner, xml_offset) = InnerHeader::parse(&payload).expect("inner header");
        println!(
            "inner stream id: {} key len: {} binaries: {}",
            inner.inner_random_stream_id,
            inner.inner_random_stream_key.len(),
            inner.binaries.len()
        );
        let xml = String::from_utf8_lossy(&payload[xml_offset..]);
        println!("===== XML =====");
        println!("{xml}");

        // Decrypt both protected Password fields in document order with the
        // inner ChaCha20 stream.
        use base64::Engine;
        let kind = match inner.inner_random_stream_id {
            2 => onepass_engine::db::ProtectedStreamKind::Salsa20,
            _ => onepass_engine::db::ProtectedStreamKind::ChaCha20,
        };
        let mut stream =
            onepass_engine::db::ProtectedStream::new(kind, &inner.inner_random_stream_key);
        let mut passwords = Vec::new();
        for b64 in ["EGccnSG0ph4=", "VZzUgcCkDHw="] {
            let mut plaintext = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap();
            stream.xor_in_place(&mut plaintext).unwrap();
            passwords.push(String::from_utf8(plaintext).unwrap());
        }
        assert_eq!(passwords, vec!["example1", "example1"]);
    } else {
        println!(
            "v3 inner stream id: {:?}",
            header.inner_random_stream_id
        );
        let xml = String::from_utf8_lossy(&payload);
        println!("===== XML =====");
        println!("{xml}");
    }
}
