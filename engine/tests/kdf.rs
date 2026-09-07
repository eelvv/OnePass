//! KDF known-answer tests.
//!
//! - Argon2 vectors are from KeePassDX's reference (JNI Argon2 reference
//!   implementation), password "password", salt "saltsaltsaltsalt", t=2,
//!   m=65536 KiB, p=2, v=0x13.
//! - AES-KDF vectors are from an independent Python (cryptography) reference.

use onepass_engine::encoding::hex;
use onepass_engine::kdf::{transform_aes_kdf, transform_argon2, Argon2Kind};

#[test]
fn argon2_keephash_vectors() {
    let pwd = b"password";
    let salt = b"saltsaltsaltsalt"; // 16 bytes
    let cases = [
        (
            Argon2Kind::Argon2i,
            "75f46c42fb7029826e6110a99b273cbb4a8a1c84f7a6221fa298dcaeb814ef0d",
        ),
        (
            Argon2Kind::Argon2d,
            "2a7047fcffea07e7714bc3eea56c02ba8d0e9046d3c3a23a28842ba2a6f11e48",
        ),
        (
            Argon2Kind::Argon2id,
            "b6f00ec2b1462c065b2e55615a2f4324c360d3ddc510986505c1cbab748cee2f",
        ),
    ];
    for (kind, expected) in cases {
        let out = transform_argon2(kind, pwd, salt, 65536, 2, 2, 0x13).unwrap();
        assert_eq!(hex::encode(&out), expected, "{kind:?}");
    }
}

#[test]
fn aes_kdf_python_vectors() {
    let seed: Vec<u8> = (0u8..32).collect();
    let key: Vec<u8> = (32u8..64).collect();
    let cases = [
        (
            1u64,
            "aec37a882b6113e1c172dd62bcba0cff15b5ff71bec097f5f06bba19154384d8",
        ),
        (
            2u64,
            "e40d724d816c01638079de3f10629a47ab20d60ad3b273317eaa99fda23bb627",
        ),
        (
            3u64,
            "96065d1f3ab267d7e9c281cb310e30b79b06d7374bd70df83a18d0c903a4cee0",
        ),
        (
            6000u64,
            "da86f7be13d8149c58bb5ebaf591bd8825c4b904d913d5daa2e25e3bdb2ab2a8",
        ),
    ];
    for (rounds, expected) in cases {
        let out = transform_aes_kdf(&seed, &key, rounds).unwrap();
        assert_eq!(hex::encode(&out), expected, "rounds={rounds}");
    }
}
