//! KDF known-answer tests.
//!
//! - Argon2 vectors are from KeePassDX's reference (JNI Argon2 reference
//!   implementation), password "password", salt "saltsaltsaltsalt", t=2,
//!   m=65536 KiB, p=2, v=0x13.
//! - AES-KDF vectors are from an independent Python (cryptography) reference
//!   implementing the KeePass spec: AES-256-ECB rounds only, no extra hash.
//!   (The chain-level SHA-256 lives in `keys::final_key`.) Cross-checked:
//!   SHA-256 of each vector below reproduces the pre-fix vectors that had the
//!   erroneous extra hash, byte for byte.

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
            "61a6936e4e8f101c1cc1f993b542a0d4e2740e8afad4e4d15d0d661b382eca89",
        ),
        (
            2u64,
            "813efd24102eb0bc47c81b02c0d9141810a26b2f74427492a8840d11c832fd2a",
        ),
        (
            3u64,
            "383c959652efd1b0666f6c015ccd7a37196638264142d00f2d5baa2adc0703e4",
        ),
        (
            6000u64,
            "314dd073796c2843a202b9f338cb8f9f601326b2ed1ee1e398260357718eb510",
        ),
    ];
    for (rounds, expected) in cases {
        let out = transform_aes_kdf(&seed, &key, rounds).unwrap();
        assert_eq!(hex::encode(&out), expected, "rounds={rounds}");
    }
}
