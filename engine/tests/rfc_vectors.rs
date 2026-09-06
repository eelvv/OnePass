//! RFC 4226 / RFC 6238 known-answer tests against the engine's public API.

use onepass_engine::encoding::base32;
use onepass_engine::otp::types::{HashAlgorithm, OtpKind, OtpParams};
use onepass_engine::otp::{generate, hotp, totp};

const SECRET: &[u8] = b"12345678901234567890";

#[test]
fn rfc4226() {
    let expected = [
        (0u64, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ];
    for (counter, code) in expected {
        assert_eq!(hotp::hotp(SECRET, counter, 6, HashAlgorithm::Sha1).unwrap(), code);
    }
}

#[test]
fn rfc6238() {
    let sha1 = [
        (59u64, "94287082"),
        (1_111_111_109, "07081804"),
        (1_111_111_111, "14050471"),
        (1_234_567_890, "89005924"),
        (2_000_000_000, "69279037"),
        (20_000_000_000, "65353130"),
    ];
    for (t, code) in sha1 {
        assert_eq!(totp::totp(SECRET, 30, t, 8, HashAlgorithm::Sha1).unwrap(), code);
    }
}

#[test]
fn rfc6238_sha256_sha512() {
    let sha256 = [
        (59u64, "32247374"),
        (1_111_111_109, "34756375"),
        (1_111_111_111, "74584430"),
        (1_234_567_890, "42829826"),
        (2_000_000_000, "78428693"),
        (20_000_000_000, "24142410"),
    ];
    for (t, code) in sha256 {
        assert_eq!(
            totp::totp(SECRET, 30, t, 8, HashAlgorithm::Sha256).unwrap(),
            code
        );
    }

    let sha512 = [
        (59u64, "69342147"),
        (1_111_111_109, "63049338"),
        (1_111_111_111, "54380122"),
        (1_234_567_890, "76671578"),
        (2_000_000_000, "56464532"),
        (20_000_000_000, "69481994"),
    ];
    for (t, code) in sha512 {
        assert_eq!(
            totp::totp(SECRET, 30, t, 8, HashAlgorithm::Sha512).unwrap(),
            code
        );
    }
}

#[test]
fn generate_via_params() {
    let p = OtpParams {
        kind: OtpKind::Totp,
        secret: SECRET.to_vec(),
        digits: 8,
        ..Default::default()
    };
    assert_eq!(generate(&p, 59).unwrap(), "94287082");
}

#[test]
fn base32_secret_through_uri() {
    // otpauth with the RFC 6238 secret base32-encoded
    let b32 = base32::encode(SECRET);
    let uri = format!(
        "otpauth://totp/Test:user?secret={b32}&digits=8&period=30&algorithm=SHA1"
    );
    let p = onepass_engine::uri::parse(&uri).unwrap();
    assert_eq!(generate(&p, 59).unwrap(), "94287082");
}
