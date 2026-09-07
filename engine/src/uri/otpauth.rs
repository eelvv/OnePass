//! `otpauth://` (Google Key URI format) and `motp://` parsing/building.
//!
//! Reference behavior follows the Google Key URI format spec, Aegis'
//! `GoogleAuthInfo`, and KeePassDX's `OtpEntryFields` (used when the URI is
//! stored as a KeePass entry's `otp` field). The implementation here is
//! written from scratch.

use crate::encoding::{base32, hex};
use crate::error::{Error, Result};
use crate::otp::types::{HashAlgorithm, OtpKind, OtpParams};
use crate::otp::yandex;
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};

const OTPAUTH_SCHEME: &str = "otpauth";
const MOTP_SCHEME: &str = "motp";

/// Parses an otpauth/motp URI into OTP parameters.
pub fn parse(uri: &str) -> Result<OtpParams> {
    let (scheme, remainder) = uri
        .split_once(':')
        .ok_or_else(|| Error::InvalidUri("missing scheme".to_string()))?;
    let scheme = scheme.to_ascii_lowercase();

    let (authority, path, query) = match scheme.as_str() {
        OTPAUTH_SCHEME => {
            let rest = remainder.strip_prefix("//").unwrap_or(remainder);
            let (auth, pq) = match rest.find(['/', '?']) {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, ""),
            };
            let (path, query) = split_path_query(pq);
            (Some(auth.to_ascii_lowercase()), path, query)
        }
        MOTP_SCHEME => {
            let rest = remainder.strip_prefix("//").unwrap_or(remainder);
            let rest = rest.strip_prefix('/').unwrap_or(rest);
            let (path, query) = split_path_query(rest);
            (None, path, query)
        }
        other => return Err(Error::InvalidUri(format!("unsupported scheme: {other}"))),
    };

    let query = parse_query(query);

    let kind = match authority {
        Some(a) => OtpKind::parse(&a)?,
        None => OtpKind::Motp,
    };

    let mut params = OtpParams::default();
    params.kind = kind;

    // --- secret ---------------------------------------------------------
    let secret_param = query
        .get("secret")
        .ok_or_else(|| Error::InvalidUri("missing secret parameter".to_string()))?;
    let secret: Vec<u8> = match kind {
        OtpKind::Motp => hex::decode(secret_param)
            .map_err(|_| Error::InvalidUri("motp secret must be hex".to_string()))?,
        _ => base32::decode_tolerant(secret_param)
            .map_err(|_| Error::InvalidUri("secret must be base32".to_string()))?,
    };
    if secret.is_empty() {
        return Err(Error::InvalidUri("empty secret".to_string()));
    }
    params.secret = secret;

    // --- label (path) ----------------------------------------------------
    let label = percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| Error::InvalidUri("label is not valid UTF-8".to_string()))?
        .to_string();
    let mut issuer = String::new();
    let mut account = String::new();
    if !label.is_empty() {
        let mut parts = label.splitn(2, ':');
        let first = parts.next().unwrap_or("");
        match parts.next() {
            Some(second) => {
                issuer = first.to_string();
                account = second.to_string();
            }
            None => account = first.to_string(),
        }
    }
    if issuer.is_empty() {
        if let Some(p) = query.get("issuer") {
            issuer = percent_decode_str(p)
                .decode_utf8()
                .map_err(|_| Error::InvalidUri("issuer is not valid UTF-8".to_string()))?
                .to_string();
        }
    }
    params.issuer = issuer;
    params.account = account;

    // --- algorithm -------------------------------------------------------
    match kind {
        OtpKind::Motp => params.algorithm = HashAlgorithm::Md5,
        OtpKind::Yandex => params.algorithm = HashAlgorithm::Sha256,
        _ => {
            params.algorithm = match query.get("algorithm") {
                Some(a) => HashAlgorithm::parse(a)?,
                None => HashAlgorithm::Sha1,
            };
        }
    }

    // --- digits ----------------------------------------------------------
    params.digits = match kind {
        OtpKind::Steam => match query.get("digits") {
            Some(d) => parse_u32("digits", d)?,
            None => 5,
        },
        OtpKind::Motp => 6,
        OtpKind::Yandex => 8,
        _ => match query.get("digits") {
            Some(d) => parse_u32("digits", d)?,
            None => crate::otp::types::DEFAULT_DIGITS,
        },
    };

    // --- period ----------------------------------------------------------
    params.period = match kind {
        OtpKind::Hotp => 0, // unused
        OtpKind::Motp => 10,
        _ => match query.get("period") {
            Some(p) => parse_u64("period", p)?,
            None => crate::otp::types::DEFAULT_PERIOD,
        },
    };

    // --- counter (HOTP) --------------------------------------------------
    if kind == OtpKind::Hotp {
        let c = query
            .get("counter")
            .ok_or_else(|| Error::InvalidUri("hotp requires a counter".to_string()))?;
        params.counter = parse_u64("counter", c)?;
    }

    // --- pin (MOTP/Yandex) ----------------------------------------------
    match kind {
        OtpKind::Motp => {
            // MOTP URIs never carry a PIN (it is user-provided); leave unset.
            params.pin = None;
        }
        OtpKind::Yandex => {
            let pin_b32 = query
                .get("pin")
                .ok_or_else(|| Error::InvalidUri("yandex requires a pin".to_string()))?;
            let pin_bytes = base32::decode(pin_b32)
                .map_err(|_| Error::InvalidUri("yandex pin must be base32".to_string()))?;
            params.pin = Some(
                String::from_utf8(pin_bytes)
                    .map_err(|_| Error::InvalidUri("yandex pin is not UTF-8".to_string()))?,
            );
            params.secret = yandex::normalize_secret(&params.secret)?;
        }
        _ => {}
    }

    params.validate()?;
    Ok(params)
}

/// Builds a URI for `params`.
///
/// TOTP/HOTP/Steam output follows the KeePassDX `otp` field shape so it
/// interoperates with KeePassXC. MOTP uses the Aegis `motp://` shape.
pub fn build(params: &OtpParams) -> Result<String> {
    params.validate()?;

    let label = if params.issuer.is_empty() {
        encode_label(&params.account)
    } else {
        format!(
            "{}:{}",
            encode_label(&params.issuer),
            encode_label(&params.account)
        )
    };

    match params.kind {
        OtpKind::Totp => {
            let mut q = base_query(params, true);
            q.push_str(&format!("&period={}", params.period));
            Ok(format!("{OTPAUTH_SCHEME}://totp/{label}?{q}"))
        }
        OtpKind::Hotp => {
            let mut q = base_query(params, true);
            q.push_str(&format!("&counter={}", params.counter));
            Ok(format!("{OTPAUTH_SCHEME}://hotp/{label}?{q}"))
        }
        OtpKind::Steam => {
            let mut q = base_query(params, false);
            q.push_str(&format!("&period={}", params.period));
            q.push_str("&encoder=steam");
            Ok(format!("{OTPAUTH_SCHEME}://steam/{label}?{q}"))
        }
        OtpKind::Yandex => {
            let mut q = base_query(params, true);
            q.push_str("&period=30");
            let pin = params.pin.as_deref().unwrap_or("");
            q.push_str(&format!("&pin={}", base32::encode(pin.as_bytes())));
            Ok(format!("{OTPAUTH_SCHEME}://yaotp/{label}?{q}"))
        }
        OtpKind::Motp => Ok(format!(
            "{MOTP_SCHEME}:/{label}?secret={}",
            hex::encode(&params.secret)
        )),
    }
}

/// Shared query parameters (secret/digits/issuer + optional algorithm).
fn base_query(params: &OtpParams, with_algorithm: bool) -> String {
    let mut q = format!("secret={}", base32::encode(&params.secret));
    q.push_str(&format!("&digits={}", params.digits));
    if !params.issuer.is_empty() {
        q.push_str(&format!("&issuer={}", encode_label(&params.issuer)));
    }
    if with_algorithm {
        q.push_str(&format!("&algorithm={}", params.algorithm.as_str()));
    }
    q
}

// ---------------------------------------------------------------------------
// helpers

fn split_path_query(pq: &str) -> (&str, &str) {
    match pq.split_once('?') {
        Some((p, q)) => {
            let p = p.strip_prefix('/').unwrap_or(p);
            (p, q)
        }
        None => {
            let p = pq.strip_prefix('/').unwrap_or(pq);
            (p, "")
        }
    }
}

fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if query.is_empty() {
        return map;
    }
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let key = k.to_ascii_lowercase();
        let value = percent_decode_str(v)
            .decode_utf8()
            .map(|s| s.to_string())
            .unwrap_or_default();
        map.insert(key, value);
    }
    map
}

fn parse_u32(name: &str, s: &str) -> Result<u32> {
    s.trim()
        .parse::<u32>()
        .map_err(|_| Error::InvalidUri(format!("bad {name}: {s}")))
}

fn parse_u64(name: &str, s: &str) -> Result<u64> {
    s.trim()
        .parse::<u64>()
        .map_err(|_| Error::InvalidUri(format!("bad {name}: {s}")))
}

fn encode_label(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_totp_basic() {
        let p = parse(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .unwrap();
        assert_eq!(p.kind, OtpKind::Totp);
        assert_eq!(p.issuer, "Example");
        assert_eq!(p.account, "alice@example.com");
        assert_eq!(p.secret, base32::decode("JBSWY3DPEHPK3PXP").unwrap());
        assert_eq!(p.algorithm, HashAlgorithm::Sha1);
        assert_eq!(p.digits, 6);
        assert_eq!(p.period, 30);
    }

    #[test]
    fn parse_totp_full_params() {
        let p = parse("otpauth://totp/acme%3Abob?secret=JBSWY3DPEHPK3PXP&period=60&digits=8&algorithm=SHA256&issuer=acme").unwrap();
        assert_eq!(p.issuer, "acme");
        assert_eq!(p.account, "bob");
        assert_eq!(p.period, 60);
        assert_eq!(p.digits, 8);
        assert_eq!(p.algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn parse_hotp_requires_counter() {
        assert!(parse("otpauth://hotp/bob?secret=JBSWY3DPEHPK3PXP").is_err());
        let p = parse("otpauth://hotp/bob?secret=JBSWY3DPEHPK3PXP&counter=42").unwrap();
        assert_eq!(p.kind, OtpKind::Hotp);
        assert_eq!(p.counter, 42);
    }

    #[test]
    fn parse_steam() {
        let p = parse("otpauth://steam/steamuser?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(p.kind, OtpKind::Steam);
        assert_eq!(p.digits, 5);
        assert_eq!(p.algorithm, HashAlgorithm::Sha1);
    }

    #[test]
    fn parse_yandex() {
        // pin is base32-encoded UTF-8; Yandex secret must be 16 bytes.
        let pin = base32::encode(b"1234");
        let secret = base32::encode(&hex::decode("00112233445566778899aabbccddeeff").unwrap());
        let p = parse(&format!("otpauth://yaotp/user?secret={secret}&pin={pin}")).unwrap();
        assert_eq!(p.kind, OtpKind::Yandex);
        assert_eq!(p.pin.as_deref(), Some("1234"));
        assert_eq!(p.digits, 8);
        assert_eq!(p.algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn parse_motp() {
        let p = parse("motp:/user?secret=00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(p.kind, OtpKind::Motp);
        assert_eq!(
            p.secret,
            hex::decode("00112233445566778899aabbccddeeff").unwrap()
        );
        assert_eq!(p.digits, 6);
        assert_eq!(p.period, 10);
        assert_eq!(p.algorithm, HashAlgorithm::Md5);
    }

    #[test]
    fn build_roundtrip_totp() {
        let p = parse(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .unwrap();
        let uri = build(&p).unwrap();
        let p2 = parse(&uri).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn build_roundtrip_hotp_steam_yandex() {
        for uri in [
            "otpauth://hotp/bob?secret=JBSWY3DPEHPK3PXP&counter=7&digits=6&algorithm=SHA256",
            "otpauth://steam/steamuser?secret=JBSWY3DPEHPK3PXP",
        ] {
            let p = parse(uri);
            assert!(p.is_ok(), "should parse: {uri}: {:?}", p.err());
        }

        // Yandex requires a 16-byte secret.
        let secret = base32::encode(&hex::decode("00112233445566778899aabbccddeeff").unwrap());
        let pin = base32::encode(b"1234");
        let p = parse(&format!("otpauth://yaotp/user?secret={secret}&pin={pin}"));
        assert!(p.is_ok(), "should parse yandex: {:?}", p.err());
    }

    #[test]
    fn build_yandex_roundtrip() {
        let p = OtpParams {
            kind: OtpKind::Yandex,
            secret: hex::decode("00112233445566778899aabbccddeeff").unwrap(),
            pin: Some("1234".to_string()),
            ..Default::default()
        };
        let uri = build(&p).unwrap();
        let p2 = parse(&uri).unwrap();
        assert_eq!(p.secret, p2.secret);
        assert_eq!(p.pin, p2.pin);
        assert_eq!(p2.kind, OtpKind::Yandex);
    }

    #[test]
    fn build_motp_roundtrip() {
        let p = OtpParams {
            kind: OtpKind::Motp,
            secret: hex::decode("00112233445566778899aabbccddeeff").unwrap(),
            pin: Some("1234".to_string()),
            issuer: "iss".to_string(),
            account: "acct".to_string(),
            ..Default::default()
        };
        let uri = build(&p).unwrap();
        let p2 = parse(&uri).unwrap();
        assert_eq!(p.secret, p2.secret);
        assert_eq!(p2.kind, OtpKind::Motp);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse("https://totp/x?secret=y").is_err());
        assert!(parse("otpauth://totp/x").is_err()); // missing secret
        assert!(parse("otpauth://bogus/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=99").is_err());
    }
}
