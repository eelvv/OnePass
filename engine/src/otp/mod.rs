//! One-time password algorithms (HOTP/TOTP/Steam/MOTP/Yandex).

pub mod hotp;
pub mod migration;
pub mod motp;
pub mod steam;
pub mod totp;
pub mod types;
pub mod yandex;

pub use types::{HashAlgorithm, OtpKind, OtpParams};

/// Generates a code for `params` at `time_secs` (UNIX seconds).
///
/// Time-based kinds (TOTP/Steam/MOTP/Yandex) use `time_secs`; HOTP ignores it
/// and uses `params.counter`.
pub fn generate(params: &OtpParams, time_secs: u64) -> crate::Result<String> {
    params.validate()?;
    match params.kind {
        OtpKind::Hotp => hotp::hotp(
            &params.secret,
            params.counter,
            params.digits,
            params.algorithm,
        ),
        OtpKind::Totp => totp::totp(
            &params.secret,
            params.period,
            time_secs,
            params.digits,
            params.algorithm,
        ),
        OtpKind::Steam => steam::steam(&params.secret, params.period, time_secs),
        OtpKind::Motp => {
            let pin = params
                .pin
                .as_deref()
                .ok_or_else(|| crate::Error::InvalidUri("MOTP requires a pin".to_string()))?;
            motp::motp(&params.secret, pin, params.period, params.digits, time_secs)
        }
        OtpKind::Yandex => {
            let pin = params
                .pin
                .as_deref()
                .ok_or_else(|| crate::Error::InvalidUri("Yandex requires a pin".to_string()))?;
            yandex::yandex(&params.secret, pin, params.period, params.digits, time_secs)
        }
    }
}

/// Generates a code using the current system time.
pub fn generate_now(params: &OtpParams) -> crate::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| crate::Error::Clock)?;
    generate(params, now.as_secs())
}

/// Seconds until the current time window rotates (time-based kinds only).
pub fn seconds_remaining(params: &OtpParams, time_secs: u64) -> crate::Result<u64> {
    if params.period == 0 {
        return Err(crate::Error::InvalidPeriod(params.period));
    }
    Ok(params.period - (time_secs % params.period))
}
