//! RFC 6238 TOTP helpers for Keystone's optional second factor.
//!
//! Secrets are Base32 (no padding), codes are 6 digits, period is 30 seconds, and the
//! MAC is HMAC-SHA1 for authenticator-app compatibility. Everything is local/offline.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use qrcode::render::svg;
use qrcode::QrCode;
use rand::rngs::OsRng;
use rand::RngCore;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const PERIOD: u64 = 30;
const DIGITS: u32 = 6;

/// Generate a 160-bit Base32 secret, matching the common authenticator-app default.
pub fn new_secret() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

/// TOTP code for `secret` at unix time `now`.
pub fn code_at(secret: &str, now: u64) -> Option<String> {
    hotp(secret, now / PERIOD)
}

/// Verify a submitted code with ±1 time-step skew.
pub fn verify_code(secret: &str, submitted: &str, now: u64) -> bool {
    let Some(code) = normalize_code(submitted) else {
        return false;
    };
    let counter = now / PERIOD;
    for step in counter.saturating_sub(1)..=counter + 1 {
        if hotp(secret, step).is_some_and(|expected| expected == code) {
            return true;
        }
    }
    false
}

/// Build an authenticator-app otpauth URI.
pub fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> String {
    let label = format!("{issuer}:{account}");
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
        label = pct_encode(&label),
        issuer = pct_encode(issuer),
        secret = secret,
    )
}

/// Render a scannable SVG QR for the otpauth URI. The input is our own URI string; the
/// generated SVG is inserted as trusted markup by the enrollment template.
pub fn qr_svg(data: &str) -> Option<String> {
    let code = QrCode::new(data.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(192, 192)
            .dark_color(svg::Color("#0F172A"))
            .light_color(svg::Color("#FFFFFF"))
            .build(),
    )
}

fn hotp(secret: &str, counter: u64) -> Option<String> {
    let key = base32_decode(secret)?;
    let mut mac = HmacSha1::new_from_slice(&key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let bin = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    let code = bin % 10u32.pow(DIGITS);
    Some(format!("{code:06}"))
}

fn normalize_code(raw: &str) -> Option<String> {
    let code: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    (code.len() == DIGITS as usize).then_some(code)
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for &b in bytes {
        buffer = (buffer << 8) | b as u16;
        bits += 8;
        while bits >= 5 {
            let idx = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(BASE32[idx] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32[idx] as char);
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for c in s.chars() {
        if c == '=' || c.is_ascii_whitespace() {
            continue;
        }
        let upper = c.to_ascii_uppercase();
        let val = match upper {
            'A'..='Z' => upper as u8 - b'A',
            '2'..='7' => upper as u8 - b'2' + 26,
            _ => return None,
        } as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            out.push(((buffer >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// High-entropy recovery code shown once after TOTP enrollment.
pub fn new_recovery_code() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let raw = URL_SAFE_NO_PAD.encode(bytes).to_ascii_uppercase();
    format!("HF-{}-{}", &raw[..5], &raw[5..10])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6238_sha1_vector() {
        // RFC 6238 Appendix B uses the ASCII key "12345678901234567890".
        let secret = base32_encode(b"12345678901234567890");
        assert_eq!(
            code_at(&secret, 59).as_deref(),
            Some("94287082").map(|s| &s[2..])
        );
    }

    #[test]
    fn generated_secret_round_trips() {
        let secret = new_secret();
        let code = code_at(&secret, 1_700_000_000).unwrap();
        assert!(verify_code(&secret, &code, 1_700_000_000));
        assert!(!verify_code(&secret, "000000", 1_700_000_000));
    }
}
