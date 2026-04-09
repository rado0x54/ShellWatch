//! Parse WebAuthn SK public keys from authorized_keys files.
//!
//! Only handles `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` keys.
//! Extracts the EC point (P-256, uncompressed) and application string
//! directly from the SSH wire format — no dependency on the ssh-key crate.

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use std::fs;
use std::io;
use std::path::Path;

use crate::agent::read_ssh_bytes;

const WEBAUTHN_SK_ALGO: &str = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

/// A parsed WebAuthn SK ECDSA P-256 public key.
#[derive(Debug, Clone)]
pub struct WebAuthnPublicKey {
    /// The raw key blob as it appears in the agent identity listing.
    /// Used for matching agent identities against authorized keys.
    pub key_blob: Vec<u8>,
    /// Uncompressed EC point (65 bytes: 0x04 || x || y).
    pub ec_point: Vec<u8>,
    /// The application/relying party ID (e.g. the ShellWatch domain).
    pub application: String,
    /// Optional comment from the authorized_keys line.
    pub comment: String,
}

/// Parse all WebAuthn SK public keys from an authorized_keys file.
pub fn parse_authorized_keys(path: &Path) -> io::Result<Vec<WebAuthnPublicKey>> {
    let content = fs::read_to_string(path)?;
    Ok(parse_authorized_keys_str(&content))
}

/// Parse WebAuthn SK public keys from authorized_keys content.
pub fn parse_authorized_keys_str(content: &str) -> Vec<WebAuthnPublicKey> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            parse_authorized_key_line(line)
        })
        .collect()
}

/// Parse a single authorized_keys line for a webauthn-sk-ecdsa key.
///
/// Format: `[options] webauthn-sk-ecdsa-sha2-nistp256@openssh.com <base64> [comment]`
fn parse_authorized_key_line(line: &str) -> Option<WebAuthnPublicKey> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    // Find the algorithm field
    let algo_idx = parts.iter().position(|&p| p == WEBAUTHN_SK_ALGO)?;
    let b64_idx = algo_idx + 1;
    if b64_idx >= parts.len() {
        log::debug!("No base64 data after algorithm in line");
        return None;
    }

    let key_blob = match BASE64_STANDARD.decode(parts[b64_idx]) {
        Ok(blob) => blob,
        Err(e) => {
            log::debug!("Failed to decode base64 key: {e}");
            return None;
        }
    };

    let comment = if b64_idx + 1 < parts.len() {
        parts[b64_idx + 1..].join(" ")
    } else {
        String::new()
    };

    match parse_webauthn_key_blob(&key_blob) {
        Some((ec_point, application)) => Some(WebAuthnPublicKey {
            key_blob,
            ec_point,
            application,
            comment,
        }),
        None => {
            log::debug!("Failed to parse key blob");
            None
        }
    }
}

/// Parse the wire format of a webauthn-sk-ecdsa key blob.
///
/// Wire format:
/// ```text
/// string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
/// string  "nistp256"
/// string  ec_point (65 bytes: 0x04 || x || y)
/// string  application
/// ```
fn parse_webauthn_key_blob(blob: &[u8]) -> Option<(Vec<u8>, String)> {
    let mut reader: &[u8] = blob;

    // Algorithm string
    let algo = read_ssh_bytes(&mut reader).ok()?;
    if algo != WEBAUTHN_SK_ALGO.as_bytes() {
        return None;
    }

    // Curve identifier ("nistp256")
    let _curve = read_ssh_bytes(&mut reader).ok()?;

    // EC point
    let ec_point = read_ssh_bytes(&mut reader).ok()?.to_vec();
    if ec_point.len() != 65 || ec_point[0] != 0x04 {
        log::debug!(
            "Invalid EC point: expected 65 bytes starting with 0x04, got {} bytes",
            ec_point.len()
        );
        return None;
    }

    // Application string (relying party ID — must be non-empty)
    let app_bytes = read_ssh_bytes(&mut reader).ok()?;
    if app_bytes.is_empty() {
        log::debug!("Empty application string in key blob");
        return None;
    }
    let application = String::from_utf8(app_bytes.to_vec()).ok()?;

    Some((ec_point, application))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid webauthn-sk-ecdsa key blob for testing.
    fn make_test_key_blob(application: &str) -> Vec<u8> {
        let mut blob = Vec::new();
        write_ssh_string(&mut blob, WEBAUTHN_SK_ALGO.as_bytes());
        write_ssh_string(&mut blob, b"nistp256");
        // 65-byte uncompressed EC point (0x04 + 32 bytes x + 32 bytes y)
        let mut ec_point = vec![0x04];
        ec_point.extend([0x01u8; 32]); // x
        ec_point.extend([0x02u8; 32]); // y
        write_ssh_string(&mut blob, &ec_point);
        write_ssh_string(&mut blob, application.as_bytes());
        blob
    }

    fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend(&(data.len() as u32).to_be_bytes());
        buf.extend(data);
    }

    #[test]
    fn test_parse_key_blob() {
        let blob = make_test_key_blob("https://example.com");
        let (ec_point, app) = parse_webauthn_key_blob(&blob).unwrap();
        assert_eq!(ec_point.len(), 65);
        assert_eq!(ec_point[0], 0x04);
        assert_eq!(app, "https://example.com");
    }

    #[test]
    fn test_parse_authorized_key_line() {
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let line = format!("{WEBAUTHN_SK_ALGO} {b64} my-key-comment");

        let key = parse_authorized_key_line(&line).unwrap();
        assert_eq!(key.application, "localhost");
        assert_eq!(key.comment, "my-key-comment");
        assert_eq!(key.ec_point.len(), 65);
    }

    #[test]
    fn test_parse_authorized_keys_str() {
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let content = format!(
            "# comment line\n\
             {WEBAUTHN_SK_ALGO} {b64} key1\n\
             \n\
             ssh-ed25519 AAAA... other-key\n\
             {WEBAUTHN_SK_ALGO} {b64} key2\n"
        );

        let keys = parse_authorized_keys_str(&content);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].comment, "key1");
        assert_eq!(keys[1].comment, "key2");
    }

    #[test]
    fn test_rejects_wrong_algo() {
        let mut blob = Vec::new();
        write_ssh_string(&mut blob, b"sk-ecdsa-sha2-nistp256@openssh.com");
        write_ssh_string(&mut blob, b"nistp256");
        let mut ec_point = vec![0x04];
        ec_point.extend([0x01u8; 32]);
        ec_point.extend([0x02u8; 32]);
        write_ssh_string(&mut blob, &ec_point);
        write_ssh_string(&mut blob, b"ssh:");
        assert!(parse_webauthn_key_blob(&blob).is_none());
    }

    #[test]
    fn test_rejects_invalid_ec_point() {
        let mut blob = Vec::new();
        write_ssh_string(&mut blob, WEBAUTHN_SK_ALGO.as_bytes());
        write_ssh_string(&mut blob, b"nistp256");
        // Wrong length EC point
        write_ssh_string(&mut blob, &[0x04, 0x01, 0x02]);
        write_ssh_string(&mut blob, b"localhost");
        assert!(parse_webauthn_key_blob(&blob).is_none());
    }
}
