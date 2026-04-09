//! WebAuthn SK ECDSA signature verification.
//!
//! Parses the extended SSH signature wire format (with origin, clientDataJSON,
//! extensions) and verifies the ECDSA P-256 signature against the constructed
//! signed_data.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::io;

use crate::agent::read_ssh_bytes;
use crate::keys::WebAuthnPublicKey;

/// Parsed WebAuthn SK ECDSA signature fields.
struct WebAuthnSignature {
    ecdsa_sig_bytes: Vec<u8>,
    flags: u8,
    counter: u32,
    client_data_json: String,
}

/// Verify a WebAuthn SK ECDSA signature from the raw SSH signature blob.
///
/// The raw blob format (WebAuthn variant):
/// ```text
/// string  algorithm ("webauthn-sk-ecdsa-sha2-nistp256@openssh.com" or "sk-ecdsa-...")
/// string  ecdsa_signature (mpint R || mpint S)
/// byte    flags
/// uint32  counter
/// string  origin
/// string  clientDataJSON
/// string  extensions (CBOR, typically empty)
/// ```
///
/// Verification constructs:
///   signed_data = SHA256(application) || flags || counter || SHA256(clientDataJSON)
/// and verifies the ECDSA P-256 signature over signed_data.
pub fn verify_webauthn_sk(
    key: &WebAuthnPublicKey,
    challenge: &[u8],
    raw_sig_blob: &[u8],
) -> Result<(), VerifyError> {
    let sig = parse_webauthn_signature(raw_sig_blob)?;

    // Validate the challenge is embedded in clientDataJSON
    validate_challenge(&sig.client_data_json, challenge)?;

    // Construct signed_data: SHA256(application) || flags || counter || SHA256(clientDataJSON)
    let app_hash = Sha256::digest(key.application.as_bytes());
    let msg_hash = Sha256::digest(sig.client_data_json.as_bytes());

    let mut signed_data = Vec::with_capacity(32 + 1 + 4 + 32);
    signed_data.extend(&app_hash);
    signed_data.push(sig.flags);
    signed_data.extend(&sig.counter.to_be_bytes());
    signed_data.extend(&msg_hash);

    // Verify ECDSA P-256 signature over signed_data
    verify_ecdsa_p256(key, &sig.ecdsa_sig_bytes, &signed_data)?;

    Ok(())
}

/// Check if a raw signature blob is a WebAuthn SK signature.
pub fn is_webauthn_signature(raw_sig_blob: &[u8]) -> bool {
    if let Ok(algo) = read_ssh_string(raw_sig_blob) {
        let algo_str = String::from_utf8_lossy(algo);
        if algo_str == "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" {
            return true;
        }
        // Also detect canonicalized sk-ecdsa with WebAuthn fields present.
        // A standard SK sig has algo + ecdsa_sig + flags(1) + counter(4) = done.
        // A WebAuthn SK sig has additional origin + clientDataJSON + extensions.
        if algo_str == "sk-ecdsa-sha2-nistp256@openssh.com" {
            // Try parsing as WebAuthn — if it has the extra fields, it's WebAuthn
            return parse_webauthn_signature(raw_sig_blob).is_ok();
        }
    }
    false
}

#[derive(Debug)]
pub enum VerifyError {
    Parse(String),
    ChallengeMismatch(String),
    Crypto(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Parse(msg) => write!(f, "Parse error: {msg}"),
            VerifyError::ChallengeMismatch(msg) => write!(f, "Challenge mismatch: {msg}"),
            VerifyError::Crypto(msg) => write!(f, "Crypto error: {msg}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<io::Error> for VerifyError {
    fn from(e: io::Error) -> Self {
        VerifyError::Parse(e.to_string())
    }
}

// --- Pure Rust verification (default) ---

#[cfg(not(feature = "native-crypto"))]
fn verify_ecdsa_p256(
    key: &WebAuthnPublicKey,
    ecdsa_sig_bytes: &[u8],
    signed_data: &[u8],
) -> Result<(), VerifyError> {
    use p256::ecdsa::signature::Verifier;

    let ecdsa_sig = parse_ecdsa_p256_signature(ecdsa_sig_bytes)?;
    let ec_point = p256::EncodedPoint::from_bytes(&key.ec_point)
        .map_err(|e| VerifyError::Crypto(format!("Invalid EC point: {e}")))?;
    let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&ec_point)
        .map_err(|e| VerifyError::Crypto(format!("Invalid verifying key: {e}")))?;
    verifying_key
        .verify(signed_data, &ecdsa_sig)
        .map_err(|e| VerifyError::Crypto(format!("Signature verification failed: {e}")))?;
    Ok(())
}

// --- OpenSSL verification (FIPS) ---

#[cfg(feature = "native-crypto")]
fn verify_ecdsa_p256(
    key: &WebAuthnPublicKey,
    ecdsa_sig_bytes: &[u8],
    signed_data: &[u8],
) -> Result<(), VerifyError> {
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::sign::Verifier;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| VerifyError::Crypto(format!("Failed to create EC group: {e}")))?;
    let mut ctx = openssl::bn::BigNumContext::new()
        .map_err(|e| VerifyError::Crypto(format!("Failed to create BigNum context: {e}")))?;
    let point = EcPoint::from_bytes(&group, &key.ec_point, &mut ctx)
        .map_err(|e| VerifyError::Crypto(format!("Failed to parse EC point: {e}")))?;
    let ec_key = EcKey::from_public_key(&group, &point)
        .map_err(|e| VerifyError::Crypto(format!("Failed to create EC key: {e}")))?;
    ec_key
        .check_key()
        .map_err(|e| VerifyError::Crypto(format!("EC key check failed: {e}")))?;
    let pkey = PKey::from_ec_key(ec_key)
        .map_err(|e| VerifyError::Crypto(format!("Failed to create PKey: {e}")))?;

    // Convert SSH mpint ECDSA signature to DER for OpenSSL
    let der_sig = ecdsa_sig_to_der(ecdsa_sig_bytes)?;

    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)
        .map_err(|e| VerifyError::Crypto(format!("Failed to create verifier: {e}")))?;
    let valid = verifier
        .verify_oneshot(&der_sig, signed_data)
        .map_err(|e| VerifyError::Crypto(format!("Verification error: {e}")))?;
    if !valid {
        return Err(VerifyError::Crypto(
            "Signature verification failed".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "native-crypto")]
fn ecdsa_sig_to_der(sig_bytes: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let sig = parse_ecdsa_p256_signature(sig_bytes)?;
    Ok(sig.to_der().as_bytes().to_vec())
}

// --- Signature parsing ---

fn parse_webauthn_signature(raw: &[u8]) -> Result<WebAuthnSignature, VerifyError> {
    let mut reader: &[u8] = raw;

    // Algorithm string (skip, already validated)
    let _algo = read_ssh_bytes(&mut reader)?;

    // ECDSA signature blob (mpint R, mpint S)
    let ecdsa_sig_bytes = read_ssh_bytes(&mut reader)?.to_vec();

    // Flags (1 byte)
    if reader.is_empty() {
        return Err(VerifyError::Parse("Missing flags".to_string()));
    }
    let flags = reader[0];
    reader = &reader[1..];

    // Counter (4 bytes, big-endian)
    if reader.len() < 4 {
        return Err(VerifyError::Parse("Missing counter".to_string()));
    }
    let counter = u32::from_be_bytes([reader[0], reader[1], reader[2], reader[3]]);
    reader = &reader[4..];

    // Origin string (WebAuthn-specific)
    let _origin = read_ssh_bytes(&mut reader)?;

    // clientDataJSON string
    let client_data_json_bytes = read_ssh_bytes(&mut reader)?;
    let client_data_json = std::str::from_utf8(client_data_json_bytes)
        .map_err(|e| VerifyError::Parse(format!("clientDataJSON not valid UTF-8: {e}")))?
        .to_string();

    // extensions (CBOR, typically empty — skip remaining bytes)

    Ok(WebAuthnSignature {
        ecdsa_sig_bytes,
        flags,
        counter,
        client_data_json,
    })
}

fn validate_challenge(client_data_json: &str, challenge: &[u8]) -> Result<(), VerifyError> {
    let parsed: serde_json::Value = serde_json::from_str(client_data_json)
        .map_err(|e| VerifyError::Parse(format!("Invalid clientDataJSON: {e}")))?;

    let expected = URL_SAFE_NO_PAD.encode(challenge);

    let actual = parsed
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::ChallengeMismatch("Missing 'challenge' field in clientDataJSON".to_string())
        })?;

    if actual != expected {
        return Err(VerifyError::ChallengeMismatch(format!(
            "expected {expected}, got {actual}"
        )));
    }

    Ok(())
}

/// Parse an ECDSA P-256 signature from SSH mpint wire format (mpint R || mpint S).
fn parse_ecdsa_p256_signature(sig_bytes: &[u8]) -> Result<p256::ecdsa::Signature, VerifyError> {
    let mut reader: &[u8] = sig_bytes;

    let r_bytes = read_ssh_mpint(&mut reader)?;
    let s_bytes = read_ssh_mpint(&mut reader)?;

    let r = pad_to_field_size(r_bytes, 32)?;
    let s = pad_to_field_size(s_bytes, 32)?;

    p256::ecdsa::Signature::from_scalars(r, s)
        .map_err(|e| VerifyError::Crypto(format!("Invalid ECDSA signature components: {e}")))
}

/// Read an SSH mpint and return the unsigned bytes.
fn read_ssh_mpint<'a>(reader: &mut &'a [u8]) -> Result<&'a [u8], VerifyError> {
    let bytes = read_ssh_bytes(reader)?;
    // mpint may have a leading zero byte for sign — strip it
    if bytes.first() == Some(&0) && bytes.len() > 1 {
        Ok(&bytes[1..])
    } else {
        Ok(bytes)
    }
}

/// Read a length-prefixed SSH string (non-advancing, from start of buffer).
fn read_ssh_string(data: &[u8]) -> Result<&[u8], VerifyError> {
    if data.len() < 4 {
        return Err(VerifyError::Parse("Buffer too short".to_string()));
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return Err(VerifyError::Parse("String truncated".to_string()));
    }
    Ok(&data[4..4 + len])
}

/// Pad a big-endian integer to the expected field size.
fn pad_to_field_size(bytes: &[u8], size: usize) -> Result<[u8; 32], VerifyError> {
    if bytes.len() > size {
        return Err(VerifyError::Crypto(format!(
            "Integer too large: {} bytes for {size}-byte field",
            bytes.len()
        )));
    }
    let mut padded = [0u8; 32];
    padded[size - bytes.len()..].copy_from_slice(bytes);
    Ok(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ssh_string(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(&(data.len() as u32).to_be_bytes());
        out.extend(data);
        out
    }

    fn make_ssh_mpint(value: &[u8]) -> Vec<u8> {
        if !value.is_empty() && value[0] & 0x80 != 0 {
            let mut with_zero = vec![0u8];
            with_zero.extend(value);
            make_ssh_string(&with_zero)
        } else {
            make_ssh_string(value)
        }
    }

    #[test]
    fn test_validate_challenge() {
        let challenge = b"test-challenge-data-here!1234567";
        let encoded = URL_SAFE_NO_PAD.encode(challenge);
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{encoded}","origin":"https://example.com"}}"#
        );
        assert!(validate_challenge(&client_data, challenge).is_ok());
        assert!(validate_challenge(&client_data, b"wrong").is_err());

        let bad_json = r#"{"type":"webauthn.get","origin":"https://example.com"}"#;
        assert!(validate_challenge(bad_json, challenge).is_err());
    }

    #[test]
    fn test_parse_ecdsa_p256_signature() {
        let r = [0x01u8; 32];
        let s = [0x02u8; 32];
        let mut sig_bytes = make_ssh_mpint(&r);
        sig_bytes.extend(make_ssh_mpint(&s));
        assert!(parse_ecdsa_p256_signature(&sig_bytes).is_ok());
    }

    #[test]
    fn test_read_ssh_mpint_strips_leading_zero() {
        let mut reader: &[u8] = &make_ssh_mpint(&[0x80, 0x01]);
        let result = read_ssh_mpint(&mut reader).unwrap();
        assert_eq!(result, &[0x80, 0x01]);
    }

    #[test]
    fn test_is_webauthn_signature() {
        let mut sig = make_ssh_string(b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com");
        sig.extend(vec![0; 100]);
        assert!(is_webauthn_signature(&sig));
    }

    #[test]
    fn test_parse_webauthn_signature() {
        let algo = b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com";
        let r = [0x01u8; 32];
        let s = [0x02u8; 32];
        let mut ecdsa_blob = make_ssh_mpint(&r);
        ecdsa_blob.extend(make_ssh_mpint(&s));

        let origin = b"https://example.com";
        let client_data = r#"{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://example.com"}"#;
        let extensions = b"";

        let mut blob = make_ssh_string(algo);
        blob.extend(make_ssh_string(&ecdsa_blob));
        blob.push(0x05); // flags
        blob.extend(&42u32.to_be_bytes()); // counter
        blob.extend(make_ssh_string(origin));
        blob.extend(make_ssh_string(client_data.as_bytes()));
        blob.extend(make_ssh_string(extensions));

        let sig = parse_webauthn_signature(&blob).unwrap();
        assert_eq!(sig.flags, 0x05);
        assert_eq!(sig.counter, 42);
        assert!(sig.client_data_json.contains("webauthn.get"));
    }
}
