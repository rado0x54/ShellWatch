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

// WebAuthn authenticator flags (from the spec)
const FLAG_UP: u8 = 0x01; // User Presence
const FLAG_AD: u8 = 0x40; // Attested Credential Data
const FLAG_ED: u8 = 0x80; // Extension Data

const WEBAUTHN_SK_ALGO: &str = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";
const SK_ALGO: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// Parsed WebAuthn SK ECDSA signature fields.
#[derive(Debug)]
struct WebAuthnSignature {
    ecdsa_sig_bytes: Vec<u8>,
    flags: u8,
    counter: u32,
    origin: String,
    client_data_json: String,
    extensions: Vec<u8>,
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
///   signed_data = SHA256(application) || flags || counter || extensions || SHA256(clientDataJSON)
/// and verifies the ECDSA P-256 signature over signed_data.
///
/// ## Counter validation
///
/// The WebAuthn counter is integrity-protected (included in signed_data) but NOT
/// checked for monotonic increase. Counter validation requires persistent state
/// (tracking the last-seen counter per key), which is not appropriate for a
/// stateless PAM module. If counter validation is needed, it should be implemented
/// at the application layer with a persistent store.
pub fn verify_webauthn_sk(
    key: &WebAuthnPublicKey,
    challenge: &[u8],
    raw_sig_blob: &[u8],
) -> Result<(), VerifyError> {
    let sig = parse_webauthn_signature(raw_sig_blob)?;

    // Validate flags per WebAuthn/OpenSSH spec
    validate_flags(sig.flags, &sig.extensions)?;

    // Validate origin contains no quote characters (prevents JSON injection,
    // matches OpenSSH's webauthn_check_prepare_hash validation)
    validate_origin(&sig.origin)?;

    // Validate clientDataJSON: type field and challenge
    validate_client_data(&sig.client_data_json, challenge)?;

    // Construct signed_data: SHA256(application) || flags || counter || extensions || SHA256(clientDataJSON)
    let app_hash = Sha256::digest(key.application.as_bytes());
    let msg_hash = Sha256::digest(sig.client_data_json.as_bytes());

    let mut signed_data = Vec::with_capacity(32 + 1 + 4 + sig.extensions.len() + 32);
    signed_data.extend(&app_hash);
    signed_data.push(sig.flags);
    signed_data.extend(&sig.counter.to_be_bytes());
    signed_data.extend(&sig.extensions);
    signed_data.extend(&msg_hash);

    // Verify ECDSA P-256 signature over signed_data
    verify_ecdsa_p256(key, &sig.ecdsa_sig_bytes, &signed_data)?;

    Ok(())
}

/// Check if a raw signature blob is a WebAuthn SK signature.
pub fn is_webauthn_signature(raw_sig_blob: &[u8]) -> bool {
    if let Ok(algo) = read_ssh_string(raw_sig_blob) {
        let algo_str = String::from_utf8_lossy(algo);
        if algo_str == WEBAUTHN_SK_ALGO {
            return true;
        }
        // Also detect canonicalized sk-ecdsa with WebAuthn fields present.
        // A standard SK sig has algo + ecdsa_sig + flags(1) + counter(4) = done.
        // A WebAuthn SK sig has additional origin + clientDataJSON + extensions.
        if algo_str == SK_ALGO {
            return parse_webauthn_signature(raw_sig_blob).is_ok();
        }
    }
    false
}

#[derive(Debug)]
pub enum VerifyError {
    Parse(String),
    ChallengeMismatch(String),
    InvalidFlags(String),
    InvalidOrigin(String),
    InvalidType(String),
    Crypto(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Parse(msg) => write!(f, "Parse error: {msg}"),
            VerifyError::ChallengeMismatch(msg) => write!(f, "Challenge mismatch: {msg}"),
            VerifyError::InvalidFlags(msg) => write!(f, "Invalid flags: {msg}"),
            VerifyError::InvalidOrigin(msg) => write!(f, "Invalid origin: {msg}"),
            VerifyError::InvalidType(msg) => write!(f, "Invalid type: {msg}"),
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

// --- Validation ---

/// Validate authenticator flags per WebAuthn spec and OpenSSH convention.
fn validate_flags(flags: u8, extensions: &[u8]) -> Result<(), VerifyError> {
    // User Presence (UP) must be set — required for sudo authentication
    if flags & FLAG_UP == 0 {
        return Err(VerifyError::InvalidFlags(
            "User Presence (UP) flag not set".to_string(),
        ));
    }

    // Attested Credential Data (AD) must NOT be set — this is an assertion,
    // not a registration. Matches OpenSSH check.
    if flags & FLAG_AD != 0 {
        return Err(VerifyError::InvalidFlags(
            "Attested Credential Data (AD) flag unexpectedly set".to_string(),
        ));
    }

    // Extension Data (ED) flag must be consistent with extensions presence.
    // Matches OpenSSH check.
    let has_ed = flags & FLAG_ED != 0;
    let has_extensions = !extensions.is_empty();
    if has_ed && !has_extensions {
        return Err(VerifyError::InvalidFlags(
            "ED flag set but no extensions present".to_string(),
        ));
    }
    if !has_ed && has_extensions {
        return Err(VerifyError::InvalidFlags(
            "Extensions present but ED flag not set".to_string(),
        ));
    }

    Ok(())
}

/// Validate that origin contains no quote characters (prevents JSON injection).
/// Matches OpenSSH's webauthn_check_prepare_hash validation.
fn validate_origin(origin: &str) -> Result<(), VerifyError> {
    if origin.contains('"') {
        return Err(VerifyError::InvalidOrigin(
            "Origin contains quote character".to_string(),
        ));
    }
    Ok(())
}

/// Validate clientDataJSON: check type field is "webauthn.get" and challenge matches.
fn validate_client_data(client_data_json: &str, challenge: &[u8]) -> Result<(), VerifyError> {
    let parsed: serde_json::Value = serde_json::from_str(client_data_json)
        .map_err(|e| VerifyError::Parse(format!("Invalid clientDataJSON: {e}")))?;

    // Validate type field (WebAuthn spec step 11)
    let type_field = parsed
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::InvalidType("Missing 'type' field in clientDataJSON".to_string())
        })?;
    if type_field != "webauthn.get" {
        return Err(VerifyError::InvalidType(format!(
            "Expected type 'webauthn.get', got '{type_field}'"
        )));
    }

    // Validate challenge
    let expected = URL_SAFE_NO_PAD.encode(challenge);
    let actual = parsed
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::ChallengeMismatch(
                "Missing 'challenge' field in clientDataJSON".to_string(),
            )
        })?;

    if actual != expected {
        return Err(VerifyError::ChallengeMismatch(format!(
            "expected {expected}, got {actual}"
        )));
    }

    Ok(())
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

    // Algorithm string — validate it's one of the expected types
    let algo = read_ssh_bytes(&mut reader)?;
    let algo_str = std::str::from_utf8(algo)
        .map_err(|e| VerifyError::Parse(format!("Algorithm not valid UTF-8: {e}")))?;
    if algo_str != WEBAUTHN_SK_ALGO && algo_str != SK_ALGO {
        return Err(VerifyError::Parse(format!(
            "Unexpected algorithm: '{algo_str}'"
        )));
    }

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
    let origin_bytes = read_ssh_bytes(&mut reader)?;
    let origin = std::str::from_utf8(origin_bytes)
        .map_err(|e| VerifyError::Parse(format!("Origin not valid UTF-8: {e}")))?
        .to_string();

    // clientDataJSON string
    let client_data_json_bytes = read_ssh_bytes(&mut reader)?;
    let client_data_json = std::str::from_utf8(client_data_json_bytes)
        .map_err(|e| VerifyError::Parse(format!("clientDataJSON not valid UTF-8: {e}")))?
        .to_string();

    // Extensions (CBOR, typically empty)
    let extensions = read_ssh_bytes(&mut reader)?.to_vec();

    Ok(WebAuthnSignature {
        ecdsa_sig_bytes,
        flags,
        counter,
        origin,
        client_data_json,
        extensions,
    })
}

/// Parse an ECDSA P-256 signature from SSH mpint wire format (mpint R || mpint S).
fn parse_ecdsa_p256_signature(sig_bytes: &[u8]) -> Result<p256::ecdsa::Signature, VerifyError> {
    let mut reader: &[u8] = sig_bytes;

    let r_bytes = read_ssh_mpint(&mut reader)?;
    let s_bytes = read_ssh_mpint(&mut reader)?;

    let r = pad_to_field_size(r_bytes)?;
    let s = pad_to_field_size(s_bytes)?;

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

/// Pad a big-endian integer to 32 bytes (P-256 field size).
fn pad_to_field_size(bytes: &[u8]) -> Result<[u8; 32], VerifyError> {
    if bytes.len() > 32 {
        return Err(VerifyError::Crypto(format!(
            "Integer too large: {} bytes for 32-byte field",
            bytes.len()
        )));
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
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

    fn make_test_sig_blob(flags: u8, extensions: &[u8]) -> Vec<u8> {
        let algo = WEBAUTHN_SK_ALGO.as_bytes();
        let r = [0x01u8; 32];
        let s = [0x02u8; 32];
        let mut ecdsa_blob = make_ssh_mpint(&r);
        ecdsa_blob.extend(make_ssh_mpint(&s));

        let origin = b"https://example.com";
        let client_data =
            r#"{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://example.com"}"#;

        let mut blob = make_ssh_string(algo);
        blob.extend(make_ssh_string(&ecdsa_blob));
        blob.push(flags);
        blob.extend(&42u32.to_be_bytes());
        blob.extend(make_ssh_string(origin));
        blob.extend(make_ssh_string(client_data.as_bytes()));
        blob.extend(make_ssh_string(extensions));
        blob
    }

    #[test]
    fn test_validate_client_data() {
        let challenge = b"test-challenge-data-here!1234567";
        let encoded = URL_SAFE_NO_PAD.encode(challenge);
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{encoded}","origin":"https://example.com"}}"#
        );
        assert!(validate_client_data(&client_data, challenge).is_ok());
        assert!(validate_client_data(&client_data, b"wrong").is_err());

        let bad_json = r#"{"type":"webauthn.get","origin":"https://example.com"}"#;
        assert!(validate_client_data(bad_json, challenge).is_err());
    }

    #[test]
    fn test_validate_client_data_wrong_type() {
        let challenge = b"test";
        let encoded = URL_SAFE_NO_PAD.encode(challenge);

        // webauthn.create should be rejected
        let client_data = format!(
            r#"{{"type":"webauthn.create","challenge":"{encoded}","origin":"https://example.com"}}"#
        );
        let err = validate_client_data(&client_data, challenge).unwrap_err();
        assert!(matches!(err, VerifyError::InvalidType(_)));

        // Missing type field
        let client_data = format!(
            r#"{{"challenge":"{encoded}","origin":"https://example.com"}}"#
        );
        let err = validate_client_data(&client_data, challenge).unwrap_err();
        assert!(matches!(err, VerifyError::InvalidType(_)));
    }

    #[test]
    fn test_validate_flags_up_required() {
        // flags=0x00 — no UP → reject
        let err = validate_flags(0x00, &[]).unwrap_err();
        assert!(matches!(err, VerifyError::InvalidFlags(_)));

        // flags=0x01 — UP set → ok
        assert!(validate_flags(0x01, &[]).is_ok());

        // flags=0x05 — UP + UV → ok
        assert!(validate_flags(0x05, &[]).is_ok());
    }

    #[test]
    fn test_validate_flags_ad_rejected() {
        // AD flag (0x40) must not be set
        let err = validate_flags(0x41, &[]).unwrap_err(); // UP + AD
        assert!(matches!(err, VerifyError::InvalidFlags(_)));
    }

    #[test]
    fn test_validate_flags_ed_consistency() {
        // ED set but no extensions → reject
        let err = validate_flags(0x81, &[]).unwrap_err(); // UP + ED, empty extensions
        assert!(matches!(err, VerifyError::InvalidFlags(_)));

        // ED not set but extensions present → reject
        let err = validate_flags(0x01, &[0x01, 0x02]).unwrap_err();
        assert!(matches!(err, VerifyError::InvalidFlags(_)));

        // ED set with extensions → ok
        assert!(validate_flags(0x81, &[0x01, 0x02]).is_ok());
    }

    #[test]
    fn test_validate_origin_no_quotes() {
        assert!(validate_origin("https://example.com").is_ok());
        assert!(validate_origin("https://example.com:8080").is_ok());

        let err = validate_origin(r#"https://example.com","evil":"true"#).unwrap_err();
        assert!(matches!(err, VerifyError::InvalidOrigin(_)));
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
        let blob = make_test_sig_blob(0x05, &[]);
        assert!(is_webauthn_signature(&blob));
    }

    #[test]
    fn test_parse_webauthn_signature() {
        let blob = make_test_sig_blob(0x05, &[]);

        let sig = parse_webauthn_signature(&blob).unwrap();
        assert_eq!(sig.flags, 0x05);
        assert_eq!(sig.counter, 42);
        assert_eq!(sig.origin, "https://example.com");
        assert!(sig.client_data_json.contains("webauthn.get"));
        assert!(sig.extensions.is_empty());
    }

    #[test]
    fn test_parse_rejects_bad_algo() {
        let mut blob = make_ssh_string(b"ssh-ed25519");
        blob.extend(vec![0; 50]);
        let err = parse_webauthn_signature(&blob).unwrap_err();
        assert!(matches!(err, VerifyError::Parse(_)));
    }

    #[test]
    fn test_parse_with_extensions() {
        let ext_data = &[0xa0, 0x01, 0x02]; // some CBOR
        let blob = make_test_sig_blob(0x81, ext_data); // UP + ED

        let sig = parse_webauthn_signature(&blob).unwrap();
        assert_eq!(sig.extensions, ext_data);
    }
}
