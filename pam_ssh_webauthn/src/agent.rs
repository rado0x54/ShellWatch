//! SSH agent protocol implementation for WebAuthn SK key operations.
//!
//! Communicates directly with the SSH agent via Unix socket, implementing only
//! the subset of the protocol needed: list_identities and sign_raw.
//! No dependency on ssh-key or ssh-agent-client-rs.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

const WEBAUTHN_SK_ALGO: &[u8] = b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

/// Max size for individual SSH string fields (64 KB). Prevents a malicious agent
/// response with len=0xFFFFFFFF from causing a huge allocation.
const MAX_STRING_LEN: usize = 64 * 1024;

/// Timeout for agent socket operations. A hung agent must not block sudo/login
/// indefinitely. The sign request may require user interaction (passkey tap),
/// so we use a generous timeout.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(60);

/// A raw identity from the SSH agent: key blob + comment.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    /// Raw key blob bytes as returned by the agent.
    pub key_blob: Vec<u8>,
    pub comment: String,
}

/// List identities from the SSH agent, returning only those with the
/// `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` algorithm.
pub fn list_webauthn_identities(socket_path: &Path) -> io::Result<Vec<AgentIdentity>> {
    let mut stream = connect_with_timeout(socket_path)?;

    // Send REQUEST_IDENTITIES
    let msg = [SSH_AGENTC_REQUEST_IDENTITIES];
    write_msg(&mut stream, &msg)?;

    // Read response
    let response = read_msg(&mut stream)?;

    if response.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty response"));
    }
    if response[0] == SSH_AGENT_FAILURE {
        return Err(io::Error::other("Agent failure"));
    }
    if response[0] != SSH_AGENT_IDENTITIES_ANSWER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected IDENTITIES_ANSWER (12), got {}", response[0]),
        ));
    }

    let body = &response[1..];
    parse_webauthn_identities(body)
}

/// Send a sign request to the SSH agent and return the raw signature blob.
/// The blob preserves all WebAuthn fields (origin, clientDataJSON, extensions).
pub fn sign_raw(socket_path: &Path, key_blob: &[u8], data: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = connect_with_timeout(socket_path)?;

    // Build SSH_AGENTC_SIGN_REQUEST message
    let mut msg = Vec::new();
    msg.push(SSH_AGENTC_SIGN_REQUEST);
    // key blob
    write_ssh_bytes(&mut msg, key_blob);
    // data to sign
    write_ssh_bytes(&mut msg, data);
    // flags = 0
    msg.extend(&0u32.to_be_bytes());

    write_msg(&mut stream, &msg)?;

    // Read response
    let response = read_msg(&mut stream)?;

    if response.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty response"));
    }
    if response[0] == SSH_AGENT_FAILURE {
        return Err(io::Error::other("Agent refused signing"));
    }
    if response[0] != SSH_AGENT_SIGN_RESPONSE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected SIGN_RESPONSE (14), got {}", response[0]),
        ));
    }

    // Response body: string signature_blob
    let mut body = &response[1..];
    let sig_blob = read_ssh_bytes(&mut body)?;
    Ok(sig_blob.to_vec())
}

fn parse_webauthn_identities(mut body: &[u8]) -> io::Result<Vec<AgentIdentity>> {
    let nkeys = read_u32(&mut body)?;
    let mut identities = Vec::new();

    for _ in 0..nkeys {
        let key_blob = read_ssh_bytes(&mut body)?.to_vec();
        let comment_bytes = read_ssh_bytes(&mut body)?;
        let comment = String::from_utf8(comment_bytes.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Check if this key uses the webauthn-sk-ecdsa algorithm
        if is_webauthn_key_blob(&key_blob) {
            identities.push(AgentIdentity { key_blob, comment });
        }
    }

    Ok(identities)
}

/// Check if a key blob starts with the webauthn-sk-ecdsa algorithm string.
fn is_webauthn_key_blob(blob: &[u8]) -> bool {
    if blob.len() < 4 {
        return false;
    }
    let algo_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    if blob.len() < 4 + algo_len {
        return false;
    }
    &blob[4..4 + algo_len] == WEBAUTHN_SK_ALGO
}

// --- Wire format helpers ---

fn connect_with_timeout(socket_path: &Path) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
    Ok(stream)
}

fn write_msg(stream: &mut UnixStream, msg: &[u8]) -> io::Result<()> {
    let len = u32::try_from(msg.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Message too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(msg)?;
    stream.flush()
}

fn read_msg(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Response too large",
        ));
    }
    let mut response = vec![0u8; resp_len];
    stream.read_exact(&mut response)?;
    Ok(response)
}

pub fn read_u32(buf: &mut &[u8]) -> io::Result<u32> {
    if buf.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Buffer too short for u32",
        ));
    }
    let value = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    *buf = &buf[4..];
    Ok(value)
}

pub fn read_ssh_bytes<'a>(buf: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let len = read_u32(buf)? as usize;
    if len > MAX_STRING_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SSH string length {len} exceeds maximum {MAX_STRING_LEN}"),
        ));
    }
    if buf.len() < len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Buffer too short for bytes",
        ));
    }
    let data = &buf[..len];
    *buf = &buf[len..];
    Ok(data)
}

fn write_ssh_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend(&(data.len() as u32).to_be_bytes());
    buf.extend(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_webauthn_key_blob() {
        let mut blob = Vec::new();
        write_ssh_bytes(&mut blob, WEBAUTHN_SK_ALGO);
        blob.extend(b"rest-of-key-data");
        assert!(is_webauthn_key_blob(&blob));

        let mut blob = Vec::new();
        write_ssh_bytes(&mut blob, b"sk-ecdsa-sha2-nistp256@openssh.com");
        blob.extend(b"rest-of-key-data");
        assert!(!is_webauthn_key_blob(&blob));

        assert!(!is_webauthn_key_blob(&[]));
        assert!(!is_webauthn_key_blob(&[0, 0, 0, 5, 1, 2]));
    }

    #[test]
    fn test_read_write_ssh_bytes() {
        let mut buf = Vec::new();
        write_ssh_bytes(&mut buf, b"hello");
        let mut reader: &[u8] = &buf;
        let result = read_ssh_bytes(&mut reader).unwrap();
        assert_eq!(result, b"hello");
        assert!(reader.is_empty());
    }
}
