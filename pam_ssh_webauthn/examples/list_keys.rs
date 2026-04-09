use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use std::env;
use std::path::Path;

fn main() {
    let socket_path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");

    let identities = pam_ssh_webauthn::agent::list_webauthn_identities(Path::new(&socket_path))
        .expect("Failed to list identities");

    if identities.is_empty() {
        println!("No WebAuthn SK identities found in agent.");
        // Also show raw count of all identities
        return;
    }

    for (i, id) in identities.iter().enumerate() {
        println!("=== Identity {i} ===");
        println!("Comment: {}", id.comment);
        println!("Blob length: {} bytes", id.key_blob.len());
        println!("Base64: {}", BASE64_STANDARD.encode(&id.key_blob));

        // Decode the wire format
        let mut reader: &[u8] = &id.key_blob;
        if let Ok(algo) = read_string(&mut reader) {
            println!("  Algorithm: {algo}");
        }
        if let Ok(curve) = read_string(&mut reader) {
            println!("  Curve: {curve}");
        }
        if let Ok(ec_point) = read_bytes(&mut reader) {
            println!("  EC point: {} bytes, starts with 0x{:02x}", ec_point.len(), ec_point.first().unwrap_or(&0));
            println!("  EC point hex: {}", hex(ec_point));
        }
        if let Ok(app) = read_string(&mut reader) {
            println!("  Application: {app}");
        }
        if !reader.is_empty() {
            println!("  Remaining: {} bytes", reader.len());
        }
        println!();
    }
}

fn read_bytes<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], &'static str> {
    if buf.len() < 4 { return Err("too short"); }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    *buf = &buf[4..];
    if buf.len() < len { return Err("truncated"); }
    let data = &buf[..len];
    *buf = &buf[len..];
    Ok(data)
}

fn read_string<'a>(buf: &mut &'a [u8]) -> Result<String, &'static str> {
    let bytes = read_bytes(buf)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| "invalid utf8")
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}
