//! pam_ssh_webauthn — PAM module for WebAuthn passkey-protected sudo.
//!
//! Authenticates via a forwarded SSH agent that holds WebAuthn SK ECDSA keys.
//! Only supports `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`.
//!
//! ## PAM configuration
//!
//! ```text
//! auth sufficient pam_ssh_webauthn.so file=/etc/security/authorized_keys
//! ```
//!
//! ## How it works
//!
//! 1. Reads authorized WebAuthn public keys from the configured file
//! 2. Connects to `$SSH_AUTH_SOCK` (forwarded through SSH)
//! 3. Lists agent identities, matches against authorized keys (raw blob comparison)
//! 4. Generates a 32-byte random challenge
//! 5. Sends SIGN_REQUEST to agent with matched key blob
//! 6. Parses WebAuthn signature (origin, clientDataJSON, extensions)
//! 7. Validates challenge is embedded in clientDataJSON
//! 8. Constructs signed_data (incl. extensions), verifies ECDSA P-256 signature
//! 9. Returns PAM_SUCCESS or PAM_AUTH_ERR

pub mod agent;
pub mod keys;
pub mod webauthn;

use log::{debug, error, info};
use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use std::ffi::CStr;
use std::path::Path;

const CHALLENGE_SIZE: usize = 32;
const DEFAULT_KEY_FILE: &str = "/etc/security/authorized_keys";

struct PamSshWebauthn;
pam::pam_hooks!(PamSshWebauthn);

impl PamHooks for PamSshWebauthn {
    fn sm_authenticate(handle: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        init_logging();

        let config = match parse_args(&args) {
            Ok(c) => c,
            Err(e) => {
                error!("pam_ssh_webauthn: invalid config: {e}");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        match do_authenticate(&config, handle) {
            Ok(true) => {
                info!("pam_ssh_webauthn: authentication successful");
                PamResultCode::PAM_SUCCESS
            }
            Ok(false) => {
                info!("pam_ssh_webauthn: no matching key");
                PamResultCode::PAM_AUTH_ERR
            }
            Err(e) => {
                error!("pam_ssh_webauthn: authentication failed: {e}");
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }

    fn sm_setcred(_handle: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        // Required by doas — nothing to do
        PamResultCode::PAM_SUCCESS
    }
}

struct Config {
    key_file: String,
    socket_path: Option<String>,
}

fn parse_args(args: &[&CStr]) -> Result<Config, String> {
    let mut key_file = DEFAULT_KEY_FILE.to_string();
    let mut socket_path = None;

    for arg in args {
        let s = arg.to_str().map_err(|e| format!("Invalid arg: {e}"))?;
        if let Some(path) = s.strip_prefix("file=") {
            key_file = path.to_string();
        } else if let Some(path) = s.strip_prefix("socket=") {
            socket_path = Some(path.to_string());
        }
    }

    Ok(Config {
        key_file,
        socket_path,
    })
}

fn do_authenticate(config: &Config, _handle: &mut PamHandle) -> Result<bool, Box<dyn std::error::Error>> {
    // Read authorized keys
    let authorized_keys = keys::parse_authorized_keys(Path::new(&config.key_file))?;
    if authorized_keys.is_empty() {
        debug!("No WebAuthn keys found in {}", config.key_file);
        return Ok(false);
    }
    info!(
        "Loaded {} WebAuthn key(s) from {}",
        authorized_keys.len(),
        config.key_file
    );

    // Get SSH_AUTH_SOCK from config override or environment
    let socket_path = match &config.socket_path {
        Some(path) => path.clone(),
        None => std::env::var("SSH_AUTH_SOCK")
            .map_err(|_| "SSH_AUTH_SOCK not set")?,
    };
    let socket = Path::new(&socket_path);

    // List agent identities
    let agent_identities = agent::list_webauthn_identities(socket)?;
    if agent_identities.is_empty() {
        debug!("No WebAuthn keys in agent");
        return Ok(false);
    }
    info!("Found {} WebAuthn key(s) in agent", agent_identities.len());

    // Match agent identities against authorized keys
    for agent_id in &agent_identities {
        for auth_key in &authorized_keys {
            if agent_id.key_blob == auth_key.key_blob {
                info!(
                    "Matched key: {} (app: {})",
                    auth_key.comment, auth_key.application
                );
                return try_authenticate(socket, auth_key, &agent_id.key_blob);
            }
        }
    }

    debug!("No agent key matched authorized keys");
    Ok(false)
}

fn try_authenticate(
    socket: &Path,
    key: &keys::WebAuthnPublicKey,
    key_blob: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    // Generate random challenge
    let mut challenge = [0u8; CHALLENGE_SIZE];
    getrandom::fill(&mut challenge).map_err(|_| "Failed to generate random challenge")?;

    // Sign via agent
    let raw_sig = agent::sign_raw(socket, key_blob, &challenge)?;

    // Verify WebAuthn signature
    webauthn::verify_webauthn_sk(key, &challenge, &raw_sig)?;

    Ok(true)
}

fn init_logging() {
    // Try syslog for production, fall back silently
    let _ = syslog::init(
        syslog::Facility::LOG_AUTH,
        log::LevelFilter::Info,
        Some("pam_ssh_webauthn"),
    );
}

/// Standalone authentication function for testing and CLI usage.
pub fn authenticate(
    socket_path: &Path,
    key_file: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    let authorized_keys = keys::parse_authorized_keys(key_file)?;
    if authorized_keys.is_empty() {
        return Ok(false);
    }

    let agent_identities = agent::list_webauthn_identities(socket_path)?;
    if agent_identities.is_empty() {
        return Ok(false);
    }

    for agent_id in &agent_identities {
        for auth_key in &authorized_keys {
            if agent_id.key_blob == auth_key.key_blob {
                return try_authenticate(socket_path, auth_key, &agent_id.key_blob);
            }
        }
    }

    Ok(false)
}
