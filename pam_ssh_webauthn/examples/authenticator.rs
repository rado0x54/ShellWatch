use std::env;
use std::path::Path;

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let socket_path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let key_file = env::args()
        .nth(1)
        .expect("Usage: authenticator <authorized_keys_file>");

    println!("Socket: {socket_path}");
    println!("Key file: {key_file}");

    match pam_ssh_webauthn::authenticate(Path::new(&socket_path), Path::new(&key_file)) {
        Ok(true) => println!("\n✅ Authentication successful"),
        Ok(false) => println!("\n❌ No matching key found"),
        Err(e) => println!("\n❌ Authentication failed: {e}"),
    }
}
