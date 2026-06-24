//! KeyAuthority implementation for ASF.
//!
//! This module manages one Ed25519 key pair per agent in a separate SQLite
//! registry (`keys_registry.db`). Private keys are encrypted at rest with
//! AES-256-GCM using the master key from `ASF_MASTER_KEY`.
//!
//! # Storage compatibility warning
//!
//! Python ASF stores encrypted private keys as PEM PKCS#8 bytes. This Rust
//! implementation intentionally stores encrypted private keys as the raw
//! 32-byte Ed25519 seed returned by `ed25519_dalek::SigningKey::to_bytes()`.
//!
//! Because the encrypted private-key plaintext format differs, Python-generated
//! keys and Rust-generated keys are NOT cross-compatible for signing. A Rust
//! process cannot sign with a Python-generated record, and the Python
//! KeyAuthority cannot sign with a Rust-generated record. The migration path is
//! to re-register all agents after switching implementations.
//!
//! Public keys are stored in PEM SubjectPublicKeyInfo form in the
//! `public_key_pem` column for schema compatibility, while public API functions
//! return raw 32-byte Ed25519 public keys.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use std::env;
use std::path::{Path, PathBuf};

/// Database handle used by this module.
///
/// If the path points to a directory, `keys_registry.db` is created/read inside
/// it. If the path points to a file, that file is used directly. This keeps the
/// public API close to the Python implementation's separate key registry while
/// avoiding an additional connection-pool dependency in the current crate.
pub type DbPool = PathBuf;

const KEY_DB_NAME: &str = "keys_registry.db";
const NONCE_LEN: usize = 12;
const ED25519_SEED_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const ED25519_SPKI_DER_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Debug)]
struct KeyRecord {
    private_key_enc: Vec<u8>,
    public_key_pem: String,
}

/// Return the default keys registry path.
///
/// Resolution order:
/// 1. `ASF_KEYS_DB`, if set.
/// 2. `ASF_ROOT/keys_registry.db`, if `ASF_ROOT` is set.
/// 3. `keys_registry.db` next to the current executable.
pub fn resolve_keys_db_path() -> DbPool {
    if let Some(path) = env::var_os("ASF_KEYS_DB") {
        return PathBuf::from(path);
    }

    if let Some(root) = env::var_os("ASF_ROOT") {
        return PathBuf::from(root).join(KEY_DB_NAME);
    }

    env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
        .join(KEY_DB_NAME)
}

/// Register an agent and return its raw 32-byte Ed25519 public key.
///
/// If the agent already exists, this returns the stored public key without
/// generating a new private key.
pub fn register_agent(pool: &DbPool, agent_id: &str) -> Result<Vec<u8>, String> {
    let conn = open_registry(pool)?;
    init_schema(&conn)?;

    if let Some(record) = load_record(&conn, agent_id)? {
        return public_key_from_pem(&record.public_key_pem).map(|key| key.to_vec());
    }

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // IMPORTANT: Rust stores the raw 32-byte seed, not PEM PKCS#8.
    let private_key_enc = encrypt(signing_key.to_bytes().as_ref())?;
    let public_key_pem = public_key_to_pem(verifying_key.as_bytes());

    conn.execute(
        "INSERT INTO agent_keys (agent_id, private_key_enc, public_key_pem) VALUES (?1, ?2, ?3)",
        params![agent_id, private_key_enc, public_key_pem],
    )
    .map_err(|err| format!("failed to insert key record for '{agent_id}': {err}"))?;

    Ok(verifying_key.to_bytes().to_vec())
}

/// Sign `message` as `agent_id` and return the raw 64-byte Ed25519 signature.
///
/// This can only sign records whose encrypted private-key plaintext is the Rust
/// raw 32-byte seed format. Python-generated PEM PKCS#8 private keys are not
/// accepted; re-register agents after migration.
pub fn sign_message(pool: &DbPool, agent_id: &str, message: &str) -> Result<Vec<u8>, String> {
    let conn = open_registry(pool)?;
    init_schema(&conn)?;

    let record = load_record(&conn, agent_id)?
        .ok_or_else(|| format!("Agent '{agent_id}' not registered in KeyAuthority."))?;

    let seed = decrypt(&record.private_key_enc)?;
    if seed.len() != ED25519_SEED_LEN {
        return Err(format!(
            "private key for agent '{agent_id}' is not a Rust raw Ed25519 seed; \
             Python PEM PKCS#8 records are not cross-compatible and must be re-registered"
        ));
    }

    let seed: [u8; ED25519_SEED_LEN] = seed
        .try_into()
        .map_err(|_| "invalid Ed25519 seed length after decryption".to_string())?;
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(message.as_bytes());

    Ok(signature.to_bytes().to_vec())
}

/// Verify `signature` over `message` using `agent_id`'s stored public key.
///
/// Returns `false` for unknown agents, malformed signatures, malformed public
/// keys, or cryptographic verification failure.
pub fn verify_signature(pool: &DbPool, agent_id: &str, message: &str, signature: &[u8]) -> bool {
    if signature.len() != ED25519_SIGNATURE_LEN {
        return false;
    }

    let conn = match open_registry(pool).and_then(|conn| {
        init_schema(&conn)?;
        Ok(conn)
    }) {
        Ok(conn) => conn,
        Err(_) => return false,
    };

    let record = match load_record(&conn, agent_id) {
        Ok(Some(record)) => record,
        _ => return false,
    };

    let verifying_key = match public_key_from_pem(&record.public_key_pem)
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).map_err(|err| err.to_string()))
    {
        Ok(key) => key,
        Err(_) => return false,
    };

    let signature_bytes: [u8; ED25519_SIGNATURE_LEN] = match signature.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key.verify(message.as_bytes(), &signature).is_ok()
}

fn open_registry(pool: &DbPool) -> Result<Connection, String> {
    let path = registry_path(pool);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create key registry directory: {err}"))?;
    }

    let conn = Connection::open(&path)
        .map_err(|err| format!("failed to open key registry '{}': {err}", path.display()))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
        .map_err(|err| {
            format!(
                "failed to configure key registry '{}': {err}",
                path.display()
            )
        })?;
    Ok(conn)
}

fn registry_path(pool: &DbPool) -> PathBuf {
    if pool.extension().is_none() || pool.is_dir() {
        pool.join(KEY_DB_NAME)
    } else {
        pool.clone()
    }
}

fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS agent_keys (
            agent_id TEXT PRIMARY KEY,
            private_key_enc BLOB NOT NULL,
            public_key_pem TEXT NOT NULL
        );
        ",
    )
    .map_err(|err| format!("failed to initialise agent_keys schema: {err}"))
}

fn load_record(conn: &Connection, agent_id: &str) -> Result<Option<KeyRecord>, String> {
    conn.query_row(
        "SELECT private_key_enc, public_key_pem FROM agent_keys WHERE agent_id = ?1",
        params![agent_id],
        |row| {
            Ok(KeyRecord {
                private_key_enc: row.get(0)?,
                public_key_pem: row.get(1)?,
            })
        },
    )
    .optional()
    .map_err(|err| format!("failed to load key record for '{agent_id}': {err}"))
}

fn master_key() -> Result<[u8; 32], String> {
    if let Ok(raw) = env::var("ASF_MASTER_KEY") {
        let decoded = BASE64_STANDARD
            .decode(raw.trim())
            .map_err(|err| format!("ASF_MASTER_KEY is not valid base64: {err}"))?;
        return decoded.try_into().map_err(|_| {
            "ASF_MASTER_KEY must decode to exactly 32 bytes for AES-256-GCM".to_string()
        });
    }

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let encoded = BASE64_STANDARD.encode(key);
    eprintln!("[KEY AUTHORITY] WARNING: ASF_MASTER_KEY not set. Generated a temporary key.");
    eprintln!("[KEY AUTHORITY] Set this environment variable to persist across restarts:");
    eprintln!("  export ASF_MASTER_KEY={encoded}");
    Ok(key)
}

fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let key = master_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|err| format!("failed to initialise AES-256-GCM: {err}"))?;

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|err| format!("AES-256-GCM encryption failed: {err}"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt(encrypted: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted.len() < NONCE_LEN {
        return Err("encrypted private key is shorter than the AES-GCM nonce".to_string());
    }

    let key = master_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|err| format!("failed to initialise AES-256-GCM: {err}"))?;
    let (nonce, ciphertext) = encrypted.split_at(NONCE_LEN);

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|err| format!("AES-256-GCM decryption failed: {err}"))
}

fn public_key_to_pem(public_key: &[u8; ED25519_SEED_LEN]) -> String {
    let mut der = Vec::with_capacity(ED25519_SPKI_DER_PREFIX.len() + public_key.len());
    der.extend_from_slice(ED25519_SPKI_DER_PREFIX);
    der.extend_from_slice(public_key);

    let b64 = BASE64_STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // Base64 output is ASCII, so this conversion cannot fail in practice.
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

fn public_key_from_pem(pem: &str) -> Result<[u8; ED25519_SEED_LEN], String> {
    let body = pem
        .lines()
        .filter(|line| !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "))
        .map(str::trim)
        .collect::<String>();

    let der = BASE64_STANDARD
        .decode(body)
        .map_err(|err| format!("public key PEM is not valid base64: {err}"))?;

    if !der.starts_with(ED25519_SPKI_DER_PREFIX) {
        return Err("public key PEM is not an Ed25519 SubjectPublicKeyInfo key".to_string());
    }

    let public_key = &der[ED25519_SPKI_DER_PREFIX.len()..];
    public_key
        .try_into()
        .map_err(|_| "public key PEM does not contain exactly 32 Ed25519 key bytes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_sign_and_verify_round_trip() {
        let unique = format!(
            "asf-key-authority-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = env::temp_dir().join(unique);
        let master_key = [7u8; 32];
        env::set_var("ASF_MASTER_KEY", BASE64_STANDARD.encode(master_key));

        let public_key = register_agent(&dir, "agent-1").expect("register");
        assert_eq!(public_key.len(), ED25519_SEED_LEN);

        let same_public_key = register_agent(&dir, "agent-1").expect("register existing");
        assert_eq!(public_key, same_public_key);

        let signature = sign_message(&dir, "agent-1", "hello").expect("sign");
        assert_eq!(signature.len(), ED25519_SIGNATURE_LEN);
        assert!(verify_signature(&dir, "agent-1", "hello", &signature));
        assert!(!verify_signature(&dir, "agent-1", "tampered", &signature));
        assert!(!verify_signature(&dir, "missing", "hello", &signature));

        let _ = std::fs::remove_dir_all(dir);
    }
}
