use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore; // For fill_bytes
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use secrecy::{SecretString, ExposeSecret};

/// The size of the salt in bytes. 16 bytes is a standard recommendation.
const SALT_LEN: usize = 16;
/// The size of the nonce for AES-GCM. 12 bytes is the standard unique nonce size.
const NONCE_LEN: usize = 12;

/// Error type for Vault operations.
#[derive(thiserror::Error, Debug)]
pub enum VaultError {
    #[error("Encryption failed")]
    EncryptionError,
    #[error("Decryption failed: Integrity check failed or wrong password")]
    DecryptionError,
    #[error("Key derivation failed")]
    KeyDerivationError,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// The encrypted Vault file structure.
#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub header: VaultHeader,
    /// The encrypted payload. This is a blob of bytes that, when decrypted,
    /// reveals the actual secret data (e.g., a JSON string of credentials).
    pub encrypted_payload: Vec<u8>,
}

impl Vault {
    /// Save the vault to a file.
    pub fn save<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), VaultError> {
        let file = std::fs::File::create(path)?;
        serde_json::to_writer(file, self).map_err(VaultError::SerializationError)
    }

    /// Load the vault from a file.
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> Result<Self, VaultError> {
        let file = std::fs::File::open(path)?;
        serde_json::from_reader(file).map_err(VaultError::SerializationError)
    }
}

/// A single entry in the vault.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultEntry {
    pub username: String,
    #[serde(serialize_with = "serialize_secret")]
    pub password: SecretString,
}

fn serialize_secret<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::Serialize;
    secret.expose_secret().serialize(serializer)
}

/// Metadata required to derive the key and decrypt the payload.
/// This part is stored in plaintext (but authenticated by the payload tag if AAD is used, 
/// though here GCM tag covers the payload. Ideally header logic validation implies checking integrity).
#[derive(Serialize, Deserialize, Debug)]
pub struct VaultHeader {
    /// Random salt used for key derivation.
    #[serde(with = "hex_serde")]
    pub salt: [u8; SALT_LEN],
    /// Random nonce used for AES-GCM encryption.
    #[serde(with = "hex_serde")]
    pub nonce: [u8; NONCE_LEN],
}

/// Helper module to serialize byte arrays as hex strings for JSON readability.
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let vec = hex::decode(&s).map_err(D::Error::custom)?;
        if vec.len() != N {
            return Err(D::Error::custom(format!(
                "Expected {} bytes, got {}",
                N,
                vec.len()
            )));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

/// Derives a 32-byte encryption key from a user password and a salt.
/// 
/// **Security Choice: Argon2id**
/// We use Argon2id (hybrid version) which is resistant to both GPU cracking (memory-hard)
/// and side-channel attacks.
/// 
/// # Arguments
/// * `password` - The user's master password.
/// * `salt` - A random 16-byte salt.
pub fn derive_key(password: &SecretString, salt: &[u8]) -> Result<Key<Aes256Gcm>, VaultError> {
    // Argon2 config: Default is robust, but we can tune it if needed.
    // Default params (m=4096, t=3, p=1) are generally good for interactive use.
    let argon2 = Argon2::default();
    
    // We need a 32-byte key for AES-256
    let mut key_material = [0u8; 32];
    
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key_material)
        .map_err(|_| VaultError::KeyDerivationError)?;
        
    let key = *Key::<Aes256Gcm>::from_slice(&key_material);
    
    // key_material should be zeroized, but code above copies it into Key. 
    // `Key` from aes-gcm doesn't auto-zeroize on drop by default without `zeroize` feature + wrapper,
    // but we can at least explicit zeroize our buffer. 
    key_material.zeroize();
    
    Ok(key)
}

/// Encrypts data using AES-256-GCM.
/// 
/// **Security Choice: AES-256-GCM**
/// - **Confidentiality**: AES-256 is the industry standard for symmetric encryption.
/// - **Integrity**: GCM (Galois/Counter Mode) allows us to verify that the data hasn't been tampered with.
/// - **Random Nonce**: We generate a new random nonce for every encryption to prevent replay attacks.
pub fn encrypt(data: &[u8], password: &SecretString) -> Result<Vault, VaultError> {
    // 1. Generate a random salt
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    
    // 2. Derive key from password + salt
    let key = derive_key(password, &salt)?;
    
    // 3. Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // 4. Encrypt
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| VaultError::EncryptionError)?;
        
    // 5. Construct Vault struct
    Ok(Vault {
        header: VaultHeader {
            salt,
            nonce: nonce_bytes,
        },
        encrypted_payload: ciphertext,
    })
}

/// Decrypts a Vault.
/// 
/// Returns `VaultError::DecryptionError` if the password is wrong or the file is corrupted/tampered.
pub fn decrypt(vault: &Vault, password: &SecretString) -> Result<Vec<u8>, VaultError> {
    // 1. Derive key using the *stored* salt
    let key = derive_key(password, &vault.header.salt)?;
    
    // 2. Decrypt using the *stored* nonce
    let nonce = Nonce::from_slice(&vault.header.nonce);
    let cipher = Aes256Gcm::new(&key);
    
    let plaintext = cipher
        .decrypt(nonce, vault.encrypted_payload.as_ref())
        .map_err(|_| VaultError::DecryptionError)?;
        
    Ok(plaintext)
}

pub fn generate_password(length: usize) -> SecretString {
    use rand::distributions::Distribution;
    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
    let mut rng = rand::thread_rng();
    let dist = rand::distributions::Slice::new(charset).unwrap();
    let s: String = (0..length)
        .map(|_| *dist.sample(&mut rng) as char)
        .collect();
    SecretString::from(s)
}
