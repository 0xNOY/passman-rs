// src/crypto.rs
use crate::error::{CryptoError, CryptoResult}; 
use crate::config::Argon2Params; // Added Argon2Params import
use log;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2
};
use chacha20poly1305::{
    aead::{Aead, NewAead, Payload}, // OsRng as AeadOsRng removed, NewAead added
    ChaCha20Poly1305, Nonce // KeyInit removed
};
use hex; // For converting hash to hex string
use rand::rngs::OsRng; // For OsRng
use rand::RngCore; // For fill_bytes method

// OWASP recommended parameters for Argon2id are now in config.rs

/// Hashes a master password using Argon2id.
/// The salt should be unique per user/store.
/// Returns the hashed password as a hex string.
pub fn hash_master_password(password: &str, salt_bytes: &[u8], argon2_config: &Argon2Params) -> CryptoResult<String> {
    let salt = SaltString::b64_encode(salt_bytes)
        .map_err(|e| { 
            let msg = format!("Salt encoding failed: {}", e); 
            log::error!("hash_master_password: {}", msg); 
            CryptoError::Argon2(msg) 
        })?;

    let params = argon2::Params::new(argon2_config.m_cost, argon2_config.t_cost, argon2_config.p_cost, None)
        .map_err(|e| {
            let msg = format!("Argon2 params error for hashing: {}", e);
            log::error!("hash_master_password: {}", msg);
            CryptoError::Argon2(msg)
        })?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| {
            let msg = format!("Hashing failed: {}", e);
            log::error!("hash_master_password: {}", msg);
            CryptoError::Argon2(msg)
        })?
        .to_string();

    Ok(password_hash)
}

/// Verifies a master password against a stored Argon2id hash.
pub fn verify_master_password(hashed_password_str: &str, password: &str) -> CryptoResult<bool> {
    let parsed_hash = PasswordHash::new(hashed_password_str)
        .map_err(|e| {
            let msg = format!("Parsing hash failed: {}", e);
            log::error!("verify_master_password: {}", msg);
            CryptoError::Argon2(msg)
        })?;

    // Parameters for Argon2 instance for verification are derived from the hash itself.
    // We don't need to create params manually here.
    // The Argon2::default() or Argon2::new with default/any valid params would be fine
    // as verify_password uses the params from parsed_hash.
    // However, to be consistent with hashing and key derivation, if specific settings were critical
    // for the library's behavior beyond what's in the hash, one might load them.
    // For password-hash crate compliance, default should be fine.
    // For verification, Argon2 parameters are derived from the hash itself.
    // We only need a default Argon2 instance.
    let argon2 = Argon2::default(); 
    
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => {
            log::warn!("verify_master_password: Password verification failed (password mismatch).");
            Ok(false) 
        }
        Err(e) => {
            let msg = format!("Verification failed: {}", e);
            log::error!("verify_master_password: {}", msg);
            Err(CryptoError::Argon2(msg))
        }
    }
}

/// Encrypts data using ChaCha20Poly1305.
/// `key` must be 32 bytes.
/// `nonce` must be 12 bytes.
pub fn encrypt_data(data: &[u8], key_bytes: &[u8; 32], nonce_bytes: &[u8; 12]) -> CryptoResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key_bytes.into());
    let nonce = Nonce::from_slice(nonce_bytes); 

    cipher.encrypt(nonce, Payload { msg: data, aad: &[] }) 
        .map_err(|e| {
            let msg = format!("Encryption failed: {}", e);
            log::error!("encrypt_data: {}", msg);
            CryptoError::ChaCha(msg)
        })
}

/// Decrypts data using ChaCha20Poly1305.
/// `key` must be 32 bytes.
/// `nonce` must be 12 bytes.
pub fn decrypt_data(encrypted_data: &[u8], key_bytes: &[u8; 32], nonce_bytes: &[u8; 12]) -> CryptoResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key_bytes.into());
    let nonce = Nonce::from_slice(nonce_bytes); 

    cipher.decrypt(nonce, Payload { msg: encrypted_data, aad: &[] }) 
        .map_err(|e| {
            // This is a common error if the key is wrong (e.g. wrong master password)
            // or data is corrupt, or nonce is wrong.
            let msg = format!("Decryption failed (key/nonce/data mismatch?): {}", e);
            log::warn!("decrypt_data: {}", msg); // Warn because this can be due to user error (wrong pass)
            CryptoError::ChaCha(msg)
        })
}

// --- Helper functions for generating salt, key, nonce (Example usage, not for direct production without review) ---

/// Generates a cryptographically secure random salt (e.g., 16 bytes for Argon2).
pub fn generate_salt() -> CryptoResult<Vec<u8>> {
    let mut salt = vec![0u8; 16]; // 16 bytes is a common size for salt
    OsRng.fill_bytes(&mut salt);
    Ok(salt)
}

/// Generates a cryptographically secure random key for ChaCha20Poly1305 (32 bytes).
pub fn generate_chacha_key() -> CryptoResult<[u8; 32]> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key); // Corrected to use OsRng
    Ok(key)
}

/// Generates a cryptographically secure random nonce for ChaCha20Poly1305 (12 bytes).
pub fn generate_chacha_nonce() -> CryptoResult<[u8; 12]> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce); // Corrected to use OsRng
    Ok(nonce)
}

/// Derives a 32-byte key from a master password and salt using Argon2id.
pub fn derive_key_from_master_password(master_password: &str, salt: &[u8], argon2_config: &Argon2Params) -> CryptoResult<[u8; 32]> {
    let params = argon2::Params::new(argon2_config.m_cost, argon2_config.t_cost, argon2_config.p_cost, Some(32))
        .map_err(|e| {
            let msg = format!("Argon2 params error for key derivation: {}", e);
            log::error!("derive_key_from_master_password: {}", msg);
            CryptoError::Argon2(msg)
        })?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    
    let mut key_bytes = [0u8; 32];
    argon2.hash_password_into(master_password.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| {
            let msg = format!("Key derivation failed: {}", e);
            log::error!("derive_key_from_master_password: {}", msg);
            CryptoError::Argon2(msg)
        })?;
    
    Ok(key_bytes)
}


#[cfg(test)]
mod tests {
    use super::*;
    // Import Argon2Params for tests
    use crate::config::Argon2Params as TestArgon2Params;


    #[test]
    fn test_hash_and_verify_master_password() {
        let password = "strongpassword123";
        let salt = generate_salt().expect("Failed to generate salt");
        let argon2_params_default = TestArgon2Params::default();

        let hashed_password = hash_master_password(password, &salt, &argon2_params_default).expect("Hashing failed");
        
        println!("Salt (hex): {}", hex::encode(&salt));
        
        assert!(verify_master_password(&hashed_password, password).expect("Verification failed"));
        assert!(!verify_master_password(&hashed_password, "wrongpassword").expect("Verification should fail for wrong password"));
    }

    #[test]
    fn test_encrypt_and_decrypt_data() {
        let data = b"This is some secret data.";
        let key = generate_chacha_key().expect("Failed to generate key");
        let nonce = generate_chacha_nonce().expect("Failed to generate nonce");

        let encrypted_data = encrypt_data(data, &key, &nonce).expect("Encryption failed");
        assert_ne!(data, encrypted_data.as_slice());

        let decrypted_data = decrypt_data(&encrypted_data, &key, &nonce).expect("Decryption failed");
        assert_eq!(data, decrypted_data.as_slice());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let data = b"Some data";
        let key1 = generate_chacha_key().unwrap();
        let key2 = generate_chacha_key().unwrap(); // Different key
        let nonce = generate_chacha_nonce().unwrap();

        let encrypted_data = encrypt_data(data, &key1, &nonce).unwrap();
        let result = decrypt_data(&encrypted_data, &key2, &nonce);
        assert!(result.is_err());
        if let Err(CryptoError::ChaCha(msg)) = result {
            // The specific error message might vary, but it should indicate a decryption failure
            assert!(msg.contains("Decryption failed") || msg.contains("authentication tag mismatch"));
        } else {
            panic!("Expected ChaCha error for wrong key decryption");
        }
    }

    #[test]
    fn test_argon2_params_constants() { // Test now checks if default config params are valid
        let argon2_params_default = TestArgon2Params::default();
        let params = argon2::Params::new(argon2_params_default.m_cost, argon2_params_default.t_cost, argon2_params_default.p_cost, None);
        assert!(params.is_ok(), "Default Argon2 params from config should be valid");
    }

    #[test]
    fn test_derive_key_from_master_password() {
        let password = "masterkey123";
        let salt = generate_salt().expect("Failed to generate salt for key derivation test");
        let argon2_params_default = TestArgon2Params::default();

        let key1 = derive_key_from_master_password(password, &salt, &argon2_params_default).expect("Key derivation failed");
        assert_eq!(key1.len(), 32);

        let key2 = derive_key_from_master_password(password, &salt, &argon2_params_default).expect("Key derivation failed for second attempt");
        assert_eq!(key1, key2);

        let salt2 = generate_salt().expect("Failed to generate different salt");
        assert_ne!(salt, salt2);
        let key3 = derive_key_from_master_password(password, &salt2, &argon2_params_default).expect("Key derivation failed with different salt");
        assert_ne!(key1, key3);
        
        let key4 = derive_key_from_master_password("anotherpassword", &salt, &argon2_params_default).expect("Key derivation failed with different password");
        assert_ne!(key1, key4);
    }
}
