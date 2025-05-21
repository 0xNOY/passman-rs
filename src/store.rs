// src/store.rs
use crate::models::PasswordStore;
use crate::error::{StoreError, StoreResult, CryptoError}; // Re-added CryptoError for specific mapping if needed by tests or direct use.
use crate::crypto;
use crate::config::Argon2Params; // Added Argon2Params import
use log; // Added log
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

// Constants for cryptographic operations
const SALT_LEN: usize = 16; // For Argon2 salt
const NONCE_LEN: usize = 12; // For ChaCha20Poly1305 standard nonce

/// Saves the password store to a file, encrypting it with a key derived from the master password.
///
/// The file format will be:
/// [SALT (SALT_LEN bytes)] [NONCE (NONCE_LEN bytes)] [ENCRYPTED DATA (...)]
pub fn save_store(store: &PasswordStore, master_password: &str, filepath: &Path, argon2_config: &Argon2Params) -> StoreResult<()> {
    log::info!("Attempting to save store to {:?}", filepath);
    // 1. Generate a new random salt
    let salt_bytes: Vec<u8> = crypto::generate_salt().map_err(|e| {
        log::error!("Failed to generate salt for saving store: {:?}", e);
        StoreError::Crypto(e)
    })?;

    // 2. Derive the encryption key using the generated salt and config
    let key = crypto::derive_key_from_master_password(master_password, &salt_bytes, argon2_config)
        .map_err(|e| {
            log::error!("Failed to derive key for saving store: {:?}", e);
            StoreError::Crypto(e)
        })?;

    // 3. Serialize the PasswordStore
    let serialized_data = bincode::serialize(store)
        .map_err(|e| {
            let msg = format!("Bincode serialization failed: {}", e);
            log::error!("save_store: {}", msg);
            StoreError::Serialization(msg)
        })?;

    // 4. Generate a new random nonce
    let nonce_array = crypto::generate_chacha_nonce().map_err(|e| {
        log::error!("Failed to generate nonce for saving store: {:?}", e);
        StoreError::Crypto(e)
    })?;
    let nonce = nonce_array.as_slice();

    // 5. Encrypt the serialized data
    let encrypted_data = crypto::encrypt_data(&serialized_data, &key, &nonce_array)
        .map_err(|e| {
            log::error!("Failed to encrypt data for saving store: {:?}", e);
            StoreError::Crypto(e)
        })?;

    // 6. Create a file and write salt, nonce, then encrypted data
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(filepath)
        .map_err(|e| {
            log::error!("Failed to open file {:?} for writing: {:?}", filepath, e);
            StoreError::Io(e) // Already covered by #[from] but explicit log is good
        })?;

    file.write_all(&salt_bytes).map_err(|e| { log::error!("Failed to write salt to {:?}: {:?}", filepath, e); e })?;
    file.write_all(nonce).map_err(|e| { log::error!("Failed to write nonce to {:?}: {:?}", filepath, e); e })?;
    file.write_all(&encrypted_data).map_err(|e| { log::error!("Failed to write encrypted data to {:?}: {:?}", filepath, e); e })?;
    
    log::info!("Password store saved successfully to {:?}", filepath);
    Ok(())
}

/// Loads the password store from a file, decrypting it with a key derived from the master password.
pub fn load_store(master_password: &str, filepath: &Path, argon2_config: &Argon2Params) -> StoreResult<PasswordStore> {
    log::info!("Attempting to load store from {:?}", filepath);
    // 1. Open and read the file
    let mut file = File::open(filepath).map_err(|e| {
        log::warn!("Failed to open store file {:?}: {:?} (This may be normal if store is not yet created)", filepath, e);
        StoreError::Io(e)
    })?;
    
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents).map_err(|e| {
        log::error!("Failed to read store file {:?}: {:?}", filepath, e);
        StoreError::Io(e)
    })?;

    // 2. Read the salt
    if file_contents.len() < SALT_LEN {
        let msg = format!("File {:?} is too short to contain salt (len: {})", filepath, file_contents.len());
        log::error!("load_store: {}", msg);
        return Err(StoreError::FormatError(msg));
    }
    let salt = &file_contents[..SALT_LEN];

    // 3. Read the nonce
    if file_contents.len() < SALT_LEN + NONCE_LEN {
        let msg = format!("File {:?} is too short to contain nonce (len: {})", filepath, file_contents.len());
        log::error!("load_store: {}", msg);
        return Err(StoreError::FormatError(msg));
    }
    let nonce_bytes = &file_contents[SALT_LEN..SALT_LEN + NONCE_LEN];
    let mut nonce_array = [0u8; NONCE_LEN];
    nonce_array.copy_from_slice(nonce_bytes);


    // 4. The rest of the file is the encrypted data
    let encrypted_data = &file_contents[SALT_LEN + NONCE_LEN..];
    
    // 5. Derive the encryption key
    let key = crypto::derive_key_from_master_password(master_password, salt, argon2_config)
        .map_err(|e| {
            log::error!("Failed to derive key for loading store: {:?}", e);
            StoreError::Crypto(e)
        })?;

    // 6. Decrypt the encrypted data
    let decrypted_data = crypto::decrypt_data(encrypted_data, &key, &nonce_array)
        .map_err(|crypto_err| { // CryptoError already logged by crypto::decrypt_data if it's a warn/error there
            log::warn!("Decryption failed for store {:?}. Wrong password or corrupted data? Error: {:?}", filepath, crypto_err);
            StoreError::Crypto(crypto_err) 
        })?;
    
    // Handle case of empty store: if encrypted_data was empty, decrypted_data will also be empty.
    // This is a valid state for an empty store.
    if encrypted_data.is_empty() {
        if decrypted_data.is_empty() {
            log::info!("Store file {:?} contained an empty encrypted store. Returning default PasswordStore.", filepath);
            return Ok(PasswordStore::default());
        } else {
            // This case should ideally not be reached if ChaCha20Poly1305 works correctly,
            // as decrypting empty ciphertext should yield empty plaintext.
            let msg = "Encrypted data was empty, but decrypted data was not. This is unexpected.".to_string();
            log::error!("load_store: {}", msg);
            return Err(StoreError::Deserialization(msg));
        }
    }
    
    // If encrypted_data was not empty, but decrypted_data is, this is an error.
    if decrypted_data.is_empty() && !encrypted_data.is_empty() {
        let msg = "Decrypted data is unexpectedly empty from non-empty ciphertext.".to_string();
        log::error!("load_store: {}", msg);
        return Err(StoreError::Deserialization(msg));
    }

    // 7. Deserialize the decrypted bytes
    let store: PasswordStore = bincode::deserialize(&decrypted_data)
        .map_err(|e| {
            let msg = format!("Bincode deserialization failed: {}", e);
            log::error!("load_store: {}", msg);
            StoreError::Deserialization(msg)
        })?;
    
    log::info!("Password store loaded successfully from {:?}", filepath);
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{PasswordEntry, PasswordStore};
    use crate::config::Argon2Params as TestArgon2Params; // For tests
    use std::fs;
    use tempfile::NamedTempFile;

    fn create_test_store() -> PasswordStore {
        let mut store = PasswordStore::new();
        store.add_entry(PasswordEntry {
            id: "1".to_string(),
            service_name: "test_service".to_string(),
            username: "test_user".to_string(),
            password: "encrypted_pass_1".to_string(), // In real use, this would be encrypted by a different mechanism or handled differently
            notes: Some("notes1".to_string()),
            created_at: "2023-01-01T00:00:00Z".to_string(),
            updated_at: "2023-01-01T00:00:00Z".to_string(),
        });
        store.add_entry(PasswordEntry {
            id: "2".to_string(),
            service_name: "another_service".to_string(),
            username: "another_user".to_string(),
            password: "encrypted_pass_2".to_string(),
            notes: None,
            created_at: "2023-01-02T00:00:00Z".to_string(),
            updated_at: "2023-01-02T00:00:00Z".to_string(),
        });
        store
    }

    #[test]
    fn test_save_and_load_store_successfully() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let filepath = temp_file.path();
        let master_password = "securepassword123";
        let original_store = create_test_store();
        let argon2_params = TestArgon2Params::default();

        // Save the store
        let save_result = save_store(&original_store, master_password, filepath, &argon2_params);
        assert!(save_result.is_ok(), "Failed to save store: {:?}", save_result.err());

        // Load the store
        let loaded_store_result = load_store(master_password, filepath, &argon2_params);
        assert!(loaded_store_result.is_ok(), "Failed to load store: {:?}", loaded_store_result.err());
        
        let loaded_store = loaded_store_result.unwrap();
        assert_eq!(original_store.entries.len(), loaded_store.entries.len());
        for i in 0..original_store.entries.len() {
            assert_eq!(original_store.entries[i].id, loaded_store.entries[i].id);
            assert_eq!(original_store.entries[i].service_name, loaded_store.entries[i].service_name);
        }
    }

    #[test]
    fn test_load_store_wrong_password() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let filepath = temp_file.path();
        let master_password = "correctpassword";
        let wrong_password = "wrongpassword";
        let original_store = create_test_store();
        let argon2_params = TestArgon2Params::default();

        save_store(&original_store, master_password, filepath, &argon2_params).expect("Failed to save store for wrong password test");

        let load_result = load_store(wrong_password, filepath, &argon2_params);
        assert!(load_result.is_err());
        match load_result.err().unwrap() {
            StoreError::Crypto(crate::error::CryptoError::ChaCha(_)) => { /* Expected */ },
            // Depending on argon2 version and exact error, this might also be Argon2 error.
            // For this test setup, ChaCha is the more direct failure point from a wrong derived key.
            other_error => panic!("Expected a CryptoError (ChaCha) due to wrong password, but got {:?}", other_error),
        }
    }
    
    #[test]
    fn test_load_store_tampered_file_salt() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let filepath = temp_file.path();
        let master_password = "securepassword";
        let original_store = create_test_store();
        let argon2_params = TestArgon2Params::default();

        save_store(&original_store, master_password, filepath, &argon2_params).expect("Saving failed");

        // Tamper with the salt
        let mut contents = fs::read(filepath).expect("Reading file failed");
        if !contents.is_empty() {
            contents[0] = !contents[0]; // Flip some bits in the salt
        }
        fs::write(filepath, contents).expect("Writing tampered file failed");
        
        let load_result = load_store(master_password, filepath);
        assert!(load_result.is_err());
        // Expect a ChaCha error because the key derived from tampered salt will be wrong
        match load_result.err().unwrap() {
            StoreError::Crypto(crate::error::CryptoError::ChaCha(_)) => {},
            other => panic!("Expected ChaCha error due to tampered salt, got {:?}", other),
        }
    }

    #[test]
    fn test_load_store_tampered_file_nonce() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let filepath = temp_file.path();
        let master_password = "securepassword";
        let original_store = create_test_store();
        let argon2_params = TestArgon2Params::default();

        save_store(&original_store, master_password, filepath, &argon2_params).expect("Saving failed");

        // Tamper with the nonce
        let mut contents = fs::read(filepath).expect("Reading file failed");
        if contents.len() > SALT_LEN {
            contents[SALT_LEN] = !contents[SALT_LEN]; // Flip some bits in the nonce
        }
        fs::write(filepath, contents).expect("Writing tampered file failed");
        
        let load_result = load_store(master_password, filepath);
        assert!(load_result.is_err());
        match load_result.err().unwrap() {
            StoreError::Crypto(CryptoError::ChaCha(_)) => {},
            other => panic!("Expected ChaCha error due to tampered nonce, got {:?}", other),
        }
    }

    #[test]
    fn test_load_store_tampered_file_data() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let filepath = temp_file.path();
        let master_password = "securepassword";
        let original_store = create_test_store();

        save_store(&original_store, master_password, filepath).expect("Saving failed");

        // Tamper with the encrypted data
        let mut contents = fs::read(filepath).expect("Reading file failed");
        if contents.len() > SALT_LEN + NONCE_LEN {
            contents[SALT_LEN + NONCE_LEN] = !contents[SALT_LEN + NONCE_LEN]; // Flip some bits
        }
        fs::write(filepath, contents).expect("Writing tampered file failed");
        
        let load_result = load_store(master_password, filepath);
        assert!(load_result.is_err());
        // Could be ChaCha error (decryption) or Deserialization error if decryption "succeeds" with garbage
        match load_result.err().unwrap() {
            StoreError::Crypto(crate::error::CryptoError::ChaCha(_)) => {},
            StoreError::Deserialization(_) => {}, 
            other => panic!("Expected ChaCha or Deserialization error due to tampered data, got {:?}", other),
        }
    }

    #[test]
    fn test_save_and_load_empty_store() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let filepath = temp_file.path();
        let master_password = "emptypassword";
        let original_store = PasswordStore::new(); 
        let argon2_params = TestArgon2Params::default();

        let save_result = save_store(&original_store, master_password, filepath, &argon2_params);
        assert!(save_result.is_ok(), "Failed to save empty store: {:?}", save_result.err());

        let loaded_store_result = load_store(master_password, filepath, &argon2_params);
        assert!(loaded_store_result.is_ok(), "Failed to load empty store: {:?}", loaded_store_result.err());
        
        let loaded_store = loaded_store_result.unwrap();
        assert_eq!(loaded_store.entries.len(), 0);
    }

     #[test]
    fn test_load_non_existent_file() {
        let filepath = Path::new("non_existent_store_file.dat");
        let master_password = "anypassword";
        let argon2_params = TestArgon2Params::default();
        let load_result = load_store(master_password, filepath, &argon2_params);
        assert!(load_result.is_err());
        match load_result.err().unwrap() {
            StoreError::Io(_) => { /* Expected */ },
            other => panic!("Expected Io error for non-existent file, got {:?}", other),
        }
    }

    #[test]
    fn test_load_too_short_file() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let filepath = temp_file.path();
        fs::write(filepath, b"short").expect("Failed to write short file");
        let argon2_params = TestArgon2Params::default();

        let master_password = "anypassword";
        let load_result = load_store(master_password, filepath, &argon2_params);
        assert!(load_result.is_err());
        match load_result.err().unwrap() {
            StoreError::FormatError(msg) => assert!(msg.contains("too short")),
            other => panic!("Expected FormatError for too short file, got {:?}", other),
        }
    }
}
