// src/models.rs
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::Utc; // DateTime removed

#[derive(Serialize, Deserialize, Debug, Clone, Default)] // Added Default
pub struct PasswordEntry {
    pub id: String, 
    pub service_name: String,
    pub username: String,
    pub password: String, // This will store the encrypted password
    pub notes: Option<String>,
    pub created_at: String, 
    pub updated_at: String, 
}

impl PasswordEntry {
    pub fn new(service_name: String, username: String, password: String, notes: Option<String>) -> Self {
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        Self {
            id: Uuid::new_v4().to_string(),
            service_name,
            username,
            password, // This password should be encrypted before being stored here ideally
            notes,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}


#[derive(Serialize, Deserialize, Debug, Default)] // Added Debug and Default
pub struct PasswordStore {
    pub entries: Vec<PasswordEntry>,
    // Potentially add metadata here later, e.g., salt for master password hashing, versioning
}

// Helper functions for PasswordStore (can be expanded later)
impl PasswordStore {
    pub fn new() -> Self {
        PasswordStore::default()
    }

    pub fn add_entry(&mut self, entry: PasswordEntry) {
        self.entries.push(entry);
    }
}
