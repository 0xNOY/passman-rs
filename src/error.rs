// src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Argon2 hashing failed: {0}")]
    Argon2(String), // Can refine later to wrap argon2::Error
    #[error("ChaCha20Poly1305 operation failed: {0}")]
    ChaCha(String), // Can refine later to wrap chacha20poly1305::Error
    #[error("Invalid key or nonce length")]
    InvalidLength,
    #[error("Hex decoding error: {0}")]
    HexDecoding(String),
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Cryptography error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Storage error: {0}")]
    Store(#[from] StoreError),
    #[error("TUI error: {0}")]
    Tui(#[from] TuiError),
    #[error("CLI error: {0}")]
    Cli(String),
    // Add other error variants as needed
}

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("Terminal I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Input handling error: {0}")]
    InputError(String),
    // Add other TUI specific errors as needed
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(String), // e.g., from bincode
    #[error("Deserialization error: {0}")]
    Deserialization(String), // e.g., from bincode
    #[error("Data format error: {0}")]
    FormatError(String), // for issues with the custom file structure
    #[error("Cryptography error during store operation: {0}")]
    Crypto(#[from] CryptoError),
}

// Result type alias for convenience
pub type AppResult<T> = Result<T, AppError>;
pub type CryptoResult<T> = Result<T, CryptoError>;
pub type StoreResult<T> = Result<T, StoreError>;
// pub type TuiResult<T> = Result<T, TuiError>; // Removed as it's unused
