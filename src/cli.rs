// src/cli.rs
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use crate::error::{AppError, AppResult, StoreError, CryptoError};
use crate::models::PasswordStore;
use crate::store;
use log; // Added log
use rpassword;
use std::io::{self, Write}; // For stdout flush

/// A simple password manager written in Rust.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(arg_required_else_help = false)] // Allow no subcommand to default to TUI
pub struct Cli {
    #[clap(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new password store
    Init {
        /// Sets the path to the password store file
        #[clap(short, long, value_parser, default_value = "passwords.enc")]
        file: PathBuf,
    },
    /// List all entries in the password store
    List {
        /// Sets the path to the password store file
        #[clap(short, long, value_parser, default_value = "passwords.enc")]
        file: PathBuf,
    },
    /// Launch the Terminal User Interface (TUI)
    Tui,
}

/// Handles the parsed CLI command.
/// Returns `Ok(true)` if the TUI should run, `Ok(false)` if a CLI command was handled and TUI should not run.
pub fn handle_cli_command(cli: Cli) -> AppResult<bool> {
    log::debug!("Handling CLI command: {:?}", cli.command);
    match cli.command {
        Some(Commands::Init { file }) => {
            log::info!("Executing 'init' command for file: {:?}", file);
            if file.exists() {
                print!("Store file {:?} already exists. Overwrite? (y/N): ", file);
                io::stdout().flush().map_err(|e| {
                    log::error!("Failed to flush stdout for overwrite confirmation: {}", e);
                    AppError::Cli(format!("Failed to flush stdout: {}", e))
                })?;
                let mut confirmation = String::new();
                io::stdin().read_line(&mut confirmation).map_err(|e| {
                    log::error!("Failed to read overwrite confirmation: {}", e);
                    AppError::Cli(format!("Failed to read confirmation: {}", e))
                })?;
                if confirmation.trim().to_lowercase() != "y" {
                    println!("Initialization cancelled.");
                    log::info!("Store initialization cancelled by user.");
                    return Ok(false);
                }
                log::info!("User confirmed overwrite for existing store file: {:?}", file);
            }

            println!("Initializing new password store at: {:?}", file);
            log::info!("Prompting for master password for new store.");
            let password = rpassword::prompt_password("Enter master password: ")
                .map_err(|e| {
                    log::error!("Failed to read master password: {}", e);
                    AppError::Cli(format!("Failed to read password: {}", e))
                })?;
            let password_confirm = rpassword::prompt_password("Confirm master password: ")
                .map_err(|e| {
                    log::error!("Failed to read master password confirmation: {}", e);
                    AppError::Cli(format!("Failed to read password confirmation: {}", e))
                })?;

            if password != password_confirm {
                log::warn!("Master password confirmation failed: passwords do not match.");
                return Err(AppError::Cli("Passwords do not match.".to_string()));
            }
            if password.is_empty() {
                log::warn!("Master password cannot be empty.");
                 return Err(AppError::Cli("Master password cannot be empty.".to_string()));
            }
            
            let store_instance = PasswordStore::default();
            match store::save_store(&store_instance, &password, &file) {
                Ok(()) => {
                    println!("Successfully initialized and saved empty password store to {:?}.", file);
                    log::info!("Successfully initialized and saved empty password store to {:?}.", file);
                }
                Err(e) => {
                    log::error!("Failed to save new store to {:?}: {}", file, e);
                    return Err(e.into()); 
                }
            }
            Ok(false) 
        }
        Some(Commands::List { file }) => {
            log::info!("Executing 'list' command for file: {:?}", file);
            if !file.exists() {
                let msg = format!(
                    "Password store file not found at: {:?}\nPlease initialize the store first using the 'init' command.",
                    file
                );
                log::error!("List command: {}", msg);
                return Err(AppError::Cli(msg));
            }
            print!("Enter master password to list entries: ");
            io::stdout().flush().map_err(|e| {
                log::error!("Failed to flush stdout for password prompt: {}", e);
                AppError::Cli(format!("Failed to flush stdout: {}", e))
            })?;
            let password = rpassword::read_password()
                .map_err(|e| {
                    log::error!("Failed to read password for list command: {}", e);
                    AppError::Cli(format!("Failed to read password: {}", e))
                })?;

            match store::load_store(&password, &file) {
                Ok(store_instance) => {
                    if store_instance.entries.is_empty() {
                        println!("No entries found in the password store.");
                        log::info!("Listed 0 entries from {:?}.", file);
                    } else {
                        println!("Password Entries:");
                        for entry in &store_instance.entries { // Iterate by reference
                            println!("  - Service: {}, Username: {}", entry.service_name, entry.username);
                        }
                        log::info!("Listed {} entries from {:?}.", store_instance.entries.len(), file);
                    }
                }
                Err(StoreError::Crypto(CryptoError::ChaCha(_))) | Err(StoreError::Crypto(CryptoError::Argon2(_))) => {
                     log::warn!("Failed to decrypt store {:?} (list command): Incorrect master password or corrupted data.", file);
                     return Err(AppError::Cli("Failed to decrypt store. Incorrect master password or corrupted data.".to_string()));
                }
                Err(e) => {
                    log::error!("Failed to load store {:?} (list command): {}", file, e);
                    return Err(e.into()); 
                }
            }
            Ok(false) 
        }
        Some(Commands::Tui) => {
            log::info!("'tui' command given, preparing to launch TUI.");
            Ok(true) 
        }
        None => {
            log::info!("No CLI command given, preparing to launch TUI by default.");
            Ok(true)
        }
    }
}
