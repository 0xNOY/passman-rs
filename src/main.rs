// src/main.rs
mod tui;
mod crypto;
mod store;
mod cli;
mod error;
mod models;

use clap::Parser; // Added clap

fn main() -> Result<(), error::AppError> {
    env_logger::init(); // Initialize logger
    log::info!("Starting PassMan-RS application");

    let cli_args = cli::Cli::parse();

    match cli::handle_cli_command(cli_args) {
        Ok(should_run_tui) => {
            if should_run_tui {
                // This log is already present in cli::handle_cli_command if command is None or Tui
                // log::info!("Launching TUI."); 
                if let Err(e) = tui::run_tui() {
                    log::error!("Application TUI error: {:#?}", e); // Use {:#?} for detailed debug view
                    eprintln!("Error: {}", e); 
                    return Err(e);
                }
            } else {
                // Specific command success is logged in handle_cli_command
                log::info!("CLI command processed.");
            }
        }
        Err(e) => {
            // Specific error context should be logged closer to the source (e.g., in handle_cli_command)
            // Here, we log that the application is terminating due to an error.
            log::error!("Application failed: {:#?}", e); // Use {:#?} for detailed debug view
            eprintln!("Error: {}", e); 
            return Err(e);
        }
    }
    
    log::info!("PassMan-RS application finished successfully.");
    Ok(())
}
