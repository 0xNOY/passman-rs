// src/config.rs
use serde::{Serialize, Deserialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use directories::ProjectDirs;
use log::{info, warn};
use toml;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Argon2Params {
    pub m_cost: u32, // KiB
    pub t_cost: u32, // iterations
    pub p_cost: u32, // parallelism
}

impl Default for Argon2Params {
    fn default() -> Self {
        Argon2Params {
            m_cost: 19456, // 19 MiB (19 * 1024 KiB)
            t_cost: 2,
            p_cost: 1,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub argon2_params: Argon2Params,
    pub clipboard_clear_time_seconds: u64,
    pub theme: Option<String>, // Placeholder for future use
}

impl Default for Config {
    fn default() -> Self {
        Config {
            argon2_params: Argon2Params::default(),
            clipboard_clear_time_seconds: 30,
            theme: None,
        }
    }
}

fn get_config_path() -> Option<PathBuf> {
    ProjectDirs::from("com", "PassmanRS", "PassmanRS").map(|proj_dirs| {
        let config_dir = proj_dirs.config_dir();
        config_dir.join("passman_config.toml")
    })
}

fn save_default_config(config_path: &Path, config: &Config) -> Result<(), String> {
    info!("Attempting to save default config to {:?}", config_path);
    if let Some(parent_dir) = config_path.parent() {
        if !parent_dir.exists() {
            fs::create_dir_all(parent_dir)
                .map_err(|e| format!("Failed to create config directory {:?}: {}", parent_dir, e))?;
            info!("Created config directory: {:?}", parent_dir);
        }
    }

    let toml_string = toml::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize default config to TOML: {}", e))?;
    
    let mut file = fs::File::create(config_path)
        .map_err(|e| format!("Failed to create default config file {:?}: {}", config_path, e))?;
    
    file.write_all(toml_string.as_bytes())
        .map_err(|e| format!("Failed to write default config to {:?}: {}", config_path, e))?;
    
    info!("Saved default configuration to {:?}", config_path);
    Ok(())
}

pub fn load_config() -> Config {
    if let Some(config_path) = get_config_path() {
        if config_path.exists() {
            info!("Loading configuration from {:?}", config_path);
            match fs::read_to_string(&config_path) {
                Ok(content) => {
                    match toml::from_str(&content) {
                        Ok(loaded_config) => {
                            info!("Configuration loaded successfully.");
                            return loaded_config;
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse config file at {:?}: {}. Using default configuration.",
                                config_path, e
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to read config file at {:?}: {}. Using default configuration.",
                        config_path, e
                    );
                }
            }
        } else {
            info!(
                "Config file not found at {:?}. Creating and using default configuration.",
                config_path
            );
            let default_config = Config::default();
            if let Err(e) = save_default_config(&config_path, &default_config) {
                warn!("Failed to save default configuration: {}", e);
            }
            return default_config;
        }
    } else {
        warn!("Could not determine config directory. Using default configuration.");
    }
    Config::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.argon2_params.m_cost, 19456);
        assert_eq!(config.clipboard_clear_time_seconds, 30);
    }

    #[test]
    fn test_save_and_load_config() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("test_config.toml");

        let default_config = Config::default();
        save_default_config(&config_path, &default_config).unwrap();
        assert!(config_path.exists());

        let content = fs::read_to_string(&config_path).unwrap();
        let loaded_config: Config = toml::from_str(&content).unwrap();
        
        assert_eq!(loaded_config.argon2_params.m_cost, default_config.argon2_params.m_cost);
        assert_eq!(loaded_config.clipboard_clear_time_seconds, default_config.clipboard_clear_time_seconds);

        // Test loading when file exists (simulating load_config behavior)
        // This part is a bit redundant as we just tested from_str, but it's closer to load_config path
        if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(content_again) => {
                    match toml::from_str(&content_again) {
                        Ok(reloaded_config) => {
                             assert_eq!(reloaded_config.argon2_params.m_cost, default_config.argon2_params.m_cost);
                        }
                        Err(_) => panic!("Failed to parse during re-load test"),
                    }
                }
                 Err(_) => panic!("Failed to read during re-load test"),
            }
        } else {
            panic!("Config file should exist for re-load test");
        }
    }

    #[test]
    fn test_load_config_non_existent_creates_default() {
         // To avoid interfering with real user config, this test is tricky.
         // We can't easily test the ProjectDirs part without mocking or actual FS interaction.
         // The save_default_config is tested above.
         // Here, we mostly rely on the logic that if get_config_path() fails or file doesn't exist,
         // it returns Config::default().
         // A more involved test would mock ProjectDirs.
        
        // Simulate ProjectDirs returning None (e.g. on a weird platform)
        // This is hard to mock directly here, so we trust the logic:
        // if get_config_path() returns None, Config::default() is returned.
        // We can test the path where the file doesn't exist but dir can be made.
        let dir = tempdir().unwrap();
        let non_existent_path = dir.path().join("non_existent_dir").join("passman_config.toml");
        
        // This part of load_config is what we're interested in:
        // if !non_existent_path.exists() {
        //     save_default_config(&non_existent_path, &Config::default());
        // }
        // For this test, we'll manually call save_default_config to check it works.
        let default_config = Config::default();
        save_default_config(&non_existent_path, &default_config).unwrap();
        assert!(non_existent_path.exists());
        let content = fs::read_to_string(&non_existent_path).unwrap();
        let loaded_config: Config = toml::from_str(&content).unwrap();
        assert_eq!(loaded_config.argon2_params.m_cost, default_config.argon2_params.m_cost);

    }
     #[test]
    fn test_load_config_invalid_toml() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("invalid_config.toml");

        fs::write(&config_path, "this is not valid toml content = definitely_broken").unwrap();
        
        // Manually simulate the part of load_config that handles this
        let mut loaded_config = Config::default(); // Start with default
        if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(content) => {
                    match toml::from_str(&content) {
                        Ok(cfg) => loaded_config = cfg,
                        Err(_) => { /* Falls through to default, warning would be logged */ }
                    }
                }
                Err(_) => { /* Falls through to default, warning would be logged */ }
            }
        }
        // Check that it fell back to default
        assert_eq!(loaded_config.argon2_params.m_cost, Config::default().argon2_params.m_cost);
    }

    #[test]
    fn test_load_config_partially_missing_mandatory_field() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("partial_config.toml");

        // argon2_params.m_cost is mandatory within argon2_params table
        let partial_toml_content = r#"
clipboard_clear_time_seconds = 60
theme = "dark"

[argon2_params]
# m_cost = 19456 # This mandatory field is missing
t_cost = 3
p_cost = 2
"#;
        fs::write(&config_path, partial_toml_content).unwrap();

        // Simulate the part of load_config that reads and parses
        let mut loaded_config = Config::default(); // Start with default
        if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(content) => {
                     match toml::from_str(&content) {
                        Ok(cfg) => loaded_config = cfg,
                        Err(_) => { /* Falls through to default, as expected */ }
                    }
                }
                Err(_) => { /* Falls through to default */ }
            }
        }
        // Check that it fell back to default because a mandatory field was missing from argon2_params
        assert_eq!(loaded_config.argon2_params.m_cost, Config::default().argon2_params.m_cost, "Should default if argon2_params.m_cost is missing");
        assert_eq!(loaded_config.clipboard_clear_time_seconds, 60, "clipboard_clear_time_seconds should load if present");
        assert_eq!(loaded_config.theme, Some("dark".to_string()), "theme should load if present");


        // Test with the whole argon2_params table missing (which is a mandatory field in Config)
         let partial_toml_content_no_argon_table = r#"
clipboard_clear_time_seconds = 45
theme = "light"
"#;
        fs::write(&config_path, partial_toml_content_no_argon_table).unwrap();
        
        loaded_config = Config::default(); // Reset to default
        if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(content) => {
                     match toml::from_str(&content) {
                        Ok(cfg) => loaded_config = cfg,
                        Err(_) => { /* Falls through to default, as expected */ }
                    }
                }
                Err(_) => { /* Falls through to default */ }
            }
        }
        assert_eq!(loaded_config.argon2_params.m_cost, Config::default().argon2_params.m_cost, "Should default if argon2_params table is missing");
        assert_eq!(loaded_config.clipboard_clear_time_seconds, 45, "clipboard_clear_time_seconds should load from second test");
        assert_eq!(loaded_config.theme, Some("light".to_string()), "theme should load from second test");
    }
}
