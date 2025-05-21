// src/generator.rs
use rand::seq::SliceRandom; // For choose_multiple
use rand::thread_rng; // For a cryptographically secure RNG

const LOWERCASE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBER_CHARS: &[u8] = b"0123456789";
const SYMBOL_CHARS: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

#[derive(Debug, Clone)]
pub struct PasswordCriteria {
    pub length: usize,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_numbers: bool,
    pub use_symbols: bool,
}

impl Default for PasswordCriteria {
    fn default() -> Self {
        PasswordCriteria {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
        }
    }
}

pub fn generate_password(criteria: &PasswordCriteria) -> Result<String, String> {
    if criteria.length == 0 {
        return Err("Password length cannot be zero.".to_string());
    }

    let mut charset = Vec::new();
    if criteria.use_lowercase {
        charset.extend_from_slice(LOWERCASE_CHARS);
    }
    if criteria.use_uppercase {
        charset.extend_from_slice(UPPERCASE_CHARS);
    }
    if criteria.use_numbers {
        charset.extend_from_slice(NUMBER_CHARS);
    }
    if criteria.use_symbols {
        charset.extend_from_slice(SYMBOL_CHARS);
    }

    if charset.is_empty() {
        return Err("At least one character set (lowercase, uppercase, numbers, symbols) must be selected.".to_string());
    }

    let mut rng = thread_rng();
    let password_bytes: Vec<u8> = charset
        .choose_multiple(&mut rng, criteria.length)
        .cloned()
        .collect();

    // Ensure the password has at least one character from each selected category
    // This is a more robust way to guarantee criteria are met than simple random selection from combined set.
    // For simplicity in this step, we'll stick to the simpler method above.
    // A full implementation would involve picking one from each required set, then filling the rest.
    // For now, if the length is very small and many categories are chosen, it might not include all.

    String::from_utf8(password_bytes)
        .map_err(|e| format!("Failed to convert password bytes to String: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_default_criteria() {
        let criteria = PasswordCriteria::default();
        let password = generate_password(&criteria).unwrap();
        assert_eq!(password.len(), criteria.length);
        println!("Generated password (default): {}", password);
    }

    #[test]
    fn test_generate_password_custom_length() {
        let criteria = PasswordCriteria {
            length: 32,
            ..Default::default()
        };
        let password = generate_password(&criteria).unwrap();
        assert_eq!(password.len(), 32);
    }

    #[test]
    fn test_generate_password_only_lowercase() {
        let criteria = PasswordCriteria {
            length: 10,
            use_uppercase: false,
            use_lowercase: true,
            use_numbers: false,
            use_symbols: false,
        };
        let password = generate_password(&criteria).unwrap();
        assert_eq!(password.len(), 10);
        assert!(password.chars().all(|c| c.is_ascii_lowercase()));
        println!("Generated password (lowercase only): {}", password);
    }

    #[test]
    fn test_generate_password_only_numbers() {
        let criteria = PasswordCriteria {
            length: 8,
            use_uppercase: false,
            use_lowercase: false,
            use_numbers: true,
            use_symbols: false,
        };
        let password = generate_password(&criteria).unwrap();
        assert_eq!(password.len(), 8);
        assert!(password.chars().all(|c| c.is_ascii_digit()));
        println!("Generated password (numbers only): {}", password);
    }
    
    #[test]
    fn test_generate_password_no_charset_selected() {
        let criteria = PasswordCriteria {
            length: 10,
            use_uppercase: false,
            use_lowercase: false,
            use_numbers: false,
            use_symbols: false,
        };
        assert!(generate_password(&criteria).is_err());
    }

    #[test]
    fn test_generate_password_zero_length() {
        let criteria = PasswordCriteria {
            length: 0,
            ..Default::default()
        };
        assert!(generate_password(&criteria).is_err());
    }

    #[test]
    fn test_all_criteria_true() {
        let criteria = PasswordCriteria { length: 20, use_uppercase: true, use_lowercase: true, use_numbers: true, use_symbols: true };
        let password = generate_password(&criteria).unwrap();
        assert_eq!(password.len(), 20);
        // Check if it *could* contain all types (not guaranteed by current simple generation)
        assert!(password.chars().any(|c| c.is_ascii_uppercase()) || !criteria.use_uppercase || password.is_empty());
        assert!(password.chars().any(|c| c.is_ascii_lowercase()) || !criteria.use_lowercase || password.is_empty());
        assert!(password.chars().any(|c| c.is_ascii_digit())    || !criteria.use_numbers    || password.is_empty());
        assert!(password.chars().any(|c| SYMBOL_CHARS.contains(&(c as u8))) || !criteria.use_symbols || password.is_empty());
        println!("Generated password (all criteria): {}", password);
    }

    #[test]
    fn test_generate_password_randomness() {
        let criteria = PasswordCriteria {
            length: 20,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
        };
        let password_1 = generate_password(&criteria).unwrap();
        let password_2 = generate_password(&criteria).unwrap();
        assert_ne!(password_1, password_2, "Generated passwords with the same criteria should generally be different.");
        println!("Generated passwords for randomness test: {} and {}", password_1, password_2);
    }
}
