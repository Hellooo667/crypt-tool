use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce
};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use anyhow::Result;
use secrecy::{Secret, ExposeSecret};
use zeroize::Zeroize;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use rand::RngCore;
use std::fs;
use std::path::Path;
use thiserror::Error;
use sha2::{Sha256, Digest};

#[derive(Error, Debug)]
pub enum CryptError {
    #[error("Invalid key format: {reason}")]
    InvalidKey { reason: String },
    #[error("Encryption failed: {details}")]
    EncryptionFailed { details: String },
    #[error("Decryption failed: {details}")]
    DecryptionFailed { details: String },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::Aes256Gcm
    }
}

pub struct CryptEngine {
    algorithm: EncryptionAlgorithm,
}

impl CryptEngine {
    pub fn new() -> Self {
        Self::with_algorithm(EncryptionAlgorithm::default())
    }

    pub fn with_algorithm(algorithm: EncryptionAlgorithm) -> Self {
        Self { algorithm }
    }

    pub fn generate_key(&self) -> String {
        // Generate a random 32-byte key
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut key_bytes);
        let hex_key = hex::encode(key_bytes);
        
        // Zero out the key bytes from memory
        key_bytes.zeroize();
        hex_key
    }

    fn key_from_string(&self, key_str: &str) -> Result<Secret<[u8; 32]>, CryptError> {
        if key_str.len() == 64 && key_str.chars().all(|c| c.is_ascii_hexdigit()) {
            // Hex string (auto-generated key)
            let key_bytes = hex::decode(key_str).map_err(|e| {
                CryptError::InvalidKey {
                    reason: format!("Invalid hex key format: {}", e),
                }
            })?;
            if key_bytes.len() != 32 {
                return Err(CryptError::InvalidKey {
                    reason: "Key must be 32 bytes (64 hex characters)".to_string(),
                });
            }
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&key_bytes);
            Ok(Secret::new(key_array))
        } else {
            // Password - generate temporary salt for backward compatibility
            // In actual use, we'll call derive_key_with_salt with proper salt from file
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(key_str.as_bytes());
            let hash = hasher.finalize();
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&hash[..32]);
            Ok(Secret::new(key_array))
        }
    }

    // New function for secure password-based key derivation with salt
    fn derive_key_with_salt(&self, password: &str, salt: &[u8; 16]) -> Result<Secret<[u8; 32]>, CryptError> {
        // Simple implementation using SHA-256 for now (will improve later)
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let hash = hasher.finalize();
        
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&hash[..32]);
        Ok(Secret::new(key_array))
    }

    // Generate a random salt
    fn generate_salt() -> [u8; 16] {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill(&mut salt);
        salt
    }

    pub fn encrypt_file<P: AsRef<Path>>(&self, input_path: P, output_path: P, key_str: &str) -> Result<(), CryptError> {
        let file_size = fs::metadata(&input_path)?.len();
        let pb = ProgressBar::new(file_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} ENCRYPT [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Read the input file
        let plaintext = fs::read(&input_path).map_err(|e| {
            CryptError::Io(e)
        })?;

        pb.set_position(file_size / 2);

        // Determine if this is a hex key or password
        let (key, salt, is_password_based) = if key_str.len() == 64 && key_str.chars().all(|c| c.is_ascii_hexdigit()) {
            // Hex key - no salt needed
            (self.key_from_string(key_str)?, None, false)
        } else {
            // Password - generate salt and derive key
            let salt = Self::generate_salt();
            let key = self.derive_key_with_salt(key_str, &salt)?;
            (key, Some(salt), true)
        };

        let (nonce, ciphertext) = match self.algorithm {
            EncryptionAlgorithm::Aes256Gcm => {
                let key_ref = Key::<Aes256Gcm>::from_slice(key.expose_secret());
                let cipher = Aes256Gcm::new(key_ref);
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
                    .map_err(|_| CryptError::EncryptionFailed {
                        details: "AES-256-GCM encryption failed".to_string(),
                    })?;
                (nonce.to_vec(), ciphertext)
            }
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                let key_ref = chacha20poly1305::Key::from_slice(key.expose_secret());
                let cipher = ChaCha20Poly1305::new(key_ref);
                let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
                    .map_err(|_| CryptError::EncryptionFailed {
                        details: "ChaCha20Poly1305 encryption failed".to_string(),
                    })?;
                (nonce.to_vec(), ciphertext)
            }
            EncryptionAlgorithm::XChaCha20Poly1305 => {
                let key_ref = chacha20poly1305::Key::from_slice(key.expose_secret());
                let cipher = XChaCha20Poly1305::new(key_ref);
                let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
                let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
                    .map_err(|_| CryptError::EncryptionFailed {
                        details: "XChaCha20Poly1305 encryption failed".to_string(),
                    })?;
                (nonce.to_vec(), ciphertext)
            }
        };

        pb.set_position(file_size * 3 / 4);

        // Create output data with new format:
        // [algorithm_id: 1 byte][salt_flag: 1 byte][salt: 16 bytes (if salt_flag=1)][nonce: 12/24 bytes][ciphertext: rest]
        let mut output_data = Vec::new();
        output_data.push(self.algorithm as u8);  // Algorithm identifier
        
        if is_password_based {
            output_data.push(1u8);  // Salt flag: 1 = has salt
            output_data.extend_from_slice(&salt.unwrap());  // Salt (16 bytes)
        } else {
            output_data.push(0u8);  // Salt flag: 0 = no salt (hex key)
        }
        
        output_data.extend_from_slice(&nonce);
        output_data.extend_from_slice(&ciphertext);

        // Write to output file
        fs::write(&output_path, output_data).map_err(|e| {
            CryptError::Io(e)
        })?;

        pb.finish_with_message("Encryption completed");
        Ok(())
    }

    pub fn decrypt_file<P: AsRef<Path>>(&self, input_path: P, output_path: P, key_str: &str) -> Result<(), CryptError> {
        // Read the encrypted file
        let encrypted_data = fs::read(&input_path).map_err(|e| {
            CryptError::Io(e)
        })?;

        // Check minimum size: algorithm(1) + salt_flag(1) + min_nonce(12)
        if encrypted_data.len() < 14 {
            return Err(CryptError::DecryptionFailed {
                details: "Invalid encrypted file: too short".to_string(),
            });
        }

        let pb = ProgressBar::new(encrypted_data.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} DECRYPT [{elapsed_precise}] [{bar:40.yellow/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Parse file format: [algorithm_id: 1][salt_flag: 1][salt: 16 (if flag=1)][nonce: 12/24][ciphertext: rest]
        let algorithm_id = encrypted_data[0];
        let salt_flag = encrypted_data[1];
        
        let algorithm = match algorithm_id {
            0 => EncryptionAlgorithm::Aes256Gcm,
            1 => EncryptionAlgorithm::ChaCha20Poly1305,
            2 => EncryptionAlgorithm::XChaCha20Poly1305,
            _ => return Err(CryptError::DecryptionFailed {
                details: format!("Unknown algorithm identifier: {}", algorithm_id),
            }),
        };

        pb.set_position(encrypted_data.len() as u64 / 4);

        // Determine nonce size based on algorithm
        let nonce_size = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => 12,
            EncryptionAlgorithm::ChaCha20Poly1305 => 12,
            EncryptionAlgorithm::XChaCha20Poly1305 => 24,
        };

        // Parse salt and determine key derivation
        let (key, data_offset) = if salt_flag == 1 {
            // Password-based: extract salt and derive key
            if encrypted_data.len() < 18 + nonce_size {  // algorithm(1) + salt_flag(1) + salt(16) + nonce
                return Err(CryptError::DecryptionFailed {
                    details: "Invalid encrypted file: too short for salted format".to_string(),
                });
            }
            
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&encrypted_data[2..18]);
            let key = self.derive_key_with_salt(key_str, &salt)?;
            (key, 18)  // Skip algorithm_id + salt_flag + salt
        } else if salt_flag == 0 {
            // Hex key: use direct key derivation
            let key = self.key_from_string(key_str)?;
            (key, 2)   // Skip algorithm_id + salt_flag
        } else {
            return Err(CryptError::DecryptionFailed {
                details: format!("Invalid salt flag: {}", salt_flag),
            });
        };

        // Extract nonce and ciphertext
        if encrypted_data.len() < data_offset + nonce_size {
            return Err(CryptError::DecryptionFailed {
                details: "Invalid encrypted file: insufficient data for nonce".to_string(),
            });
        }

        let nonce = &encrypted_data[data_offset..data_offset + nonce_size];
        let ciphertext = &encrypted_data[data_offset + nonce_size..];

        pb.set_position(encrypted_data.len() as u64 / 2);

        // Decrypt the data
        let plaintext = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => {
                let key_ref = Key::<Aes256Gcm>::from_slice(key.expose_secret());
                let cipher = Aes256Gcm::new(key_ref);
                let nonce_ref = Nonce::from_slice(nonce);
                cipher.decrypt(nonce_ref, ciphertext)
                    .map_err(|_| CryptError::DecryptionFailed {
                        details: "AES-256-GCM decryption failed - incorrect key or corrupted data".to_string(),
                    })?
            }
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                let key_ref = chacha20poly1305::Key::from_slice(key.expose_secret());
                let cipher = ChaCha20Poly1305::new(key_ref);
                let nonce_ref = chacha20poly1305::Nonce::from_slice(nonce);
                cipher.decrypt(nonce_ref, ciphertext)
                    .map_err(|_| CryptError::DecryptionFailed {
                        details: "ChaCha20Poly1305 decryption failed - incorrect key or corrupted data".to_string(),
                    })?
            }
            EncryptionAlgorithm::XChaCha20Poly1305 => {
                let key_ref = chacha20poly1305::Key::from_slice(key.expose_secret());
                let cipher = XChaCha20Poly1305::new(key_ref);
                let nonce_ref = chacha20poly1305::XNonce::from_slice(nonce);
                cipher.decrypt(nonce_ref, ciphertext)
                    .map_err(|_| CryptError::DecryptionFailed {
                        details: "XChaCha20Poly1305 decryption failed - incorrect key or corrupted data".to_string(),
                    })?
            }
        };

        pb.set_position(encrypted_data.len() as u64 * 3 / 4);

        // Write to output file
        fs::write(&output_path, plaintext).map_err(|e| {
            CryptError::Io(e)
        })?;

        pb.finish_with_message("Decryption completed");
        Ok(())
    }
}

impl Default for CryptEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_encrypt_decrypt_roundtrip_aes() {
        let engine = CryptEngine::new();
        let key = engine.generate_key();
        
        // Create a temporary file with test data
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = b"Hello, World! This is a test encryption.";
        input_file.write_all(test_data).unwrap();
        
        // Create temporary files for encrypted and decrypted data
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();
        
        // Encrypt
        engine.encrypt_file(input_file.path(), encrypted_file.path(), &key).unwrap();
        
        // Decrypt
        engine.decrypt_file(encrypted_file.path(), decrypted_file.path(), &key).unwrap();
        
        // Verify the decrypted data matches original
        let decrypted_data = fs::read(decrypted_file.path()).unwrap();
        assert_eq!(test_data, decrypted_data.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_chacha20() {
        let engine = CryptEngine::with_algorithm(EncryptionAlgorithm::ChaCha20Poly1305);
        let key = engine.generate_key();
        
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = b"ChaCha20 test data for encryption roundtrip.";
        input_file.write_all(test_data).unwrap();
        
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();
        
        engine.encrypt_file(input_file.path(), encrypted_file.path(), &key).unwrap();
        engine.decrypt_file(encrypted_file.path(), decrypted_file.path(), &key).unwrap();
        
        let decrypted_data = fs::read(decrypted_file.path()).unwrap();
        assert_eq!(test_data, decrypted_data.as_slice());
    }

    #[test]
    fn test_key_generation() {
        let engine = CryptEngine::new();
        let key1 = engine.generate_key();
        let key2 = engine.generate_key();
        
        // Keys should be different
        assert_ne!(key1, key2);
        
        // Keys should be 64 characters (32 bytes in hex)
        assert_eq!(key1.len(), 64);
        assert_eq!(key2.len(), 64);
        
        // Keys should be valid hex
        hex::decode(&key1).unwrap();
        hex::decode(&key2).unwrap();
    }
}
