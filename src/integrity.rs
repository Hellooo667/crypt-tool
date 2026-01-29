use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read};
use std::path::Path;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

pub struct IntegrityVerifier;

impl IntegrityVerifier {
    /// Calculate HMAC-SHA256 of a file with a key
    pub fn calculate_hmac(file_path: &Path, key: &[u8]) -> Result<String> {
        let mut file = File::open(file_path)
            .with_context(|| format!("Failed to open file for hashing: {}", file_path.display()))?;
        
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|_| anyhow::anyhow!("Invalid HMAC key length"))?;
        
        let mut buffer = [0; 8192];
        
        loop {
            let bytes_read = file.read(&mut buffer)
                .with_context(|| format!("Failed to read file: {}", file_path.display()))?;
            
            if bytes_read == 0 {
                break;
            }
            
            mac.update(&buffer[..bytes_read]);
        }
        
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }
    
    /// Calculate simple SHA-256 hash (for backward compatibility)
    pub fn calculate_hash(file_path: &Path) -> Result<String> {
        let mut file = File::open(file_path)
            .with_context(|| format!("Failed to open file for hashing: {}", file_path.display()))?;
        
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];
        
        loop {
            let bytes_read = file.read(&mut buffer)
                .with_context(|| format!("Failed to read file: {}", file_path.display()))?;
            
            if bytes_read == 0 {
                break;
            }
            
            hasher.update(&buffer[..bytes_read]);
        }
        
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    /// Add integrity metadata to encrypted file with HMAC
    pub fn add_metadata_hmac(encrypted_file: &Path, original_hmac: &str, algorithm: &str, key: &[u8]) -> Result<()> {
        // Create a separate metadata file instead of appending to binary
        let metadata_file = encrypted_file.with_extension("meta");
        let metadata = format!("INTEGRITY:{}:{}:HMAC-SHA256", algorithm, original_hmac);
        
        std::fs::write(&metadata_file, metadata)
            .with_context(|| format!("Failed to write integrity metadata file: {}", metadata_file.display()))?;
        
        Ok(())
    }
    
    /// Add integrity metadata to encrypted file (legacy SHA-256)
    pub fn add_metadata(encrypted_file: &Path, original_hash: &str, algorithm: &str) -> Result<()> {
        // Create a separate metadata file instead of appending to binary
        let metadata_file = encrypted_file.with_extension("meta");
        let metadata = format!("INTEGRITY:{}:{}:SHA256", algorithm, original_hash);
        
        std::fs::write(&metadata_file, metadata)
            .with_context(|| format!("Failed to write integrity metadata file: {}", metadata_file.display()))?;
        
        Ok(())
    }
    
    /// Extract and verify integrity metadata with HMAC
    pub fn verify_integrity_hmac(encrypted_file: &Path, decrypted_file: &Path, key: &[u8]) -> Result<bool> {
        let metadata = Self::extract_metadata(encrypted_file)?;
        
        if let Some((algorithm, expected_hmac, hash_type)) = metadata {
            let actual_value = match hash_type.as_str() {
                "HMAC-SHA256" => Self::calculate_hmac(decrypted_file, key)?,
                "SHA256" => Self::calculate_hash(decrypted_file)?,
                _ => {
                    println!("Warning: unknown hash type: {}", hash_type);
                    return Ok(true); // Don't fail on unknown types
                }
            };
            
            println!("Integrity verification:");
            println!("   Algorithm: {}", algorithm);
            println!("   Hash Type: {}", hash_type);
            println!("   Expected:  {}", expected_hmac);
            println!("   Actual:    {}", actual_value);
            
            let is_valid = expected_hmac == actual_value;
            if is_valid {
                println!("File integrity verified successfully.");
            } else {
                println!("File integrity verification FAILED.");
            }
            
            Ok(is_valid)
        } else {
            println!("Warning: no integrity metadata found in encrypted file");
            Ok(true) // Don't fail if no metadata exists (backward compatibility)
        }
    }
    
    /// Extract and verify integrity metadata (legacy)
    pub fn verify_integrity(encrypted_file: &Path, decrypted_file: &Path) -> Result<bool> {
        let metadata = Self::extract_metadata(encrypted_file)?;
        
        if let Some((algorithm, expected_hash, _)) = metadata {
            let actual_hash = Self::calculate_hash(decrypted_file)?;
            
            println!("Integrity verification:");
            println!("   Algorithm: {}", algorithm);
            println!("   Expected:  {}", expected_hash);
            println!("   Actual:    {}", actual_hash);
            
            let is_valid = expected_hash == actual_hash;
            if is_valid {
                println!("File integrity verified successfully.");
            } else {
                println!("File integrity verification FAILED.");
            }
            
            Ok(is_valid)
        } else {
            println!("Warning: no integrity metadata found in encrypted file");
            Ok(true) // Don't fail if no metadata exists (backward compatibility)
        }
    }
    
    /// Extract integrity metadata from encrypted file
    fn extract_metadata(encrypted_file: &Path) -> Result<Option<(String, String, String)>> {
        // Look for a separate metadata file
        let metadata_file = encrypted_file.with_extension("meta");
        
        if !metadata_file.exists() {
            return Ok(None);
        }
        
        let content = std::fs::read_to_string(&metadata_file)
            .with_context(|| format!("Failed to read metadata file: {}", metadata_file.display()))?;
        
        // Parse integrity metadata
        if content.starts_with("INTEGRITY:") {
            let parts: Vec<&str> = content.split(':').collect();
            if parts.len() >= 4 {
                let hash_type = if parts.len() >= 4 {
                    parts[3].to_string()
                } else {
                    "SHA256".to_string()
                };
                return Ok(Some((parts[1].to_string(), parts[2].to_string(), hash_type)));
            }
        }
        
        Ok(None)
    }
    
    /// Pre-encryption integrity check with HMAC
    pub fn pre_encrypt_check_hmac(file_path: &Path, key: &[u8], verbose: bool) -> Result<String> {
        if verbose {
            println!("Calculating file integrity HMAC...");
        }
        
        let hmac = Self::calculate_hmac(file_path, key)?;
        
        if verbose {
            println!("   Original file HMAC: {}", hmac);
        }
        
        Ok(hmac)
    }
    
    /// Pre-encryption integrity check (legacy)
    pub fn pre_encrypt_check(file_path: &Path, verbose: bool) -> Result<String> {
        if verbose {
            println!("Calculating file integrity hash...");
        }
        
        let hash = Self::calculate_hash(file_path)?;
        
        if verbose {
            println!("   Original file hash: {}", hash);
        }
        
        Ok(hash)
    }
    
    /// Post-decryption integrity check with HMAC
    pub fn post_decrypt_check_hmac(encrypted_file: &Path, decrypted_file: &Path, key: &[u8], verbose: bool) -> Result<()> {
        if verbose {
            println!("Verifying file integrity with HMAC...");
        }
        
        let is_valid = Self::verify_integrity_hmac(encrypted_file, decrypted_file, key)?;
        
        if !is_valid {
            anyhow::bail!("File integrity verification failed! The decrypted file may be corrupted.");
        }
        
        Ok(())
    }
    
    /// Post-decryption integrity check (legacy)
    pub fn post_decrypt_check(encrypted_file: &Path, decrypted_file: &Path, verbose: bool) -> Result<()> {
        if verbose {
            println!("Verifying file integrity...");
        }
        
        let is_valid = Self::verify_integrity(encrypted_file, decrypted_file)?;
        
        if !is_valid {
            anyhow::bail!("File integrity verification failed! The decrypted file may be corrupted.");
        }
        
        Ok(())
    }
}
