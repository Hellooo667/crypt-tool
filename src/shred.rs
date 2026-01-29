use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use zeroize::Zeroize;

pub struct SecureDelete;

impl SecureDelete {
    /// Securely delete a file by overwriting with zeros and removing
    pub fn shred_file(file_path: &Path, passes: u32, verbose: bool) -> Result<()> {
        if !file_path.exists() {
            return Ok(()); // File already gone
        }
        
        if verbose {
            println!("Securely deleting: {}", file_path.display());
            println!("   Using {} zero-overwrite passes", passes);
        }
        
        let file_size = std::fs::metadata(file_path)
            .with_context(|| format!("Failed to get file size: {}", file_path.display()))?
            .len();
        
        // Open file for writing
        let mut file = OpenOptions::new()
            .write(true)
            .open(file_path)
            .with_context(|| format!("Failed to open file for shredding: {}", file_path.display()))?;
        
        for pass in 1..=passes {
            if verbose {
                println!("   Pass {}/{}: Overwriting with zeros", pass, passes);
            }
            
            // Seek to beginning
            file.seek(SeekFrom::Start(0))
                .with_context(|| "Failed to seek to file beginning")?;
            
            // Overwrite with zeros using zeroize
            let mut bytes_written = 0u64;
            while bytes_written < file_size {
                let chunk_size = std::cmp::min(8192, file_size - bytes_written) as usize;
                let mut buffer = vec![0u8; chunk_size];
                // zeroize ensures the buffer is properly zeroed
                buffer.zeroize();
                
                file.write_all(&buffer)
                    .with_context(|| "Failed to write zeros during shredding")?;
                
                bytes_written += chunk_size as u64;
            }
            
            // Force write to disk
            file.sync_all()
                .with_context(|| "Failed to sync file during shredding")?;
        }
        
        drop(file); // Close file before deletion
        
        // Remove the file entry
        std::fs::remove_file(file_path)
            .with_context(|| format!("Failed to remove file: {}", file_path.display()))?;
        
        if verbose {
            println!("File securely deleted: {}", file_path.display());
        }
        
        Ok(())
    }
    
    /// Standard shred (3 passes) - the main method used by the application
    pub fn shred_standard(file_path: &Path, verbose: bool) -> Result<()> {
        Self::shred_file(file_path, 3, verbose)
    }
}
