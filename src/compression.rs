use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

pub struct CompressionEngine;

impl CompressionEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn compress<P: AsRef<Path>>(&self, source_path: P, output_path: P) -> Result<()> {
        // Check if 7z is available
        self.check_7zip_available()?;

        let source = source_path.as_ref();
        let output = output_path.as_ref();

        println!("Compressing {} -> {}", source.display(), output.display());

        let mut cmd = Command::new("7z");
        cmd.arg("a")           // Add to archive
           .arg("-t7z")        // Use 7z format
           .arg("-mx=9")       // Maximum compression level
           .arg("-mmt=on")     // Multi-threading on
           .arg(output)        // Output archive path
           .arg(source);       // Source path

        let output_result = cmd.output()
            .context("Failed to execute 7z command")?;

        if !output_result.status.success() {
            let stderr = String::from_utf8_lossy(&output_result.stderr);
            anyhow::bail!("7zip compression failed: {}", stderr);
        }

        println!("Compression completed: {}", output.display());
        Ok(())
    }

    pub fn decompress<P: AsRef<Path>>(&self, archive_path: P, output_dir: P) -> Result<()> {
        // Check if 7z is available
        self.check_7zip_available()?;

        let archive = archive_path.as_ref();
        let output = output_dir.as_ref();

        println!("Decompressing {} -> {}", archive.display(), output.display());

        // Create output directory if it doesn't exist
        std::fs::create_dir_all(output)
            .with_context(|| format!("Failed to create output directory: {}", output.display()))?;

        let mut cmd = Command::new("7z");
        cmd.arg("x")                              // Extract with full paths
           .arg(archive)                          // Archive path
           .arg(format!("-o{}", output.display())) // Output directory
           .arg("-y");                            // Yes to all prompts

        let output_result = cmd.output()
            .context("Failed to execute 7z extract command")?;

        if !output_result.status.success() {
            let stderr = String::from_utf8_lossy(&output_result.stderr);
            anyhow::bail!("7zip decompression failed: {}", stderr);
        }

        println!("Decompression completed to: {}", output.display());
        Ok(())
    }

    fn check_7zip_available(&self) -> Result<()> {
        let output = Command::new("7z")
            .arg("--help")
            .output();

        match output {
            Ok(result) if result.status.success() => Ok(()),
            Ok(_) => anyhow::bail!("7zip is installed but not working correctly"),
            Err(_) => anyhow::bail!(
                "7zip not found. Please install 7zip:\n\
                 - Ubuntu/Debian: sudo apt install p7zip-full\n\
                 - Fedora/RHEL: sudo dnf install p7zip p7zip-plugins\n\
                 - Arch: sudo pacman -S p7zip\n\
                 - macOS: brew install p7zip"
            ),
        }
    }

    pub fn is_7zip_available(&self) -> bool {
        self.check_7zip_available().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::{tempdir, NamedTempFile};
    use std::io::Write;

    #[test]
    fn test_7zip_availability() {
        let engine = CompressionEngine::new();
        // This test will pass if 7zip is installed
        // Comment out if 7zip is not available in test environment
        // assert!(engine.is_7zip_available());
    }

    #[test]
    fn test_compress_decompress_roundtrip() {
        let engine = CompressionEngine::new();
        
        // Skip test if 7zip is not available
        if !engine.is_7zip_available() {
            println!("Skipping compression test - 7zip not available");
            return;
        }

        // Create a temporary directory with test files
        let temp_dir = tempdir().unwrap();
        let source_dir = temp_dir.path().join("source");
        fs::create_dir_all(&source_dir).unwrap();

        // Create test files
        let test_file1 = source_dir.join("test1.txt");
        let test_file2 = source_dir.join("test2.txt");
        fs::write(&test_file1, "Hello, World! File 1").unwrap();
        fs::write(&test_file2, "Hello, World! File 2").unwrap();

        // Create temporary archive file
        let archive_file = temp_dir.path().join("test_archive.7z");
        
        // Compress
        engine.compress(&source_dir, &archive_file).unwrap();
        assert!(archive_file.exists());

        // Create extraction directory
        let extract_dir = temp_dir.path().join("extracted");
        
        // Decompress
        engine.decompress(&archive_file, &extract_dir).unwrap();
        
        // Verify extracted files
        let extracted_file1 = extract_dir.join("source").join("test1.txt");
        let extracted_file2 = extract_dir.join("source").join("test2.txt");
        
        assert!(extracted_file1.exists());
        assert!(extracted_file2.exists());
        
        assert_eq!(fs::read_to_string(&extracted_file1).unwrap(), "Hello, World! File 1");
        assert_eq!(fs::read_to_string(&extracted_file2).unwrap(), "Hello, World! File 2");
    }
}
