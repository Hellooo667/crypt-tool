use anyhow::{Context, Result};
use clap::{Arg, ArgMatches, Command};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process;

mod crypto;
mod compression;
mod batch;
mod integrity;
mod shred;

use crate::crypto::{CryptEngine, EncryptionAlgorithm};
use crate::compression::CompressionEngine;
use crate::batch::BatchProcessor;
use crate::integrity::IntegrityVerifier;
use crate::shred::SecureDelete;

// Function to save generated key to file
fn save_key_to_file(key: &str, filepath: &str) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(filepath)
        .with_context(|| format!("Failed to create key file: {}", filepath))?;
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    writeln!(file, "# Encryption Key Generated on Unix timestamp: {}", timestamp)?;
    writeln!(file, "# Keep this file secure and do not share it")?;
    writeln!(file, "{}", key)?;
    
    // Set restrictive permissions (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(filepath, permissions)
            .with_context(|| format!("Failed to set permissions on key file: {}", filepath))?;
    }
    
    Ok(())
}

#[derive(Debug)]
struct Config {
    source_path: PathBuf,
    output_path: Option<PathBuf>,
    key: Option<String>,
    compress: bool,
    decrypt: bool,
    algorithm: EncryptionAlgorithm,
    verbose: bool,
    batch_patterns: Option<Vec<String>>,
    exclude_patterns: Option<Vec<String>>,
    verify_integrity: bool,
    shred_original: bool,
    check_integrity: bool,
    save_key_file: Option<String>,
}

impl Config {
    fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let source_path = if let Some(file_path) = matches.get_one::<String>("file") {
            PathBuf::from(file_path)
        } else if let Some(dir_path) = matches.get_one::<String>("directory") {
            PathBuf::from(dir_path)
        } else if let Some(decrypt_path) = matches.get_one::<String>("decrypt") {
            PathBuf::from(decrypt_path)
        } else if matches.contains_id("batch") {
            // For batch operations, use current directory as base
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        } else {
            anyhow::bail!("No source path specified");
        };

        let output_path = matches.get_one::<String>("output").map(PathBuf::from);
        let key = matches.get_one::<String>("key").cloned();
        
        let compress = if matches.get_flag("no_compress") {
            false
        } else {
            matches.get_flag("compress") || !matches.contains_id("decrypt")
        };

        let decrypt = matches.contains_id("decrypt");
        
        // Validate that we have a proper input source
        if !decrypt && !matches.contains_id("file") && !matches.contains_id("directory") && !matches.contains_id("batch") {
            anyhow::bail!("No source specified. Use --file, --dir, --decrypt, or --batch");
        }
        
        if decrypt && !matches.contains_id("batch") && !matches.contains_id("decrypt") {
            anyhow::bail!("When using --decrypt without --batch, you must specify the encrypted file");
        }
        
        let algorithm = match matches.get_one::<String>("algorithm") {
            Some(algo) => match algo.as_str() {
                "aes256gcm" | "aes" => EncryptionAlgorithm::Aes256Gcm,
                "chacha20poly1305" | "chacha20" => EncryptionAlgorithm::ChaCha20Poly1305,
                "xchacha20poly1305" | "xchacha20" => EncryptionAlgorithm::XChaCha20Poly1305,
                _ => {
                    anyhow::bail!("Unsupported algorithm: {}. Use: aes256gcm, chacha20poly1305, xchacha20poly1305", algo);
                }
            },
            None => EncryptionAlgorithm::Aes256Gcm,
        };

        let verbose = matches.get_flag("verbose");
        
        // New features
        let batch_patterns = matches.get_many::<String>("batch")
            .map(|patterns| patterns.cloned().collect::<Vec<_>>());
        let exclude_patterns = matches.get_many::<String>("exclude")
            .map(|patterns| patterns.cloned().collect::<Vec<_>>());
        let verify_integrity = !matches.get_flag("no_verify"); // Default to true, disable with --no-verify
        let shred_original = !matches.get_flag("no_shred"); // Default to true, disable with --no-shred
        let check_integrity = matches.get_flag("check");
        let save_key_file = matches.get_one::<String>("save_key").cloned();

        Ok(Config {
            source_path,
            output_path,
            key,
            compress,
            decrypt,
            algorithm,
            verbose,
            batch_patterns,
            exclude_patterns,
            verify_integrity,
            shred_original,
            check_integrity,
            save_key_file,
        })
    }
}

fn build_cli() -> Command {
    Command::new("encrypt")
        .about("File Encryption Tool")
        .version("2.0.0")
        .author("Secure Tools Developer")
        .arg_required_else_help(true)
        .arg(
            Arg::new("file")
                .short('u')
                .long("file")
                .value_name("FILE_PATH")
                .help("Path to file to encrypt")
                .conflicts_with_all(&["directory", "decrypt"])
        )
        .arg(
            Arg::new("directory")
                .short('d')
                .short_alias('l')
                .long("dir")
                .value_name("DIR_PATH")
                .help("Path to directory to encrypt")
                .conflicts_with_all(&["file", "decrypt"])
        )
        .arg(
            Arg::new("decrypt")
                .long("decrypt")
                .value_name("ENCRYPTED_FILE")
                .help("Path to encrypted file to decrypt (or use as flag with --batch for batch decryption)")
                .conflicts_with_all(&["file", "directory"])
                .num_args(0..=1)
        )
        .arg(
            Arg::new("algorithm")
                .short('a')
                .long("algorithm")
                .value_name("ALGORITHM")
                .help("Encryption algorithm to use")
                .value_parser(["aes256gcm", "aes", "chacha20poly1305", "chacha20", "xchacha20poly1305", "xchacha20"])
                .default_value("aes256gcm")
        )
        .arg(
            Arg::new("compress")
                .short('c')
                .long("compress")
                .action(clap::ArgAction::SetTrue)
                .help("Enable compression (default for encryption)")
                .conflicts_with("no_compress")
        )
        .arg(
            Arg::new("no_compress")
                .short('n')
                .long("no-compress")
                .action(clap::ArgAction::SetTrue)
                .help("Disable compression (faster for pre-compressed files)")
                .conflicts_with("compress")
        )
        .arg(
            Arg::new("key")
                .long("key")
                .value_name("ENCRYPTION_KEY")
                .help("Encryption key (hex or password - auto-generated if not provided)")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("OUTPUT_PATH")
                .help("Output path for encrypted/decrypted file")
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
                .help("Enable verbose output")
        )
        .arg(
            Arg::new("batch")
                .short('b')
                .long("batch")
                .value_name("PATTERNS")
                .action(clap::ArgAction::Append)
                .help("Batch encrypt/decrypt files matching patterns (e.g., \"*.jpg,*.png\" or \"*.7z.enc\")")
                .conflicts_with_all(&["file", "directory"])
        )
        .arg(
            Arg::new("exclude")
                .short('e')
                .long("exclude")
                .value_name("PATTERNS")
                .action(clap::ArgAction::Append)
                .help("Exclude files matching patterns (e.g., \"*.tmp,*.log\")")
                .requires("batch")
        )
        .arg(
            Arg::new("no_verify")
                .long("no-verify")
                .action(clap::ArgAction::SetTrue)
                .help("Disable integrity verification (HMAC-SHA256 checksum is enabled by default)")
        )
        .arg(
            Arg::new("no_shred")
                .long("no-shred")
                .action(clap::ArgAction::SetTrue)
                .help("Disable secure deletion of original files (shredding is enabled by default for both encrypt and decrypt)")
        )
        .arg(
            Arg::new("check")
                .long("check")
                .action(clap::ArgAction::SetTrue)
                .help("Verify file integrity (use with --decrypt)")
                .requires("decrypt")
        )
        .arg(
            Arg::new("save_key")
                .long("save-key")
                .value_name("KEY_FILE")
                .help("Save generated key to specified file")
                .conflicts_with_all(&["decrypt", "key"])
        )
        .after_help("ALGORITHMS:
    - aes256gcm, aes        : AES-256-GCM (most compatible)
    - chacha20poly1305     : ChaCha20-Poly1305 (fast)  
    - xchacha20poly1305    : XChaCha20-Poly1305 (large nonce)

🛡️  SECURITY (enabled by default):
    - Integrity verification (HMAC-SHA256)
    - Secure deletion of original files
")
}

fn main() {
    let matches = build_cli().get_matches();
    
    let config = match Config::from_matches(&matches) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("❌ Configuration error: {}", e);
            process::exit(1);
        }
    };

    let result = if config.decrypt && config.batch_patterns.is_some() {
        run_batch_decrypt(&config)
    } else if config.decrypt {
        run_decrypt(&config)
    } else if config.batch_patterns.is_some() {
        run_batch_encrypt(&config)
    } else {
        run_encrypt(&config)
    };

    match result {
        Ok(_) => {
            println!("🎉 Operation completed successfully!");
        }
        Err(e) => {
            eprintln!("❌ Operation failed: {}", e);
            
            // Print additional context for common errors
            if let Some(crypto_error) = e.downcast_ref::<crypto::CryptError>() {
                match crypto_error {
                    crypto::CryptError::InvalidKey { .. } => {
                        eprintln!("💡 Tip: Use a hex key (64 chars) or any password");
                    }
                    crypto::CryptError::DecryptionFailed { .. } => {
                        eprintln!("💡 Tip: Check your key and ensure the file isn't corrupted");
                    }
                    _ => {}
                }
            }
            
            process::exit(1);
        }
    }
}

fn run_batch_encrypt(config: &Config) -> Result<()> {
    let patterns = config.batch_patterns.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Batch patterns not provided"))?;
    
    let batch_processor = BatchProcessor::new(
        patterns.clone(), 
        config.exclude_patterns.clone()
    );
    
    // Find all files matching the patterns
    let files = batch_processor.find_files(Some(&config.source_path))?;
    
    if files.is_empty() {
        println!("⚠️  No files found matching the specified patterns");
        return Ok(());
    }
    
    batch_processor.print_summary(&files);
    
    // Generate or use provided key (same for all files)
    let crypto_engine = CryptEngine::with_algorithm(config.algorithm);
    let key = match &config.key {
        Some(k) => {
            if config.verbose {
                println!("🔑 Using provided key for all files");
            }
            k.clone()
        }
        None => {
            let generated_key = crypto_engine.generate_key();
            println!("\n🔑 GENERATED ENCRYPTION KEY (batch operation):");
            println!("   {}", generated_key);
            println!("⚠️  IMPORTANT: Save this key securely - you'll need it for decryption!");
            println!("   Copy this key to a safe location before proceeding.");
            
            // Save key to file if specified
            if let Some(key_file) = &config.save_key_file {
                match save_key_to_file(&generated_key, key_file) {
                    Ok(()) => println!("💾 Key saved to file: {}", key_file),
                    Err(e) => eprintln!("⚠️  Warning: Failed to save key to file: {}", e),
                }
            }
            
            if !config.verbose || std::env::var("ENCRYPT_NO_PAUSE").is_err() {
                println!("   Press Enter to continue...");
                let _ = std::io::Read::read(&mut std::io::stdin(), &mut [0u8; 1]);
            }
            println!();
            generated_key
        }
    };
    
    // Process each file
    let mut successful = 0;
    let mut failed = 0;
    
    for (index, file_path) in files.iter().enumerate() {
        println!("\n📄 Processing file {}/{}: {}", index + 1, files.len(), file_path.display());
        
        let file_config = Config {
            source_path: file_path.clone(),
            output_path: config.output_path.clone(),
            key: Some(key.clone()),
            compress: config.compress,
            decrypt: false,
            algorithm: config.algorithm,
            verbose: config.verbose,
            batch_patterns: None,
            exclude_patterns: None,
            verify_integrity: config.verify_integrity,
            shred_original: config.shred_original,
            check_integrity: false,
            save_key_file: None, // Not needed during batch processing
        };
        
        match run_single_encrypt(&file_config) {
            Ok(_) => {
                successful += 1;
                if config.shred_original {
                    match SecureDelete::shred_standard(file_path, config.verbose) {
                        Ok(_) => {
                            if config.verbose {
                                println!("   ✅ Original file securely deleted");
                            }
                        }
                        Err(e) => {
                            eprintln!("   ⚠️  Failed to shred original file: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("   ❌ Failed to encrypt {}: {}", file_path.display(), e);
                failed += 1;
            }
        }
    }
    
    println!("\n🎯 Batch Operation Complete:");
    println!("   ✅ Successfully encrypted: {} files", successful);
    if failed > 0 {
        println!("   ❌ Failed to encrypt: {} files", failed);
    }
    
    Ok(())
}

fn run_batch_decrypt(config: &Config) -> Result<()> {
    let patterns = config.batch_patterns.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Batch patterns not provided"))?;
    
    let batch_processor = BatchProcessor::new(
        patterns.clone(), 
        config.exclude_patterns.clone()
    );
    
    // Find all files matching the patterns
    let files = batch_processor.find_files(Some(&config.source_path))?;
    
    if files.is_empty() {
        println!("⚠️  No files found matching the specified patterns");
        return Ok(());
    }
    
    batch_processor.print_summary(&files);
    
    let key = config.key.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Key is required for decryption"))?;
    
    // Process each file
    let mut successful = 0;
    let mut failed = 0;
    
    for (index, file_path) in files.iter().enumerate() {
        println!("\n📄 Processing file {}/{}: {}", index + 1, files.len(), file_path.display());
        
        let file_config = Config {
            source_path: file_path.clone(),
            output_path: config.output_path.clone(),
            key: Some(key.clone()),
            compress: config.compress,
            decrypt: true,
            algorithm: config.algorithm,
            verbose: config.verbose,
            batch_patterns: None,
            exclude_patterns: None,
            verify_integrity: config.verify_integrity,
            shred_original: config.shred_original,
            check_integrity: config.check_integrity,
            save_key_file: None,
        };
        
        match run_decrypt(&file_config) {
            Ok(_) => {
                successful += 1;
                // Shred encrypted file after successful decryption if requested
                if config.shred_original {
                    match SecureDelete::shred_standard(file_path, config.verbose) {
                        Ok(_) => {
                            if config.verbose {
                                println!("   ✅ Encrypted file securely deleted");
                            }
                        }
                        Err(e) => {
                            eprintln!("   ⚠️  Failed to shred encrypted file: {}", e);
                        }
                    }
                    
                    // Also shred the corresponding .meta file
                    let meta_file = {
                        let file_str = file_path.to_string_lossy();
                        if file_str.ends_with(".7z.enc") {
                            PathBuf::from(file_str.replace(".7z.enc", ".7z.meta"))
                        } else if file_str.ends_with(".enc") {
                            PathBuf::from(file_str.replace(".enc", ".meta"))
                        } else {
                            PathBuf::from(format!("{}.meta", file_str))
                        }
                    };
                    
                    if meta_file.exists() {
                        match SecureDelete::shred_standard(&meta_file, config.verbose) {
                            Ok(_) => {
                                if config.verbose {
                                    println!("   ✅ Metadata file securely deleted");
                                }
                            }
                            Err(e) => {
                                eprintln!("   ⚠️  Failed to shred metadata file: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("   ❌ Failed to decrypt {}: {}", file_path.display(), e);
                failed += 1;
            }
        }
    }
    
    println!("\n🎯 Batch Decryption Complete:");
    println!("   ✅ Successfully decrypted: {} files", successful);
    if failed > 0 {
        println!("   ❌ Failed to decrypt: {} files", failed);
    }
    
    Ok(())
}

fn run_single_encrypt(config: &Config) -> Result<()> {
    let crypto_engine = CryptEngine::with_algorithm(config.algorithm);
    let compression_engine = CompressionEngine::new();
    
    let key = config.key.as_ref().unwrap(); // Should be guaranteed by caller
    
    // Convert key to bytes for HMAC
    let key_bytes = if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
        // Hex key
        hex::decode(key).unwrap_or_else(|_| key.as_bytes().to_vec())
    } else {
        // Regular password key
        key.as_bytes().to_vec()
    };
    
    // Pre-encryption integrity check if requested
    let original_hmac = if config.verify_integrity {
        Some(IntegrityVerifier::pre_encrypt_check_hmac(&config.source_path, &key_bytes, config.verbose)?)
    } else {
        None
    };
    
    // Determine output path
    let output_path = match &config.output_path {
        Some(path) => path.clone(),
        None => {
            let extension = if config.compress { ".7z.enc" } else { ".enc" };
            let source_str = config.source_path.to_string_lossy();
            PathBuf::from(format!("{}{}", source_str, extension))
        }
    };

    // Create temporary directory for intermediate files
    let temp_dir = tempfile::tempdir()
        .context("Failed to create temporary directory")?;

    let file_to_encrypt = if config.compress {
        // Step 1: Compress with 7zip
        let compressed_file = temp_dir.path().join("compressed.7z");
        if config.verbose {
            println!("📦 Compressing {} -> {}", config.source_path.display(), compressed_file.display());
        }
        compression_engine.compress(&config.source_path, &compressed_file)
            .context("Compression failed")?;
        compressed_file
    } else {
        // Use source file directly
        config.source_path.clone()
    };

    // Step 2: Encrypt with selected algorithm
    if config.verbose {
        println!("🔐 Encrypting with {:?}...", config.algorithm);
    }
    
    crypto_engine.encrypt_file(&file_to_encrypt, &output_path, key)
        .context("Encryption failed")?;
    
    // Add integrity metadata if requested
    if let Some(hmac) = original_hmac {
        IntegrityVerifier::add_metadata_hmac(&output_path, &hmac, &format!("{:?}", config.algorithm), &key_bytes)?;
        if config.verbose {
            println!("✅ HMAC integrity metadata added to encrypted file");
        }
    }

    if config.verbose {
        println!("✅ Successfully encrypted: {}", output_path.display());
    }
    
    Ok(())
}

fn run_encrypt(config: &Config) -> Result<()> {
    if !config.source_path.exists() {
        anyhow::bail!("Source path does not exist: {}", config.source_path.display());
    }

    let crypto_engine = CryptEngine::with_algorithm(config.algorithm);

    if config.verbose {
        println!("🔧 Using algorithm: {:?}", config.algorithm);
        println!("📦 Compression: {}", if config.compress { "enabled" } else { "disabled" });
    }

    // Generate or use provided key
    let key = match &config.key {
        Some(k) => {
            if config.verbose {
                println!("🔑 Using provided key");
            }
            k.clone()
        }
        None => {
            let generated_key = crypto_engine.generate_key();
            println!("\n🔑 GENERATED ENCRYPTION KEY:");
            println!("   {}", generated_key);
            println!("⚠️  IMPORTANT: Save this key securely - you'll need it for decryption!");
            println!("   Copy this key to a safe location before proceeding.");
            
            // Save key to file if specified
            if let Some(key_file) = &config.save_key_file {
                match save_key_to_file(&generated_key, key_file) {
                    Ok(()) => println!("💾 Key saved to file: {}", key_file),
                    Err(e) => eprintln!("⚠️  Warning: Failed to save key to file: {}", e),
                }
            }
            
            if !config.verbose || std::env::var("ENCRYPT_NO_PAUSE").is_err() {
                println!("   Press Enter to continue...");
                let _ = std::io::Read::read(&mut std::io::stdin(), &mut [0u8; 1]);
            }
            println!();
            generated_key
        }
    };
    
    let enhanced_config = Config {
        source_path: config.source_path.clone(),
        output_path: config.output_path.clone(),
        key: Some(key),
        compress: config.compress,
        decrypt: config.decrypt,
        algorithm: config.algorithm,
        verbose: config.verbose,
        batch_patterns: None,
        exclude_patterns: None,
        verify_integrity: config.verify_integrity,
        shred_original: config.shred_original,
        check_integrity: config.check_integrity,
        save_key_file: None, // Not needed for single encryption after key generation
    };
    
    // Run single file encryption
    run_single_encrypt(&enhanced_config)?;
    
    // Shred original if requested
    if config.shred_original {
        SecureDelete::shred_standard(&config.source_path, config.verbose)?;
    }
    
    Ok(())
}

fn run_decrypt(config: &Config) -> Result<()> {
    if !config.source_path.exists() {
        anyhow::bail!("Encrypted file does not exist: {}", config.source_path.display());
    }

    let key = config.key.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Key is required for decryption"))?;

    // Convert key to bytes for HMAC
    let key_bytes = if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
        // Hex key
        hex::decode(key).unwrap_or_else(|_| key.as_bytes().to_vec())
    } else {
        // Regular password key
        key.as_bytes().to_vec()
    };

    // Auto-detect algorithm from file (the crypto engine will handle this)
    let crypto_engine = CryptEngine::new();  // Algorithm will be detected from file
    let compression_engine = CompressionEngine::new();

    if config.verbose {
        println!("🔍 Auto-detecting encryption algorithm from file...");
    }

    // Create temporary directory for intermediate files
    let temp_dir = tempfile::tempdir()
        .context("Failed to create temporary directory")?;

    // Step 1: Decrypt
    if config.verbose {
        println!("🔓 Decrypting...");
    }
    let decrypted_file = temp_dir.path().join("decrypted");
    crypto_engine.decrypt_file(&config.source_path, &decrypted_file, key)
        .context("Decryption failed")?;

    // Determine if file was compressed based on extension
    let was_compressed = config.source_path.to_string_lossy().ends_with(".7z.enc");

    if was_compressed {
        // Step 2: Decompress
        if config.verbose {
            println!("📦 Decompressing...");
        }
        let output_dir = match &config.output_path {
            Some(path) => path.clone(),
            None => {
                // Default to current directory
                let current_dir = std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."));
                current_dir
            }
        };

        compression_engine.decompress(&decrypted_file, &output_dir)
            .context("Decompression failed")?;
        
        // Integrity check if requested
        if config.check_integrity {
            IntegrityVerifier::post_decrypt_check_hmac(&config.source_path, &decrypted_file, &key_bytes, config.verbose)?;
        }
        
        println!("✅ Successfully decrypted and decompressed to: {}", output_dir.display());
    } else {
        // Just copy the decrypted file
        let output_path = match &config.output_path {
            Some(path) => path.clone(),
            None => {
                let source_str = config.source_path.to_string_lossy();
                let without_enc = source_str.strip_suffix(".enc").unwrap_or(&source_str);
                PathBuf::from(without_enc)
            }
        };

        fs::copy(&decrypted_file, &output_path)
            .context("Failed to copy decrypted file")?;
        
        // Integrity check if requested
        if config.check_integrity {
            IntegrityVerifier::post_decrypt_check_hmac(&config.source_path, &output_path, &key_bytes, config.verbose)?;
        }
        
        println!("✅ Successfully decrypted: {}", output_path.display());
    }

    // Shred encrypted file and meta file after successful decryption if requested
    if config.shred_original {
        match SecureDelete::shred_standard(&config.source_path, config.verbose) {
            Ok(_) => {
                if config.verbose {
                    println!("✅ Encrypted file securely deleted");
                }
            }
            Err(e) => {
                eprintln!("⚠️  Failed to shred encrypted file: {}", e);
            }
        }
        
        // Also shred the corresponding .meta file
        let meta_file = {
            let file_str = config.source_path.to_string_lossy();
            if file_str.ends_with(".7z.enc") {
                PathBuf::from(file_str.replace(".7z.enc", ".7z.meta"))
            } else if file_str.ends_with(".enc") {
                PathBuf::from(file_str.replace(".enc", ".meta"))
            } else {
                PathBuf::from(format!("{}.meta", file_str))
            }
        };
        
        if meta_file.exists() {
            match SecureDelete::shred_standard(&meta_file, config.verbose) {
                Ok(_) => {
                    if config.verbose {
                        println!("✅ Metadata file securely deleted");
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Failed to shred metadata file: {}", e);
                }
            }
        }
    }

    Ok(())
}
