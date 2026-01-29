# Encrypt

High-performance command-line file encryption tool written in Rust. Supports strong modern ciphers, optional compression, batch processing, integrity checking, and secure shredding of originals.

## Features

- AES-256-GCM and ChaCha20-Poly1305 based authenticated encryption
- Optional 7zip compression before encryption
- Passwords or 64‑character hex keys
- Single files, directories, and batch patterns
- Integrity verification and secure file shredding
- Progress bars and parallel processing (rayon)

## Requirements

- Rust (stable, via rustup)
- 7zip / p7zip for compression support
   - Ubuntu/Debian: `sudo apt install p7zip-full`
   - Fedora/RHEL: `sudo dnf install p7zip p7zip-plugins`
   - Arch Linux: `sudo pacman -S p7zip`

## Installation

```bash
git clone <this-repo-url>
cd crypt
cargo build --release

# optional: install binary into PATH
sudo cp target/release/encrypt /usr/local/bin/encrypt
```

## Basic Usage

Encrypt a single file (auto-generated key printed once):

```bash
encrypt -u /path/to/file
```

Encrypt with your own key:

```bash
encrypt -u /path/to/file --key "my-strong-password-123"
```

Decrypt a file:

```bash
encrypt --decrypt /path/to/file.7z.enc --key "my-strong-password-123"
```

Encrypt a directory:

```bash
encrypt -d /path/to/folder
```

Batch encrypt using patterns and exclusions:

```bash
encrypt -b "*.jpg,*.png" --exclude "*.tmp,*.log" --key "media-key"
```

Enable integrity verification and secure shredding:

```bash
encrypt -u secret.pdf --verify --shred --key "secure-key"
```

## Key Management

- String keys: any string (padded/truncated to 32 bytes)
- Hex keys: 64‑character hex string (32 bytes)
- Auto-generated keys can be saved with `--save-key <file>` and are printed once on the terminal.

Always store keys securely; without the correct key, data cannot be recovered.

## Common Options

- `-u, --file <FILE>`: encrypt a single file
- `-d, --dir <DIR>`: encrypt a directory
- `--decrypt <FILE>`: decrypt an encrypted file
- `-b, --batch <PATTERNS>`: batch mode with glob patterns
- `-c, --compress` / `-n, --no-compress`: enable/disable compression
- `--verify`: add integrity verification metadata
- `--check`: verify integrity during decryption
- `--shred`: securely delete original after successful encryption
- `--save-key <FILE>`: write generated key to a key file

Run `encrypt --help` for the complete CLI reference.

## Development

Run tests:

```bash
cargo test
```

Build and run from source:

```bash
cargo run -- -u myfile.txt --key "test-key"
```
