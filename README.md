# Iron Vault 🛡️

A secure, command-line password manager built in Rust.
It uses **Argon2id** for key derivation and **AES-256-GCM** for authenticated encryption.

## 🚀 Getting Started

### 1. Build and Run
You can run the program directly using `cargo`.
```bash
cargo run -- <command>
```

Or build a high-performance release binary:
```bash
cargo build --release
./target/release/iron-vault <command>
```

### 2. Initialize the Vault
First, you need to create your secure vault. Run:
```bash
cargo run -- init
```
You will be prompted to set a **Master Password**.
> **⚠️ IMPORTANT:** Do not forget this password! There is no recovery mechanism. If you lose it, your data is lost forever.

## 🔑 Key Commands

### Add a Password (`add`)
Store a new credential. The securest way is **Interactive Mode**:
```bash
cargo run -- add
```
It will guide you step-by-step so your sensitive data isn't saved in your shell history.

### Get a Password (`get`)
Retrieve a password. It will be copied to your **clipboard** for 10 seconds.
```bash
cargo run -- get google
```
*(Replace `google` with your service name)*

### List Services (`list`)
See what you have stored:
```bash
cargo run -- list
```

### Generate a Strong Password (`gen`)
Need a new password?
```bash
cargo run -- gen              # Generates 20 chars
cargo run -- gen --length 32  # Generates 32 chars
```

### Delete a Password (`delete`)
Remove an old entry:
```bash
cargo run -- delete google
```

## 🔒 Security Features
- **Encryption**: AES-256-GCM (Authenticated Encryption).
- **Key Derivation**: Argon2id (Memory-hard password hashing).
- **Memory Safety**: Rust's ownership model + `zeroize` for clearing memory.
- **Clipboard**: Passwords are automatically cleared from the clipboard after 60 seconds.
