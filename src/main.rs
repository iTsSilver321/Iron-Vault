use clap::{Parser, Subcommand};
use iron_vault::{encrypt, Vault};
use std::path::Path;
use std::time::Duration;
use std::thread;
use std::io::{self, Write};
use arboard::Clipboard;
use colored::*;
use inquire::{Text, Password, Select, Confirm};

const VAULT_FILE: &str = "vault.json";

#[derive(Parser)]
#[command(name = "iron-vault")]
#[command(about = "A secure CLI password manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init,
    /// Add a new secret
    Add {
        service: Option<String>,
        username: Option<String>,
        password: Option<String>,
    },
    /// Get a secret
    Get {
        service: Option<String>,
    },
    /// Delete a secret
    Delete {
        service: Option<String>,
    },
    /// Generate a strong password
    Gen {
        #[arg(short, long, default_value_t = 20)]
        length: usize,
    },
    /// List all services
    List,
    /// Run the interactive tutorial
    Tutorial,
}

fn run_tutorial() {
    println!("{}", "\nWelcome to the Iron Vault Tutorial! 🚀".green().bold());
    println!("This quick tour will teach you the basics of securing your passwords.\n");

    let _ = Confirm::new("Ready to start?")
        .with_default(true)
        .prompt();

    // Step 1: Concepts
    println!("\n{}", "1. Core Concepts".cyan().bold());
    println!("- **Vault**: Your encrypted password database (stored in `vault.json`).");
    println!("- **Master Password**: The ONLY key to your vault. If you lose it, your data is gone forever!");
    
    let _ = Text::new("Press Enter to continue...").prompt();

    // Step 2: Adding a Password
    println!("\n{}", "2. Adding a Password".cyan().bold());
    println!("To add a credential, run:");
    println!("  {}", "iron-vault add".yellow());
    println!("It will interactively ask for the Service, Username, and Password.");
    println!("(Passwords are hidden while you type!)");

    let _ = Text::new("Press Enter to continue...").prompt();

    // Step 3: Getting a Password
    println!("\n{}", "3. Retrieving a Password".cyan().bold());
    println!("To get a password, run:");
    println!("  {}", "iron-vault get".yellow());
    println!("If you don't provide a service name, it will show you a searchable list!");
    println!("The password is copied to your **clipboard** and cleared after 60 seconds.");

    let _ = Text::new("Press Enter to continue...").prompt();

    // Step 4: Generating Passwords
    println!("\n{}", "4. Generating Strong Passwords".cyan().bold());
    println!("Need a strong password? Run:");
    println!("  {}", "iron-vault gen --length 25".yellow());
    println!("It generates a secure password and copies it to your clipboard automatically.");

    let _ = Text::new("Press Enter to continue...").prompt();

    println!("\n{}", "🎉 Tutorial Complete!".green().bold());
    println!("You are now ready to use Iron Vault.");
    println!("Try adding your first password now via `iron-vault add`.");
}

fn print_banner() {
    println!("{}", r#"
  ___                   _   _            _ _   
 |_ _|_ __ ___  _ __   | | | | __ _ _ __| | |_ 
  | || '__/ _ \| '_ \  | | | |/ _` | '__| | __|
  | || | | (_) | | | | \ \_/ / (_| | |  | | |_ 
 |___|_|  \___/|_| |_|  \___/ \__,_|_|  |_|\__|
                                               
"#.cyan().bold());
    println!("{}", "Secure Password Manager v0.1.0".bright_black());
    println!("{}", "--------------------------------------------------".bright_black());
}

fn main() {
    print_banner();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init => {
            if Path::new(VAULT_FILE).exists() {
                eprintln!("{}", format!("Error: Vault file '{}' already exists.", VAULT_FILE).red());
                std::process::exit(1);
            }

            println!("Initializing new vault.");
            println!("Enter Master Password:");
            let password = rpassword::read_password().unwrap_or_else(|e| {
                eprintln!("Error reading password: {}", e);
                std::process::exit(1);
            });
            
            println!("Confirm Master Password:");
            let confirm = rpassword::read_password().unwrap_or_else(|e| {
                eprintln!("Error reading password: {}", e);
                std::process::exit(1);
            });

            if password != confirm {
                eprintln!("Error: Passwords do not match.");
                std::process::exit(1);
            }

            // Create an empty JSON object as the initial payload
            let initial_payload = b"{}";
            
            match encrypt(initial_payload, &password) {
                Ok(vault) => {
                    if let Err(e) = vault.save(VAULT_FILE) {
                        eprintln!("Error saving vault: {}", e);
                        std::process::exit(1);
                    }
                    println!("Vault initialized successfully at '{}'", VAULT_FILE);
                    
                    println!();
                    let run_tut = Confirm::new("Would you like to take a quick tour of Iron Vault?")
                        .with_default(true)
                        .prompt()
                        .unwrap_or(false);

                    if run_tut {
                        run_tutorial();
                    }
                }
                Err(e) => {
                    eprintln!("Error initializing vault: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Add { service, username, password } => {
            let service = match service {
                Some(s) => s.clone(),
                None => Text::new("Service Name:")
                    .with_placeholder("e.g. google")
                    .prompt()
                    .unwrap_or_else(|_| std::process::exit(1)),
            };

            let username = match username {
                Some(u) => u.clone(),
                None => Text::new("Username/Email:")
                    .with_placeholder("e.g. user@example.com")
                    .prompt()
                    .unwrap_or_else(|_| std::process::exit(1)),
            };

            let password = match password {
                Some(p) => p.clone(),
                None => Password::new("Password:")
                    .with_display_mode(inquire::PasswordDisplayMode::Masked)
                    .with_custom_confirmation_message("Confirm Password:")
                    .with_custom_confirmation_error_message("Passwords do not match")
                    .prompt()
                    .unwrap_or_else(|_| std::process::exit(1)),
            };

            // 1. Load the vault
            if !Path::new(VAULT_FILE).exists() {
                eprintln!("Error: Vault file '{}' does not exist. Run 'init' first.", VAULT_FILE);
                std::process::exit(1);
            }
            let vault = Vault::load(VAULT_FILE).unwrap_or_else(|e| {
                eprintln!("Failed to load vault: {}", e);
                std::process::exit(1);
            });

            // 2. Prompt for master password
            println!("Enter Master Password:");
            let master_password = rpassword::read_password().unwrap_or_else(|e| {
                eprintln!("Error reading password: {}", e);
                std::process::exit(1);
            });

            // 3. Decrypt
            let decrypted_bytes = iron_vault::decrypt(&vault, &master_password).unwrap_or_else(|_| {
                eprintln!("Error: Access Denied. Wrong password or corrupted vault.");
                std::process::exit(1);
            });

            // 4. Parse JSON
            let mut entries: std::collections::HashMap<String, iron_vault::VaultEntry> =
                serde_json::from_slice(&decrypted_bytes).unwrap_or_else(|e| {
                    eprintln!("Failed to parse vault JSON: {}", e);
                    std::process::exit(1);
                });

            // 5. Add entry
            entries.insert(
                service.clone(),
                iron_vault::VaultEntry {
                    username: username.clone(),
                    password,
                },
            );

            // 6. Serialize and Re-encrypt
            let new_payload = serde_json::to_vec(&entries).expect("Failed to serialize entries");
            let new_vault = encrypt(&new_payload, &master_password).expect("Failed to encrypt vault");

            // 7. Save
            new_vault.save(VAULT_FILE).unwrap_or_else(|e| {
                eprintln!("Failed to save vault: {}", e);
                std::process::exit(1);
            });
            println!("Added entry for service '{}'", service);
        }
        Commands::Get { service } => {
            // ... (Load vault code remains similar, but we need to match service option)
            if !Path::new(VAULT_FILE).exists() {
                eprintln!("{}", format!("Error: Vault file '{}' does not exist. Run 'init' first.", VAULT_FILE).red());
                std::process::exit(1);
            }
            let vault = Vault::load(VAULT_FILE).unwrap_or_else(|e| {
                eprintln!("{}", format!("Failed to load vault: {}", e).red());
                std::process::exit(1);
            });

            println!("{}", "Enter Master Password:".yellow());
            let master_password = Password::new("Master Password:")
                .without_confirmation()
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .prompt()
                .unwrap_or_else(|_| std::process::exit(1));

            let decrypted_bytes = iron_vault::decrypt(&vault, &master_password).unwrap_or_else(|_| {
                eprintln!("{}", "Error: Access Denied. Wrong password or corrupted vault.".red().bold());
                std::process::exit(1);
            });

            let entries: std::collections::HashMap<String, iron_vault::VaultEntry> =
                serde_json::from_slice(&decrypted_bytes).unwrap_or_else(|e| {
                    eprintln!("{}", format!("Failed to parse vault JSON: {}", e).red());
                    std::process::exit(1);
                });

            let service_name = match service {
                Some(s) => s.clone(),
                None => {
                    let options: Vec<String> = entries.keys().cloned().collect();
                    if options.is_empty() {
                         println!("{}", "No services found in vault.".yellow());
                         return;
                    }
                    Select::new("Select a service:", options).prompt().unwrap_or_else(|_| std::process::exit(0))
                }
            };

            match entries.get(&service_name) {
                Some(entry) => {
                    println!("{} {}", "Service:".cyan(), service_name.green().bold());
                    println!("{} {}", "Username:".cyan(), entry.username.yellow());
                    
                    match Clipboard::new() {
                        Ok(mut clipboard) => {
                            if let Err(e) = clipboard.set_text(&entry.password) {
                                eprintln!("{}", format!("Error copying to clipboard: {}", e).red());
                                println!("Password: {}", entry.password); // Fallback
                            } else {
                                println!("{}", "Password copied to clipboard!".green().bold());
                                println!("{}", "Clearing in 60 seconds...".yellow());
                                thread::sleep(Duration::from_secs(60));
                                if let Err(e) = clipboard.clear() {
                                    eprintln!("{}", format!("Error clearing clipboard: {}", e).red());
                                } else {
                                    println!("{}", "Clipboard cleared.".green());
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("{}", format!("Error initializing clipboard: {}", e).red());
                            println!("Password: {}", entry.password); // Fallback
                        }
                    }
                }
                None => {
                    eprintln!("{}", format!("No entry found for service '{}'", service_name).red());
                }
            }
        }
        Commands::Delete { service } => {
            if !Path::new(VAULT_FILE).exists() {
                eprintln!("{}", format!("Error: Vault file '{}' does not exist. Run 'init' first.", VAULT_FILE).red());
                std::process::exit(1);
            }
             let vault = Vault::load(VAULT_FILE).unwrap_or_else(|e| {
                eprintln!("{}", format!("Failed to load vault: {}", e).red());
                std::process::exit(1);
            });

            println!("{}", "Enter Master Password:".yellow());
            let master_password = Password::new("Master Password:")
                .without_confirmation()
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .prompt()
                .unwrap_or_else(|_| std::process::exit(1));

            let decrypted_bytes = iron_vault::decrypt(&vault, &master_password).unwrap_or_else(|_| {
                eprintln!("{}", "Error: Access Denied. Wrong password or corrupted vault.".red().bold());
                std::process::exit(1);
            });

             let mut entries: std::collections::HashMap<String, iron_vault::VaultEntry> =
                serde_json::from_slice(&decrypted_bytes).unwrap_or_else(|e| {
                    eprintln!("{}", format!("Failed to parse vault JSON: {}", e).red());
                    std::process::exit(1);
                });

             let service_name = match service {
                Some(s) => s.clone(),
                None => {
                    let options: Vec<String> = entries.keys().cloned().collect();
                     if options.is_empty() {
                         println!("{}", "No services found in vault.".yellow());
                         return;
                    }
                    Select::new("Select a service to delete:", options).prompt().unwrap_or_else(|_| std::process::exit(0))
                }
            };
            
            // Confirmation
            let confirmation = Confirm::new(&format!("Are you sure you want to delete '{}'?", service_name))
                .with_default(false)
                .with_help_message("This action cannot be undone.")
                .prompt()
                .unwrap_or(false);

            if !confirmation {
                println!("{}", "Deletion cancelled.".yellow());
                return;
            }

            if entries.remove(&service_name).is_some() {
                 let new_payload = serde_json::to_vec(&entries).expect("Failed to serialize entries");
                let new_vault = encrypt(&new_payload, &master_password).expect("Failed to encrypt vault");

                new_vault.save(VAULT_FILE).unwrap_or_else(|e| {
                    eprintln!("{}", format!("Failed to save vault: {}", e).red());
                    std::process::exit(1);
                });
                println!("{}", format!("Deleted entry for service '{}'", service_name).green().bold());
            } else {
                eprintln!("{}", format!("No entry found for service '{}'", service_name).red());
            }
        }
        Commands::List => {
            if !Path::new(VAULT_FILE).exists() {
                eprintln!("{}", format!("Error: Vault file '{}' does not exist. Run 'init' first.", VAULT_FILE).red());
                std::process::exit(1);
            }
            let vault = Vault::load(VAULT_FILE).unwrap_or_else(|e| {
                eprintln!("{}", format!("Failed to load vault: {}", e).red());
                std::process::exit(1);
            });

            println!("{}", "Enter Master Password:".yellow());
             let master_password = Password::new("Master Password:")
                .without_confirmation()
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .prompt()
                .unwrap_or_else(|_| std::process::exit(1));

            let decrypted_bytes = iron_vault::decrypt(&vault, &master_password).unwrap_or_else(|_| {
                eprintln!("{}", "Error: Access Denied. Wrong password or corrupted vault.".red().bold());
                std::process::exit(1);
            });

             let entries: std::collections::HashMap<String, iron_vault::VaultEntry> =
                serde_json::from_slice(&decrypted_bytes).unwrap_or_else(|e| {
                    eprintln!("{}", format!("Failed to parse vault JSON: {}", e).red());
                    std::process::exit(1);
                });

            if entries.is_empty() {
                println!("{}", "No entries found.".yellow());
            } else {
                println!("{}", "Available services:".cyan().bold());
                println!("--------------------------------------------------");
                for service in entries.keys() {
                    println!("- {}", service.green());
                }
                println!("--------------------------------------------------");
            }
        }
        Commands::Gen { length } => {
            let password = iron_vault::generate_password(*length);
            println!("{}", format!("Generated password of length {}", length).cyan());
            
            match Clipboard::new() {
                Ok(mut clipboard) => {
                    if let Err(e) = clipboard.set_text(&password) {
                        eprintln!("{}", format!("Error copying to clipboard: {}", e).red());
                        println!("Password: {}", password); // Fallback
                    } else {
                        println!("{}", "Password copied to clipboard!".green().bold());
                        println!("{}", "Clearing in 60 seconds...".yellow());
                        thread::sleep(Duration::from_secs(60));
                        if let Err(e) = clipboard.clear() {
                            eprintln!("{}", format!("Error clearing clipboard: {}", e).red());
                        } else {
                            println!("{}", "Clipboard cleared.".green());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", format!("Error initializing clipboard: {}", e).red());
                    println!("Password: {}", password); // Fallback
                }
            }
        }
        Commands::Tutorial => {
            run_tutorial();
        }
    }
}
