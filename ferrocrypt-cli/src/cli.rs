use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use ferrocrypt::secrecy::{ExposeSecret, SecretString};
use ferrocrypt::{
    CryptoError, KdfLimit, PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME, decode_recipient,
    default_encrypted_filename, detect_encryption_mode, encode_recipient, generate_key_pair,
    hybrid_auto, hybrid_encrypt_from_recipient, public_key_fingerprint, symmetric_auto,
    validate_secret_key_file,
};
use rpassword::prompt_password;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use subtle::ConstantTimeEq;

const PASSPHRASE_ENV: &str = "FERROCRYPT_PASSPHRASE";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Subcommand to run. If omitted, the CLI starts in interactive mode.
    #[command(subcommand)]
    pub command: Option<CliCommand>,
}

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    #[command(alias = "gen")]
    Keygen {
        #[arg(short, long)]
        output_path: String,
    },

    #[command(alias = "hyb")]
    Hybrid {
        #[arg(short, long)]
        input_path: String,

        #[arg(short, long)]
        output_path: String,

        #[arg(
            short,
            long,
            help = "Key file path (public for encrypt, private for decrypt)"
        )]
        key: Option<String>,

        #[arg(
            short,
            long,
            conflicts_with = "key",
            help = "Bech32 recipient string for encryption (fcr1...)"
        )]
        recipient: Option<String>,

        #[arg(
            short,
            long,
            help = "Save encrypted output to this file path (encrypt only)"
        )]
        save_as: Option<String>,

        #[arg(long, help = "Maximum KDF memory cost to accept (MiB, decrypt only)")]
        max_kdf_memory: Option<u32>,
    },

    #[command(alias = "fp")]
    Fingerprint {
        #[arg(help = "Path to a public key file")]
        public_key_file: String,
    },

    #[command(alias = "rc")]
    Recipient {
        #[arg(help = "Path to a public key file")]
        public_key_file: String,
    },

    #[command(alias = "sym")]
    Symmetric {
        #[arg(short, long)]
        input_path: String,

        #[arg(short, long)]
        output_path: String,

        #[arg(
            short,
            long,
            help = "Save encrypted output to this file path (encrypt only)"
        )]
        save_as: Option<String>,

        #[arg(long, help = "Maximum KDF memory cost to accept (MiB, decrypt only)")]
        max_kdf_memory: Option<u32>,
    },
}

/// Reads a passphrase from the `FERROCRYPT_PASSPHRASE` environment variable
/// (for non-interactive use) or prompts via the TTY with hidden input.
///
/// When `confirm` is `true` (encryption), the user is prompted twice and the
/// inputs are compared in constant time.
fn read_passphrase(confirm: bool) -> Result<SecretString, CryptoError> {
    if let Ok(val) = std::env::var(PASSPHRASE_ENV) {
        let secret = SecretString::from(val);
        if secret.expose_secret().is_empty() {
            return Err(CryptoError::InvalidInput(
                "Passphrase must not be empty".to_string(),
            ));
        }
        return Ok(secret);
    }

    let passphrase = SecretString::from(prompt_password("Passphrase: ").map_err(CryptoError::Io)?);

    if passphrase.expose_secret().is_empty() {
        return Err(CryptoError::InvalidInput(
            "Passphrase must not be empty".to_string(),
        ));
    }

    if confirm {
        let confirm_passphrase =
            SecretString::from(prompt_password("Confirm passphrase: ").map_err(CryptoError::Io)?);

        if !bool::from(
            passphrase
                .expose_secret()
                .as_bytes()
                .ct_eq(confirm_passphrase.expose_secret().as_bytes()),
        ) {
            return Err(CryptoError::InvalidInput(
                "Passphrases do not match".to_string(),
            ));
        }
    }

    Ok(passphrase)
}

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 60.0 {
        format!("{secs:.2} sec")
    } else {
        format!("{} min, {:.2} sec", secs as u32 / 60, secs % 60.0)
    }
}

fn effective_encrypt_output(
    output_dir: &Path,
    input_path: &Path,
    save_as: Option<&str>,
) -> Result<PathBuf, CryptoError> {
    match save_as {
        Some(p) => Ok(PathBuf::from(p)),
        None => Ok(output_dir.join(default_encrypted_filename(input_path)?)),
    }
}

fn check_encrypt_conflict(
    output_dir: &Path,
    input_path: &Path,
    save_as: Option<&str>,
) -> Result<(), CryptoError> {
    let target = effective_encrypt_output(output_dir, input_path, save_as)?;
    if target.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Already exists: {}",
            target.display()
        )));
    }
    Ok(())
}

fn check_keygen_conflict(output_dir: &Path) -> Result<(), CryptoError> {
    let secret_exists = output_dir.join(PRIVATE_KEY_FILENAME).exists();
    let pub_exists = output_dir.join(PUBLIC_KEY_FILENAME).exists();
    match (secret_exists, pub_exists) {
        (true, true) => Err(CryptoError::InvalidInput(
            "Key pair already exists in output folder".into(),
        )),
        (true, false) => Err(CryptoError::InvalidInput(
            "Private key already exists in output folder".into(),
        )),
        (false, true) => Err(CryptoError::InvalidInput(
            "Public key already exists in output folder".into(),
        )),
        _ => Ok(()),
    }
}

pub fn run() -> Result<(), CryptoError> {
    let cli = Cli::parse();

    if let Some(cmd) = cli.command {
        run_command(cmd)?;
    } else {
        interactive_mode()?;
    }

    Ok(())
}

fn run_command(cmd: CliCommand) -> Result<(), CryptoError> {
    match cmd {
        CliCommand::Keygen { output_path } => {
            let output_path = Path::new(&output_path);
            check_keygen_conflict(output_path)?;
            let passphrase = read_passphrase(true)?;
            let info = generate_key_pair(&passphrase, output_path, |msg| eprintln!("{msg}"))?;
            let recipient = encode_recipient(&info.public_key_path)?;
            println!("\nGenerated key pair in {}\n", output_path.display());
            println!("Public key fingerprint: {}", info.fingerprint);
            println!("Public key recipient:   {}", recipient);
        }

        CliCommand::Fingerprint { public_key_file } => {
            let fp = public_key_fingerprint(Path::new(&public_key_file))?;
            println!("{}", fp);
        }

        CliCommand::Recipient { public_key_file } => {
            let recipient = encode_recipient(Path::new(&public_key_file))?;
            println!("{}", recipient);
        }

        CliCommand::Hybrid {
            input_path,
            output_path,
            key,
            recipient,
            save_as,
            max_kdf_memory,
        } => {
            let input_path = Path::new(&input_path);
            let output_path = Path::new(&output_path);
            let is_encrypt = detect_encryption_mode(input_path)?.is_none();
            let kdf_limit = max_kdf_memory.map(KdfLimit::from_mib).transpose()?;
            let start = std::time::Instant::now();

            if is_encrypt {
                if kdf_limit.is_some() {
                    return Err(CryptoError::InvalidInput(
                        "--max-kdf-memory is for decryption only".to_string(),
                    ));
                }
                check_encrypt_conflict(output_path, input_path, save_as.as_deref())?;
            } else {
                if recipient.is_some() {
                    return Err(CryptoError::InvalidInput(
                        "--recipient is for encryption only".to_string(),
                    ));
                }
                if save_as.is_some() {
                    return Err(CryptoError::InvalidInput(
                        "--save-as is for encryption only".to_string(),
                    ));
                }
            }

            let output = if is_encrypt {
                if let Some(ref r) = recipient {
                    let recipient_bytes = decode_recipient(r)?;
                    println!("Encrypting to: {}", r);
                    hybrid_encrypt_from_recipient(
                        input_path,
                        output_path,
                        &recipient_bytes,
                        save_as.as_deref().map(Path::new),
                        |msg| eprintln!("{msg}"),
                    )?
                } else {
                    let key = key.as_deref().ok_or_else(|| {
                        CryptoError::InvalidInput(
                            "Encrypt requires --key or --recipient".to_string(),
                        )
                    })?;
                    let key_path = Path::new(key);
                    if let Ok(fp) = public_key_fingerprint(key_path) {
                        println!("Encrypting to: {}", fp);
                    }
                    hybrid_auto(
                        input_path,
                        output_path,
                        key_path,
                        &SecretString::from(String::new()),
                        save_as.as_deref().map(Path::new),
                        kdf_limit.as_ref(),
                        |msg| eprintln!("{msg}"),
                    )?
                }
            } else {
                let key = key.as_deref().ok_or_else(|| {
                    CryptoError::InvalidInput("Decrypt requires --key".to_string())
                })?;
                let key_path = Path::new(key);
                validate_secret_key_file(key_path)?;
                let passphrase = read_passphrase(false)?;
                hybrid_auto(
                    input_path,
                    output_path,
                    key_path,
                    &passphrase,
                    save_as.as_deref().map(Path::new),
                    kdf_limit.as_ref(),
                    |msg| eprintln!("{msg}"),
                )?
            };

            let action = if is_encrypt {
                "Encrypted to"
            } else {
                "Decrypted to"
            };
            println!(
                "\n{} {} in {}\n",
                action,
                output.display(),
                format_duration(start.elapsed())
            );
        }

        CliCommand::Symmetric {
            input_path,
            output_path,
            save_as,
            max_kdf_memory,
        } => {
            let input_path = Path::new(&input_path);
            let output_path = Path::new(&output_path);
            let is_encrypt = detect_encryption_mode(input_path)?.is_none();
            let kdf_limit = max_kdf_memory.map(KdfLimit::from_mib).transpose()?;
            let start = std::time::Instant::now();

            if is_encrypt {
                if kdf_limit.is_some() {
                    return Err(CryptoError::InvalidInput(
                        "--max-kdf-memory is for decryption only".to_string(),
                    ));
                }
                check_encrypt_conflict(output_path, input_path, save_as.as_deref())?;
            } else if save_as.is_some() {
                return Err(CryptoError::InvalidInput(
                    "--save-as is for encryption only".to_string(),
                ));
            }

            let passphrase = read_passphrase(is_encrypt)?;
            let output = symmetric_auto(
                input_path,
                output_path,
                &passphrase,
                save_as.as_deref().map(Path::new),
                kdf_limit.as_ref(),
                |msg| eprintln!("{msg}"),
            )?;
            let action = if is_encrypt {
                "Encrypted to"
            } else {
                "Decrypted to"
            };
            println!(
                "\n{} {} in {}\n",
                action,
                output.display(),
                format_duration(start.elapsed())
            );
        }
    }

    Ok(())
}

fn interactive_mode() -> Result<(), CryptoError> {
    println!("\nFerroCrypt interactive mode\n");
    println!(
        "Commands: symmetric (sym), hybrid (hyb), keygen (gen), fingerprint (fp), recipient (rc), quit\n"
    );

    let mut rl = match DefaultEditor::new() {
        Ok(editor) => editor,
        Err(e) => {
            eprintln!("Failed to initialize line editor: {e}");
            return Ok(());
        }
    };

    loop {
        match rl.readline("ferrocrypt> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                if line.eq_ignore_ascii_case("exit") || line.eq_ignore_ascii_case("quit") {
                    break;
                }

                if let Err(e) = rl.add_history_entry(line) {
                    eprintln!("Failed to add history entry: {e}");
                }

                let parts: Vec<String> = match shell_words::split(line) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Parse error: {e}");
                        continue;
                    }
                };

                let args = std::iter::once("ferrocrypt".to_string()).chain(parts);

                match Cli::try_parse_from(args) {
                    Ok(cli) => {
                        if let Some(cmd) = cli.command {
                            if let Err(e) = run_command(cmd) {
                                eprintln!("Error: {e}");
                            }
                        } else {
                            eprintln!(
                                "No command given. Try: symmetric (sym), hybrid (hyb), keygen (gen), fingerprint (fp), recipient (rc)"
                            );
                        }
                    }
                    Err(e) => {
                        if let Err(print_err) = e.print() {
                            eprintln!("Failed to print error: {print_err}");
                        }
                    }
                }
            }

            Err(ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(err) => {
                eprintln!("Error: {err}");
                break;
            }
        }
    }

    Ok(())
}
