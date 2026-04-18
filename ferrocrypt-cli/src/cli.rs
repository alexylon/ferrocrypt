use std::io::{IsTerminal, stdin};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use ferrocrypt::secrecy::{ExposeSecret, SecretString};
use ferrocrypt::{
    CryptoError, KdfLimit, PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME, decode_recipient,
    default_encrypted_filename, detect_encryption_mode, encode_recipient, generate_key_pair,
    hybrid_decrypt, hybrid_encrypt, hybrid_encrypt_from_recipient, public_key_fingerprint,
    symmetric_decrypt, symmetric_encrypt, validate_secret_key_file,
};
use rpassword::prompt_password;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use subtle::ConstantTimeEq;

const PASSPHRASE_ENV: &str = "FERROCRYPT_PASSPHRASE";
const BINARY_NAME: &str = env!("CARGO_BIN_NAME");
const INTERACTIVE_PROMPT: &str = concat!(env!("CARGO_BIN_NAME"), "> ");
const SUBCOMMAND_HELP: &str =
    "symmetric (sym), hybrid (hyb), keygen (gen), fingerprint (fp), recipient (rc)";

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "\
Command-line interface for FerroCrypt.

File formats and primitives:
  Symmetric (v3.0): Argon2id -> HKDF-SHA3-256 -> XChaCha20-Poly1305
  Hybrid    (v4.0): X25519 ECDH -> HKDF-SHA256 -> XChaCha20-Poly1305",
    after_help = "\
Examples:
  ferrocrypt sym -i secret.txt -o ./encrypted
  ferrocrypt sym -i secret.txt -s ./secret.fcr
  ferrocrypt sym -i ./encrypted/secret.fcr -o ./decrypted
  ferrocrypt gen -o ./keys
  ferrocrypt hyb -i secret.txt -o ./encrypted -k ./keys/public.key
  ferrocrypt hyb -i secret.txt -s ./secret.fcr -r fcr1...
  ferrocrypt hyb -i ./encrypted/secret.fcr -o ./decrypted -k ./keys/private.key
  ferrocrypt fp ./keys/public.key
  ferrocrypt rc ./keys/public.key

Run <command> --help for full options (e.g. ferrocrypt sym --help)"
)]
pub struct Cli {
    /// Subcommand to run. If omitted, the CLI starts in interactive mode.
    #[command(subcommand)]
    pub command: Option<CliCommand>,
}

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    #[command(visible_alias = "gen", about = "Generate a key pair")]
    Keygen {
        #[arg(short, long, help = "Directory to write key files into")]
        output_path: String,
    },

    #[command(visible_alias = "hyb", about = "Hybrid encrypt or decrypt")]
    Hybrid {
        #[arg(short, long, help = "File or directory to process")]
        input_path: String,

        #[arg(short, long, help = "Output directory (optional with --save-as)")]
        output_path: Option<String>,

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

    #[command(visible_alias = "fp", about = "Show public key fingerprint")]
    Fingerprint {
        #[arg(help = "Path to a public key file")]
        public_key_file: String,
    },

    #[command(visible_alias = "rc", about = "Show public key recipient string")]
    Recipient {
        #[arg(help = "Path to a public key file")]
        public_key_file: String,
    },

    #[command(visible_alias = "sym", about = "Symmetric encrypt or decrypt")]
    Symmetric {
        #[arg(short, long, help = "File or directory to process")]
        input_path: String,

        #[arg(short, long, help = "Output directory (optional with --save-as)")]
        output_path: Option<String>,

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

/// Wraps a raw passphrase string in a zeroizing [`SecretString`] and rejects
/// the empty input at the single enforcement point. The env-var source and
/// primary prompt both funnel through here so the emptiness rule cannot drift
/// between them. The confirmation prompt (encryption only) is intentionally
/// *not* routed through this helper: its outcome must be decided by the
/// constant-time byte compare against the primary, so the error surfaced to
/// the user cannot distinguish "empty confirmation" from "non-empty wrong
/// confirmation."
fn validate_non_empty_passphrase(raw: String) -> Result<SecretString, CryptoError> {
    let secret = SecretString::from(raw);
    if secret.expose_secret().is_empty() {
        return Err(CryptoError::InvalidInput(
            "Passphrase must not be empty".to_string(),
        ));
    }
    Ok(secret)
}

/// Reads a passphrase from the `FERROCRYPT_PASSPHRASE` environment variable
/// for non-interactive use, or prompts via the controlling terminal with
/// hidden input. Refuses to prompt when stdin is not a terminal so callers
/// (cron, systemd, Docker without `-t`, CI, piped scripts) fail fast instead
/// of blocking on a hidden console.
///
/// When `confirm` is `true` (encryption), the user is prompted twice and the
/// inputs are compared in constant time.
fn read_passphrase(confirm: bool) -> Result<SecretString, CryptoError> {
    if let Ok(val) = std::env::var(PASSPHRASE_ENV) {
        return validate_non_empty_passphrase(val);
    }

    // `rpassword` bypasses stdin and reads directly from the controlling
    // terminal (`/dev/tty` on Unix, `CONIN$` on Windows), so redirecting the
    // child's stdin to a pipe or null is not enough on its own to prevent a
    // hang. The guard has to run before the prompt is attempted.
    if !stdin().is_terminal() {
        return Err(CryptoError::InvalidInput(format!(
            "No passphrase provided: set the {PASSPHRASE_ENV} environment variable or run from an interactive terminal"
        )));
    }

    let passphrase =
        validate_non_empty_passphrase(prompt_password("Passphrase: ").map_err(CryptoError::Io)?)?;

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

fn require_output_path(output_path: &Option<String>) -> Result<&Path, CryptoError> {
    output_path
        .as_deref()
        .map(Path::new)
        .ok_or_else(|| CryptoError::InvalidInput("--output-path is required".to_string()))
}

/// Resolves the output directory for an encrypt operation. When `--save-as`
/// is given, the library ignores the output directory entirely, so an empty
/// path is returned if the caller did not provide one.
fn resolve_encrypt_output_dir(
    output_path: &Option<String>,
    save_as: Option<&str>,
) -> Result<PathBuf, CryptoError> {
    if save_as.is_some() {
        Ok(output_path
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_default())
    } else {
        Ok(PathBuf::from(require_output_path(output_path)?))
    }
}

fn check_encrypt_conflict(
    output_dir: &Path,
    input_path: &Path,
    save_as: Option<&str>,
) -> Result<(), CryptoError> {
    let target = match save_as {
        Some(p) => PathBuf::from(p),
        None => output_dir.join(default_encrypted_filename(input_path)?),
    };
    if target.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Already exists: {}",
            target.display()
        )));
    }
    Ok(())
}

fn reject_encrypt_only_flag(flag: &str, is_set: bool) -> Result<(), CryptoError> {
    if is_set {
        Err(CryptoError::InvalidInput(format!(
            "{flag} is for encryption only"
        )))
    } else {
        Ok(())
    }
}

fn reject_decrypt_only_flag(flag: &str, is_set: bool) -> Result<(), CryptoError> {
    if is_set {
        Err(CryptoError::InvalidInput(format!(
            "{flag} is for decryption only"
        )))
    } else {
        Ok(())
    }
}

fn print_result(is_encrypt: bool, output: &Path, elapsed: std::time::Duration) {
    let action = if is_encrypt {
        "Encrypted to"
    } else {
        "Decrypted to"
    };
    println!(
        "\n{} {} in {}\n",
        action,
        output.display(),
        format_duration(elapsed)
    );
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
            let is_encrypt = detect_encryption_mode(input_path)?.is_none();
            let start = std::time::Instant::now();

            let output = if is_encrypt {
                reject_decrypt_only_flag("--max-kdf-memory", max_kdf_memory.is_some())?;
                let output_dir = resolve_encrypt_output_dir(&output_path, save_as.as_deref())?;
                check_encrypt_conflict(&output_dir, input_path, save_as.as_deref())?;
                let save_as_path = save_as.as_deref().map(Path::new);

                if let Some(r) = recipient.as_deref() {
                    let recipient_bytes = decode_recipient(r)?;
                    println!("Encrypting to: {r}");
                    hybrid_encrypt_from_recipient(
                        input_path,
                        &output_dir,
                        &recipient_bytes,
                        save_as_path,
                        |msg| eprintln!("{msg}"),
                    )?
                } else {
                    let key = key.as_deref().ok_or_else(|| {
                        CryptoError::InvalidInput(
                            "Encrypt requires --key or --recipient".to_string(),
                        )
                    })?;
                    let key_path = Path::new(key);
                    match public_key_fingerprint(key_path) {
                        Ok(fp) => println!("Encrypting to: {fp}"),
                        Err(_) => println!("Using key file: {}", key_path.display()),
                    }
                    hybrid_encrypt(input_path, &output_dir, key_path, save_as_path, |msg| {
                        eprintln!("{msg}")
                    })?
                }
            } else {
                reject_encrypt_only_flag("--recipient", recipient.is_some())?;
                reject_encrypt_only_flag("--save-as", save_as.is_some())?;
                let output_dir = require_output_path(&output_path)?;
                let key = key.as_deref().ok_or_else(|| {
                    CryptoError::InvalidInput("Decrypt requires --key".to_string())
                })?;
                let key_path = Path::new(key);
                validate_secret_key_file(key_path)?;
                let kdf_limit = max_kdf_memory.map(KdfLimit::from_mib).transpose()?;
                let passphrase = read_passphrase(false)?;
                hybrid_decrypt(
                    input_path,
                    output_dir,
                    key_path,
                    &passphrase,
                    kdf_limit.as_ref(),
                    |msg| eprintln!("{msg}"),
                )?
            };

            print_result(is_encrypt, &output, start.elapsed());
        }

        CliCommand::Symmetric {
            input_path,
            output_path,
            save_as,
            max_kdf_memory,
        } => {
            let input_path = Path::new(&input_path);
            let is_encrypt = detect_encryption_mode(input_path)?.is_none();
            let start = std::time::Instant::now();

            let output = if is_encrypt {
                reject_decrypt_only_flag("--max-kdf-memory", max_kdf_memory.is_some())?;
                let output_dir = resolve_encrypt_output_dir(&output_path, save_as.as_deref())?;
                check_encrypt_conflict(&output_dir, input_path, save_as.as_deref())?;
                let passphrase = read_passphrase(true)?;
                symmetric_encrypt(
                    input_path,
                    &output_dir,
                    &passphrase,
                    save_as.as_deref().map(Path::new),
                    |msg| eprintln!("{msg}"),
                )?
            } else {
                reject_encrypt_only_flag("--save-as", save_as.is_some())?;
                let output_dir = require_output_path(&output_path)?;
                let kdf_limit = max_kdf_memory.map(KdfLimit::from_mib).transpose()?;
                let passphrase = read_passphrase(false)?;
                symmetric_decrypt(
                    input_path,
                    output_dir,
                    &passphrase,
                    kdf_limit.as_ref(),
                    |msg| eprintln!("{msg}"),
                )?
            };

            print_result(is_encrypt, &output, start.elapsed());
        }
    }

    Ok(())
}

fn interactive_mode() -> Result<(), CryptoError> {
    println!("\nFerroCrypt interactive mode\n");
    println!("Commands: {SUBCOMMAND_HELP}, quit\n");

    let mut rl = match DefaultEditor::new() {
        Ok(editor) => editor,
        Err(e) => {
            eprintln!("Failed to initialize line editor: {e}");
            return Ok(());
        }
    };

    loop {
        match rl.readline(INTERACTIVE_PROMPT) {
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

                let args = std::iter::once(BINARY_NAME.to_string()).chain(parts);

                match Cli::try_parse_from(args) {
                    Ok(cli) => {
                        if let Some(cmd) = cli.command {
                            if let Err(e) = run_command(cmd) {
                                eprintln!("Error: {e}");
                            }
                        } else {
                            eprintln!("No command given. Try: {SUBCOMMAND_HELP}");
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
