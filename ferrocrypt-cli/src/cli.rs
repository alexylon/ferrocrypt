use std::io::{self, IsTerminal, Read, Write, stdin};
use std::path::{Path, PathBuf};

use clap::{ArgAction, Parser, Subcommand};
use ferrocrypt::secrecy::{ExposeSecret, SecretString};
use ferrocrypt::{
    CryptoError, Decryptor, Encryptor, KdfLimit, MAGIC, PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME,
    PrivateKey, PublicKey, default_encrypted_filename, generate_key_pair,
    validate_private_key_file,
};
use rpassword::prompt_password;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use subtle::ConstantTimeEq;

const PASSPHRASE_ENV: &str = "FERROCRYPT_PASSPHRASE";
const BINARY_NAME: &str = env!("CARGO_BIN_NAME");
const INTERACTIVE_PROMPT: &str = concat!(env!("CARGO_BIN_NAME"), "> ");
const SUBCOMMAND_HELP: &str = "encrypt (enc), decrypt (dec), keygen (gen), fingerprint (fp)";

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "\
Command-line interface for FerroCrypt.

File format v1 and primitives:
  Passphrase: Argon2id -> HKDF-SHA3-256 -> XChaCha20-Poly1305
  Public-key: X25519 ECDH -> HKDF-SHA3-256 -> XChaCha20-Poly1305",
    after_help = "\
Examples:
  ferrocrypt encrypt -i secret.txt -o ./encrypted
  ferrocrypt encrypt -i secret.txt -s ./secret.fcr
  ferrocrypt encrypt -i secret.txt -o ./encrypted -p
  ferrocrypt encrypt -i secret.txt -o ./encrypted -k ./keys/public.key
  ferrocrypt encrypt -i secret.txt -o ./encrypted -r fcr1...
  ferrocrypt decrypt -i ./encrypted/secret.fcr -o ./decrypted
  ferrocrypt decrypt -i ./encrypted/secret.fcr -o ./decrypted -K ./keys/private.key
  ferrocrypt keygen  -o ./keys
  ferrocrypt fingerprint ./keys/public.key

Run <command> --help for full options (e.g. ferrocrypt encrypt --help)"
)]
pub struct Cli {
    /// Subcommand to run. If omitted, the CLI starts in interactive mode.
    #[command(subcommand)]
    pub command: Option<CliCommand>,
}

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    #[command(visible_alias = "enc", about = "Encrypt a file or directory")]
    Encrypt {
        #[arg(
            short = 'i',
            long = "input",
            value_name = "INPUT",
            help = "File or directory to encrypt"
        )]
        input: PathBuf,

        #[arg(
            short = 'o',
            long = "output-dir",
            value_name = "DIR",
            conflicts_with = "save_as",
            required_unless_present = "save_as",
            help = "Directory where the encrypted .fcr file will be written"
        )]
        output_dir: Option<PathBuf>,

        #[arg(
            short = 's',
            long = "save-as",
            value_name = "FILE",
            conflicts_with = "output_dir",
            required_unless_present = "output_dir",
            help = "Exact encrypted output file path"
        )]
        save_as: Option<PathBuf>,

        #[arg(
            short = 'p',
            long = "passphrase",
            conflicts_with_all = ["recipient", "public_key"],
            help = "Encrypt with a passphrase (default when no recipient is given)"
        )]
        passphrase: bool,

        #[arg(
            short = 'r',
            long = "recipient",
            value_name = "FCR1",
            action = ArgAction::Append,
            help = "Public recipient string (fcr1...). Repeatable"
        )]
        recipient: Vec<String>,

        #[arg(
            short = 'k',
            long = "public-key",
            value_name = "PUBLIC_KEY_FILE",
            action = ArgAction::Append,
            help = "Public key file. Repeatable"
        )]
        public_key: Vec<PathBuf>,

        #[arg(
            long = "allow-double-encrypt",
            help = "Allow encrypting an input that already looks like a FerroCrypt file"
        )]
        allow_double_encrypt: bool,
    },

    #[command(visible_alias = "dec", about = "Decrypt a .fcr file")]
    Decrypt {
        #[arg(
            short = 'i',
            long = "input",
            value_name = "INPUT",
            help = "Encrypted .fcr file to decrypt"
        )]
        input: PathBuf,

        #[arg(
            short = 'o',
            long = "output-dir",
            value_name = "DIR",
            help = "Directory where decrypted output will be written"
        )]
        output_dir: PathBuf,

        #[arg(
            short = 'K',
            long = "private-key",
            value_name = "PRIVATE_KEY_FILE",
            help = "Private key file (required for public-recipient files)"
        )]
        private_key: Option<PathBuf>,

        #[arg(
            long,
            value_name = "MIB",
            help = "Maximum Argon2id memory cost to accept (MiB)"
        )]
        max_kdf_memory: Option<u32>,
    },

    #[command(visible_alias = "gen", about = "Generate a key pair")]
    Keygen {
        #[arg(
            short = 'o',
            long = "output-dir",
            value_name = "DIR",
            help = "Directory to write private.key and public.key"
        )]
        output_dir: PathBuf,
    },

    #[command(visible_alias = "fp", about = "Show public key fingerprint")]
    Fingerprint {
        #[arg(value_name = "PUBLIC_KEY_FILE", help = "Path to a public key file")]
        public_key_file: PathBuf,
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

fn check_encrypt_conflict(
    input_path: &Path,
    output_dir: Option<&Path>,
    save_as: Option<&Path>,
) -> Result<(), CryptoError> {
    let target = match save_as {
        Some(path) => path.to_path_buf(),
        None => {
            // clap's `required_unless_present` guarantees output_dir is set
            // here when save_as is None; the dispatcher relies on the same
            // invariant when it forwards an empty PathBuf to the library
            // for the save-as path.
            let dir = output_dir.ok_or(CryptoError::InternalInvariant(
                "--output-dir or --save-as required",
            ))?;
            dir.join(default_encrypted_filename(input_path)?)
        }
    };
    if target.exists() {
        return Err(CryptoError::InvalidInput(format!(
            "Already exists: {}",
            target.display()
        )));
    }
    Ok(())
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
    let private_exists = output_dir.join(PRIVATE_KEY_FILENAME).exists();
    let public_exists = output_dir.join(PUBLIC_KEY_FILENAME).exists();
    match (private_exists, public_exists) {
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

/// Cheap probe: does this regular file's first 4 bytes match the FerroCrypt
/// magic? Returns `false` for directories, missing files, and unreadable
/// files — `Encryptor::write` will surface those as typed errors later.
/// The redesign deliberately keeps this off the `Decryptor::open` path so
/// the encrypt flow does not run header validation just to refuse work.
fn input_looks_encrypted(input_path: &Path) -> bool {
    if !input_path.is_file() {
        return false;
    }
    let Ok(mut file) = std::fs::File::open(input_path) else {
        return false;
    };
    let mut magic = [0u8; MAGIC.len()];
    file.read_exact(&mut magic).is_ok() && magic == MAGIC
}

/// Default-deny double-encryption gate. If the input looks like a FerroCrypt
/// file: when the override flag is set, warn and proceed; otherwise prompt
/// y/N on a TTY (default N) or refuse outright on a non-TTY. Mirrors the
/// `read_passphrase` TTY-or-explicit-flag pattern.
fn confirm_or_reject_double_encrypt(
    input_path: &Path,
    allow_double_encrypt: bool,
) -> Result<(), CryptoError> {
    if !input_looks_encrypted(input_path) {
        return Ok(());
    }

    if allow_double_encrypt {
        eprintln!("warning: input appears to already be a FerroCrypt file; encrypting again");
        return Ok(());
    }

    if !stdin().is_terminal() {
        return Err(CryptoError::InvalidInput(
            "refusing to encrypt an existing FerroCrypt file; \
             pass --allow-double-encrypt to confirm"
                .to_string(),
        ));
    }

    eprintln!("warning: input appears to already be a FerroCrypt file");
    eprint!("Encrypt it again (produce a double-encrypted file)? [y/N] ");
    io::stderr().flush().ok();

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(CryptoError::Io)?;
    let trimmed = answer.trim();
    if matches!(trimmed, "y" | "Y") {
        Ok(())
    } else {
        Err(CryptoError::InvalidInput(
            "aborted: refusing to encrypt an existing FerroCrypt file".to_string(),
        ))
    }
}

fn load_encrypt_recipients(
    recipient_strings: Vec<String>,
    public_key_files: Vec<PathBuf>,
) -> Result<Vec<PublicKey>, CryptoError> {
    let mut recipients = Vec::with_capacity(recipient_strings.len() + public_key_files.len());

    for recipient in recipient_strings {
        recipients.push(PublicKey::from_recipient_string(&recipient)?);
    }
    for file in public_key_files {
        recipients.push(PublicKey::from_key_file(file));
    }

    Ok(recipients)
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
        CliCommand::Encrypt {
            input,
            output_dir,
            save_as,
            passphrase: _,
            recipient,
            public_key,
            allow_double_encrypt,
        } => run_encrypt(
            input,
            output_dir,
            save_as,
            recipient,
            public_key,
            allow_double_encrypt,
        ),

        CliCommand::Decrypt {
            input,
            output_dir,
            private_key,
            max_kdf_memory,
        } => run_decrypt(input, output_dir, private_key, max_kdf_memory),

        CliCommand::Keygen { output_dir } => run_keygen(output_dir),
        CliCommand::Fingerprint { public_key_file } => run_fingerprint(public_key_file),
    }
}

fn run_encrypt(
    input: PathBuf,
    output_dir: Option<PathBuf>,
    save_as: Option<PathBuf>,
    recipient: Vec<String>,
    public_key: Vec<PathBuf>,
    allow_double_encrypt: bool,
) -> Result<(), CryptoError> {
    check_encrypt_conflict(&input, output_dir.as_deref(), save_as.as_deref())?;
    confirm_or_reject_double_encrypt(&input, allow_double_encrypt)?;

    let start = std::time::Instant::now();
    let recipients = load_encrypt_recipients(recipient, public_key)?;

    let mut encryptor = if recipients.is_empty() {
        let passphrase = read_passphrase(true)?;
        Encryptor::with_passphrase(passphrase)
    } else {
        for r in &recipients {
            if let Ok(fp) = r.fingerprint() {
                println!("Encrypting to: {fp}");
            }
        }
        Encryptor::with_recipients(recipients)?
    };

    if let Some(save_as_path) = save_as.as_deref() {
        encryptor = encryptor.save_as(save_as_path);
    }

    // When `--save-as` is given the library ignores the output directory;
    // pass an empty PathBuf so the value is still well-typed.
    let library_output_dir = output_dir.unwrap_or_default();

    let output = encryptor
        .write(&input, &library_output_dir, |ev| eprintln!("{ev}"))?
        .output_path;

    print_result(true, &output, start.elapsed());
    Ok(())
}

fn run_decrypt(
    input: PathBuf,
    output_dir: PathBuf,
    private_key: Option<PathBuf>,
    max_kdf_memory: Option<u32>,
) -> Result<(), CryptoError> {
    let start = std::time::Instant::now();
    let limit = max_kdf_memory.map(KdfLimit::from_mib).transpose()?;

    let output = match Decryptor::open(&input)? {
        Decryptor::Passphrase(mut decryptor) => {
            if private_key.is_some() {
                return Err(CryptoError::InvalidInput(
                    "this file is sealed with a passphrase; --private-key is not applicable"
                        .to_string(),
                ));
            }
            if let Some(limit) = limit {
                decryptor = decryptor.kdf_limit(limit);
            }
            let passphrase = read_passphrase(false)?;
            decryptor
                .decrypt(passphrase, &output_dir, |ev| eprintln!("{ev}"))?
                .output_path
        }
        Decryptor::Recipient(mut decryptor) => {
            let private_key = private_key.ok_or_else(|| {
                CryptoError::InvalidInput(
                    "this file is sealed to public-key recipients; --private-key is required"
                        .to_string(),
                )
            })?;
            validate_private_key_file(&private_key)?;
            if let Some(limit) = limit {
                decryptor = decryptor.kdf_limit(limit);
            }
            let passphrase = read_passphrase(false)?;
            decryptor
                .decrypt(
                    PrivateKey::from_key_file(&private_key),
                    passphrase,
                    &output_dir,
                    |ev| eprintln!("{ev}"),
                )?
                .output_path
        }
        _ => {
            return Err(CryptoError::InvalidInput(
                "unsupported FerroCrypt encryption mode".to_string(),
            ));
        }
    };

    print_result(false, &output, start.elapsed());
    Ok(())
}

fn run_keygen(output_dir: PathBuf) -> Result<(), CryptoError> {
    check_keygen_conflict(&output_dir)?;
    let passphrase = read_passphrase(true)?;
    let outcome = generate_key_pair(&output_dir, passphrase, |ev| eprintln!("{ev}"))?;
    let recipient = PublicKey::from_key_file(&outcome.public_key_path).to_recipient_string()?;
    println!("\nGenerated key pair in {}\n", output_dir.display());
    println!("Public key fingerprint: {}", outcome.fingerprint);
    println!("Public key recipient:   {}", recipient);
    Ok(())
}

fn run_fingerprint(public_key_file: PathBuf) -> Result<(), CryptoError> {
    let fp = PublicKey::from_key_file(&public_key_file).fingerprint()?;
    println!("{}", fp);
    Ok(())
}

/// Outcome of dispatching a single REPL input line. The outer interactive
/// loop uses this to decide what to print and whether to continue or exit.
/// Returning a typed outcome instead of printing inline keeps the dispatch
/// logic unit-testable without a TTY.
#[derive(Debug)]
enum ReplOutcome {
    /// User typed `exit` / `quit` (case-insensitive). Loop should break.
    Exit,
    /// Empty or whitespace-only input. Loop should continue silently.
    Empty,
    /// Parse succeeded but no subcommand was given. Unreachable through
    /// normal trimmed input; kept as a defensive fallback in case shell-word
    /// split or the clap parser ever accepts a bare flag-only invocation.
    NoCommand,
    /// Shell-word split failed (unclosed quote, etc).
    ShellError(shell_words::ParseError),
    /// Clap argument parsing failed, or `--help` / `--version` was used
    /// (which clap surfaces via `ErrorKind::DisplayHelp` / `DisplayVersion`).
    ParseError(clap::Error),
    /// Command ran to completion successfully.
    Ran,
    /// Command ran but returned a runtime error.
    Failed(CryptoError),
}

fn is_exit_command(trimmed: &str) -> bool {
    trimmed.eq_ignore_ascii_case("exit") || trimmed.eq_ignore_ascii_case("quit")
}

/// Parses a single line of REPL input and dispatches it. The raw line is
/// trimmed, checked for the `exit` / `quit` sentinels, shell-split, and
/// then fed through the same `Cli` parser as the subcommand entry point.
fn dispatch_repl_line(line: &str) -> ReplOutcome {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return ReplOutcome::Empty;
    }
    if is_exit_command(trimmed) {
        return ReplOutcome::Exit;
    }

    let parts = match shell_words::split(trimmed) {
        Ok(v) => v,
        Err(e) => return ReplOutcome::ShellError(e),
    };

    let args = std::iter::once(BINARY_NAME.to_string()).chain(parts);

    match Cli::try_parse_from(args) {
        Ok(cli) => match cli.command {
            Some(cmd) => match run_command(cmd) {
                Ok(()) => ReplOutcome::Ran,
                Err(e) => ReplOutcome::Failed(e),
            },
            None => ReplOutcome::NoCommand,
        },
        Err(e) => ReplOutcome::ParseError(e),
    }
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
                let trimmed = line.trim();
                if !trimmed.is_empty() && !is_exit_command(trimmed) {
                    if let Err(e) = rl.add_history_entry(trimmed) {
                        eprintln!("Failed to add history entry: {e}");
                    }
                }
                match dispatch_repl_line(&line) {
                    ReplOutcome::Exit => break,
                    ReplOutcome::Empty => {}
                    ReplOutcome::NoCommand => {
                        eprintln!("No command given. Try: {SUBCOMMAND_HELP}");
                    }
                    ReplOutcome::ShellError(e) => eprintln!("Parse error: {e}"),
                    ReplOutcome::ParseError(e) => {
                        if let Err(print_err) = e.print() {
                            eprintln!("Failed to print error: {print_err}");
                        }
                    }
                    ReplOutcome::Ran => {}
                    ReplOutcome::Failed(e) => eprintln!("Error: {e}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_recognized_case_insensitively_and_with_whitespace() {
        for input in ["exit", "quit", "EXIT", "Quit", "  exit  ", "\tquit\n"] {
            assert!(
                matches!(dispatch_repl_line(input), ReplOutcome::Exit),
                "input {input:?} should be Exit"
            );
        }
    }

    #[test]
    fn words_containing_exit_or_quit_are_not_exit() {
        for input in ["exiting", "quitter", "exit now", "goto quit", "unquit"] {
            assert!(
                !matches!(dispatch_repl_line(input), ReplOutcome::Exit),
                "input {input:?} should NOT be Exit"
            );
        }
    }

    #[test]
    fn empty_or_whitespace_is_empty() {
        for input in ["", "   ", "\t", "\n", "\r\n", " \t\n "] {
            assert!(
                matches!(dispatch_repl_line(input), ReplOutcome::Empty),
                "input {input:?} should be Empty"
            );
        }
    }

    #[test]
    fn unclosed_quote_is_shell_error() {
        assert!(matches!(
            dispatch_repl_line("encrypt -i 'unclosed"),
            ReplOutcome::ShellError(_)
        ));
    }

    #[test]
    fn unknown_subcommand_is_parse_error() {
        assert!(matches!(
            dispatch_repl_line("nonexistent-subcommand"),
            ReplOutcome::ParseError(_)
        ));
    }

    #[test]
    fn missing_required_arg_is_parse_error() {
        assert!(matches!(
            dispatch_repl_line("encrypt"),
            ReplOutcome::ParseError(_)
        ));
    }

    #[test]
    fn help_flag_surfaces_as_display_help_kind() {
        match dispatch_repl_line("--help") {
            ReplOutcome::ParseError(e) => {
                assert_eq!(e.kind(), clap::error::ErrorKind::DisplayHelp)
            }
            other => panic!("expected ParseError(DisplayHelp), got {other:?}"),
        }
    }

    #[test]
    fn version_flag_surfaces_as_display_version_kind() {
        match dispatch_repl_line("--version") {
            ReplOutcome::ParseError(e) => {
                assert_eq!(e.kind(), clap::error::ErrorKind::DisplayVersion)
            }
            other => panic!("expected ParseError(DisplayVersion), got {other:?}"),
        }
    }

    #[test]
    fn subcommand_help_surfaces_as_display_help_kind() {
        match dispatch_repl_line("encrypt --help") {
            ReplOutcome::ParseError(e) => {
                assert_eq!(e.kind(), clap::error::ErrorKind::DisplayHelp)
            }
            other => panic!("expected ParseError(DisplayHelp), got {other:?}"),
        }
    }

    /// Builds a process-unique path inside the OS temp dir, shell-quoted
    /// for safe interpolation into a REPL line. Guarantees the path does
    /// not exist at test start and handles temp-dir paths that contain
    /// spaces (e.g. Windows user profiles with spaces).
    fn nonexistent_temp_path_quoted() -> String {
        let path = std::env::temp_dir().join(format!(
            "ferrocrypt-unit-nonexistent-{}",
            std::process::id()
        ));
        shell_words::quote(&path.to_string_lossy()).into_owned()
    }

    #[test]
    fn fingerprint_on_nonexistent_path_is_failed() {
        let line = format!("fp {}", nonexistent_temp_path_quoted());
        match dispatch_repl_line(&line) {
            ReplOutcome::Failed(_) => {}
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
