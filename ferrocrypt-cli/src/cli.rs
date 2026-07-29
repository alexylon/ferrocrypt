use std::io::{self, IsTerminal, Read, Write, stdin};
use std::path::{Path, PathBuf};

use clap::{ArgAction, Args, Parser, Subcommand};
use ferrocrypt::secrecy::{ExposeSecret, SecretString};
use ferrocrypt::{
    ArchiveLimits, CryptoError, Decryptor, Encryptor, IncompleteOutputPolicy, KdfLimit, KdfParams,
    KeyPairGenerator, MAGIC, PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME, PrivateKey, PublicKey,
    default_encrypted_filename, validate_private_key_file,
};
use rpassword::prompt_password;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use subtle::ConstantTimeEq;

const PASSPHRASE_ENV: &str = "FERROCRYPT_PASSPHRASE";

/// Returns the debug-only test-fast Argon2id override for the CLI's
/// `encrypt` (passphrase path) and `keygen` subcommands when the
/// `FERROCRYPT_INTERNAL_TEST_FAST_KDF` env var requests it, otherwise
/// `None` so the caller uses the floored [`KdfParams::default`]. The
/// override sits at the writer's production memory floor, so the caller
/// applies it through the ordinary `kdf_params` builder.
///
/// All override-related state — env-var name, activation value, and the
/// fast Argon2id triple — lives inside the `cfg(debug_assertions)` scope, so
/// a standard release build, which leaves `debug_assertions` at its
/// release-profile default of off, compiles the branch out entirely: the env
/// var has no effect there and there is no live reference to the fast triple.
/// The boundary is `debug_assertions`, not the profile name, so a non-default
/// `[profile.release] debug-assertions = true` would keep the branch;
/// production builds MUST use the default release profile and MUST NOT set the
/// env var. Aligned with `ferrocrypt-test-support::fast_kdf_params` and the
/// lib's internal `KdfParams::test_fast_default` (values 19 MiB / 1 / 4).
fn test_fast_kdf_override() -> Option<KdfParams> {
    #[cfg(debug_assertions)]
    {
        const INTERNAL_TEST_FAST_KDF_ENV: &str = "FERROCRYPT_INTERNAL_TEST_FAST_KDF";
        const INTERNAL_TEST_FAST_KDF_VALUE: &str = "1";
        // Local copies, deliberately. The single source of truth for the
        // test-fast-KDF triple lives in `ferrocrypt-test-support`, but
        // that crate is `publish = false` and Cargo refuses to publish a
        // crate whose regular dep tree includes a non-publishable
        // workspace member. `ferrocrypt-cli` is `publish = true`, so it
        // cannot take a regular dep on `ferrocrypt-test-support`. Keep
        // these aligned with `ferrocrypt-test-support::TEST_FAST_KDF_*`.
        const TEST_FAST_KDF_MEM_COST: u32 = 19 * 1024;
        const TEST_FAST_KDF_TIME_COST: u32 = 1;
        const TEST_FAST_KDF_LANES: u32 = 4;

        if std::env::var(INTERNAL_TEST_FAST_KDF_ENV).as_deref() == Ok(INTERNAL_TEST_FAST_KDF_VALUE)
        {
            eprintln!(
                "warning: {INTERNAL_TEST_FAST_KDF_ENV} is set; using fast \
                 Argon2id parameters. This is for in-tree CLI tests only and \
                 has no effect in release builds. Do not use this in production."
            );
            return Some(KdfParams {
                mem_cost: TEST_FAST_KDF_MEM_COST,
                time_cost: TEST_FAST_KDF_TIME_COST,
                lanes: TEST_FAST_KDF_LANES,
            });
        }
    }
    None
}

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");
const INTERACTIVE_PROMPT: &str = concat!(env!("CARGO_BIN_NAME"), "> ");
const SUBCOMMAND_HELP: &str = "encrypt (enc), decrypt (dec), keygen (gen), fingerprint (fp)";

// Shared by both double-encrypt refusal paths (no TTY and interactive decline)
// so they report the same wording and the same override hint.
const DOUBLE_ENCRYPT_REFUSAL: &str = "Refusing to encrypt an existing FerroCrypt file; \
     pass --allow-double-encrypt to confirm";

/// Writes a line to stdout, tolerating a reader that has closed the pipe.
///
/// `println!` panics when a write to stdout fails, and Rust's runtime leaves
/// `SIGPIPE` ignored, so piping a command into a reader that exits early — for
/// example `ferrocrypt fingerprint key.pub | head` — would otherwise abort
/// with a panic. A closed reader is a normal outcome, not a failure: a
/// `BrokenPipe` write is dropped so the command still runs to completion and
/// exits on its own status. Any other stdout error keeps `println!`'s loud
/// behavior, since it signals a genuine problem worth surfacing.
fn print_stdout_line(args: std::fmt::Arguments) {
    let mut stdout = io::stdout().lock();
    if let Err(e) = writeln!(stdout, "{args}") {
        if e.kind() != io::ErrorKind::BrokenPipe {
            panic!("failed printing to stdout: {e}");
        }
    }
}

/// `println!` for stdout that does not panic when the reader has closed the
/// pipe. Routes every line through [`print_stdout_line`] so the broken-pipe
/// handling lives in one place; use it for all stdout output.
macro_rules! outln {
    () => { print_stdout_line(format_args!("")) };
    ($($arg:tt)*) => { print_stdout_line(format_args!($($arg)*)) };
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "\
Command-line interface for FerroCrypt.

File format and primitives:
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

/// Bytes in one mebibyte. `--max-archive-size` and
/// `--max-archive-manifest` are given in MiB, because the byte counts
/// behind them are too long to type comfortably.
const BYTES_PER_MIB: u32 = 1024 * 1024;

/// Converts a MiB flag value into a byte count for a cap of type `T`,
/// rejecting a value the cap cannot hold. Mirrors [`KdfLimit::from_mib`],
/// so every MiB flag refuses an out-of-range number instead of quietly
/// applying a cap the caller did not ask for. `label` names the cap in the
/// rejection.
fn mib_to_bytes<T: TryFrom<u64>>(label: &str, mib: u64) -> Result<T, CryptoError> {
    mib.checked_mul(u64::from(BYTES_PER_MIB))
        .and_then(|bytes| T::try_from(bytes).ok())
        .ok_or_else(|| CryptoError::InvalidInput(format!("{label} limit overflow: {mib} MiB")))
}

/// Caps on the size and shape of the archive inside a `.fcr` file, set by
/// both `encrypt` and `decrypt`.
///
/// Both sides apply the same caps, so a tree encrypted with a raised cap
/// needs the same flag on the matching decrypt. Every default is read from
/// [`ArchiveLimits`], so the value clap shows in `--help` is the library's
/// own and cannot drift from it.
///
/// The remaining [`ArchiveLimits`] caps bound the extension regions
/// reserved for future format revisions. Nothing this release writes fills
/// them, so they stay library-only rather than becoming flags no run can
/// reach.
#[derive(Args, Debug, Clone, Copy)]
// `about = None` stops clap lifting the doc comment above over the `about`
// of whichever subcommand flattens this group.
#[command(about = None, long_about = None, next_help_heading = "Archive limits")]
pub struct ArchiveLimitArgs {
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = ArchiveLimits::ENTRY_COUNT_DEFAULT,
        help = "Maximum number of files and directories in one archive"
    )]
    max_archive_entries: u32,

    #[arg(
        long,
        value_name = "MIB",
        default_value_t = ArchiveLimits::TOTAL_PLAINTEXT_BYTES_DEFAULT / u64::from(BYTES_PER_MIB),
        help = "Maximum combined size of the files in one archive (MiB)"
    )]
    max_archive_size: u64,

    #[arg(
        long,
        value_name = "COMPONENTS",
        default_value_t = ArchiveLimits::PATH_DEPTH_DEFAULT,
        help = "Maximum number of components in one archived path"
    )]
    max_archive_path_depth: u32,

    #[arg(
        long,
        value_name = "BYTES",
        default_value_t = ArchiveLimits::PATH_BYTES_DEFAULT,
        help = "Maximum length of one archived path (bytes)"
    )]
    max_archive_path_bytes: u32,

    #[arg(
        long,
        value_name = "MIB",
        default_value_t = ArchiveLimits::MANIFEST_BYTES_DEFAULT / BYTES_PER_MIB,
        help = "Maximum size of the archive manifest, the list of archived paths (MiB)"
    )]
    max_archive_manifest: u32,
}

impl ArchiveLimitArgs {
    /// Builds the [`ArchiveLimits`] these flags describe, rejecting a MiB
    /// value whose byte count the cap cannot hold.
    fn to_limits(self) -> Result<ArchiveLimits, CryptoError> {
        Ok(ArchiveLimits::default()
            .max_entry_count(self.max_archive_entries)
            .max_total_plaintext_bytes(mib_to_bytes("Archive size", self.max_archive_size)?)
            .max_path_depth(self.max_archive_path_depth)
            .max_path_bytes(self.max_archive_path_bytes)
            .max_manifest_bytes(mib_to_bytes(
                "Archive manifest",
                u64::from(self.max_archive_manifest),
            )?))
    }
}

/// Caps on the Argon2id parameters `decrypt` will accept from a file.
#[derive(Args, Debug, Clone, Copy)]
// `about = None` for the reason given on `ArchiveLimitArgs`.
#[command(about = None, long_about = None, next_help_heading = "Passphrase limits")]
pub struct KdfLimitArgs {
    #[arg(
        long,
        value_name = "MIB",
        help = "Maximum Argon2id memory cost to accept (MiB). When omitted, the limit is 1 GiB; 0 rejects every file"
    )]
    max_kdf_memory: Option<u32>,

    #[arg(
        long,
        value_name = "ITERATIONS",
        help = "Maximum Argon2id time cost (iteration count) to accept. When omitted, the limit is the format maximum; 0 rejects every file"
    )]
    max_kdf_time_cost: Option<u32>,

    #[arg(
        long,
        value_name = "LANES",
        help = "Maximum Argon2id lane count (parallelism) to accept. When omitted, the limit is the format maximum; 0 rejects every file"
    )]
    max_kdf_lanes: Option<u32>,
}

impl KdfLimitArgs {
    /// Builds the decrypt-side [`KdfLimit`] these flags describe. Returns
    /// `None` when no flag is set, so the library default applies. When any
    /// flag is set, memory starts from `--max-kdf-memory` (or the 1 GiB
    /// default) and `--max-kdf-time-cost` / `--max-kdf-lanes` tighten the
    /// time-cost and lane caps. An unset time-cost or lane cap stays at the
    /// format maximum and so rejects nothing the structural check would not;
    /// an unset memory cap stays at the 1 GiB default, below the 2 GiB
    /// structural maximum, so it still rejects a header that asks for more
    /// than 1 GiB.
    fn to_limit(self) -> Result<Option<KdfLimit>, CryptoError> {
        if self.max_kdf_memory.is_none()
            && self.max_kdf_time_cost.is_none()
            && self.max_kdf_lanes.is_none()
        {
            return Ok(None);
        }
        let mut limit = match self.max_kdf_memory {
            Some(mib) => KdfLimit::from_mib(mib)?,
            None => KdfLimit::default(),
        };
        if let Some(time_cost) = self.max_kdf_time_cost {
            limit = limit.with_max_time_cost(time_cost);
        }
        if let Some(lanes) = self.max_kdf_lanes {
            limit = limit.with_max_lanes(lanes);
        }
        Ok(Some(limit))
    }
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

        #[command(flatten)]
        archive_limits: ArchiveLimitArgs,
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
            help = "Private key file (required for public-key files)"
        )]
        private_key: Option<PathBuf>,

        #[arg(
            long = "keep-partial",
            help = "Keep the .incomplete staged plaintext on decrypt failure (forensic / recovery use)"
        )]
        keep_partial: bool,

        // Both groups carry their own help heading, and clap applies a
        // heading to every argument that follows it, so they come last.
        #[command(flatten)]
        kdf_limits: KdfLimitArgs,

        #[command(flatten)]
        archive_limits: ArchiveLimitArgs,
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
/// The variable is read but not unset, so it stays readable by other local
/// processes of the same user (for example via `ps eww` or
/// `/proc/<pid>/environ`) for the process lifetime — the usual tradeoff of
/// passing a secret through the environment. Prefer the interactive prompt
/// when that visibility matters.
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

/// Reports whether a directory entry already exists at `path`, treating a
/// symlink — including a dangling one — as occupied. Unlike [`Path::exists`],
/// this does not follow the link, so a broken symlink at an intended output
/// path is caught here as a conflict, failing fast before any passphrase
/// prompt, rather than slipping past to the library's no-clobber guard.
fn path_occupied(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
}

/// Where an `encrypt` run writes its output. `--output-dir` and `--save-as`
/// are mutually exclusive and jointly required, so exactly one of the pair is
/// present once arguments are parsed. Holding that in one value keeps the
/// rest of the encrypt path from having to reason about the two combinations
/// clap rejects.
enum EncryptTarget {
    /// `--output-dir`: the file name is derived from the input.
    Dir(PathBuf),
    /// `--save-as`: the exact output path.
    File(PathBuf),
}

impl EncryptTarget {
    /// Narrows the parsed pair to the single target. `--save-as` wins if both
    /// are somehow present, and neither is a usage error — the same one clap
    /// reports before this is reached, restated here so the guarantee is
    /// enforced rather than assumed.
    fn from_args(
        output_dir: Option<PathBuf>,
        save_as: Option<PathBuf>,
    ) -> Result<Self, CryptoError> {
        match (save_as, output_dir) {
            (Some(file), _) => Ok(Self::File(file)),
            (None, Some(dir)) => Ok(Self::Dir(dir)),
            (None, None) => Err(CryptoError::InvalidInput(
                "Either --output-dir or --save-as is required".to_string(),
            )),
        }
    }

    /// Output directory to hand the library. `--save-as` supplies the whole
    /// path through `Encryptor::save_as`, and the library ignores this value
    /// in that case, so an empty path keeps the argument well-typed.
    fn library_output_dir(&self) -> &Path {
        match self {
            Self::Dir(dir) => dir,
            Self::File(_) => Path::new(""),
        }
    }
}

fn check_encrypt_conflict(input_path: &Path, target: &EncryptTarget) -> Result<(), CryptoError> {
    let target = match target {
        EncryptTarget::File(path) => path.clone(),
        EncryptTarget::Dir(dir) => dir.join(default_encrypted_filename(input_path)?),
    };
    if path_occupied(&target) {
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
    outln!(
        "\n{} {} in {}\n",
        action,
        output.display(),
        format_duration(elapsed)
    );
}

fn check_keygen_conflict(output_dir: &Path) -> Result<(), CryptoError> {
    let private_exists = path_occupied(&output_dir.join(PRIVATE_KEY_FILENAME));
    let public_exists = path_occupied(&output_dir.join(PUBLIC_KEY_FILENAME));
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
            DOUBLE_ENCRYPT_REFUSAL.to_string(),
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
    if trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err(CryptoError::InvalidInput(
            DOUBLE_ENCRYPT_REFUSAL.to_string(),
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
            archive_limits,
        } => run_encrypt(
            input,
            EncryptTarget::from_args(output_dir, save_as)?,
            recipient,
            public_key,
            allow_double_encrypt,
            archive_limits,
        ),

        CliCommand::Decrypt {
            input,
            output_dir,
            private_key,
            kdf_limits,
            archive_limits,
            keep_partial,
        } => run_decrypt(
            input,
            output_dir,
            private_key,
            kdf_limits,
            archive_limits,
            keep_partial,
        ),

        CliCommand::Keygen { output_dir } => run_keygen(output_dir),
        CliCommand::Fingerprint { public_key_file } => run_fingerprint(public_key_file),
    }
}

fn run_encrypt(
    input: PathBuf,
    target: EncryptTarget,
    recipient: Vec<String>,
    public_key: Vec<PathBuf>,
    allow_double_encrypt: bool,
    archive_limits: ArchiveLimitArgs,
) -> Result<(), CryptoError> {
    // Ahead of the conflict check and the passphrase prompt: an unusable
    // flag value is a usage error and must not cost the user either.
    let archive_limits = archive_limits.to_limits()?;
    check_encrypt_conflict(&input, &target)?;
    confirm_or_reject_double_encrypt(&input, allow_double_encrypt)?;

    let start = std::time::Instant::now();
    let recipients = load_encrypt_recipients(recipient, public_key)?;

    let mut encryptor = if recipients.is_empty() {
        let passphrase = read_passphrase(true)?;
        let enc = Encryptor::with_passphrase(passphrase);
        match test_fast_kdf_override() {
            Some(fast) => enc.kdf_params(fast),
            None => enc,
        }
    } else {
        for r in &recipients {
            if let Ok(fp) = r.fingerprint() {
                outln!("Encrypting to: {fp}");
            }
        }
        Encryptor::with_public_keys(recipients)?
    };

    encryptor = encryptor.archive_limits(archive_limits);

    if let EncryptTarget::File(save_as_path) = &target {
        encryptor = encryptor.save_as(save_as_path);
    }

    let output = encryptor
        .write(&input, target.library_output_dir(), |ev| eprintln!("{ev}"))?
        .output_path;

    print_result(true, &output, start.elapsed());
    Ok(())
}

fn run_decrypt(
    input: PathBuf,
    output_dir: PathBuf,
    private_key: Option<PathBuf>,
    kdf_limits: KdfLimitArgs,
    archive_limits: ArchiveLimitArgs,
    keep_partial: bool,
) -> Result<(), CryptoError> {
    let start = std::time::Instant::now();
    let limit = kdf_limits.to_limit()?;
    let archive_limits = archive_limits.to_limits()?;
    let policy = if keep_partial {
        IncompleteOutputPolicy::RetainOnError
    } else {
        IncompleteOutputPolicy::DeleteOnError
    };

    let output = match Decryptor::open(&input)? {
        Decryptor::Passphrase(mut decryptor) => {
            if private_key.is_some() {
                return Err(CryptoError::InvalidInput(
                    "This file is sealed with a passphrase; --private-key is not applicable"
                        .to_string(),
                ));
            }
            if let Some(limit) = limit {
                decryptor = decryptor.kdf_limit(limit);
            }
            decryptor = decryptor
                .archive_limits(archive_limits)
                .incomplete_output_policy(policy);
            let passphrase = read_passphrase(false)?;
            decryptor
                .decrypt(passphrase, &output_dir, |ev| eprintln!("{ev}"))?
                .output_path
        }
        Decryptor::PrivateKey(mut decryptor) => {
            let private_key = private_key.ok_or_else(|| {
                CryptoError::InvalidInput(
                    "This file is sealed to public-key recipients; --private-key is required"
                        .to_string(),
                )
            })?;
            validate_private_key_file(&private_key)?;
            if let Some(limit) = limit {
                decryptor = decryptor.kdf_limit(limit);
            }
            decryptor = decryptor
                .archive_limits(archive_limits)
                .incomplete_output_policy(policy);
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
                "Unsupported FerroCrypt encryption mode".to_string(),
            ));
        }
    };

    print_result(false, &output, start.elapsed());
    Ok(())
}

fn run_keygen(output_dir: PathBuf) -> Result<(), CryptoError> {
    check_keygen_conflict(&output_dir)?;
    let passphrase = read_passphrase(true)?;
    let generator = KeyPairGenerator::with_passphrase(passphrase);
    let generator = match test_fast_kdf_override() {
        Some(fast) => generator.kdf_params(fast),
        None => generator,
    };
    let outcome = generator.write(&output_dir, |ev| eprintln!("{ev}"))?;
    let recipient = PublicKey::from_key_file(&outcome.public_key_path).to_recipient_string()?;
    outln!("\nGenerated key pair in {}\n", output_dir.display());
    outln!("Public key fingerprint: {}", outcome.fingerprint);
    outln!("Public key recipient:   {}", recipient);
    Ok(())
}

fn run_fingerprint(public_key_file: PathBuf) -> Result<(), CryptoError> {
    let fp = PublicKey::from_key_file(&public_key_file).fingerprint()?;
    outln!("{}", fp);
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
    /// normal input — a line that shell-word-splits to nothing (blank or a
    /// `#` comment) returns [`ReplOutcome::Empty`] first — but kept as a
    /// defensive fallback in case the clap parser ever accepts an invocation
    /// with no subcommand.
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
    // A line that is entirely a `#` comment splits to nothing; ignore it like
    // a blank line rather than reporting a missing command.
    if parts.is_empty() {
        return ReplOutcome::Empty;
    }

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
    outln!("\nFerroCrypt interactive mode\n");
    outln!("Commands: {SUBCOMMAND_HELP}, quit\n");

    let mut rl = match DefaultEditor::new() {
        Ok(editor) => editor,
        Err(e) => {
            return Err(CryptoError::Io(io::Error::other(format!(
                "Failed to initialize line editor: {e}"
            ))));
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
                outln!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                outln!();
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

    fn kdf_args(
        max_kdf_memory: Option<u32>,
        max_kdf_time_cost: Option<u32>,
        max_kdf_lanes: Option<u32>,
    ) -> KdfLimitArgs {
        KdfLimitArgs {
            max_kdf_memory,
            max_kdf_time_cost,
            max_kdf_lanes,
        }
    }

    /// `KdfLimitArgs::to_limit` maps the optional `--max-kdf-*` flags onto a
    /// single `KdfLimit`: no flag yields `None` (library default applies),
    /// and any flag fills the unset dimensions from the default so only the
    /// named caps are tightened.
    #[test]
    fn kdf_limit_args_map_flags_onto_one_limit() {
        assert_eq!(kdf_args(None, None, None).to_limit().unwrap(), None);

        let default = KdfLimit::default();

        let mem_only = kdf_args(Some(512), None, None).to_limit().unwrap().unwrap();
        assert_eq!(mem_only.max_mem_cost_kib, 512 * 1024);
        assert_eq!(mem_only.max_time_cost, default.max_time_cost);
        assert_eq!(mem_only.max_lanes, default.max_lanes);

        let time_only = kdf_args(None, Some(3), None).to_limit().unwrap().unwrap();
        assert_eq!(time_only.max_mem_cost_kib, default.max_mem_cost_kib);
        assert_eq!(time_only.max_time_cost, 3);
        assert_eq!(time_only.max_lanes, default.max_lanes);

        let lanes_only = kdf_args(None, None, Some(2)).to_limit().unwrap().unwrap();
        assert_eq!(lanes_only.max_mem_cost_kib, default.max_mem_cost_kib);
        assert_eq!(lanes_only.max_time_cost, default.max_time_cost);
        assert_eq!(lanes_only.max_lanes, 2);

        let all = kdf_args(Some(256), Some(2), Some(1))
            .to_limit()
            .unwrap()
            .unwrap();
        assert_eq!(all.max_mem_cost_kib, 256 * 1024);
        assert_eq!(all.max_time_cost, 2);
        assert_eq!(all.max_lanes, 1);
    }

    /// Parses a command line the way the binary does, so the assertions
    /// below cover the clap defaults as well as the mapping.
    fn archive_args(line: &str) -> ArchiveLimitArgs {
        let args = std::iter::once(BINARY_NAME.to_string())
            .chain(shell_words::split(line).expect("test command line must split"));
        match Cli::try_parse_from(args).expect("test command line must parse") {
            Cli {
                command: Some(CliCommand::Encrypt { archive_limits, .. }),
            } => archive_limits,
            other => panic!("expected an encrypt command, got {other:?}"),
        }
    }

    /// Left alone, the flags reproduce the library defaults exactly, so a
    /// run that names none of them behaves as if the CLI never set any cap.
    #[test]
    fn archive_limit_args_default_to_the_library_limits() {
        let parsed = archive_args("encrypt -i in -o out");
        assert_eq!(parsed.to_limits().unwrap(), ArchiveLimits::default());
    }

    /// Each flag replaces exactly one cap and leaves the rest at their
    /// defaults, and the two MiB flags are converted to bytes.
    #[test]
    fn archive_limit_args_map_flags_onto_one_limit() {
        let parsed = archive_args(
            "encrypt -i in -o out --max-archive-entries 400000 --max-archive-size 128 \
             --max-archive-path-depth 128 --max-archive-path-bytes 8192 \
             --max-archive-manifest 256",
        );
        assert_eq!(
            parsed.to_limits().unwrap(),
            ArchiveLimits::default()
                .max_entry_count(400_000)
                .max_total_plaintext_bytes(128 * 1024 * 1024)
                .max_path_depth(128)
                .max_path_bytes(8192)
                .max_manifest_bytes(256 * 1024 * 1024)
        );
    }

    /// A MiB value whose byte count the cap cannot hold is refused, like
    /// `--max-kdf-memory` refuses one, rather than quietly applying a cap
    /// the caller did not ask for. Both flags are checked at their exact
    /// boundary: the largest accepted value, then one MiB more.
    #[test]
    fn archive_limit_args_reject_an_out_of_range_size() {
        let size_max = u64::MAX / u64::from(BYTES_PER_MIB);
        assert!(
            archive_args(&format!(
                "encrypt -i in -o out --max-archive-size {size_max}"
            ))
            .to_limits()
            .is_ok()
        );
        match archive_args(&format!(
            "encrypt -i in -o out --max-archive-size {}",
            size_max + 1
        ))
        .to_limits()
        {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(
                    msg.starts_with("Archive size limit overflow: "),
                    "got: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        let manifest_max = u32::MAX / BYTES_PER_MIB;
        assert!(
            archive_args(&format!(
                "encrypt -i in -o out --max-archive-manifest {manifest_max}"
            ))
            .to_limits()
            .is_ok()
        );
        match archive_args(&format!(
            "encrypt -i in -o out --max-archive-manifest {}",
            manifest_max + 1
        ))
        .to_limits()
        {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(
                    msg.starts_with("Archive manifest limit overflow: "),
                    "got: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    /// `EncryptTarget::from_args` narrows the two mutually exclusive output
    /// flags to one target. `--save-as` wins if both reach it, and neither
    /// present is a usage rejection — clap reports that first, so this arm is
    /// unreachable through the command line and only a unit test can cover it.
    #[test]
    fn encrypt_target_narrows_the_output_flags() {
        let dir = PathBuf::from("out");
        let file = PathBuf::from("out/exact.fcr");

        assert!(matches!(
            EncryptTarget::from_args(Some(dir.clone()), None),
            Ok(EncryptTarget::Dir(d)) if d == dir
        ));
        assert!(matches!(
            EncryptTarget::from_args(None, Some(file.clone())),
            Ok(EncryptTarget::File(f)) if f == file
        ));
        assert!(matches!(
            EncryptTarget::from_args(Some(dir), Some(file.clone())),
            Ok(EncryptTarget::File(f)) if f == file
        ));

        match EncryptTarget::from_args(None, None) {
            Err(CryptoError::InvalidInput(msg)) => {
                assert_eq!(msg, "Either --output-dir or --save-as is required");
            }
            Err(other) => panic!("expected InvalidInput, got {other:?}"),
            Ok(_) => panic!("expected a rejection when neither flag is present"),
        }
    }

    /// The library takes an output directory on both routes and ignores it
    /// when `--save-as` supplied the whole path, so that route hands it an
    /// empty path rather than inventing a directory.
    #[test]
    fn encrypt_target_supplies_the_library_output_dir() {
        assert_eq!(
            EncryptTarget::Dir(PathBuf::from("out")).library_output_dir(),
            Path::new("out")
        );
        assert_eq!(
            EncryptTarget::File(PathBuf::from("out/exact.fcr")).library_output_dir(),
            Path::new("")
        );
    }

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
    fn comment_only_line_is_empty() {
        for input in ["#", "# a comment", "   # indented", "## still a comment"] {
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
