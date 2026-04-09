use std::path::Path;

use clap::{Parser, Subcommand};
use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    CryptoError, detect_encryption_mode, generate_key_pair, hybrid_auto, public_key_fingerprint,
    symmetric_auto, validate_secret_key_file,
};

use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Subcommand to run. If omitted, the CLI starts in interactive mode.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[command(alias = "gen")]
    Keygen {
        #[arg(short, long)]
        outpath: String,

        #[arg(short, long)]
        passphrase: String,
    },

    #[command(alias = "hyb")]
    Hybrid {
        #[arg(short, long)]
        inpath: String,

        #[arg(short, long)]
        outpath: String,

        #[arg(short, long)]
        key: String,

        #[arg(short, long, default_value = "")]
        passphrase: String,

        #[arg(
            short,
            long,
            help = "Save encrypted output to this file path (encrypt only)"
        )]
        save_as: Option<String>,
    },

    #[command(alias = "fp")]
    Fingerprint {
        #[arg(help = "Path to a public key file")]
        key_file: String,
    },

    #[command(alias = "sym")]
    Symmetric {
        #[arg(short, long)]
        inpath: String,

        #[arg(short, long)]
        outpath: String,

        #[arg(short, long)]
        passphrase: String,

        #[arg(
            short,
            long,
            help = "Save encrypted output to this file path (encrypt only)"
        )]
        save_as: Option<String>,
    },
}

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 60.0 {
        format!("{secs:.2} sec")
    } else {
        format!("{} min, {:.2} sec", secs as u32 / 60, secs % 60.0)
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

fn run_command(cmd: Command) -> Result<(), CryptoError> {
    match cmd {
        Command::Keygen {
            outpath,
            passphrase,
        } => {
            let outpath = Path::new(&outpath);
            let passphrase = SecretString::from(passphrase);
            let info = generate_key_pair(&passphrase, outpath, |msg| eprintln!("{msg}"))?;
            println!("\nGenerated key pair in {}\n", outpath.display());
            println!("Public key fingerprint: {}", info.fingerprint);
        }

        Command::Fingerprint { key_file } => {
            let fp = public_key_fingerprint(Path::new(&key_file))?;
            println!("{}", fp);
        }

        Command::Hybrid {
            inpath,
            outpath,
            key,
            passphrase,
            save_as,
        } => {
            let inpath = Path::new(&inpath);
            let outpath = Path::new(&outpath);
            let key = Path::new(&key);
            let is_encrypt = detect_encryption_mode(inpath)?.is_none();
            if is_encrypt {
                if let Ok(fp) = public_key_fingerprint(key) {
                    println!("Encrypting to: {}", fp);
                }
            } else {
                validate_secret_key_file(key)?;
            }
            let passphrase = SecretString::from(passphrase);
            let start = std::time::Instant::now();
            let output = hybrid_auto(
                inpath,
                outpath,
                key,
                &passphrase,
                save_as.as_deref().map(Path::new),
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

        Command::Symmetric {
            inpath,
            outpath,
            passphrase,
            save_as,
        } => {
            let inpath = Path::new(&inpath);
            let outpath = Path::new(&outpath);
            let is_encrypt = detect_encryption_mode(inpath)?.is_none();
            let passphrase = SecretString::from(passphrase);
            let start = std::time::Instant::now();
            let output = symmetric_auto(
                inpath,
                outpath,
                &passphrase,
                save_as.as_deref().map(Path::new),
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
    println!("Commands: symmetric (sym), hybrid (hyb), keygen (gen), fingerprint (fp), quit\n");

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
                                "No command given. Try: symmetric (sym), hybrid (hyb), keygen (gen)"
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
