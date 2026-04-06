use clap::{Parser, Subcommand};
use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    CryptoError, detect_encryption_mode, generate_key_pair, hybrid_encryption,
    public_key_fingerprint, symmetric_encryption,
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
            let passphrase = SecretString::from(passphrase);
            generate_key_pair(&passphrase, &outpath, |_| {})?;
            let pub_key = std::path::Path::new(&outpath)
                .join("public.key")
                .to_string_lossy()
                .to_string();
            match public_key_fingerprint(&pub_key) {
                Ok(fp) => println!("Public key fingerprint: {}", fp),
                Err(e) => eprintln!("Warning: could not compute fingerprint: {}", e),
            }
        }

        Command::Fingerprint { key_file } => {
            let fp = public_key_fingerprint(&key_file)?;
            println!("{}", fp);
        }

        Command::Hybrid {
            inpath,
            outpath,
            key,
            passphrase,
            save_as,
        } => {
            // Only print fingerprint when encrypting (input is not an .fcr file)
            if detect_encryption_mode(&inpath).is_none() {
                if let Ok(fp) = public_key_fingerprint(&key) {
                    println!("Encrypting to: {}", fp);
                }
            }
            let passphrase = SecretString::from(passphrase);
            hybrid_encryption(
                &inpath,
                &outpath,
                &key,
                &passphrase,
                save_as.as_deref(),
                |_| {},
            )?;
        }

        Command::Symmetric {
            inpath,
            outpath,
            passphrase,
            save_as,
        } => {
            let passphrase = SecretString::from(passphrase);
            symmetric_encryption(&inpath, &outpath, &passphrase, save_as.as_deref(), |_| {})?;
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

                let args = std::iter::once("ferrocrypt".to_string()).chain(parts.into_iter());

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
