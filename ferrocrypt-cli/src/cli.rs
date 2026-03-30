use clap::{Parser, Subcommand};
use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    CryptoError, generate_asymmetric_key_pair, hybrid_encryption, symmetric_encryption,
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
    Keygen {
        #[arg(short, long)]
        outpath: String,

        #[arg(short, long)]
        passphrase: String,

        #[arg(short = 'b', long, default_value_t = 4096)]
        bit_size: u32,
    },

    Hybrid {
        #[arg(short, long)]
        inpath: String,

        #[arg(short, long)]
        outpath: String,

        #[arg(short, long)]
        key: String,

        #[arg(short, long, default_value = "")]
        passphrase: String,
    },

    Symmetric {
        #[arg(short, long)]
        inpath: String,

        #[arg(short, long)]
        outpath: String,

        #[arg(short, long)]
        passphrase: String,
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
            bit_size,
        } => {
            let passphrase = SecretString::from(passphrase);
            generate_asymmetric_key_pair(bit_size, &passphrase, &outpath)?;
        }

        Command::Hybrid {
            inpath,
            outpath,
            key,
            passphrase,
        } => {
            let passphrase = SecretString::from(passphrase);
            hybrid_encryption(&inpath, &outpath, &key, &passphrase)?;
        }

        Command::Symmetric {
            inpath,
            outpath,
            passphrase,
        } => {
            let passphrase = SecretString::from(passphrase);
            symmetric_encryption(&inpath, &outpath, &passphrase)?;
        }
    }

    Ok(())
}

fn interactive_mode() -> Result<(), CryptoError> {
    println!("\nFerrocrypt interactive mode\n");
    println!("Type `keygen`, `hybrid`, or `symmetric` with flags, or `quit` to exit.\n");

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
                            eprintln!("No command given. Try: keygen, hybrid, symmetric");
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
