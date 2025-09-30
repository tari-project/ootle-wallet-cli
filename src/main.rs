use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ootle-wallet-cli")]
#[command(about = "A CLI tool for Ootle wallet operations")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new wallet
    Create {
        /// Name of the wallet
        #[arg(short, long)]
        name: String,
        /// Optional password for the wallet
        #[arg(short, long)]
        password: Option<String>,
    },
    /// List all wallets
    List,
    /// Get wallet balance
    Balance {
        /// Name of the wallet
        #[arg(short, long)]
        name: String,
    },
    /// Send funds from wallet
    Send {
        /// Source wallet name
        #[arg(short, long)]
        from: String,
        /// Destination address
        #[arg(short, long)]
        to: String,
        /// Amount to send
        #[arg(short, long)]
        amount: f64,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Create { name, password }) => {
            println!("Creating wallet: {}", name);
            if let Some(_pwd) = password {
                println!("With password protection");
            } else {
                println!("Without password protection");
            }
        }
        Some(Commands::List) => {
            println!("Listing all wallets:");
            println!("  - wallet1 (active)");
            println!("  - wallet2");
        }
        Some(Commands::Balance { name }) => {
            println!("Balance for wallet '{}': 1000.00 TARI", name);
        }
        Some(Commands::Send { from, to, amount }) => {
            println!("Sending {} TARI from '{}' to '{}'", amount, from, to);
        }
        None => {
            println!("Ootle Wallet CLI - Use --help for usage information");
        }
    }
}
