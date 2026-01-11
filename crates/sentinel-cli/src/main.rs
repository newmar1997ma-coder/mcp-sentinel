//! MCP Sentinel CLI - Command-line interface for the security gateway

use clap::Parser;

#[derive(Parser)]
#[command(name = "sentinel")]
#[command(about = "MCP Sentinel - Active Defense for Model Context Protocol")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Start the sentinel gateway
    Start {
        /// Configuration file path
        #[arg(short, long, default_value = "config/sentinel.toml")]
        config: String,
    },
    /// Check configuration validity
    Check {
        /// Configuration file path
        #[arg(short, long, default_value = "config/sentinel.toml")]
        config: String,
    },
    /// Show sentinel status
    Status,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt::init();

    match cli.command {
        Some(Commands::Start { config }) => {
            println!("Starting MCP Sentinel with config: {}", config);
        }
        Some(Commands::Check { config }) => {
            println!("Checking config: {}", config);
        }
        Some(Commands::Status) => {
            println!("Sentinel status: READY");
        }
        None => {
            println!("MCP Sentinel v0.1.0 - Use --help for commands");
        }
    }

    Ok(())
}
