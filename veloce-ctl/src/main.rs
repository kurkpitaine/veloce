mod commands;

use std::ffi::OsString;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "velocectl")]
#[command(about = "Query or send commands to the Veloce V2X stack", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Manage the local PKI configuration
    #[command(subcommand)]
    Pki(PkiArgs),
}

#[derive(Debug, Subcommand)]
enum PkiArgs {
    /// Create a PKI configuration or reinitialize an existing one
    #[command(subcommand)]
    Init(PkiInitArgs),
}

#[derive(Debug, Subcommand)]
enum PkiInitArgs {
    /// Automatically initialize the PKI configuration from ECTL.
    Auto {
        /// The canonical name of the local ITS Station, which should be registered into the PKI.
        canonical_name: OsString,

        /// The URL of the European C-ITS Point Of Contact server.
        #[arg(long, default_value = Some("https://cpoc.jrc.ec.europa.eu/L0/"))]
        cpoc_url: Option<OsString>,
    },
    /// Manually initialize the PKI configuration.
    Manual {
        /// The canonical name of the local ITS Station, which should be registered into the PKI
        canonical_name: OsString,

        /// The URL of the Enrollment Authority server.
        #[arg(long = "ea-url")]
        ea: OsString,

        /// The URL of the Authorization Authority server.
        #[arg(long = "aa-url")]
        aa: OsString,
    },
}

pub fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pki(PkiArgs::Init(args)) => {
            println!("Init PKI with canonical name {:?}", args);
        }
    }
}
