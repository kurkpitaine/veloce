use clap::Parser;

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(name = "veloce")]
#[command(author, about = "Veloce, an ETSI Geonetworking V2X stack", long_about = None)]
pub(crate) struct Cli {
    #[clap(
        short = 'c',
        long = "config",
        global = true,
        help = "Sets a custom config file"
    )]
    pub config: Option<String>,

    #[clap(
        short = 't',
        long = "test",
        global = true,
        help = "Run Veloce in conformance testing mode",
        default_missing_value = "true"
    )]
    pub conformance: Option<bool>,
}
