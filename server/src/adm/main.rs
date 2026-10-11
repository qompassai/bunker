mod command;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use enum_as_inner::EnumAsInner;

use bunker_server::config;
use command::generate_hybrid_key::{self, GenerateHybridKey};
use command::make_token::{self, MakeToken};
use command::show_hybrid_public_key::{self, ShowHybridPublicKey};

/// Bunker server administration utilities.
#[derive(Debug, Parser)]
#[clap(version, author = "Qompass AI <map@qompass.ai>")]
#[clap(propagate_version = true)]
pub struct Opts {
    /// Path to the config file.
    #[clap(short = 'f', long, global = true)]
    config: Option<PathBuf>,

    /// The sub-command.
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand, EnumAsInner)]
pub enum Command {
    GenerateHybridKey(GenerateHybridKey),
    MakeToken(MakeToken),
    ShowHybridPublicKey(ShowHybridPublicKey),
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    match opts.command {
        // Key-management commands intentionally do not load the server
        // configuration: generating a hybrid key is a prerequisite for
        // writing the configuration that references it, and inspecting a
        // key file must stay possible when the server is down.
        Command::GenerateHybridKey(_) => generate_hybrid_key::run(opts).await?,
        Command::ShowHybridPublicKey(_) => show_hybrid_public_key::run(opts).await?,
        Command::MakeToken(_) => {
            let config = config::load_config(opts.config.as_deref(), false).await?;
            make_token::run(config, opts).await?
        }
    }

    Ok(())
}
