use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use crate::Opts;
use bunker_server::config::read_hybrid_keypair_file;

/// $ bunkeradm show-hybrid-public-key /etc/bunker/hybrid-secret.key
///
/// Reads a hybrid secret key file and prints the corresponding public key
/// in canonical format (`{name}:{base64}` over a 1,984-byte payload).
/// The file is parsed strictly, exactly as the server parses it at load
/// time, so a corrupted file is refused here too.
#[derive(Debug, Parser)]
pub struct ShowHybridPublicKey {
    /// Path to the file containing the hybrid secret key.
    secret_file: PathBuf,
}

pub async fn run(opts: Opts) -> Result<()> {
    let args = opts.command.as_show_hybrid_public_key().unwrap();
    let keypair = read_hybrid_keypair_file(&args.secret_file)?;
    println!("{}", keypair.export_public_key());
    Ok(())
}
