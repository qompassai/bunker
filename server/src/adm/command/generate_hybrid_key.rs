use anyhow::{anyhow, Result};
use clap::Parser;

use crate::Opts;
use bunker::signing::HybridKeypair;

/// $ bunkeradm generate-hybrid-key --name "cache.example.org-1"
///
/// Generates a new hybrid (Ed25519 + ML-DSA-65) signing keypair and prints
/// its canonical secret representation (`{name}:{base64}` over a 96-byte
/// payload: a 64-byte Ed25519 keypair followed by a 32-byte ML-DSA-65 seed)
/// to stdout. Nothing is written to disk: store the output in a file with
/// mode 0400 owned by root, per the key-management runbook.
#[derive(Debug, Parser)]
pub struct GenerateHybridKey {
    /// Name of the hybrid signing key.
    ///
    /// Cannot be empty and cannot contain colons.
    #[clap(long)]
    name: String,
}

pub async fn run(opts: Opts) -> Result<()> {
    let args = opts.command.as_generate_hybrid_key().unwrap();
    let keypair = HybridKeypair::generate(&args.name)
        .map_err(|e| anyhow!("Failed to generate hybrid keypair: {e}"))?;
    println!("{}", keypair.export_keypair());
    Ok(())
}
