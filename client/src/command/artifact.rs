//! Artifact commands.
//!
//! Artifacts are release binaries stored in a cache next to the
//! Nix binary cache data. They are addressed by content digest
//! on the server; `push` uploads them and `pull` downloads
//! them, verifying the bytes against the served digest.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::api::ApiClient;
use crate::cache::CacheRef;
use crate::cli::Opts;
use crate::config::Config;
use bunker::api::v1::artifacts::ArtifactUploadRequest;

/// Manage release artifacts stored in a cache.
#[derive(Debug, Parser)]
pub struct Artifact {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Pull(Pull),
    Push(Push),
}

/// Download an artifact from a cache.
///
/// You need the `pull` permission on the cache (public caches
/// grant it to everyone).
///
/// The download is streamed to disk and verified against the
/// SHA-256 digest the server serves for the artifact. If the
/// bytes do not match the digest, the download is discarded
/// and the command fails — a corrupt or substituted artifact
/// is never left in place.
#[derive(Debug, Clone, Parser)]
#[command(disable_version_flag = true)]
struct Pull {
    /// The cache to download from.
    ///
    /// This can be either `servername:cachename` or `cachename`
    /// when using the default server.
    cache: CacheRef,

    /// Name of the artifact (e.g. `light-show`).
    #[clap(long)]
    name: String,

    /// Version of the artifact (e.g. `1.4.2`); `latest`
    /// resolves to the newest uploaded version.
    #[clap(long, default_value = "latest")]
    version: String,

    /// File name of the artifact (e.g. `light-show.tar.gz`).
    #[clap(long)]
    file: String,

    /// Where to write the artifact. Defaults to the artifact's
    /// file name in the current directory.
    output: Option<PathBuf>,
}

/// Upload an artifact to a cache.
///
/// You need the `push` permission on the cache.
///
/// The file is streamed to the server, never loaded into
/// memory. Its file name is sent as the artifact's filename;
/// rename the file first if it should be recorded under a
/// different name. The client computes the file's SHA-256
/// digest and size and declares them to the server, which
/// verifies what it receives against them.
///
/// Uploading the same name, version and file with identical
/// contents again succeeds without changing anything. The same
/// name and version with different contents is rejected:
/// versions are immutable once uploaded.
#[derive(Debug, Clone, Parser)]
#[command(disable_version_flag = true)]
struct Push {
    /// The cache to upload to.
    ///
    /// This can be either `servername:cachename` or `cachename`
    /// when using the default server.
    cache: CacheRef,

    /// Name of the artifact (e.g. `light-show`).
    #[clap(long)]
    name: String,

    /// Version of the artifact (e.g. `1.4.2`).
    #[clap(long)]
    version: String,

    /// The artifact file to upload.
    file: PathBuf,
}

pub async fn run(opts: Opts) -> Result<()> {
    let sub = opts.command.as_artifact().unwrap();

    match &sub.command {
        Command::Pull(pull) => pull_artifact(pull).await,
        Command::Push(push) => push_artifact(push).await,
    }
}

async fn pull_artifact(args: &Pull) -> Result<()> {
    let config = Config::load()?;
    let (_server_name, server, cache_name) = config.resolve_cache(&args.cache)?;

    let mut api = ApiClient::from_server_config(server.clone())?;

    // Confirm remote cache validity, query cache config.
    let cache_config = api.get_cache_config(cache_name).await?;

    if let Some(api_endpoint) = &cache_config.api_endpoint {
        // Use delegated API endpoint.
        api.set_endpoint(api_endpoint)?;
    }

    let dest = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(&args.file));

    let downloaded = api
        .download_artifact(cache_name, &args.name, &args.version, &args.file, &dest)
        .await?;

    println!(
        "Downloaded {} {} ({})",
        args.name, downloaded.version, args.file
    );
    println!("sha256: {}", downloaded.sha256);
    println!("size: {} bytes", downloaded.bytes_written);
    println!("saved to: {}", dest.display());

    Ok(())
}

async fn push_artifact(args: &Push) -> Result<()> {
    let filename = args
        .file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("The file path {:?} has no usable file name", args.file))?
        .to_owned();

    let config = Config::load()?;
    let (_server_name, server, cache_name) = config.resolve_cache(&args.cache)?;

    let mut api = ApiClient::from_server_config(server.clone())?;

    // Confirm remote cache validity, query cache config.
    let cache_config = api.get_cache_config(cache_name).await?;

    if let Some(api_endpoint) = &cache_config.api_endpoint {
        // Use delegated API endpoint.
        api.set_endpoint(api_endpoint)?;
    }

    let (sha256, size) = hash_file(&args.file).await?;

    let request = ArtifactUploadRequest {
        cache: cache_name.to_owned(),
        name: args.name.clone(),
        version: args.version.clone(),
        filename,
    };

    let file = tokio::fs::File::open(&args.file).await?;
    let response = api.upload_artifact(&request, &sha256, size, file).await?;

    println!(
        "Uploaded {} {} ({})",
        response.name, response.version, response.filename
    );
    println!("sha256: {}", response.sha256);
    println!("size: {} bytes", response.size);

    Ok(())
}

/// Computes the SHA-256 digest and byte count of a file,
/// streaming it in bounded chunks.
async fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }

    Ok((hex::encode(hasher.finalize()), size))
}
