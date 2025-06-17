use anyhow::{Result, anyhow};
use chrono::{Duration as ChronoDuration, Utc};
use clap::Parser;
use humantime::Duration;

use crate::Opts;
use bunker::cache::CacheNamePattern;
use bunker_server::access::Token;
use bunker_server::config::Config;

/// $ bunkeradm make-token --sub "alice" --validity "2y" --pull "dev-*" --push "dev-*" --pull "prod"
#[derive(Debug, Parser)]
pub struct MakeToken {
    #[clap(long)]
    sub: String,

    #[clap(long)]
    validity: Duration,

    #[clap(long)]
    dump_claims: bool,

    #[clap(long = "pull", value_name = "PATTERN")]
    pull_patterns: Vec<CacheNamePattern>,

    #[clap(long = "push", value_name = "PATTERN")]
    push_patterns: Vec<CacheNamePattern>,

    #[clap(long = "delete", value_name = "PATTERN")]
    delete_patterns: Vec<CacheNamePattern>,

    #[clap(long = "create-cache", value_name = "PATTERN")]
    create_cache_patterns: Vec<CacheNamePattern>,

    #[clap(long = "configure-cache", value_name = "PATTERN")]
    configure_cache_patterns: Vec<CacheNamePattern>,

    #[clap(long = "configure-cache-retention", value_name = "PATTERN")]
    configure_cache_retention_patterns: Vec<CacheNamePattern>,

    #[clap(long = "destroy-cache", value_name = "PATTERN")]
    destroy_cache_patterns: Vec<CacheNamePattern>,
}

macro_rules! grant_permissions {
    ($token:ident, $list:expr, $perm:ident) => {
        for pattern in $list {
            let perm = $token.get_or_insert_permission_mut(pattern.to_owned());
            perm.$perm = true;
        }
    };
}

pub async fn run(config: Config, opts: Opts) -> Result<()> {
    let sub = opts.command.as_make_token().unwrap();
    let duration = ChronoDuration::from_std(sub.validity.into())?;
    let exp = Utc::now()
        .checked_add_signed(duration)
        .ok_or_else(|| anyhow!("Expiry timestamp overflowed"))?;

    let mut token = Token::new(sub.sub.to_owned(), &exp);

    grant_permissions!(token, &sub.pull_patterns, pull);
    grant_permissions!(token, &sub.push_patterns, push);
    grant_permissions!(token, &sub.delete_patterns, delete);
    grant_permissions!(token, &sub.create_cache_patterns, create_cache);
    grant_permissions!(token, &sub.configure_cache_patterns, configure_cache);
    grant_permissions!(
        token,
        &sub.configure_cache_retention_patterns,
        configure_cache_retention
    );
    grant_permissions!(token, &sub.destroy_cache_patterns, destroy_cache);

    if sub.dump_claims {
        println!("{}", serde_json::to_string(token.opaque_claims())?);
    } else {
        let signature_type = config.jwt.signing_config.into();

        let encoded_token = token.encode(
            &signature_type,
            &config.jwt.token_bound_issuer,
            &config.jwt.token_bound_audiences,
        )?;
        println!("{}", encoded_token);
    }

    Ok(())
}
