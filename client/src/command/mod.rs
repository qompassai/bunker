pub mod artifact;
pub mod cache;
pub mod get_closure;
pub mod login;
pub mod push;
pub mod r#use;
pub mod watch_store;

/// Error returned by Nix subcommands in builds without Nix store support.
///
/// Subset builds (Windows, Android) compile without the `nix` feature.
/// The Nix subcommands stay visible in the CLI, but invoking one must
/// fail loudly and clearly instead of silently doing the wrong thing.
#[cfg(not(feature = "nix"))]
pub(crate) fn nix_store_not_compiled(command: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "`bunker {command}` requires Nix store support, but this binary was built \
         without Nix store support (the `nix` feature is disabled). \
         Use a full build for Nix store commands."
    )
}
