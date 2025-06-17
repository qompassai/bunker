/// The distributor of this Bunker client.
///
/// Common values include `nixpkgs`, `bunker` and `dev`.
pub const BUNKER_DISTRIBUTOR: &str = if let Some(distro) = option_env!("BUNKER_DISTRIBUTOR") {
    distro
} else {
    "unknown"
};
