//! The Bunker client's HTTP API, configuration and cache
//! references, as a library.
//!
//! The `bunker` binary and other in-workspace consumers (the
//! `bunker-mcp` server) share this one implementation, so they
//! resolve servers and tokens identically and validate artifact
//! addresses with the same code.

#![forbid(unsafe_code)]

pub mod api;
pub mod cache;
pub mod config;
pub mod version;
