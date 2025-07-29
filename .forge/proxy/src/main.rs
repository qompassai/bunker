// /qompassai/bunker/proxy/src/main.rs
// Qompass AI Bunker Reverse Proxy Server
// Copyright (C) 2025 Qompass AI, All rights reserved
// --------------------------------------------------

use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora::tls::TlsAcceptor;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
struct ReverseProxy;
#[async_trait]
impl ProxyHttp for ReverseProxy {
    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut HttpCtx) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new("127.0.0.1:8080", true, "localhost".to_string())))
    }
    async fn request_filter(&self, session: &mut Session, _ctx: &mut HttpCtx) -> Result<()> {
        println!("Received request for: {}", session.req_header().uri.path());
        Ok(())
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let config_dir = env::var("XDG_CONFIG_HOME")
        .or_else(|_| env::var("HOME").map(|h| format!("{}/.config", h)))
        .expect("Failed to determine config directory");
    let cert_path = PathBuf::from(&config_dir)
        .join("bunker")
        .join("bunker_cert.pem");
    let key_path = PathBuf::from(&config_dir)
        .join("bunker")
        .join("bunker_key.pem");

    if !cert_path.exists() || !key_path.exists() {
        panic!(
            "Certificate files not found in: {:?}\n\
            Generate them with:\n\
            mkdir -p ~/.config/bunker && \
            openssl genpkey -algorithm ED25519 -out ~/.config/bunker/bunker_key.pem && \
            openssl req -x509 -key ~/.config/bunker/bunker_key.pem \
              -out ~/.config/bunker/bunker_cert.pem \
              -days 90 -subj '/CN=localhost'",  // 90-day validity
            cert_path.parent().unwrap()
        );
    }
    let mut tls_config = TlsAcceptor::new(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
        None
    )?;
    tls_config.set_min_proto_version(Some(pingora::tls::Protocol::TLSv1_3))?;
    tls_config.set_ciphersuites("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")?;
    let mut server = Server::new(None).unwrap();
    server.bootstrap();
    let mut proxy = pingora::proxy::http_proxy_service(
        &server.configuration,
        ReverseProxy,
        Some(Arc::new(tls_config)),
    );
    proxy.add_tcp("[::]:4430");
    server.add_service(proxy);
    server.run_forever().await
}
