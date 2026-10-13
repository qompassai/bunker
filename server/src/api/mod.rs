//! HTTP API.

mod artifacts;
mod binary_cache;
mod v1;

use axum::{response::Html, routing::get, Router};

async fn placeholder() -> Html<&'static str> {
    Html(include_str!("placeholder.html"))
}

pub(crate) fn get_router() -> Router {
    Router::new()
        .route("/", get(placeholder))
        .merge(artifacts::get_router())
        .merge(binary_cache::get_router())
        .merge(v1::get_router())
}
