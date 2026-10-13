pub(crate) mod artifacts;
mod cache_config;
mod get_missing_paths;
mod upload_path;

use axum::{
    Router,
    routing::{delete, get, patch, post, put},
};

pub(crate) fn get_router() -> Router {
    Router::new()
        .route("/_api/v1/artifacts", put(artifacts::upload_artifact))
        .route(
            "/_api/v1/artifacts/:cache/:name/:version/:file",
            delete(artifacts::delete_artifact),
        )
        .route(
            "/_api/v1/get-missing-paths",
            post(get_missing_paths::get_missing_paths),
        )
        .route("/_api/v1/upload-path", put(upload_path::upload_path))
        .route(
            "/:cache/bunker-cache-info",
            get(cache_config::get_cache_config),
        )
        .route(
            "/_api/v1/cache-config/:cache",
            get(cache_config::get_cache_config),
        )
        .route(
            "/_api/v1/cache-config/:cache",
            post(cache_config::create_cache),
        )
        .route(
            "/_api/v1/cache-config/:cache",
            patch(cache_config::configure_cache),
        )
        .route(
            "/_api/v1/cache-config/:cache",
            delete(cache_config::destroy_cache),
        )
}
