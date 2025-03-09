use axum::{
    Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

mod handlers;
mod models;
mod rsa_service;

use handlers::{
    decrypt, decrypt_binary, encrypt, encrypt_binary, encrypt_file, get_public_key, get_stats, root,
};
use rsa_service::RsaService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Set up the encryption service
    let service = Arc::new(RsaService::new(Some(4096))?);

    // Print public key for testing
    tracing::info!(
        "Server started with public key:\n{}",
        service.export_public_key()?
    );

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build application with routes
    let app = Router::new()
        .route("/", get(root))
        .route("/public-key", post(get_public_key))
        .route("/encrypt", post(encrypt))
        .route("/decrypt", post(decrypt))
        .route("/encrypt-binary", post(encrypt_binary))
        .route("/decrypt-binary", post(decrypt_binary))
        .route("/encrypt-file", post(encrypt_file))
        .route("/stats", get(get_stats))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(service);

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("RSA encryption service listening on {}", addr);

    // Create a TCP listener
    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Run with tokio
    axum::serve(listener, app).await?;

    Ok(())
}
