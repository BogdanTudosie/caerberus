use axum::{
    routing::{post, get},
    Router,
};
use std::net::TcpListener;
use std::net::SocketAddr;
use std::sync::Arc;

mod models;
mod rsa_service;
mod handlers;

use rsa_service::RsaService;
use handlers::{get_public_key, encrypt, decrypt, get_main_endpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up the encryption service
    let service = Arc::new(RsaService::new()?);
    
    // Print public key for testing
    println!("Server started with public key:\n{}", service.export_public_key()?);
    
    // Build application with routes
    let app = Router::new()
        .route("/", get(get_main_endpoint))
        .route("/public-key", post(get_public_key))
        .route("/encrypt", post(encrypt))
        .route("/decrypt", post(decrypt))
        .with_state(service);
    
    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("RSA encryption service listening on {}", addr);

    // Create a TCP listener
    let listener = TcpListener::bind(addr)?;

    // Run with tokio
    axum::serve(
        tokio::net::TcpListener::from_std(listener)?,
        app
    ).await?;
    
    Ok(())
}