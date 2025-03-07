// This file allows the components to be used as a library as well
pub mod models;
pub mod rsa_service;
pub mod handlers;

// Re-export important types for easier use
pub use models::{EncryptRequest, EncryptResponse, DecryptRequest, DecryptResponse, KeyResponse};
pub use rsa_service::RsaService;
pub use handlers::{get_public_key, encrypt, decrypt};