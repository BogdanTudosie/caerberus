use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use base64;

use crate::models::{EncryptRequest, EncryptResponse, DecryptRequest, DecryptResponse, KeyResponse};
use crate::rsa_service::RsaService;

pub async fn get_main_endpoint() -> Result<Json<&'static str>, StatusCode> {
    Ok(Json("Welcome to the RSA encryption service!"))
}

// Handler to get the public key
pub async fn get_public_key(
    State(service): State<Arc<RsaService>>,
) -> Result<Json<KeyResponse>, StatusCode> {
    let public_key = service.export_public_key()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(KeyResponse { public_key }))
}

// Handler to encrypt data
pub async fn encrypt(
    State(service): State<Arc<RsaService>>,
    Json(payload): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, StatusCode> {
    // Determine if we're dealing with plain text or binary data
    let data = if payload.is_binary {
        base64::decode(&payload.data)
            .map_err(|_| StatusCode::BAD_REQUEST)?
    } else {
        payload.data.into_bytes()
    };
    
    let encrypted = service.encrypt(&data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Always return Base64 for encrypted data
    let encrypted_b64 = base64::encode(&encrypted);
    
    Ok(Json(EncryptResponse {
        encrypted_data: encrypted_b64,
    }))
}

// Handler to decrypt data
pub async fn decrypt(
    State(service): State<Arc<RsaService>>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, StatusCode> {
    // Convert from Base64 back to binary
    let encrypted_data = base64::decode(&payload.encrypted_data)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let decrypted = service.decrypt(&encrypted_data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Return according to requested format
    if payload.to_string {
        let decrypted_str = String::from_utf8(decrypted)
            .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
        
        Ok(Json(DecryptResponse {
            data_string: Some(decrypted_str),
            data_base64: None,
        }))
    } else {
        Ok(Json(DecryptResponse {
            data_string: None,
            data_base64: Some(base64::encode(&decrypted)),
        }))
    }
}