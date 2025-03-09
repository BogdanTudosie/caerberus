use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64;
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;

use crate::rsa_service::RsaService;
use crate::{
    models::{
        DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, ErrorResponse,
        KeyResponse,
    },
    rsa_service::CryptoError,
};

pub struct BinaryResponse(pub Vec<u8>);

impl IntoResponse for BinaryResponse {
    fn into_response(self) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/octet-stream".parse().unwrap(),
        );

        (headers, self.0).into_response()
    }
}

pub async fn root() -> &'static str {
    "RSA Encryption Service API\n\nEndpoints:\n- POST /public-key: Get the public key\n- POST /encrypt: Encrypt data\n- POST /decrypt: Decrypt data\n- POST /encrypt-binary: Encrypt binary data\n- POST /decrypt-binary: Decrypt binary data\n- GET /stats: Get service statistics";
}

pub async fn get_main_endpoint() -> Result<Json<&'static str>, StatusCode> {
    Ok(Json("Welcome to the RSA encryption service!"))
}

// Handler to get the public key
pub async fn get_public_key(
    State(service): State<Arc<RsaService>>,
) -> Result<Json<KeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();

    let public_key = service.export_public_key().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to export public key: {}", e),
                uptime_seconds: todo!(),
                version: todo!(),
            }),
        )
    })?;

    // Record operation timing
    let elapsed = start.elapsed();
    println!("public_key operation took: {:?}", elapsed);

    Ok(Json(KeyResponse { public_key }))
}

// Handler to encrypt data
pub async fn encrypt(
    State(service): State<Arc<RsaService>>,
    Json(payload): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, StatusCode> {
    // Determine if we're dealing with plain text or binary data
    let data = if payload.is_binary {
        base64::decode(&payload.data).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid base64 encoding".to_string(),
                    uptime_seconds: todo!(),
                    version: todo!(),
                }),
            )
        })?
    } else {
        payload.data.into_bytes()
    };

    let encrypted = service.encrypt(&data).map_err(|e| {
        let status = match e {
            CryptoError::TooLarge(_, _) => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (
            status,
            Json(ErrorResponse {
                error: format!("Encryption failed: {}", e),
                uptime_seconds: todo!(),
                version: todo!(),
            }),
        )
    })?;

    // Always return Base64 for encrypted data
    let encrypted_b64 = base64::encode(&encrypted);

    // Record operation timing
    let elapsed = start.elapsed();
    println!("encrypt operation took: {:?}", elapsed);

    Ok(Json(EncryptResponse {
        encrypted_data: encrypted_b64,
    }))
}

// Handler to decrypt JSON data
pub async fn decrypt(
    State(service): State<Arc<RsaService>>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();

    // Convert from Base64 back to binary
    let encrypted_data = base64::decode(&payload.encrypted_data).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid base64 encoding".to_string(),
                uptime_seconds: todo!(),
                version: todo!(),
            }),
        )
    })?;

    let decrypted = service.decrypt(&encrypted_data).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Decryption failed: {}", e),
                uptime_seconds: todo!(),
                version: todo!(),
            }),
        )
    })?;

    // Return according to requested format
    let response = if payload.to_string {
        let decrypted_str = String::from_utf8(decrypted).map_err(|_| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    error: "Decrypted data is not valid UTF-8".to_string(),
                    uptime_seconds: todo!(),
                    version: todo!(),
                }),
            )
        })?;

        DecryptResponse {
            data_string: Some(decrypted_str),
            data_base64: None,
        }
    } else {
        DecryptResponse {
            data_string: None,
            data_base64: Some(base64::encode(&decrypted)),
        }
    };

    // Record operation timing
    let elapsed = start.elapsed();
    println!("decrypt operation took: {:?}", elapsed);

    Ok(Json(response))
}

// Handler to encrypt binary data directly
pub async fn encrypt_binary(
    State(service): State<Arc<RsaService>>,
    body: Bytes,
) -> Result<BinaryResponse, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();
    
    let encrypted = service.encrypt(&body)
        .map_err(|e| {
            let status = match e {
                CryptoError::TooLarge(_, _) => StatusCode::PAYLOAD_TOO_LARGE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            
            (
                status,
                Json(ErrorResponse {
                    error: format!("Encryption failed: {}", e),
                    uptime_seconds: todo!(),
                    version: todo!(),
                })
            )
        })?;
    
    // Record operation timing
    let elapsed = start.elapsed();
    println!("encrypt_binary operation took: {:?}", elapsed);
    
    Ok(BinaryResponse(encrypted))
}

// Handler to decrypt binary data directly
pub async fn decrypt_binary(
    State(service): State<Arc<RsaService>>,
    body: Bytes,
) -> Result<BinaryResponse, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();
    
    let decrypted = service.decrypt(&body)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Decryption failed: {}", e),
                    uptime_seconds: todo!(),
                    version: todo!(),
                })
            )
        })?;
    
    // Record operation timing
    let elapsed = start.elapsed();
    println!("decrypt_binary operation took: {:?}", elapsed);
    
    Ok(BinaryResponse(decrypted))
}

// Handler for file uploads
pub async fn encrypt_file(
    State(service): State<Arc<RsaService>>,
    mut multipart: Multipart,
) -> Result<Json<EncryptResponse>, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();
    
    // Process the multipart form
    let mut file_data = Vec::new();
    let mut found_file = false;
    
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Multipart error: {}", e),
                uptime_seconds: todo!(),
                version: todo!(),
            })
        )
    })? {
        if field.name() == Some("file") {
            file_data = field.bytes().await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to read file: {}", e),
                        uptime_seconds: todo!(),
                        version: todo!(),
                    })
                )
            })?.to_vec();
            found_file = true;
            break;
        }
    }
    
    if !found_file {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No file field found in multipart form".to_string(),
                uptime_seconds: todo!(),
                version: todo!(),
            })
        ));
    }
    
    // Encrypt the file data
    let encrypted = service.encrypt(&file_data)
        .map_err(|e| {
            let status = match e {
                CryptoError::TooLarge(_, _) => StatusCode::PAYLOAD_TOO_LARGE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            
            (
                status,
                Json(ErrorResponse {
                    error: format!("Encryption failed: {}", e),
                    uptime_seconds: todo!(),
                    version: todo!(),
                })
            )
        })?;
    
    // Return the encrypted data as base64
    let encrypted_b64 = base64::encode(&encrypted);
    
    // Record operation timing
    let elapsed = start.elapsed();
    println!("encrypt_file operation took: {:?}", elapsed);
    
    Ok(Json(EncryptResponse {
        encrypted_data: encrypted_b64,
    }))
}

// Service health check and statistics
pub async fn get_stats() -> Json<StatsResponse> {
    Json(StatsResponse {
        status: "healthy".to_string(),
        uptime_seconds: 0, // In a real service, calculate this
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}