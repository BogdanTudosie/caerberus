use serde::{Deserialize, Serialize};

// Request/Response models for RSA operations

// Model for encryption request
#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    pub data: String,
    #[serde(default)]
    pub is_binary: bool,
}

// Model for encryption response
#[derive(Debug, Serialize)]
pub struct EncryptResponse {
    pub encrypted_data: String,
}

// Model for decryption request
#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    pub encrypted_data: String,
    #[serde(default)]
    pub to_string: bool,
}

// Model for decryption response
#[derive(Debug, Serialize)]
pub struct DecryptResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_string: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_base64: Option<String>,
}

// Model for public key response
#[derive(Debug, Serialize)]
pub struct KeyResponse {
    pub public_key: String,
}

// Model for error responses
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// Model for service statistics
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub version: String,
}