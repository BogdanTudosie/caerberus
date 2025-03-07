use openssl::rsa::{Rsa, Padding};
use openssl::pkey::PKey;
use std::error::Error;

// Custom error type for better error handling
#[derive(Debug)]
pub enum CryptoError {
    TooLarge(usize, usize),
    OpenSslError(openssl::error::ErrorStack),
    Other(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::TooLarge(size, max) => write!(f, "Data too large: {} bytes (max: {} bytes)", size, max),
            CryptoError::OpenSslError(e) => write!(f, "OpenSSL error: {}", e),
            CryptoError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

// RSA service using OpenSSL
pub struct RsaService {
    private_key: PKey<openssl::pkey::Private>,
    public_key: PKey<openssl::pkey::Public>,
}

impl RsaService {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // Generate a new 2048-bit RSA key pair
        let rsa = Rsa::generate(2048)?;
        let private_key = PKey::from_rsa(rsa.clone())?;
        
        // Extract the public key from the private key
        let public_key_rsa = rsa.public_key_to_pem()?;
        let public_key_rsa = Rsa::public_key_from_pem(&public_key_rsa)?;
        let public_key = PKey::from_rsa(public_key_rsa)?;
        
        Ok(Self {
            private_key,
            public_key,
        })
    }
    
    pub fn export_public_key(&self) -> Result<String, Box<dyn Error>> {
        let rsa = self.public_key.rsa()?;
        let pem = std::str::from_utf8(&rsa.public_key_to_pem()?)?
            .to_string();
        Ok(pem)
    }
    
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let rsa = self.public_key.rsa()?;
        
        // RSA encryption can only handle limited data size based on key size
        if data.len() > (rsa.size() as usize - 42) { // Approximate PKCS#1 v1.5 padding size
            return Err("Data too large for RSA encryption".into());
        }
        
        let mut buf = vec![0; rsa.size() as usize];
        let encrypted_len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1)?;
        buf.truncate(encrypted_len);
        
        Ok(buf)
    }
    
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let rsa = self.private_key.rsa()?;
        
        let mut buf = vec![0; rsa.size() as usize];
        let decrypted_len = rsa.private_decrypt(data, &mut buf, Padding::PKCS1)?;
        buf.truncate(decrypted_len);
        
        Ok(buf)
    }
}