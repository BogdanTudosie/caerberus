use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
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
            CryptoError::TooLarge(size, max) => {
                write!(f, "Data too large: {} bytes (max: {} bytes)", size, max)
            }
            CryptoError::OpenSslError(e) => write!(f, "OpenSSL error: {}", e),
            CryptoError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<openssl::error::ErrorStack> for CryptoError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        CryptoError::OpenSslError(e)
    }
}

// RSA service using OpenSSL
pub struct RsaService {
    private_key: PKey<openssl::pkey::Private>,
    public_key: PKey<openssl::pkey::Public>,
    key_size: u32,
}

impl RsaService {
    pub fn new(key_size: Option<u32>) -> Result<Self, CryptoError> {
        let key_size = key_size.unwrap_or(2048);

        // Generate a new RSA key pair
        let rsa = Rsa::generate(key_size).map_err(CryptoError::from)?;
        let private_key = PKey::from_rsa(rsa.clone()).map_err(CryptoError::from)?;

        // Extract the public key from the private key
        let public_key_rsa = rsa.public_key_to_pem().map_err(CryptoError::from)?;
        let public_key_rsa =
            Rsa::public_key_from_pem(&public_key_rsa).map_err(CryptoError::from)?;
        let public_key = PKey::from_rsa(public_key_rsa).map_err(CryptoError::from)?;

        Ok(Self {
            private_key,
            public_key,
            key_size,
        })
    }

    pub fn export_public_key(&self) -> Result<String, Box<dyn Error>> {
        let rsa = self.public_key.rsa()?;
        let pem = std::str::from_utf8(&rsa.public_key_to_pem()?)?.to_string();
        Ok(pem)
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let rsa = self.public_key.rsa()?;

        // RSA encryption can only handle limited data size based on key size
        if data.len() > (rsa.size() as usize - 42) {
            // Approximate PKCS#1 v1.5 padding size
            return Err("Data too large for RSA encryption".into());
        }

        let mut buf = vec![0; rsa.size() as usize];
        let encrypted_len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1)?;
        buf.truncate(encrypted_len);

        Ok(buf)
    }

    pub fn export_public_key(&self) -> Result<String, CryptoError> {
        let rsa = self.public_key.rsa().map_err(CryptoError::from)?;
        let pem = std::str::from_utf8(&rsa.public_key_to_pem().map_err(CryptoError::from)?)
            .map_err(|e| CryptoError::Other(e.to_string()))?
            .to_string();
        Ok(pem)
    }

    pub fn encrypt_small(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let rsa = self.public_key.rsa().map_err(CryptoError::from)?;

        // RSA encryption can only handle limited data size based on key size
        if data.len() > (rsa.size() as usize - 42) {
            // Approximate PKCS#1 v1.5 padding size
            return Err(CryptoError::TooLarge(data.len(), rsa.size() as usize - 42));
        }

        let mut buf = vec![0; rsa.size() as usize];
        let encrypted_len = rsa
            .public_encrypt(data, &mut buf, Padding::PKCS1)
            .map_err(CryptoError::from)?;
        buf.truncate(encrypted_len);

        Ok(buf)
    }

    // Pure RSA decryption - only for small data
    pub fn decrypt_small(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let rsa = self.private_key.rsa().map_err(CryptoError::from)?;

        let mut buf = vec![0; rsa.size() as usize];
        let decrypted_len = rsa
            .private_decrypt(data, &mut buf, Padding::PKCS1)
            .map_err(CryptoError::from)?;

        buf.truncate(decrypted_len);
        Ok(buf)
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // For small data, use direct RSA encryption
        if data.len() <= ((self.key_size / 8) as usize - 42) {
            return self.encrypt_small(data);
        }

        // For larger data, use hybrid encryption (AES + RSA)
        // 1. Generate a random AES key
        let mut aes_key = vec![0; 32]; // 256-bit AES key
        rand_bytes(&mut aes_key).map_err(CryptoError::from)?;

        // 2. Encrypt the data with AES
        let mut iv = vec![0; 16]; // AES initialization vector
        rand_bytes(&mut iv).map_err(CryptoError::from)?;

        let encrypted_data =
            encrypt(Cipher::aes_256_cbc(), &aes_key, Some(&iv), data).map_err(CryptoError::from)?;

        // 3. Encrypt the AES key with RSA
        let encrypted_key = self.encrypt_small(&aes_key)?;

        // 4. Format: [encrypted_key_length(4 bytes)][encrypted_key][iv][encrypted_data]
        let key_len = encrypted_key.len() as u32;
        let mut result = Vec::with_capacity(4 + key_len as usize + iv.len() + encrypted_data.len());

        // Add key length as 4 bytes
        result.extend_from_slice(&key_len.to_be_bytes());
        // Add encrypted key
        result.extend_from_slice(&encrypted_key);
        // Add IV
        result.extend_from_slice(&iv);
        // Add encrypted data
        result.extend_from_slice(&encrypted_data);

        Ok(result)
    }

    // Hybrid decryption for data of any size (RSA + AES)
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Ensure we have at least the key length
        if data.len() < 4 {
            return Err(CryptoError::Other("Invalid data format".to_string()));
        }

        // Extract the key length (first 4 bytes)
        let mut key_len_bytes = [0u8; 4];
        key_len_bytes.copy_from_slice(&data[0..4]);
        let key_len = u32::from_be_bytes(key_len_bytes) as usize;

        // Ensure we have enough data for the key
        if data.len() < 4 + key_len {
            return Err(CryptoError::Other("Invalid data format".to_string()));
        }

        // Extract the encrypted key
        let encrypted_key = &data[4..4 + key_len];

        // Check if this is small data direct RSA encryption
        if key_len == data.len() - 4 {
            return self.decrypt_small(encrypted_key);
        }

        // Extract the IV (16 bytes for AES-256-CBC)
        if data.len() < 4 + key_len + 16 {
            return Err(CryptoError::Other("Invalid data format".to_string()));
        }

        let iv = &data[4 + key_len..4 + key_len + 16];

        // Extract the encrypted data
        let encrypted_data = &data[4 + key_len + 16..];

        // Decrypt the AES key with RSA
        let aes_key = self.decrypt_small(encrypted_key)?;

        // Decrypt the data with AES
        let decrypted_data = decrypt(Cipher::aes_256_cbc(), &aes_key, Some(iv), encrypted_data)
            .map_err(CryptoError::from)?;

        Ok(decrypted_data)
    }
}
