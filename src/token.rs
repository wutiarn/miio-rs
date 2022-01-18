use bytes::{Bytes, BytesMut};
use openssl::error::ErrorStack;
use openssl::hash::DigestBytes;
use openssl::symm::Cipher;
use std::ops::Deref;

pub struct MiIoToken {
    token_hash: DigestBytes,
    iv: DigestBytes,
}

impl MiIoToken {
    pub fn new(token: &str) -> Result<MiIoToken, anyhow::Error> {
        let message_digest = openssl::hash::MessageDigest::md5();
        let token_bytes = token.as_bytes();
        let token_hash = openssl::hash::hash(message_digest, token_bytes)?;

        let iv = {
            let bytes = [token_hash.deref(), token_bytes.deref()].concat();
            openssl::hash::hash(message_digest, bytes.deref())?
        };

        Ok(MiIoToken { token_hash, iv })
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let cipher = Cipher::aes_128_cbc();
        let encrypted = openssl::symm::encrypt(cipher, &self.token_hash, Some(&self.iv), msg)?;
        Ok(encrypted)
    }

    pub fn decrypt(&self, msg: &mut BytesMut) {}
}

#[cfg(test)]
mod tests {
    use crate::token::MiIoToken;

    #[test]
    fn test_token_construction() {
        let token = MiIoToken::new("test").unwrap();

        let actual_token_hash = hex::encode(token.token_hash);
        let expected_token_hash = "098f6bcd4621d373cade4e832627b4f6";
        println!("Actual token hash: {actual_token_hash}");
        assert_eq!(expected_token_hash, actual_token_hash);

        let actual_iv = hex::encode(token.iv);
        let expected_iv = "0a9172716ae6428409885b8b829ccb05";
        println!("Actual iv: {actual_iv}");
        assert_eq!(expected_iv, actual_iv);
    }

    #[test]
    fn test_token_encryption() {
        let payload = "Hello world";
        let token = MiIoToken::new("586e584268475142564d485234734d4b").unwrap();
        let encrypted = token.encrypt(&payload.as_bytes()).unwrap();
        let actual_encrypted_hex = hex::encode(encrypted);
        let expected_encrypted_hex = "098f6bcd4621d373cade4e832627b4f6";
        println!("Actual encrypted hex: {actual_encrypted_hex}");
        assert_eq!(expected_encrypted_hex, actual_encrypted_hex);
    }
}
