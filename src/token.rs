

use openssl::hash::{DigestBytes, hash, MessageDigest};
use openssl::symm::Cipher;
use std::ops::Deref;

pub struct MiIoToken {
    pub token_bytes: Vec<u8>,
    token_md5: DigestBytes,
    iv: DigestBytes,
}

impl MiIoToken {
    pub fn new(token_hex: &str) -> Result<MiIoToken, anyhow::Error> {
        let message_digest = MessageDigest::md5();
        let token_bytes = hex::decode(token_hex)?;
        let token_md5 = hash(message_digest, token_bytes.deref())?;

        let iv = {
            let bytes = [token_md5.deref(), token_bytes.deref()].concat();
            hash(message_digest, bytes.deref())?
        };

        Ok(MiIoToken { token_bytes, token_md5, iv })
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let cipher = Cipher::aes_128_cbc();
        let encrypted = openssl::symm::encrypt(cipher, &self.token_md5, Some(&self.iv), msg)?;
        Ok(encrypted)
    }

    pub fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let cipher = Cipher::aes_128_cbc();
        let decrypted = openssl::symm::decrypt(cipher, &self.token_md5, Some(&self.iv), msg)?;
        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use crate::token::MiIoToken;

    #[test]
    fn test_token_construction() {
        let token_hex = "586e584268475142564d485234734d4b";
        let token = MiIoToken::new(token_hex).unwrap();

        assert_eq!(token_hex, hex::encode(token.token_bytes));

        let actual_token_hash = hex::encode(token.token_md5);
        let expected_token_hash = "4b579cef88edea8530fb8d00e4f8957e";
        println!("Actual token hash: {actual_token_hash}");
        assert_eq!(expected_token_hash, actual_token_hash);

        let actual_iv = hex::encode(token.iv);
        let expected_iv = "da0980c978339c0e4610ed1498ba4db2";
        println!("Actual iv: {actual_iv}");
        assert_eq!(expected_iv, actual_iv);
    }

    #[test]
    fn test_token_encryption() {
        let payload = "Hello world";
        let token = MiIoToken::new("586e584268475142564d485234734d4b").unwrap();

        let encrypted = token.encrypt(&payload.as_bytes()).unwrap();
        let actual_encrypted_hex = hex::encode(&encrypted);
        let expected_encrypted_hex = "00ddf4342e3a4f49984204a2eceefeef";
        println!("Actual encrypted hex: {actual_encrypted_hex}");
        assert_eq!(expected_encrypted_hex, actual_encrypted_hex);

        let decrypted = token.decrypt(encrypted.deref()).unwrap();
        assert_eq!(payload.as_bytes(), decrypted.deref())
    }
}
