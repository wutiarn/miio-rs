use bytes::{Bytes, BytesMut};
use openssl::hash::DigestBytes;
use std::ops::Deref;

pub struct MiIoToken {
    token_hash: DigestBytes,
}

impl MiIoToken {
    pub fn new(token: &str) -> Result<MiIoToken, anyhow::Error> {
        let message_digest = openssl::hash::MessageDigest::md5();
        let token_hash = openssl::hash::hash(message_digest, token.as_bytes())?;

        Ok(MiIoToken { token_hash })
    }

    pub fn encrypt(&self, msg: &mut BytesMut) {}

    pub fn decrypt(&self, msg: &mut BytesMut) {}
}


#[cfg(test)]
mod tests {
    use crate::token::MiIoToken;

    #[test]
    fn test_token_construction() {
        let token = MiIoToken::new("test").unwrap();
        let actual_hash = hex::encode(token.token_hash);
        println!("Actual hash: {actual_hash}");

        let expected_hash = "098f6bcd4621d373cade4e832627b4f6";
        assert_eq!(expected_hash, actual_hash)
    }
}