use std::any::Any;
use std::collections::HashMap;

use bytes::{BufMut, Bytes, BytesMut};
use lazy_static::lazy_static;
use openssl::hash::hash;
use openssl::hash::MessageDigest;
use serde::Serialize;

use crate::token::MiIoToken;

const MAGIC: u16 = 0x2131;

lazy_static! {
    static ref HELLO_PACKET: Bytes = {
        let capacity = 32;
        let mut packet = BytesMut::with_capacity(capacity);
        packet.put_u16(MAGIC);
        packet.put_u16(capacity as u16);
        packet.put_slice(&[0xffu8; 28]);
        packet.freeze()
    };
}

#[derive(Serialize)]
pub struct MiIoCommand {
    method: String,
    params: Vec<Box<dyn Serialize>>,
    id: u32
}

impl MiIoCommand {
    fn new(method: String, params: Vec<Box<dyn Any>>) -> MiIoCommand {
        MiIoCommand {
            method,
            params,
            id: 0
        }
    }
}

fn construct_packet(
    token: MiIoToken,
    device_id: u32,
    timestamp: u32,
    mut payload: MiIoCommand
) -> Result<Bytes, anyhow::Error> {
    payload.id = timestamp;
    let payload = serde_json::to_string(&payload)?;
    let encrypted_payload = token.encrypt(&payload.as_bytes())?;
    let packet_len = encrypted_payload.len() + 32;
    let mut packet = BytesMut::with_capacity(packet_len);

    packet.put_u16(MAGIC);
    packet.put_u16(packet_len as u16);
    packet.put_u32(0); // unknown1
    packet.put_u32(device_id);
    packet.put_u32(timestamp);
    packet.put_slice(&token.token_bytes);
    packet.put_slice(&encrypted_payload);

    let packet_md5_hash = hash(MessageDigest::md5(), &packet)?;
    packet[16..32].copy_from_slice(&packet_md5_hash);

    Ok(packet.freeze())
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use crate::packets::{construct_packet, HELLO_PACKET, MiIoCommand};
    use crate::token::MiIoToken;

    //noinspection SpellCheckingInspection
    #[test]
    fn hello_packet_is_valid() {
        let expected = "21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let actual = hex::encode(HELLO_PACKET.deref());
        println!("Actual: {actual}");
        assert_eq!(actual, expected);
    }

    #[test]
    fn construct_packet_works() {
        let token = MiIoToken::new("3c92df7588021efbcd6bd55c9147bed0").unwrap();
        let command = MiIoCommand::new("miIO.info".to_string(), vec![]);
        let packet_bytes = construct_packet(token, 133525349, 70633, command).unwrap();
        let expected_packet_hex = "213100500000000007f56f65000113e95424d99f4f6f0e89fb5c5d54e79e2c413083a0b3cebdbe3b2813dd94f20e5247acf3e9f86e51ed9f95caa50ffa1f899d3026f0fcfae93a52dbdc4fc088a54205";
        assert_eq!(expected_packet_hex, hex::encode(&packet_bytes))
    }
}
