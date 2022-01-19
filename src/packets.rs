use std::ops::Deref;
use std::string::String;

use anyhow::anyhow;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use lazy_static::lazy_static;
use openssl::hash::hash;
use openssl::hash::MessageDigest;
use serde::Serialize;

use crate::token::MiIoToken;

const MAGIC: u16 = 0x2131;
const HEADER_SIZE: usize = 32; // bytes

lazy_static! {
    pub static ref HELLO_PACKET: Bytes = {
        let capacity = HEADER_SIZE;
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
    params: Vec<serde_json::Value>,
    id: u32,
}

impl MiIoCommand {
    pub fn new(method: String, params: Vec<serde_json::Value>) -> MiIoCommand {
        MiIoCommand {
            method,
            params,
            id: 0,
        }
    }
}

pub struct DecodedPacket {
    pub device_id: u32,
    pub timestamp: u32,
    pub data: Option<String>,
}

pub fn construct_packet(
    token: MiIoToken,
    device_id: u32,
    timestamp: u32,
    mut payload: MiIoCommand,
) -> Result<Bytes, anyhow::Error> {
    payload.id = timestamp;
    let payload = serde_json::to_string(&payload)?;
    let encrypted_payload = token.encrypt(&payload.as_bytes())?;
    let packet_len = encrypted_payload.len() + HEADER_SIZE;
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

pub fn decode_packet(bytes: &[u8], token: Option<MiIoToken>) -> Result<DecodedPacket, anyhow::Error> {
    let mut cursor = std::io::Cursor::new(bytes);
    if cursor.read_u16::<BigEndian>()? != MAGIC {
        return Err(anyhow!("Packet magic is invalid"));
    };
    let packet_len: usize = cursor.read_u16::<BigEndian>()? as usize;
    cursor.read_u32::<BigEndian>()?; // Skip unknown 1 field
    let device_id = cursor.read_u32::<BigEndian>()?;
    let timestamp = cursor.read_u32::<BigEndian>()?;
    drop(cursor);

    let data: Option<String> = if packet_len > HEADER_SIZE && token.is_some() {
        let token = token.unwrap();
        validate_packet_checksum(bytes, &token.token_bytes)?;
        let encrypted_bytes = &bytes[HEADER_SIZE..packet_len];
        let decrypted_bytes = token.decrypt(encrypted_bytes)?;
        // Some(String::from_utf8_lossy(&decrypted_bytes).to_string())
        Some(String::from_utf8(decrypted_bytes)?)
    } else {
        None
    };

    Ok(DecodedPacket {
        device_id,
        timestamp,
        data,
    })
}

fn validate_packet_checksum(packet: &[u8], token_bytes: &[u8]) -> Result<(), anyhow::Error> {
    let checksum = &packet[16..32];
    let mut packet = packet.to_owned();
    packet[16..32].copy_from_slice(token_bytes);
    let packet_md5_hash = hash(MessageDigest::md5(), &packet)?;
    if packet_md5_hash.deref() != checksum {
        return Err(anyhow!("MiIo packet checksum validation failed"))
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use crate::packets::{construct_packet, decode_packet, HELLO_PACKET, MiIoCommand};
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
    fn packet_construction_works() {
        let token = MiIoToken::new("3c92df7588021efbcd6bd55c9147bed0").unwrap();
        let command = MiIoCommand::new("miIO.info".to_string(), vec![]);
        let packet_bytes = construct_packet(token, 133525349, 70633, command).unwrap();
        let expected_packet_hex = "213100500000000007f56f65000113e95424d99f4f6f0e89fb5c5d54e79e2c413083a0b3cebdbe3b2813dd94f20e5247acf3e9f86e51ed9f95caa50ffa1f899d3026f0fcfae93a52dbdc4fc088a54205";
        assert_eq!(expected_packet_hex, hex::encode(&packet_bytes))
    }

    #[test]
    fn packet_decode_works() {
        let packet_hex = "213100500000000007f56f65000113e95424d99f4f6f0e89fb5c5d54e79e2c413083a0b3cebdbe3b2813dd94f20e5247acf3e9f86e51ed9f95caa50ffa1f899d3026f0fcfae93a52dbdc4fc088a54205";
        let token = MiIoToken::new("3c92df7588021efbcd6bd55c9147bed0").unwrap();

        let packet_bytes = hex::decode(packet_hex).unwrap();
        let decoded_packet = decode_packet(&packet_bytes, Some(token)).unwrap();
        let packet_data = decoded_packet.data.unwrap();
        println!("Packet data: {}", packet_data);

        assert_eq!(r#"{"method":"miIO.info","params":[],"id":70633}"#, packet_data);
        assert_eq!(133525349, decoded_packet.device_id);
        assert_eq!(70633, decoded_packet.timestamp);
    }
}
