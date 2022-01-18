use lazy_static::lazy_static;
use std::collections::HashMap;
use bytes::{BufMut, Bytes, BytesMut};
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

fn construct_packet(
    deviceId: u8,
    token: MiIoToken,
    payload: &str,
    timestamp: u8
) -> Result<Bytes, anyhow::Error> {
    let encrypted = token.encrypt(&payload.as_bytes())?;
    todo!()
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use crate::packets::HELLO_PACKET;

    //noinspection SpellCheckingInspection
    #[test]
    fn hello_packet_is_valid() {
        let expected = "21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let actual = hex::encode(HELLO_PACKET.deref());
        println!("Actual: {actual}");
        assert_eq!(actual, expected);
    }
}
