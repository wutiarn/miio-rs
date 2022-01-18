use lazy_static::lazy_static;
use std::collections::HashMap;
use bytes::{BufMut, Bytes, BytesMut};
use crate::token::MiIoToken;

const MAGIC: u16 = 0x2131;

lazy_static! {
    static ref HELLO_PACKET: Bytes = {
        let mut packet = BytesMut::with_capacity(32);
        packet.fill(0xffu8);
        packet.put_u16(MAGIC);
        packet.put_u16(packet.len() as u16);
        packet.freeze()
    };
}

fn construct_packet(
    deviceId: u8,
    token: MiIoToken,
    payload: &str,
    timestamp: u8
) {
    let mut payload = BytesMut::from(payload);
    token.encrypt(&mut payload);
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use crate::packets::HELLO_PACKET;

    #[test]
    fn hello_packet_is_valid() {
        let expected = "[21, 31, 00, 20, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF, FF]";
        let data: &[u8] = HELLO_PACKET.deref();
        let actual = format!("{:02X?}", data);
        println!("Actual: {actual}");
        assert_eq!(actual, expected);
    }
}
