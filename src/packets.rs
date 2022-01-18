use lazy_static::lazy_static;
use std::collections::HashMap;

const MAGIC: u16 = 0x2131;

lazy_static! {
    static ref HELLO_PACKET: [u8; 32] = {
        let mut packet = [0u8; 32];
        let packet_len = packet.len() as u16;
        packet[0..2].copy_from_slice(&MAGIC.to_be_bytes());
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[4..32].copy_from_slice(&[0xffu8; 28]);
        packet
    };
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
