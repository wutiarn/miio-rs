use lazy_static::lazy_static;
use std::collections::HashMap;

const MAGIC: u16 = 0x2131;

lazy_static! {
    static ref HELLO_PACKET: [u8; 32] = {
        let mut packet = [0u8; 32];
        packet[5..10].copy_from_slice(&[1u8; 5]);
        packet
    };
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use crate::packets::HELLO_PACKET;

    #[test]
    fn hello_packet_is_valid() {
        let data: &[u8] = HELLO_PACKET.deref();
        println!("{:02X?}", data)
    }
}
