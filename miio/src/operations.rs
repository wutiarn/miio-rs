use std::any::Any;
use log::info;

use crate::device::MiIoDevice;
use crate::packets::MiIoCommand;

pub fn send_request(device: &MiIoDevice, mut payload: MiIoCommand) {
    info!("Sending request: {device:?}, {payload:?}");
}

fn send_hello_packet() {}

