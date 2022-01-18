use std::any::Any;

use crate::device::MiIoDevice;

pub fn send_request(device: &MiIoDevice, method: &str, params: Vec<&dyn Any>) {}

fn send_hello_packet() {

}

