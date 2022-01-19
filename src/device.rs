
use std::net::IpAddr;
use crate::token::MiIoToken;

pub struct MiIoDevice {
    ip_address: IpAddr,
    token: MiIoToken
}
