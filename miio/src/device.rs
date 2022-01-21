
use std::net::IpAddr;
use crate::token::MiIoToken;

#[derive(Debug)]
pub struct MiIoDevice {
    pub ip_address: IpAddr,
    pub token: MiIoToken
}
