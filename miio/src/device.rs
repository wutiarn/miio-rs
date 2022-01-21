
use std::net::IpAddr;
use crate::token::MiIoToken;

pub struct MiIoDevice {
    pub ip_address: IpAddr,
    pub token: MiIoToken
}
