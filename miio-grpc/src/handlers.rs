use anyhow::anyhow;
use log::info;
use tonic::Response;
use miio::device::MiIoDevice;
use miio::packets::MiIoCommand;
use miio::token::MiIoToken;
use crate::{DeviceResponse, SendCommandRequest};
use crate::error::AppError;

pub fn send_command(request: SendCommandRequest) -> Result<DeviceResponse, AppError> {
    info!("{:?}", request.command);
    let device_dto = request.device.ok_or(anyhow!("Device must be present"))?;
    let device = MiIoDevice {
        token: MiIoToken::new(device_dto.token.as_str())?,
        ip_address: device_dto.inet_address.parse()?
    };
    let command = request.command.ok_or(anyhow!("Command must be present"))?;
    let command = MiIoCommand::new(
        command.method,
        vec![]
    );
    let result = miio::operations::send_request(&device, command);
    Ok(DeviceResponse::default())
}