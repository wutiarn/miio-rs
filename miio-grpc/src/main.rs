use env_logger::Target;
use log::{info, LevelFilter};
use tonic::{Request, Response, Status};
use tonic::transport::Server;

use miio::device::MiIoDevice;
use miio::packets::MiIoCommand;
use miio::token::MiIoToken;

use crate::miio_grpc::{DeviceResponse, SendCommandRequest};
use crate::miio_grpc::miio_commands_server::MiioCommandsServer;

pub mod miio_grpc {
    tonic::include_proto!("miio");
}

#[derive(Default)]
pub struct MiioCommandsImpl {}

#[tonic::async_trait]
impl miio_grpc::miio_commands_server::MiioCommands for MiioCommandsImpl {
    async fn send_command(&self, request: Request<SendCommandRequest>) -> Result<Response<DeviceResponse>, Status> {
        let request = request.into_inner();
        info!("{:?}", request.command);
        let device = MiIoDevice {
            token: MiIoToken::new(request.device?.token.as_str())?,
            ip_address: request.device?.inet_address.parse()?
        };
        let command = MiIoCommand::new(
            request.command?.method,
            vec![]
        );
        let result = miio::operations::send_request(&device, command);
        Ok(Response::new(DeviceResponse::default()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .target(Target::Stdout)
        .init();

    let addr = "0.0.0.0:50051".parse().unwrap();
    println!("MiioCommandsServer listening on {}", addr);
    Server::builder()
        .add_service(MiioCommandsServer::new(MiioCommandsImpl::default()))
        .serve(addr)
        .await?;

    Ok(())
}
