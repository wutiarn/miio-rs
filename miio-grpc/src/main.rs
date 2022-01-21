use log::info;
use tonic::{Request, Response, Status};
use tonic::transport::Server;
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
        Ok(Response::new(DeviceResponse::default()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:50051".parse().unwrap();
    println!("MiioCommandsServer listening on {}", addr);
    Server::builder()
        .add_service(MiioCommandsServer::new(MiioCommandsImpl::default()))
        .serve(addr)
        .await?;

    Ok(())
}
