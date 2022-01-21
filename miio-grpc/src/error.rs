use std::error::Error;
use std::net::AddrParseError;
use log::warn;
use thiserror::Error;
use tonic::{Code, Status};

#[derive(Error, Debug)]
pub enum AppError {
    #[error("internal error")]
    Internal(anyhow::Error)
}

impl From<AppError> for Status {
    fn from(app_err: AppError) -> Self {
        match app_err {
            AppError::Internal(e) => {
                warn!("Handling error: {}", e.to_string());
                Status::internal(
                    format!("Internal error: {}", e.to_string())
                )
            }
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e)
    }
}

impl From<AddrParseError> for AppError {
    fn from(e: AddrParseError) -> Self {
        AppError::Internal(e.into())
    }
}
