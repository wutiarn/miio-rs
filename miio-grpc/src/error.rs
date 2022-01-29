use std::error::Error;
use std::fmt::Display;
use std::net::AddrParseError;
use log::warn;
use thiserror::Error;
use tonic::{Code, Status};

#[derive(Error, Debug)]
pub enum AppError {
    #[error("AddrParseError: {0}")]
    IncorrectInetAddress(#[from] AddrParseError),
    #[error("Required field is missing: {0}")]
    MissingRequiredField(&'static str),
    #[error("Anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error)
}

impl From<AppError> for Status {
    fn from(e: AppError) -> Self {
        warn!("Handling error: {}", e.to_string());
        Status::internal(e.to_string())
    }
}
