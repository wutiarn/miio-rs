use thiserror::Error;
use tonic::{Code, Status};

#[derive(Error, Debug)]
pub enum AppError {
    #[error("internal error")]
    Internal(#[from] std::io::Error)
}

impl From<AppError> for Status {
    fn from(app_err: AppError) -> Self {
        match app_err {
            AppError::Internal(e) => Status::internal(
                format!("Internal error: {}", e.to_string())
            )
        }
    }
}