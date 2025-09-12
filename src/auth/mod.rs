mod auth;
mod middleware;
pub use auth::*;
pub use middleware::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

// Assuming you have a Claims struct for JWT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub exp: usize,  // expiration
}
impl Claims {
    pub fn new(sub: String, exp: usize) -> Self {
        Self { sub, exp }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    username: String,
    pass: String,
}
