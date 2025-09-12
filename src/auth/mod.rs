mod auth;
use auth::*;
use serde::{Deserialize, Serialize};

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
