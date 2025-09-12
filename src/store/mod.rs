mod db_store;
pub use db_store::*;
use serde::{Deserialize, Serialize};
use sqlx::types::BigDecimal;

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub user_id: String,
    pub username: String,
    pub password: String,
    pub pk: String,
    pub btc_addr: String,
    pub evm_addr: String,
    pub booky_balance: BigDecimal,
}

impl User {
    pub fn new(
        user_id: String,
        username: String,
        password: String,
        pk: String,
        btc_addr: String,
        evm_addr: String,
        booky_balance: BigDecimal,
    ) -> Self {
        Self {
            user_id, // Will be set by DB
            username,
            password,
            pk,
            btc_addr,
            evm_addr,
            booky_balance,
        }
    }
}
