mod db_store;
pub use db_store::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub user_id: i64,
    pub username: String,
    pub password: String,
    pub pk: String,
    pub btc_addr: String,
    pub evm_addr: String,
    pub booky_balance: f64,
}
