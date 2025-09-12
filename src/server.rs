use moka::future::Cache;
use std::{sync::Arc, time::Duration};

use crate::store::Store;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Service {
    Mines,
    Apex,
}

// Application state
#[derive(Clone)]
pub struct AppState {
    pub sessions: Arc<Cache<Service, Arc<Cache<String, serde_json::Value>>>>,
    pub store: Arc<Store>,
    pub jwt_secret: String,
}

impl AppState {
    pub fn new(
        sessions: Arc<Cache<Service, Arc<Cache<String, serde_json::Value>>>>,
        store: Arc<Store>,
        jwt_secret: String,
    ) -> Self {
        Self {
            sessions,
            store,
            jwt_secret,
        }
    }
    pub async fn default() -> Self {
        let pg_defautl = "postgresql://postgres:postgres@localhost:5432/postgres";
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2000)
            .connect(pg_defautl)
            .await
            .unwrap();
        Self {
            sessions: Arc::new(
                Cache::builder()
                    .time_to_live(Duration::from_secs(30 * 60))
                    .build(),
            ),
            store: Arc::new(Store::new(pool).await.unwrap()),
            jwt_secret: String::from("secret"),
        }
    }
}
