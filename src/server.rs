use moka::future::Cache;
use std::{sync::Arc, time::Duration};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Service {
    Mines,
}

// Application state
#[derive(Clone)]
pub struct AppState {
    pub sessions: Arc<Cache<Service, Arc<Cache<String, serde_json::Value>>>>,
}


impl Default for AppState {
    fn default() -> Self {
        Self {
            sessions: Arc::new(
                Cache::builder()
                    .time_to_live(Duration::from_secs(30 * 60))
                    .build(),
            ),
        }
    }
}
