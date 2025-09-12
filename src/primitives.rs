use moka::future::Cache;
use std::{hash::Hash, sync::Arc, time::Duration};

pub fn new_moka_cache<T: Eq + Hash + Send + Sync + 'static, U: Clone + Send + Sync + 'static>(
    ttl: Duration,
) -> Arc<Cache<T, U>> {
    Arc::new(Cache::builder().time_to_live(ttl).build())
}
