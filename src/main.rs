use crate::{mines::router, server::AppState};
use moka::future::Cache;
use std::sync::Arc;

mod mines;
mod primitives;
mod server;
mod store;
#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt().try_init();
    let sessions = Arc::new(Cache::builder().build());
    let app_state = AppState { sessions };
    let mines_router = router(Arc::new(app_state)).await;
    // serve this route in 0.0.0.0 : 5433
    let listener = tokio::net::TcpListener::bind("0.0.0.0:5433").await.unwrap();
    tracing::info!("server started at 0.0.0.0:5433");
    axum::serve(listener, mines_router).await.unwrap();
}
