use crate::{auth::AuthLayer, mines::router, server::AppState, store::Store};
use axum::{Router, routing::get};
use moka::future::Cache;
use std::sync::Arc;
mod apex;
mod auth;
mod mines;
mod primitives;
mod server;
mod store;

const JWT_SECRET: &str = "JWT_SECRET";

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt().try_init();
    let sessions = Arc::new(Cache::builder().build());
    let pg_default = "postgresql://postgres:postgres@localhost:5432/postgres";
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2000)
        .connect(pg_default)
        .await
        .unwrap();
    let store = Arc::new(Store::new(pool).await.expect("unable to create store"));
    let app_state = AppState::new(sessions, store, JWT_SECRET.to_string());

    use tower_http::cors::{Any, CorsLayer};

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let apex_router = apex::router(Arc::new(app_state.clone()));
    let mines_router = router(Arc::new(app_state)).await;
    let app_router = Router::new()
        .route("/", get(|| async { "Choose Rich API is running!" }))
        .merge(apex_router)
        .merge(mines_router)
        .layer(AuthLayer {
            expected_secret: "X-Server-secret".to_string(),
            jwt_secret: JWT_SECRET.to_string(),
        })
        .layer(cors);

    // serve this route in 0.0.0.0 : 5433
    let listener = tokio::net::TcpListener::bind("0.0.0.0:5433").await.unwrap();
    tracing::info!("server started at 0.0.0.0:5433");
    axum::serve(listener, app_router).await.unwrap();
}
