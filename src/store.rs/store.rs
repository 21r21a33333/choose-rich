#[derive(Clone)]
// The `Orderbook` trait implementation. Provides various orderbook queries direct from db.
pub struct Store {
    pub pool: Pool<Postgres>,
}

impl OrderbookProvider {
    pub fn new(pool: Pool<Postgres>) -> Self {
        OrderbookProvider { pool }
    }

    pub async fn from_db_url(db_url: &str) -> Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2000)
            .connect(db_url)
            .await?;
        Ok(Self::new(pool))
    }
}
