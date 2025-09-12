use crate::store::User;
use sqlx::{Pool, Postgres, Result};

pub struct Store {
    pool: Pool<Postgres>,
}

impl Store {
    /// Run database migration to create the users table if it does not exist.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                pk VARCHAR(255) NOT NULL,
                btc_addr VARCHAR(255) NOT NULL,
                evm_addr VARCHAR(255) NOT NULL,
                booky_balance DECIMAL(18, 2) NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        //create indexes
        self.create_indexes().await?;
        Ok(())
    }
    pub async fn new(pool: Pool<Postgres>) -> Result<Self> {
        let store = Store { pool };
        store.migrate().await?;
        Ok(store)
    }

    // Create a new user
    pub async fn create_user(&self, user: &User) -> Result<User> {
        sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (username, password, pk, btc_addr, evm_addr, booky_balance)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(&user.username)
        .bind(&user.password)
        .bind(&user.pk)
        .bind(&user.btc_addr)
        .bind(&user.evm_addr)
        .bind(user.booky_balance)
        .fetch_one(&self.pool)
        .await
    }

    // Read a user by ID
    pub async fn get_user_by_id(&self, user_id: i64) -> Result<Option<User>> {
        sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
    }

    // Read a user by username
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users WHERE username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
    }

    // Update a user
    pub async fn update_user(&self, user: &User) -> Result<User> {
        sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET username = $1, password = $2, pk = $3, btc_addr = $4, evm_addr = $5, booky_balance = $6
            WHERE user_id = $7
            RETURNING *
            "#
        )
        .bind(&user.username)
        .bind(&user.password)
        .bind(&user.pk)
        .bind(&user.btc_addr)
        .bind(&user.evm_addr)
        .bind(user.booky_balance)
        .bind(user.user_id.to_string())
        .fetch_one(&self.pool)
        .await
    }

    // Delete a user
    pub async fn delete_user(&self, user_id: i64) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM users WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    // Create indexes
    pub async fn create_indexes(&self) -> Result<()> {
        // Index on username for faster lookups
        sqlx::query(
            r#"
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Index on btc_addr for cryptocurrency-related queries
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_users_btc_addr ON users (btc_addr)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Index on evm_addr for Ethereum-related queries
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_users_evm_addr ON users (evm_addr)
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
