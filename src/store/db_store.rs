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
                user_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                pk VARCHAR(255) NOT NULL,
                btc_addr VARCHAR(255) NOT NULL,
                evm_addr VARCHAR(255) NOT NULL,
                booky_balance NUMERIC NOT NULL
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
        .bind(user.booky_balance.clone())
        .fetch_one(&self.pool)
        .await
    }

    // Read a user by ID
    pub async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>> {
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
        .bind(user.booky_balance.clone())
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

#[cfg(test)]
mod tests {
    use bigdecimal::BigDecimal;

    use super::*;
    use crate::store::User; // Assuming User is in crate::store
    async fn create_default_store() -> Store {
        let pg_default = "postgresql://postgres:postgres@localhost:5432/postgres";
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2000)
            .connect(pg_default)
            .await
            .unwrap();
        let store = Store::new(pool.clone()).await.unwrap();
        clear_db(&pool).await;
        store
    }
    async fn clear_db(pool: &Pool<Postgres>) {
        sqlx::query(
            r#"
            Truncate table users CASCADE
            "#,
        )
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_create_user() {
        let store = create_default_store().await;
        let user_id = uuid::Uuid::new_v4().to_string();
        let user = User {
            user_id: user_id.clone(), // Ignored on insert
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            pk: "testpk".to_string(),
            btc_addr: "testbtc".to_string(),
            evm_addr: "testevm".to_string(),
            booky_balance: BigDecimal::from(100), // Assuming f64 or BigDecimal; adjust if needed
        };

        let created_user = store.create_user(&user).await.unwrap();

        // Assert the returned user matches the input (except auto-generated ID)
        assert_eq!(created_user.username, user.username);
        assert_eq!(created_user.password, user.password);
        assert_eq!(created_user.pk, user.pk);
        assert_eq!(created_user.btc_addr, user.btc_addr);
        assert_eq!(created_user.evm_addr, user.evm_addr);
        assert_eq!(created_user.booky_balance, user.booky_balance);
        assert_ne!(created_user.user_id, user_id); // Should be auto-generated
    }

    #[tokio::test]
    async fn test_get_user_by_username() {
        let store = create_default_store().await;
        let user_id = uuid::Uuid::new_v4().to_string();
        let user = User {
            user_id: user_id.clone(),
            username: "getuser".to_string(),
            password: "getpass".to_string(),
            pk: "getpk".to_string(),
            btc_addr: "getbtc".to_string(),
            evm_addr: "getevm".to_string(),
            booky_balance: BigDecimal::from(200),
        };

        let created_user = store.create_user(&user).await.unwrap();

        let fetched_user = store
            .get_user_by_username(&user.username)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched_user.user_id, created_user.user_id);
        assert_eq!(fetched_user.username, user.username);
        assert_eq!(fetched_user.password, user.password);
        // ... similarly for other fields
    }

    #[tokio::test]
    async fn test_get_user_by_id() {
        let store = create_default_store().await;
        let user_id = uuid::Uuid::new_v4().to_string();
        let user = User {
            user_id: user_id.clone(),
            username: "iduser".to_string(),
            password: "idpass".to_string(),
            pk: "idpk".to_string(),
            btc_addr: "idbtc".to_string(),
            evm_addr: "idevm".to_string(),
            booky_balance: BigDecimal::from(300),
        };

        let created_user = store.create_user(&user).await.unwrap();
        let user_id = created_user.user_id;
        let fetched_user = store.get_user_by_id(&user_id).await.unwrap().unwrap();
        assert_eq!(fetched_user.user_id, user_id);
        assert_eq!(fetched_user.username, user.username);
        // ... other fields
    }

    #[tokio::test]
    async fn test_update_user() {
        let store = create_default_store().await;
        let user_id = uuid::Uuid::new_v4().to_string();
        let mut user = User {
            user_id: user_id.clone(),
            username: "updateuser".to_string(),
            password: "updatepass".to_string(),
            pk: "updatepk".to_string(),
            btc_addr: "updatebtc".to_string(),
            evm_addr: "updateevm".to_string(),
            booky_balance: BigDecimal::from(400),
        };

        let created_user = store.create_user(&user).await.unwrap();
        user.user_id = created_user.user_id;

        // Update with new values
        user.username = "updateduser".to_string();
        user.password = "updatedpass".to_string();
        user.booky_balance = BigDecimal::from(500);

        let updated_user = store.update_user(&user).await.unwrap();

        assert_eq!(updated_user.username, "updateduser");
        assert_eq!(updated_user.password, "updatedpass");
        assert_eq!(updated_user.booky_balance, BigDecimal::from(500));
        assert_eq!(updated_user.user_id, user.user_id);
    }

    #[tokio::test]
    async fn test_delete_user() {
        let store = create_default_store().await;
        let user_id = uuid::Uuid::new_v4().to_string();
        let user = User {
            user_id: user_id.clone(),
            username: "deleteuser".to_string(),
            password: "deletepass".to_string(),
            pk: "deletepk".to_string(),
            btc_addr: "deletebtc".to_string(),
            evm_addr: "deleteevm".to_string(),
            booky_balance: BigDecimal::from(600),
        };

        let created_user = store.create_user(&user).await.unwrap();
        let user_id = created_user.user_id;

        let deleted_user = store.get_user_by_id(&user_id).await.unwrap();
        assert!(deleted_user.is_none());
    }

    #[tokio::test]
    async fn test_migrate_creates_table() {
        let pg_default = "postgresql://postgres:postgres@localhost:5432/postgres";
        let pool = sqlx::postgres::PgPool::connect(pg_default).await.unwrap();

        // Drop table if exists to test creation
        let _ = sqlx::query("DROP TABLE IF EXISTS users CASCADE")
            .execute(&pool)
            .await;

        let store = Store { pool };
        store.migrate().await.unwrap();

        // Verify table exists
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!(row.0);

        // Verify indexes exist
        let idx_username: (bool,) = sqlx::query_as(
            "SELECT EXISTS (SELECT FROM pg_indexes WHERE indexname = 'idx_users_username')",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!(idx_username.0);

        // Similarly for other indexes...
    }

    #[tokio::test]
    async fn test_get_nonexistent_user() {
        let store = create_default_store().await;
        let user = store.get_user_by_username("nonexistent").await.unwrap();
        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_create_user_unique_username() {
        let store = create_default_store().await;
        let user_id = uuid::Uuid::new_v4().to_string();
        let user1 = User {
            user_id: user_id.clone(),
            username: "uniqueuser".to_string(),
            password: "pass1".to_string(),
            pk: "pk1".to_string(),
            btc_addr: "btc1".to_string(),
            evm_addr: "evm1".to_string(),
            booky_balance: BigDecimal::from(700),
        };

        let _ = store.create_user(&user1).await.unwrap();

        let user2 = User {
            user_id: user_id.clone(),
            username: "uniqueuser".to_string(), // Duplicate
            password: "pass2".to_string(),
            pk: "pk2".to_string(),
            btc_addr: "btc2".to_string(),
            evm_addr: "evm2".to_string(),
            booky_balance: BigDecimal::from(800),
        };

        let result = store.create_user(&user2).await;
        assert!(result.is_err()); // Should fail due to unique constraint
    }
}
