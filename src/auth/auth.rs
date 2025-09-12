use crate::{
    auth::{AuthRequest, Claims},
    server::AppState,
    store::User,
};
use alloy::signers::local::PrivateKeySigner;
use axum::{Json, extract::State};
use bigdecimal::BigDecimal;
use bitcoin::{Address, Network, PublicKey, key::Secp256k1, secp256k1::SecretKey};
use garden::api::{
    bad_request, internal_error,
    primitives::{ApiResult, Response},
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Generate a unique private key as hex string
fn generate_private_key() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Derive EVM (Ethereum) address from private key hex
fn derive_evm_address(private_key_hex: &str) -> eyre::Result<String> {
    let private_key_bytes = hex::decode(private_key_hex)?;
    let signer = PrivateKeySigner::from_slice(private_key_bytes.as_slice())
        .map_err(|e| eyre::eyre!("Invalid private key: {}", e))?;
    let address = signer.address();
    Ok(address.to_string())
}

/// Derive BTC address (P2PKH) from private key hex
fn derive_btc_address(private_key_hex: &str) -> eyre::Result<String> {
    let private_key_bytes =
        hex::decode(private_key_hex).map_err(|e| eyre::eyre!("Invalid private key hex: {}", e))?;
    let secp = Secp256k1::new();
    // Create SecretKey from the private key bytes
    let secret_key = SecretKey::from_slice(&private_key_bytes)
        .map_err(|e| eyre::eyre!("Invalid private key: {}", e))?;
    // Create PublicKey from SecretKey
    let public_key = PublicKey::new(secret_key.public_key(&secp));
    // Create P2PKH address from the public key
    let address = Address::p2pkh(&public_key, Network::Regtest);
    Ok(address.to_string())
}

/// Hash password (simple SHA256, use bcrypt/argon2 in production)
fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate JWT token for user_id
async fn generate_jwt(user_id: String, secret: &str) -> eyre::Result<String> {
    let expiration = (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize;
    let claims = Claims::new(user_id, expiration);
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| eyre::eyre!("Token generation failed: {}", e))?;
    Ok(token)
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequest>,
) -> ApiResult<String> {
    // Check if user exists
    if state
        .store
        .get_user_by_username(&payload.username)
        .await
        .map_err(|_e| internal_error("Internal Error"))?
        .is_some()
    {
        return Err(bad_request("User Already Exists")); // Or custom error
    }

    // Generate keys and addresses
    let pk = generate_private_key();
    let evm_addr = derive_evm_address(&pk).map_err(|_e| internal_error("Internal Error"))?;
    let btc_addr = derive_btc_address(&pk).map_err(|_e| internal_error("Internal Error"))?;
    let hashed_password = hash_password(&payload.pass);

    // Create user
    let mut user = User {
        user_id: uuid::Uuid::new_v4().to_string(), // Will be set by DB
        username: payload.username.to_string(),
        password: hashed_password,
        pk,
        btc_addr,
        evm_addr,
        booky_balance: BigDecimal::from(0),
    };

    let created_user = state
        .store
        .create_user(&mut user)
        .await
        .map_err(|_e| internal_error("Internal Error"))?;

    // Issue JWT token
    let token = generate_jwt(created_user.user_id, &state.jwt_secret)
        .await
        .map_err(|_e| internal_error("Internal Error"))?;

    Ok(Response::ok(token))
}

/// Login router handler
async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequest>,
) -> ApiResult<String> {
    // Fetch user by username
    let user = state
        .store
        .get_user_by_username(&payload.username)
        .await
        .map_err(|_e| internal_error("Internal Error"))?
        .ok_or_else(|| bad_request("Invalid username or password"))?;

    // Verify password
    let hashed_password = hash_password(&payload.pass);
    if user.password != hashed_password {
        return Err(bad_request("Invalid username or password"));
    }

    // Issue JWT token
    let token = generate_jwt(user.user_id, &state.jwt_secret)
        .await
        .map_err(|_e| internal_error("Internal Error"))?;

    Ok(Response::ok(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{AuthRequest, Claims},
        server::AppState,
    };
    use axum::{
        Json,
        body::Body,
        extract::State,
        http::{Request, StatusCode},
    };
    use axum_test::expect_json::uuid;
    use bigdecimal::BigDecimal;
    use jsonwebtoken::{DecodingKey, Validation, decode};
    use std::sync::Arc;

    // Helper function to create test app state
    async fn create_test_app_state() -> Arc<AppState> {
        Arc::new(AppState::default().await)
    }

    #[test]
    fn test_generate_private_key() {
        let pk1 = generate_private_key();
        let pk2 = generate_private_key();

        // Should generate 64 character hex strings (32 bytes)
        assert_eq!(pk1.len(), 64);
        assert_eq!(pk2.len(), 64);

        // Should be valid hex
        assert!(hex::decode(&pk1).is_ok());
        assert!(hex::decode(&pk2).is_ok());

        // Should be unique
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_derive_evm_address() {
        // Test with a known private key
        let private_key = generate_private_key();
        let result = derive_evm_address(&private_key);
        assert!(result.is_ok());

        let address = result.unwrap();
        // EVM addresses should start with 0x and be 42 characters long
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);

        // make sure returns the same address on retry
        let result = derive_evm_address(&private_key);
        assert!(result.is_ok());

        assert_eq!(address, result.unwrap())
    }

    #[test]
    fn test_derive_evm_address_invalid() {
        // Test with invalid hex
        let result = derive_evm_address("invalid_hex");
        assert!(result.is_err());

        // Test with wrong length
        let result = derive_evm_address("123456");
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_btc_address() {
        // Test with a known private key
        let private_key = &generate_private_key();
        let result = derive_btc_address(private_key);
        assert!(result.is_ok());

        let address = result.unwrap();

        // make sure returns the same address on retry
        let result = derive_btc_address(private_key);
        assert!(result.is_ok());

        assert_eq!(address, result.unwrap())
    }

    #[test]
    fn test_derive_btc_address_invalid() {
        // Test with invalid hex
        let result = derive_btc_address("invalid_hex");
        assert!(result.is_err());

        // Test with wrong length
        let result = derive_btc_address("123456");
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_password() {
        let password = "test_password";
        let hash1 = hash_password(password);
        let hash2 = hash_password(password);

        // Same password should produce same hash
        assert_eq!(hash1, hash2);

        // Hash should be 64 characters (SHA256)
        assert_eq!(hash1.len(), 64);

        // Different passwords should produce different hashes
        let different_hash = hash_password("different_password");
        assert_ne!(hash1, different_hash);
    }

    #[tokio::test]
    async fn test_generate_jwt() {
        let user_id = "test_user_123".to_string();
        let secret = "test_secret";

        let token = generate_jwt(user_id.clone(), secret).await;
        assert!(token.is_ok());

        let token = token.unwrap();

        // Verify the token can be decoded
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::default(),
        );

        assert!(token_data.is_ok());
        let claims = token_data.unwrap().claims;
        assert_eq!(claims.sub, user_id);
    }
    #[tokio::test]
    async fn test_register_success() {
        let state = create_test_app_state().await;
        // generate a random uuid
        let user_id = uuid::Uuid::new_v4().to_string();
        let auth_request = AuthRequest {
            username: user_id.clone(),
            pass: "testpassword".to_string(),
        };

        let result = register(State(state), Json(auth_request)).await;
        assert!(result.is_ok());

        let response = result.clone().unwrap();
        // Should return a JWT token
        assert!(!response.result.clone().unwrap().is_empty());

        // Verify the token is valid
        let token_data = decode::<Claims>(
            &response.result.unwrap(),
            &DecodingKey::from_secret("secret".as_ref()),
            &Validation::default(),
        );
        dbg!(&token_data);
        assert!(token_data.is_ok());
    }

    #[tokio::test]
    async fn test_register_user_already_exists() {
        let state = create_test_app_state().await;

        // First registration
        let user_id = uuid::Uuid::new_v4().to_string();
        let auth_request = AuthRequest {
            username: user_id.clone(),
            pass: "testpassword".to_string(),
        };
        let result1 = register(State(state.clone()), Json(auth_request.clone())).await;
        assert!(result1.is_ok());

        // Second registration with same username
        let result2 = register(State(state), Json(auth_request)).await;
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn test_login_success() {
        let state = create_test_app_state().await;
        let user_id = uuid::Uuid::new_v4().to_string();

        let auth_request = AuthRequest {
            username: user_id.clone(),
            pass: "testpassword".to_string(),
        };

        // First register the user
        let _ = register(State(state.clone()), Json(auth_request.clone())).await;

        // Then try to login
        let result = login(State(state), Json(auth_request)).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        // Should return a JWT token
        assert!(!response.result.clone().unwrap().is_empty());

        // Verify the token is valid
        let token_data = decode::<Claims>(
            &response.result.unwrap(),
            &DecodingKey::from_secret("secret".as_ref()),
            &Validation::default(),
        );
        assert!(token_data.is_ok());
    }

    #[tokio::test]
    async fn test_login_invalid_username() {
        let state = create_test_app_state().await;
        let auth_request = AuthRequest {
            username: "nonexistent_user".to_string(),
            pass: "testpassword".to_string(),
        };

        let result = login(State(state), Json(auth_request)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_login_invalid_password() {
        let state = create_test_app_state().await;
        let register_request = AuthRequest {
            username: "testuser".to_string(),
            pass: "correct_password".to_string(),
        };

        // Register user
        let _ = register(State(state.clone()), Json(register_request)).await;

        // Try to login with wrong password
        let login_request = AuthRequest {
            username: "testuser".to_string(),
            pass: "wrong_password".to_string(),
        };

        let result = login(State(state), Json(login_request)).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_key_generation_consistency() {
        // Generate a private key and verify both BTC and EVM addresses can be derived
        let pk = generate_private_key();

        let evm_result = derive_evm_address(&pk);
        let btc_result = derive_btc_address(&pk);

        assert!(evm_result.is_ok());
        assert!(btc_result.is_ok());

        // Verify addresses are different
        assert_ne!(evm_result.unwrap(), btc_result.unwrap());
    }
}
