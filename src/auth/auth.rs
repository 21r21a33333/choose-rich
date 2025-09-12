use crate::{
    auth::{AuthRequest, Claims},
    server::AppState,
    store::User,
};
use alloy::signers::local::PrivateKeySigner;
use axum::{Json, extract::State};
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
    let booky_balance = 0.0;

    // Create user
    let mut user = User {
        user_id: uuid::Uuid::new_v4().to_string(), // Will be set by DB
        username: payload.username.to_string(),
        password: hashed_password,
        pk,
        btc_addr,
        evm_addr,
        booky_balance,
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
