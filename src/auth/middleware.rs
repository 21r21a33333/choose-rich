use alloy::transports::BoxFuture;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{self, HeaderMap, StatusCode};
use axum::response::Response;
use jsonwebtoken::{DecodingKey, Validation, decode};
use std::task::{Context, Poll};
use std::time::SystemTime;
use tower::{Layer, Service};

use crate::auth::{AuthError, Claims};

/// Constant representing the admin address for privileged access
pub const ADMIN_ADDRESS: &str = "Admin";

/// Layer struct to inject authentication middleware into the service stack
#[derive(Clone)]
pub struct AuthLayer {
    pub expected_secret: String, // Expected server secret for admin authentication
    pub jwt_secret: String,      // Secret used to validate JWT tokens
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    /// Wrap the inner service with AuthMiddleware, passing secrets
    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            admin_secret: self.expected_secret.clone(),
            jwt_secret: self.jwt_secret.clone(),
        }
    }
}

/// Middleware struct that performs authentication on incoming requests
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    admin_secret: String,
    jwt_secret: String,
}

impl<S> Service<Request> for AuthMiddleware<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    /// Polls readiness of the inner service
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Handles incoming requests, authenticates, and either forwards or rejects them
    fn call(&mut self, mut req: Request) -> Self::Future {
        let admin_secret = self.admin_secret.clone();
        let jwt_secret = self.jwt_secret.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            match authenticate(req.headers(), &admin_secret, &jwt_secret) {
                Ok(addr) => {
                    // Insert authenticated address into request extensions
                    req.extensions_mut().insert(addr);
                    inner.call(req).await
                }
                Err(_) => Ok(unauthorized_response()),
            }
        })
    }
}

// ============= Authentication Logic =============

/// Authenticates the request using either server secret or JWT
fn authenticate(
    headers: &HeaderMap,
    expected_secret: &str,
    jwt_secret: &str,
) -> Result<String, AuthError> {
    if let Some(_) = headers.get("X-Server-secret") {
        // If server secret header is present, validate it
        validate_server_secret(headers, expected_secret)?;
        Ok(ADMIN_ADDRESS.to_string())
    } else {
        // Otherwise, validate JWT authentication
        validate_jwt_auth(headers, jwt_secret)
    }
}

/// Returns a 401 Unauthorized response
fn unauthorized_response() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::empty())
        .unwrap_or_default()
}

// ============= Validation Functions =============

/// Validates the server secret header for admin access
pub fn validate_server_secret(headers: &HeaderMap, expected_secret: &str) -> Result<(), AuthError> {
    let provided_secret = get_header_value(headers, "X-Server-secret");

    if provided_secret != expected_secret {
        return Err(AuthError::SignatureVerificationFailed(format!(
            "invalid server secret"
        )));
    }

    Ok(())
}

/// Validates the JWT Authorization header and returns the user ID if valid
pub fn validate_jwt_auth(headers: &HeaderMap, jwt_secret: &str) -> Result<String, AuthError> {
    let token = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    let valid_token = match token {
        Some(token) => token.strip_prefix("Bearer ").unwrap_or(token),
        None => {
            return Err(AuthError::SignatureVerificationFailed(
                "Missing Authorization header".to_string(),
            ));
        }
    };

    // Validate the JWT token
    validate_jwt(valid_token, jwt_secret)
}

// ============= Helper Functions =============

/// Retrieves a header value as a String, or empty string if missing/invalid
fn get_header_value(headers: &HeaderMap, key: &str) -> String {
    headers
        .get(key)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Decodes and validates a JWT, returning the user ID if valid and not expired
pub fn validate_jwt(jwt: &str, secret: &str) -> Result<String, AuthError> {
    // Decode and validate the JWT token
    let token = decode::<Claims>(
        jwt,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|e| AuthError::SignatureVerificationFailed(e.to_string()))?;

    // Check if token has expired
    is_expired(token.claims.exp as u64)?;

    Ok(token.claims.sub)
}

/// Get the current Unix timestamp in seconds
fn get_current_timestamp() -> Result<u64, AuthError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| AuthError::InternalError(e.to_string()))
}

/// Checks if the given expiration timestamp is in the past
fn is_expired(expiration: u64) -> Result<(), AuthError> {
    let current_timestamp = get_current_timestamp()?;

    if current_timestamp >= expiration {
        Err(AuthError::SignatureVerificationFailed(format!(
            "Token expired at {expiration}, current time is {current_timestamp}"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::{HeaderMap, Method};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_SECRET: &str = "test_secret_key_123";
    const TEST_JWT_SECRET: &str = "jwt_secret_key_456";
    const TEST_USER_ID: &str = "test_user_123";

    fn create_test_jwt(user_id: &str, exp_offset_secs: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = Claims {
            sub: user_id.to_string(),
            exp: (now as i64 + exp_offset_secs) as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET.as_ref()),
        )
        .unwrap()
    }

    fn create_server_secret_headers(secret: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("X-Server-secret", secret.parse().unwrap());
        headers
    }

    fn create_jwt_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", token).parse().unwrap(),
        );
        headers
    }

    pub fn create_test_service_with_auth()
    -> impl tower::Service<
        Request<Body>,
        Response = axum::response::Response,
        Error = axum::BoxError,
    > + Clone {
        tower::ServiceBuilder::new()
            .layer(AuthLayer {
                expected_secret: TEST_SECRET.to_string(),
                jwt_secret: TEST_JWT_SECRET.to_string(),
            })
            .service_fn(|req: Request<Body>| async move {
                let body = if let Some(user_id) = req.extensions().get::<String>() {
                    format!("{}", user_id)
                } else {
                    "Anonymous".to_string()
                };

                Ok::<_, axum::BoxError>(
                    axum::response::Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from(body))
                        .unwrap(),
                )
            })
    }

    #[cfg(test)]
    mod unit_tests {
        use super::*;

        #[tokio::test]
        async fn test_valid_jwt_token() {
            let token = create_test_jwt(TEST_USER_ID, 3600); // 1 hour from now
            let mut headers = HeaderMap::new();
            headers.insert(
                "Authorization",
                format!("Bearer {}", token).parse().unwrap(),
            );

            let result = validate_jwt_auth(&headers, TEST_JWT_SECRET);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), TEST_USER_ID);
        }

        #[tokio::test]
        async fn test_expired_jwt_token() {
            let token = create_test_jwt(TEST_USER_ID, -3600); // 1 hour ago
            let mut headers = HeaderMap::new();
            headers.insert(
                "Authorization",
                format!("Bearer {}", token).parse().unwrap(),
            );

            let result = validate_jwt_auth(&headers, TEST_JWT_SECRET);
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_invalid_jwt_token() {
            let mut headers = HeaderMap::new();
            headers.insert("Authorization", "Bearer invalid_token".parse().unwrap());

            let result = validate_jwt_auth(&headers, TEST_JWT_SECRET);
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_missing_authorization_header() {
            let headers = HeaderMap::new();
            let result = validate_jwt_auth(&headers, TEST_JWT_SECRET);
            assert!(result.is_err());
            match result.unwrap_err() {
                AuthError::SignatureVerificationFailed(msg) => {
                    assert!(msg.contains("Missing Authorization header"))
                }
                _ => panic!("Expected SignatureVerificationFailed error for missing header"),
            }
        }

        #[tokio::test]
        async fn test_jwt_without_bearer_prefix() {
            let token = create_test_jwt(TEST_USER_ID, 3600);
            let mut headers = HeaderMap::new();
            headers.insert("Authorization", token.parse().unwrap());

            let result = validate_jwt_auth(&headers, TEST_JWT_SECRET);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), TEST_USER_ID);
        }

        #[tokio::test]
        async fn test_valid_server_secret() {
            let headers = create_server_secret_headers(TEST_SECRET);
            let result = validate_server_secret(&headers, TEST_SECRET);
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_invalid_server_secret() {
            let headers = create_server_secret_headers("wrong_secret");
            let result = validate_server_secret(&headers, TEST_SECRET);
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_jwt_with_wrong_secret() {
            let token = create_test_jwt(TEST_USER_ID, 3600);
            let mut headers = HeaderMap::new();
            headers.insert(
                "Authorization",
                format!("Bearer {}", token).parse().unwrap(),
            );

            let result = validate_jwt_auth(&headers, "wrong_jwt_secret");
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_authenticate_with_server_secret() {
            let headers = create_server_secret_headers(TEST_SECRET);
            let result = authenticate(&headers, TEST_SECRET, TEST_JWT_SECRET);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ADMIN_ADDRESS);
        }

        #[tokio::test]
        async fn test_authenticate_with_jwt() {
            let token = create_test_jwt(TEST_USER_ID, 3600);
            let headers = create_jwt_headers(&token);
            let result = authenticate(&headers, TEST_SECRET, TEST_JWT_SECRET);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), TEST_USER_ID);
        }
    }

    #[cfg(test)]
    mod integration_tests {
        use tower::ServiceExt;

        use super::*;
        use std::usize;

        #[tokio::test]
        async fn test_middleware_with_valid_server_secret() {
            let middleware = create_test_service_with_auth();
            let payload = serde_json::json!({"test": "data"});

            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();

            request
                .headers_mut()
                .insert("X-Server-secret", TEST_SECRET.parse().unwrap());

            let response = middleware.oneshot(request).await;
            assert!(response.is_ok());
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
            assert_eq!(body_str, "Admin");
        }

        #[tokio::test]
        async fn test_middleware_with_invalid_server_secret() {
            let middleware = create_test_service_with_auth();
            let payload = serde_json::json!({"test": "data"});

            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();

            request
                .headers_mut()
                .insert("X-Server-secret", "invalid_secret".parse().unwrap());

            let response = middleware.oneshot(request).await;
            assert!(response.is_ok());
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn test_middleware_with_valid_jwt_token() {
            let middleware = create_test_service_with_auth();
            let token = create_test_jwt(TEST_USER_ID, 3600);
            let payload = serde_json::json!({"test": "data"});

            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();

            request.headers_mut().insert(
                "Authorization",
                format!("Bearer {}", token).parse().unwrap(),
            );

            let response = middleware.oneshot(request).await;
            assert!(response.is_ok());
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
            assert_eq!(body_str, TEST_USER_ID);
        }

        #[tokio::test]
        async fn test_middleware_with_expired_jwt_token() {
            let middleware = create_test_service_with_auth();
            let token = create_test_jwt(TEST_USER_ID, -3600); // expired 1 hour ago
            let payload = serde_json::json!({"test": "data"});

            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();

            request.headers_mut().insert(
                "Authorization",
                format!("Bearer {}", token).parse().unwrap(),
            );

            let response = middleware.oneshot(request).await;
            assert!(response.is_ok());
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn test_middleware_with_invalid_jwt_token() {
            let middleware = create_test_service_with_auth();
            let payload = serde_json::json!({"test": "data"});

            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();

            request
                .headers_mut()
                .insert("Authorization", "Bearer invalid_token".parse().unwrap());

            let response = middleware.oneshot(request).await;
            assert!(response.is_ok());
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn test_middleware_with_jwt_without_bearer_prefix() {
            let middleware = create_test_service_with_auth();
            let token = create_test_jwt(TEST_USER_ID, 3600);
            let payload = serde_json::json!({"test": "data"});

            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();

            request
                .headers_mut()
                .insert("Authorization", token.parse().unwrap());

            let response = middleware.oneshot(request).await;
            assert!(response.is_ok());
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
            assert_eq!(body_str, TEST_USER_ID);
        }

        #[tokio::test]
        async fn test_middleware_with_no_auth_headers() {
            let middleware = create_test_service_with_auth();
            let payload = serde_json::json!({"test": "data"});

            let request = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();

            let response = middleware.oneshot(request).await;
            assert!(response.is_ok());
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn test_middleware_server_secret_takes_precedence_over_jwt() {
            let middleware = create_test_service_with_auth();
            let token = create_test_jwt(TEST_USER_ID, 3600);
            let payload = serde_json::json!({"test": "data"});

            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();

            // Add both server secret and JWT token
            request
                .headers_mut()
                .insert("X-Server-secret", TEST_SECRET.parse().unwrap());
            request.headers_mut().insert(
                "Authorization",
                format!("Bearer {}", token).parse().unwrap(),
            );

            let response = middleware.oneshot(request).await;
            assert!(response.is_ok());
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
            // Should return "Admin" since server secret takes precedence
            assert_eq!(body_str, "Admin");
        }

        #[tokio::test]
        async fn test_middleware_preserves_request_body_with_jwt() {
            let middleware = create_test_service_with_auth();
            let token = create_test_jwt(TEST_USER_ID, 3600);
            let payload = serde_json::json!({"important": "data", "number": 42});
            let payload_bytes = serde_json::to_vec(&payload).unwrap();

            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .body(Body::from(payload_bytes.clone()))
                .unwrap();

            request.headers_mut().insert(
                "Authorization",
                format!("Bearer {}", token).parse().unwrap(),
            );

            let response = middleware.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn test_multiple_users_with_different_jwt_tokens() {
            let middleware = create_test_service_with_auth();

            // Test first user
            let user1_id = "user_001";
            let token1 = create_test_jwt(user1_id, 3600);
            let payload = serde_json::json!({"test": "data"});

            let mut request1 = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();

            request1.headers_mut().insert(
                "Authorization",
                format!("Bearer {}", token1).parse().unwrap(),
            );

            let response1 = middleware.clone().oneshot(request1).await.unwrap();
            assert_eq!(response1.status(), StatusCode::OK);

            let body_bytes1 = axum::body::to_bytes(response1.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_str1 = String::from_utf8(body_bytes1.to_vec()).unwrap();
            assert_eq!(body_str1, user1_id);

            // Test second user
            let user2_id = "user_002";
            let token2 = create_test_jwt(user2_id, 3600);

            let mut request2 = Request::builder()
                .method(Method::POST)
                .uri("/test")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();

            request2.headers_mut().insert(
                "Authorization",
                format!("Bearer {}", token2).parse().unwrap(),
            );

            let response2 = middleware.oneshot(request2).await.unwrap();
            assert_eq!(response2.status(), StatusCode::OK);

            let body_bytes2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_str2 = String::from_utf8(body_bytes2.to_vec()).unwrap();
            assert_eq!(body_str2, user2_id);
        }
    }
}
