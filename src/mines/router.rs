use crate::{
    mines::{
        CashoutRequest, CashoutResponse, GameSession, MoveRequest, MoveResponse, SESSION_TTL,
        SessionStatus, StartGameRequest, StartGameResponse,
    },
    primitives::new_moka_cache,
    server::{AppState, Service},
};
use axum::{
    Extension, Json, Router,
    extract::State,
    routing::{get, post},
};
use garden::api::{
    bad_request, internal_error,
    primitives::{ApiResult, Response},
};
use serde_json::to_value;
use std::sync::Arc;

async fn start_game(
    State(state): State<Arc<AppState>>,
    Extension(user_addr): Extension<String>,
    Json(payload): Json<StartGameRequest>,
) -> ApiResult<StartGameResponse> {
    let session = GameSession::new(payload.amount, payload.blocks, payload.mines, user_addr)
        .map_err(|e| bad_request(&e.to_string()))?;
    let response = StartGameResponse {
        id: session.id.clone(),
        amount: payload.amount,
        blocks: payload.blocks,
        mines: payload.mines,
        session_status: SessionStatus::Active,
    };

    let service_state = match state.sessions.get(&Service::Mines).await {
        Some(cache) => cache,
        None => {
            let cache = new_moka_cache(SESSION_TTL);
            state.sessions.insert(Service::Mines, cache.clone()).await;
            cache
        }
    };

    service_state
        .insert(
            session.id.clone(),
            to_value(&session).map_err(|_| internal_error("Serialization error"))?,
        )
        .await;

    Ok(Response::ok(response))
}

async fn make_move(
    State(state): State<Arc<AppState>>,
    Extension(user_addr): Extension<String>,
    Json(payload): Json<MoveRequest>,
) -> ApiResult<MoveResponse> {
    let service_state = state
        .sessions
        .get(&Service::Mines)
        .await
        .ok_or(bad_request("Session not found"))?;
    let mut session: GameSession = service_state
        .get(&payload.id)
        .await
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or(bad_request("Session not found"))?;

    let response = session
        .make_move(payload.block, user_addr)
        .map_err(|e| bad_request(&e.to_string()))?;
    service_state
        .insert(
            session.id.clone(),
            to_value(&session).map_err(|_| internal_error("Serialization error"))?,
        )
        .await;

    if response.session_status == SessionStatus::Ended {
        // if the session is ended, delete the session
        // state.store.upda
    }

    Ok(Response::ok(response))
}

async fn cashout(
    State(state): State<Arc<AppState>>,
    Extension(user_addr): Extension<String>,
    Json(payload): Json<CashoutRequest>,
) -> ApiResult<CashoutResponse> {
    let service_state = state
        .sessions
        .get(&Service::Mines)
        .await
        .ok_or(bad_request("Session not found"))?;
    let mut session: GameSession = service_state
        .get(&payload.id)
        .await
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or(bad_request("Session not found"))?;

    let response = session
        .cashout(user_addr)
        .map_err(|e| bad_request(&e.to_string()))?;
    service_state
        .insert(
            session.id.clone(),
            to_value(&session).map_err(|_| internal_error("Serialization error"))?,
        )
        .await;

    Ok(Response::ok(response))
}

async fn health_check() -> &'static str {
    "Mines API is running!"
}

pub async fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/mines/start", post(start_game))
        .route("/mines/move", post(make_move))
        .route("/mines/cashout", post(cashout))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_game_session_new_valid() {
        let result = GameSession::new(100, 25, 5, "string".to_string());
        assert!(result.is_ok());
        let session = result.unwrap();
        assert_eq!(session.src, 100);
        assert_eq!(session.blocks, 25);
        assert_eq!(session.mines, 5);
        assert_eq!(session.mine_positions.len(), 5);
        assert_eq!(session.status, SessionStatus::Active);
    }

    #[test]
    fn test_game_session_new_invalid_blocks() {
        let result = GameSession::new(100, 7, 2, "string".to_string());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid Blocks");
    }

    #[tokio::test]
    async fn test_make_move_safe_block() {
        let mut session = GameSession::new(100, 25, 5, "string".to_string()).unwrap();
        let block = (1..=session.blocks)
            .find(|b| !session.mine_positions.contains(b))
            .unwrap();
        let result = session.make_move(block, "string".to_string());
        assert!(result.is_ok());
        dbg!(&result);
        let response = result.unwrap();
        assert_eq!(response.session_status, SessionStatus::Active);
        assert!(response.current_multiplier.is_some());
        assert!(response.potential_payout.is_some());
        assert!(response.final_payout.is_none());
        assert!(response.bomb_blocks.is_none());
        assert_eq!(response.actions.len(), 1);
    }

    // loop through all valid blocks and make sure the current_multiplier is increasing and potential payout
    // is increasing
    #[tokio::test]
    async fn test_make_move_valid_blocks() {
        let mut session = GameSession::new(100, 25, 5, "string".to_string()).unwrap();
        for block in 1..=25 {
            let result = session.make_move(block, "string".to_string());
            if session.mine_positions.contains(&block) {
                // If we hit a mine, the game should end and this should be the last move
                assert!(result.is_ok());
                let response = result.unwrap();
                assert_eq!(response.session_status, SessionStatus::Ended);
                break; // Game is over, no more moves possible
            } else {
                // Safe block, should succeed
                assert!(result.is_ok());
                let response = result.unwrap();
                assert_eq!(response.session_status, SessionStatus::Active);
            }
        }
    }

    #[tokio::test]
    async fn test_make_move_mine_block() {
        let mut session = GameSession::new(100, 25, 5, "string".to_string()).unwrap();
        let block = *session.mine_positions.iter().next().unwrap();
        let result = session.make_move(block, "string".to_string());
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.session_status, SessionStatus::Ended);
        assert!(response.current_multiplier.is_none());
        assert!(response.potential_payout.is_none());
        assert_eq!(response.final_payout, Some(0));
        assert_eq!(response.bomb_blocks.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn test_cashout_active_session() {
        let mut session = GameSession::new(100, 25, 5, "string".to_string()).unwrap();
        // take a block not in mine block
        let block = (1..=session.blocks)
            .find(|b| !session.mine_positions.contains(b))
            .unwrap();
        session.make_move(block, "string".to_string()).unwrap();
        let result = session.cashout("string".to_string());
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.session_status, SessionStatus::Ended);
        assert!(response.final_payout > 0);
        assert_eq!(response.src, 100);
        assert_eq!(response.bomb_blocks.len(), 5);
        // Verify that all bomb blocks are included
        for &bomb_block in &response.bomb_blocks {
            assert!(session.mine_positions.contains(&bomb_block));
        }
    }

    #[tokio::test]
    async fn test_iterate_valid_blocks_increasing_payout_multiplier() {
        let mut session = GameSession::new(100, 25, 5, "string".to_string()).unwrap();
        let mut last_multiplier = 1.0;
        let mut last_payout = 100;

        // Collect safe blocks (those not containing mines)
        let safe_blocks: Vec<u32> = (1..=session.blocks)
            .filter(|b| !session.mine_positions.contains(b))
            .collect();

        // Iterate through safe blocks up to a reasonable limit to avoid excessive moves
        for &block in safe_blocks.iter().take(5) {
            let result = session.make_move(block, "string".to_string());
            assert!(
                result.is_ok(),
                "Move should be successful for block {}",
                block
            );
            let response = result.unwrap();

            assert_eq!(
                response.session_status,
                SessionStatus::Active,
                "Session should remain active"
            );
            assert!(
                response.current_multiplier.is_some(),
                "Current multiplier should be present"
            );
            assert!(
                response.potential_payout.is_some(),
                "Potential payout should be present"
            );
            assert!(
                response.final_payout.is_none(),
                "Final payout should not be set"
            );
            assert!(
                response.bomb_blocks.is_none(),
                "Bomb blocks should not be revealed"
            );

            let current_multiplier = response.current_multiplier.unwrap();
            let current_payout = response.potential_payout.unwrap();

            assert!(
                current_multiplier > last_multiplier,
                "Multiplier should increase: {} > {}",
                current_multiplier,
                last_multiplier
            );
            assert!(
                current_payout > last_payout,
                "Payout should increase: {} > {}",
                current_payout,
                last_payout
            );

            last_multiplier = current_multiplier;
            last_payout = current_payout;
        }
    }

    #[tokio::test]
    async fn test_house_edge_implementation() {
        let mut session = GameSession::new(100, 25, 5, "string".to_string()).unwrap();

        // Find a safe block to make a move
        let safe_block = (1..=25)
            .find(|&b| !session.mine_positions.contains(&b))
            .unwrap();

        let result = session.make_move(safe_block, "string".to_string()).unwrap();
        let multiplier = result.current_multiplier.unwrap();

        // With 1% house edge, the multiplier should be 99% of the theoretical value
        // Theoretical multiplier for first safe pick: 25/20 = 1.25
        // With house edge: 0.99 * 1.25 = 1.2375
        let expected_multiplier = 0.99 * (25.0 / 20.0);

        assert!(
            (multiplier - expected_multiplier).abs() < 0.0001,
            "Expected multiplier ~{}, got {}",
            expected_multiplier,
            multiplier
        );

        // Verify the payout is reduced by house edge
        let expected_payout = (100.0 * expected_multiplier) as u32;
        let actual_payout = result.potential_payout.unwrap();

        assert_eq!(
            actual_payout, expected_payout,
            "Expected payout {}, got {}",
            expected_payout, actual_payout
        );
    }

    #[tokio::test]
    async fn test_multiple_moves_house_edge() {
        let mut session = GameSession::new(1000, 25, 5, "string".to_string()).unwrap();

        // Make several safe moves and verify house edge is applied consistently
        let safe_blocks: Vec<u32> = (1..=25)
            .filter(|&b| !session.mine_positions.contains(&b))
            .take(3)
            .collect();

        for (i, &block) in safe_blocks.iter().enumerate() {
            let result = session.make_move(block, "string".to_string()).unwrap();
            let multiplier = result.current_multiplier.unwrap();

            // Calculate expected multiplier with house edge
            let safe_picks = (i + 1) as u32;
            let remaining_safe = 25 - 5 - i as u32;
            let theoretical_multiplier = (0..safe_picks).fold(1.0, |acc, j| {
                let remaining = 25 - 5 - j;
                acc * 25.0 / remaining as f64
            });
            let expected_multiplier = theoretical_multiplier * 0.99_f64.powi(safe_picks as i32);

            assert!(
                (multiplier - expected_multiplier).abs() < 0.0001,
                "Move {}: Expected multiplier ~{}, got {}",
                i + 1,
                expected_multiplier,
                multiplier
            );
        }
    }
    // Start a test server and write tests using reqwest and tokio
}
