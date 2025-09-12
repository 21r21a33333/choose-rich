use crate::{
    primitives::new_moka_cache,
    server::{AppState, Service},
};
use axum::{Router, extract::State, response::Json, routing::post};
use garden::api::{
    bad_request, internal_error,
    primitives::{ApiResult, Response},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::to_value;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

const SESSION_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartGameRequest {
    pub amount: u32,
    pub option: GameOption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GameOption {
    Blinder,
    NonBlinder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartGameResponse {
    pub id: String,
    pub amount: u32,
    pub option: GameOption,
    pub system_number: u32,
    pub user_number: Option<u32>, // Only for blinder mode
    pub payout_high: Option<f64>,
    pub probability_high: Option<f64>,
    pub payout_low: Option<f64>,
    pub probability_low: Option<f64>,
    pub payout_equal: Option<f64>,
    pub probability_equal: Option<f64>,
    pub payout_percentage: Option<f64>,    // Only for blinder
    pub blinder_suit: Option<BlinderSuit>, // Only for blinder mode
    pub session_status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlinderSuit {
    pub won: bool,
    pub payout: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChooseRequest {
    pub id: String,
    pub choice: Choice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Choice {
    High,
    Low,
    Equal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChooseResponse {
    pub id: String,
    pub choice: Option<Choice>, // None for Blinder
    pub user_number: u32,
    pub system_number: u32,
    pub won: bool,
    pub payout: u32,
    pub session_status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameSession {
    pub id: String,
    pub amount: u32,
    pub option: GameOption,
    pub system_number: u32,
    pub user_number: Option<u32>,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionStatus {
    Active,
    Ended,
}

impl GameSession {
    pub fn new(amount: u32, option: GameOption) -> Self {
        let mut rng = rand::thread_rng();
        let system_number = rng.gen_range(0..=9);
        let user_number = match option {
            GameOption::Blinder => Some(rng.gen_range(0..=9)),
            GameOption::NonBlinder => None,
        };
        GameSession {
            id: Uuid::new_v4().to_string(),
            amount,
            option,
            system_number,
            user_number,
            status: SessionStatus::Active,
        }
    }

    pub fn get_choice_info(&self, choice: &Choice) -> (f64, f64) {
        let true_probability = match choice {
            Choice::High => (9.0 - self.system_number as f64) / 10.0,
            Choice::Low => self.system_number as f64 / 10.0,
            Choice::Equal => 1.0 / 10.0, // Always 1/10 = 0.1 (10% chance)
        };
        let payout = if true_probability > 0.0 {
            (1.0 - 0.01) / true_probability
        } else {
            0.0
        };
        (true_probability, payout)
    }

    pub fn make_choice(&mut self, choice: Choice) -> eyre::Result<ChooseResponse> {
        if self.status != SessionStatus::Active {
            return Err(eyre::eyre!("Session is not active"));
        }
        if matches!(self.option, GameOption::Blinder) {
            return Err(eyre::eyre!("Cannot make choice in blinder mode"));
        }
        self.status = SessionStatus::Ended;
        let mut rng = rand::thread_rng();
        let user_number = rng.gen_range(0..=9);
        let (_prob, payout_multiplier) = self.get_choice_info(&choice);
        let won = match choice {
            Choice::High => user_number > self.system_number,
            Choice::Low => user_number < self.system_number,
            Choice::Equal => user_number == self.system_number,
        };
        let payout = if won {
            (self.amount as f64 * payout_multiplier) as u32
        } else {
            0
        };
        Ok(ChooseResponse {
            id: self.id.clone(),
            choice: Some(choice),
            user_number,
            system_number: self.system_number,
            won,
            payout,
            session_status: self.status.clone(),
        })
    }

    pub fn get_blinder_result(&mut self) -> eyre::Result<BlinderSuit> {
        if self.status != SessionStatus::Active {
            return Err(eyre::eyre!("Session is not active"));
        }
        if !matches!(self.option, GameOption::Blinder) {
            return Err(eyre::eyre!("Not a blinder game"));
        }
        self.status = SessionStatus::Ended;
        let user_number = self.user_number.unwrap();
        let won = user_number > self.system_number; // Draw means system wins
        let probability = 0.45; // 45% chance of winning (user_number > system_number)
        let payout_multiplier = (1.0 - 0.01) / probability; // 1% house edge
        let payout = if won {
            (self.amount as f64 * payout_multiplier) as u32
        } else {
            0
        };
        Ok(BlinderSuit { won, payout })
    }
}

async fn start_game(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<StartGameRequest>,
) -> ApiResult<StartGameResponse> {
    let mut session = GameSession::new(payload.amount, payload.option.clone());
    let (
        payout_high,
        prob_high,
        payout_low,
        prob_low,
        payout_equal,
        prob_equal,
        payout_percentage,
        blinder_suit,
    ) = match payload.option {
        GameOption::Blinder => {
            let blinder_result = session
                .get_blinder_result()
                .map_err(|e| bad_request(&e.to_string()))?;
            let probability = 0.45; // 45% win probability
            let payout_percentage = (1.0 - 0.01) / probability;
            (
                None,
                None,
                None,
                None,
                None,
                None,
                Some(payout_percentage),
                Some(blinder_result),
            )
        }
        GameOption::NonBlinder => {
            let high_prob = (9 - session.system_number) as f64 / 10.0;
            let low_prob = session.system_number as f64 / 10.0;
            let equal_prob = 1.0 / 10.0;
            let high_payout = if high_prob > 0.0 {
                (1.0 - 0.01) / high_prob
            } else {
                0.0
            };
            let low_payout = if low_prob > 0.0 {
                (1.0 - 0.01) / low_prob
            } else {
                0.0
            };
            let equal_payout = (1.0 - 0.01) / equal_prob;
            (
                Some(high_payout),
                Some(high_prob),
                Some(low_payout),
                Some(low_prob),
                Some(equal_payout),
                Some(equal_prob),
                None,
                None,
            )
        }
    };
    let response = StartGameResponse {
        id: session.id.clone(),
        amount: payload.amount,
        option: payload.option,
        system_number: session.system_number,
        user_number: session.user_number,
        payout_high,
        probability_high: prob_high,
        payout_low,
        probability_low: prob_low,
        payout_equal,
        probability_equal: prob_equal,
        payout_percentage,
        blinder_suit,
        session_status: session.status.clone(),
    };
    let service_state = match state.sessions.get(&Service::Apex).await {
        Some(cache) => cache,
        None => {
            let cache = new_moka_cache(SESSION_TTL);
            state.sessions.insert(Service::Apex, cache.clone()).await;
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

async fn make_choice(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ChooseRequest>,
) -> ApiResult<ChooseResponse> {
    let service_state = state
        .sessions
        .get(&Service::Apex)
        .await
        .ok_or(bad_request("Session not found"))?;
    let mut session: GameSession = service_state
        .get(&payload.id)
        .await
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or(bad_request("Session not found"))?;
    let response = session
        .make_choice(payload.choice)
        .map_err(|e| bad_request(&e.to_string()))?;
    service_state
        .insert(
            session.id.clone(),
            to_value(&session).map_err(|_| internal_error("Serialization error"))?,
        )
        .await;
    Ok(Response::ok(response))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/start", post(start_game))
        .route("/choose", post(make_choice))
        .with_state(state)
}
