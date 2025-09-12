mod router;
use rand::Rng;
pub use router::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use uuid::Uuid;

const SESSION_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartGameRequest {
    pub amount: u32,
    pub blocks: u32,
    pub mines: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartGameResponse {
    pub id: String,
    pub amount: u32,
    pub blocks: u32,
    pub mines: u32,
    pub session_status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveRequest {
    pub id: String,
    pub block: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveAction {
    pub block: u32,
    pub multiplier: f64,
    pub safe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveResponse {
    pub id: String,
    pub actions: HashMap<String, MoveAction>,
    pub current_multiplier: Option<f64>,
    pub potential_payout: Option<u32>,
    pub final_payout: Option<u32>,
    pub bomb_blocks: Option<Vec<u32>>,
    pub session_status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CashoutRequest {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CashoutResponse {
    pub id: String,
    pub src: u32,
    pub final_payout: u32,
    pub actions: HashMap<String, MoveAction>,
    pub bomb_blocks: Vec<u32>,
    pub session_status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameSession {
    pub id: String,
    pub user_id: String,
    pub src: u32,
    pub blocks: u32,
    pub mines: u32,
    pub mine_positions: HashSet<u32>,
    pub revealed_blocks: HashSet<u32>,
    pub actions: HashMap<String, MoveAction>,
    pub current_multiplier: f64,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionStatus {
    Active,
    Ended,
}

impl GameSession {
    pub fn new(src: u32, blocks: u32, mines: u32, user_id: String) -> eyre::Result<Self> {
        if blocks.isqrt() * blocks.isqrt() != blocks {
            return Err(eyre::eyre!("Invalid Blocks"));
        }

        let mut mine_positions = HashSet::with_capacity(mines as usize);
        let mut rng = rand::thread_rng();
        while mine_positions.len() < mines as usize {
            mine_positions.insert(rng.gen_range(1..=blocks));
        }

        Ok(GameSession {
            id: Uuid::new_v4().to_string(),
            src,
            blocks,
            user_id,
            mines,
            mine_positions,
            revealed_blocks: HashSet::new(),
            actions: HashMap::new(),
            current_multiplier: 1.0,
            status: SessionStatus::Active,
        })
    }

    pub fn make_move(&mut self, block: u32, user_id: String) -> eyre::Result<MoveResponse> {
        if self.user_id != user_id {
            return Err(eyre::eyre!("User ID does not match"));
        }

        if self.status != SessionStatus::Active {
            return Err(eyre::eyre!("Session is not active"));
        }
        if block < 1 || block > self.blocks || self.revealed_blocks.contains(&block) {
            return Err(eyre::eyre!("Invalid block"));
        }

        self.revealed_blocks.insert(block);
        let move_number = format!("move_{}", self.actions.len() + 1);

        if self.mine_positions.contains(&block) {
            self.status = SessionStatus::Ended;
            self.actions.insert(
                move_number,
                MoveAction {
                    block,
                    multiplier: 0.0,
                    safe: false,
                },
            );
            return Ok(MoveResponse {
                id: self.id.clone(),
                actions: self.actions.clone(),
                current_multiplier: None,
                potential_payout: None,
                final_payout: Some(0),
                bomb_blocks: Some(self.mine_positions.iter().copied().collect()),
                session_status: SessionStatus::Ended,
            });
        }

        let safe_picks = self.revealed_blocks.len() as u32;
        self.current_multiplier = self.calculate_multiplier(safe_picks);
        self.actions.insert(
            move_number,
            MoveAction {
                block,
                multiplier: self.current_multiplier,
                safe: true,
            },
        );

        Ok(MoveResponse {
            id: self.id.clone(),
            actions: self.actions.clone(),
            current_multiplier: Some(self.current_multiplier),
            potential_payout: Some((self.src as f64 * self.current_multiplier) as u32),
            final_payout: None,
            bomb_blocks: None,
            session_status: self.status.clone(),
        })
    }

    pub fn cashout(&mut self, user_id: String) -> eyre::Result<CashoutResponse> {
        if self.user_id != user_id {
            return Err(eyre::eyre!("User ID does not match"));
        }

        if self.status != SessionStatus::Active {
            return Err(eyre::eyre!("Session is not active"));
        }

        self.status = SessionStatus::Ended;
        let final_payout = (self.src as f64 * self.current_multiplier) as u32;
        Ok(CashoutResponse {
            id: self.id.clone(),
            src: self.src,
            final_payout,
            actions: self.actions.clone(),
            bomb_blocks: self.mine_positions.iter().copied().collect(),
            session_status: self.status.clone(),
        })
    }

    fn calculate_multiplier(&self, safe_picks: u32) -> f64 {
        const HOUSE_EDGE: f64 = 0.01; // 1% house edge

        (0..safe_picks).fold(1.0, |acc, i| {
            let remaining = self.blocks - self.mines - i;
            if remaining > 0 {
                // Apply house edge: multiply by (1 - house_edge) to reduce payouts
                acc * (1.0 - HOUSE_EDGE) * self.blocks as f64 / remaining as f64
            } else {
                acc
            }
        })
    }
}
