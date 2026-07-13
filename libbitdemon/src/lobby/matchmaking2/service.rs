use std::error::Error;

use crate::lobby::matchmaking2::result::*;

pub type ThreadSafeMatchmaking2Service = dyn Matchmaking2Service + Sync + Send;

/// Implements domain logic concerning matchmaking 2 service.
pub trait Matchmaking2Service {
    fn get_performance_values(&self, online_id: u64) -> Result<f32, Box<dyn Error>>;
    fn submit_performance(&self, performance_values: &Vec<StoredPerformanceValue>) -> Result<(), Box<dyn Error>>;
    fn create_session(&self, info: MatchMaking2Info) -> Result<LobbySessionId, Box<dyn Error>>;
    fn update_session_players(&self, session_id: LobbySessionId, num_players: u32, info: MatchMaking2Info) -> Result<(), Box<dyn Error>>;
    fn find_sessions_paged(&self, title_id: u32, race_type: u32, num_results_per_page: u32) -> Result<Vec<MatchMaking2Info>, Box<dyn Error>>;
    fn delete_session(&self, session_id: LobbySessionId) -> Result<(), Box<dyn Error>>;
}
