mod service;

use crate::lobby::matchmaking2::service::DwMatchmaking2Service;
use bitdemon::lobby::matchmaking2::Matchmaking2Handler;
use bitdemon::lobby::ThreadSafeLobbyHandler;
use bitdemon::networking::session_manager::SessionManager;
use std::sync::Arc;

pub fn create_matchmaking2_handler(
    _session_manager: Arc<SessionManager>,
) -> Arc<ThreadSafeLobbyHandler> {
    Arc::new(Matchmaking2Handler::new(DwMatchmaking2Service::new(
    )))
}
