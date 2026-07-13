use bitdemon::lobby::matchmaking2::Matchmaking2Service;
use bitdemon::lobby::matchmaking2::result::MatchMaking2GameInfo::SkySn;
use bitdemon::lobby::matchmaking2::result::{LobbySessionId, MatchMaking2Info, StoredPerformanceValue};
use rustls::lock::Mutex;
use std::sync::Arc;
use snafu::{Snafu, ensure};

#[derive(Debug, Snafu)]
enum AuthenticationRequestDeserializationError {
    #[snafu(display("The LobbySessionId {id:?} was not found"))]
    SessionIdNotFoundError { id: u64 },
}

pub struct DwMatchmaking2Service {
    session_id_counter: Mutex<u64>,
    lobby_lock: Mutex<Vec<MatchMaking2Info>>
}

impl Matchmaking2Service for DwMatchmaking2Service {
    fn get_performance_values(&self, _online_id: u64) -> Result<f32, Box<dyn std::error::Error>> {
        Ok(1.0)
    }

    fn submit_performance(&self, _performance_values: &Vec<StoredPerformanceValue>) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    fn create_session(&self, info: MatchMaking2Info) -> Result<LobbySessionId, Box<dyn std::error::Error>> {
        let mut mut_info = info;

        {
            let mut session_id = self.session_id_counter.lock().unwrap();
            mut_info.session_id = LobbySessionId::new(*session_id);
            *session_id += 1;
        }

        mut_info.num_players = 1;

        {
            let mut lobby_list = self.lobby_lock.lock().unwrap();
            (*lobby_list).push(mut_info.clone());
        }

        Ok(mut_info.session_id)
    }

    fn update_session_players(&self, session_id: LobbySessionId, num_players: u32, info: MatchMaking2Info) -> Result<(), Box<dyn std::error::Error>> {
        let mut lobby_list = self.lobby_lock.lock().unwrap();
        let mut session_index = 0xFFFFFFFFFFFFFFFFusize;

        for i in 0..lobby_list.len() {
            if lobby_list[i].session_id.id == session_id.id {
                session_index = i;
                break;
            }
        }

        ensure!(session_index != 0xFFFFFFFFFFFFFFFFusize, SessionIdNotFoundSnafu { id: session_id.id });

        lobby_list[session_index] = info.clone();
        lobby_list[session_index].session_id.id = session_id.id;
        lobby_list[session_index].num_players = num_players;

        Ok(())
    }

    fn find_sessions_paged(&self, _title_id: u32, race_type: u32, num_results_per_page: u32) -> Result<Vec<MatchMaking2Info>, Box<dyn std::error::Error>> {
        let lobby_list = self.lobby_lock.lock().unwrap();
        let mut results = vec![];

        for i in 0..lobby_list.len() {
            let mut matches = true;

            match &lobby_list[i].game_specific {
                SkySn(game_specific) => {
                    matches &= game_specific.race_type == race_type;
                }
            }

            if matches {
                results.push(lobby_list[i].clone());

                if results.len() == num_results_per_page as usize {
                    break;
                }
            }
        }

        Ok(results)
    }

    fn delete_session(&self, session_id: LobbySessionId) -> Result<(), Box<dyn std::error::Error>> {
        let mut lobby_list = self.lobby_lock.lock().unwrap();
        let mut session_index = 0xFFFFFFFFFFFFFFFFusize;

        for i in 0..lobby_list.len() {
            if lobby_list[i].session_id.id == session_id.id {
                session_index = i;
                break;
            }
        }

        ensure!(session_index != 0xFFFFFFFFFFFFFFFFusize, SessionIdNotFoundSnafu { id: session_id.id });

        lobby_list.remove(session_index);

        Ok(())
    }}

impl DwMatchmaking2Service {
    pub fn new() -> Arc<DwMatchmaking2Service> {
        let service = Arc::new(DwMatchmaking2Service {
            session_id_counter: Mutex::new(1),
            lobby_lock: Mutex::new(Vec::new())
        });

        service
    }
}
