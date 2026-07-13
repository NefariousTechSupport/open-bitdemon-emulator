use crate::lobby::matchmaking2::handler::Matchmaking2TaskId::*;
use crate::lobby::response::task_reply::TaskReply;
use crate::lobby::matchmaking2::result::{LobbySessionId, MatchMaking2Info, StoredPerformanceValue};
use crate::lobby::matchmaking2::ThreadSafeMatchmaking2Service;
use crate::lobby::LobbyHandler;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_reader::BdReader;
use crate::messaging::bd_response::{BdResponse, ResponseCreator};
use crate::messaging::BdErrorCode::{self, NoError};
use crate::messaging::bd_serialization::{BdDeserialize, BdSerialize};
use crate::networking::bd_session::BdSession;
use log::warn;
use num_traits::FromPrimitive;
use std::error::Error;
use std::sync::Arc;

pub struct Matchmaking2Handler {
    pub matchmaking2_service: Arc<ThreadSafeMatchmaking2Service>,
}

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone, FromPrimitive, ToPrimitive)]
#[repr(u8)]
enum Matchmaking2TaskId {
    CreateSession = 1,
    DeleteSession = 3,
    SubmitPerformance = 9,
    GetPerformanceValues = 10,
    UpdateSessionPlayers = 12,
    FindSessionsPaged = 13,
    //FindSessionsById = 14
}

impl LobbyHandler for Matchmaking2Handler {
    fn handle_message(
        &self,
        session: &mut BdSession,
        mut message: BdMessage,
    ) -> Result<BdResponse, Box<dyn Error>> {
        let task_id_value = message.reader.read_u8()?;
        let maybe_task_id = Matchmaking2TaskId::from_u8(task_id_value);
        if maybe_task_id.is_none() {
            warn!("Client called unknown task {task_id_value}");
            return TaskReply::with_only_error_code(BdErrorCode::NoError, task_id_value)
                .to_response();
        }
        let task_id = maybe_task_id.unwrap();

        match task_id {
            CreateSession => self.create_session(session, &mut message.reader),
            DeleteSession => self.delete_session(session, &mut message.reader),
            SubmitPerformance => self.submit_performance(session, &mut message.reader),
            GetPerformanceValues => self.get_performance_values(session, &mut message.reader),
            UpdateSessionPlayers => self.update_session_players(session, &mut message.reader),
            FindSessionsPaged => self.find_sessions_paged(session, &mut message.reader),
            //FindSessionsById => self.find_sessions_by_id(session, &mut message.reader)
        }
    }
}

impl Matchmaking2Handler {
    pub fn new(matchmaking2_service: Arc<ThreadSafeMatchmaking2Service>) -> Matchmaking2Handler {
        Matchmaking2Handler {
            matchmaking2_service,
        }
    }

    fn create_session(
        &self,
        _session: &mut BdSession,
        reader: &mut BdReader,
    ) -> Result<BdResponse, Box<dyn Error>> {
        // unsure as to what this string actually is
        let _server_name = reader.read_str()?;

        let info = MatchMaking2Info::deserialize(reader)?;

        let session_id = self.matchmaking2_service.create_session(info)?;

        Ok(TaskReply::with_results(CreateSession, vec![Box::from(session_id)]).to_response()?)
    }

    fn delete_session(
        &self,
        _session: &mut BdSession,
        reader: &mut BdReader,
    ) -> Result<BdResponse, Box<dyn Error>> {
        // unsure as to what this string actually is
        let _server_name = reader.read_str()?;

        let session_id = LobbySessionId::deserialize(reader)?;

        // todo: ensure the client is allowed to update this
        let result = self.matchmaking2_service.delete_session(session_id);

        match result {
            Ok(()) => Ok(TaskReply::with_only_error_code(BdErrorCode::NoError, UpdateSessionPlayers).to_response()?),
            Err(_) => Ok(TaskReply::with_only_error_code(BdErrorCode::InvalidSessionId, UpdateSessionPlayers).to_response()?)
        }
    }

    fn submit_performance(
        &self,
        _session: &mut BdSession,
        reader: &mut BdReader,
    ) -> Result<BdResponse, Box<dyn Error>> {
        // unsure as to what this string actually is
        let _server_name = reader.read_str()?;
        let num_performance_values = reader.remaining_bytes().unwrap() / 0x10;
        let mut performance_values = Vec::new();

        while performance_values.len() < num_performance_values {
            let online_id = reader.read_u64()?;
            let skill = reader.read_i64()?;

            performance_values.push(StoredPerformanceValue { online_id, player_skill: skill as f32 } );
        }

        let _ = self.matchmaking2_service.submit_performance(&performance_values);

        Ok(TaskReply::with_only_error_code(NoError, SubmitPerformance).to_response()?)
    }

    fn get_performance_values(
        &self,
        _session: &mut BdSession,
        reader: &mut BdReader,
    ) -> Result<BdResponse, Box<dyn Error>> {
        // unsure as to what this string actually is
        let _server_name = reader.read_str()?;

        let _num_players = reader.read_u32()?;
        let online_id = reader.read_u64()?;

        let result = self.matchmaking2_service.get_performance_values(online_id);

        match result {
            Ok(player_skill) => Ok(TaskReply::with_results(
                GetPerformanceValues,
                vec![Box::from(StoredPerformanceValue { online_id, player_skill })]
            ).to_response()?),
            Err(_) => Ok(TaskReply::with_only_error_code(BdErrorCode::AccessDenied, GetPerformanceValues).to_response()?)
        }
    }

    fn update_session_players(
        &self,
        _session: &mut BdSession,
        reader: &mut BdReader,
    ) -> Result<BdResponse, Box<dyn Error>> {
        // unsure as to what this string actually is
        let _server_name = reader.read_str()?;

        let session_id = LobbySessionId::deserialize(reader)?;
        let num_players = reader.read_u32()?;

        let info = MatchMaking2Info::deserialize(reader)?;

        // todo: ensure the client is allowed to update this
        let result = self.matchmaking2_service.update_session_players(session_id, num_players, info);

        match result {
            Ok(()) => Ok(TaskReply::with_only_error_code(BdErrorCode::NoError, UpdateSessionPlayers).to_response()?),
            Err(_) => Ok(TaskReply::with_only_error_code(BdErrorCode::InvalidSessionId, UpdateSessionPlayers).to_response()?)
        }
    }

    fn find_sessions_paged(
        &self,
        _session: &mut BdSession,
        reader: &mut BdReader,
    ) -> Result<BdResponse, Box<dyn Error>> {
        let _server_name = reader.read_str()?;

        let _ = reader.read_u32()?;
        let _ = reader.read_bool()?;
        let _ = reader.read_blob()?; // security id?
        let num_results_per_page = reader.read_u32()?;

        // session params, game specific, hardcoded for skysn
        let _ = reader.read_u32()?;
        let title_id = reader.read_u32()?;
        let race_type = reader.read_u32()?;
        let _player_count = reader.read_u32()?;
        let _has_action_pack = reader.read_u32()?;
        let _nat_type = reader.read_u32()?;
        let _tier0 = reader.read_u32()?;
        let _tier1 = reader.read_u32()?;
        let _tier2 = reader.read_u32()?;
        let _tier3 = reader.read_u32()?;
        let _tier0_weight = reader.read_f32()?;
        let _tier1_weight = reader.read_f32()?;
        let _tier2_weight = reader.read_f32()?;
        let _tier3_weight = reader.read_f32()?;
        let _skill = reader.read_f32()?;
        let _skill_weight = reader.read_f32()?;

        let result = self.matchmaking2_service.find_sessions_paged(title_id, race_type, num_results_per_page);

        match result {
            Ok(lobbies) => { 
                let mut lobbies_serializable: Vec<Box<dyn BdSerialize>> = Vec::new();
                for i in 0..lobbies.len() {
                    lobbies_serializable.push(Box::new(lobbies[i].clone()));
                }

                Ok(TaskReply::with_results(FindSessionsPaged, lobbies_serializable).to_response()?)
            },
            Err(_) => Ok(TaskReply::with_only_error_code(BdErrorCode::AuthUnknownError,FindSessionsPaged).to_response()?)
        }
    }

    /*fn find_sessions_by_id(
        &self,
        session: &mut BdSession,
        reader: &mut BdReader,
    ) -> Result<BdResponse, Box<dyn Error>> {

    }

    fn handle_matchmaking2_error(
        code: Matchmaking2ServiceError,
        task_id: Matchmaking2TaskId,
    ) -> Result<Result<BdResponse, Box<dyn Error>>, Box<dyn Error>> {
        Ok(Ok(TaskReply::with_only_error_code(
            match code {
                /*Matchmaking2ServiceError::PermissionDeniedError => BdErrorCode::PermissionDenied,
                Matchmaking2ServiceError::Matchmaking2DataTooLargeError => {
                    BdErrorCode::Matchmaking2DataTooLarge
                }
                Matchmaking2ServiceError::TooManyUsersError => {
                    BdErrorCode::Matchmaking2TooManyUsers
                }*/
            },
            task_id,
        )
        .to_response()?))
    }*/
}
