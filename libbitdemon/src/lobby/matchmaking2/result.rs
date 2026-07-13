use snafu::{Snafu, ensure};

use crate::lobby::matchmaking2::result::MatchMaking2GameInfo::SkySn;
use crate::messaging::StreamMode;
use crate::messaging::bd_reader::BdReader;
use crate::messaging::bd_serialization::{BdDeserialize, BdSerialize};
use crate::messaging::bd_writer::BdWriter;
use crate::networking::bd_common_addr::BdCommonAddr;
use std::error::Error;

#[derive(Debug, Snafu)]
enum MatchMaking2DeserializeError {
    #[snafu(display("Expected len 0x08 but got len {len:?} when reading bdSecurityId from buffer."))]
    InvalidSecurityIdError { len: usize },

    #[snafu(display("Expected len 0x10 but got len {len:?} when reading bdSecurityKey from buffer."))]
    InvalidSecurityKeyError { len: usize },

    #[snafu(display("Expected len 0x08 but got len {len:?} when reading bdSessionId from buffer."))]
    InvalidLobbySessionIdError { len: usize },
}

pub struct StoredPerformanceValue {
    pub online_id: u64,
    pub player_skill: f32
}

impl BdSerialize for StoredPerformanceValue {
    fn serialize(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>> {
        writer.write_u64(self.online_id)?;
        writer.write_f32(self.player_skill)?;

        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct LobbySessionId {
    pub id: u64
}

impl LobbySessionId {
    pub fn new(id: u64) -> LobbySessionId {
        LobbySessionId {
            id
        }
    }
}

impl BdSerialize for LobbySessionId {
    fn serialize(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>> {
        writer.write_blob(&u64::to_le_bytes(self.id))?;

        Ok(())
    }
}

impl BdDeserialize for LobbySessionId {
    fn deserialize(reader: &mut BdReader) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized
    {
        let id = reader.read_blob()?;

        ensure!(id.len() == 0x08, InvalidLobbySessionIdSnafu { len: id.len() });

        Ok(LobbySessionId {
            id: u64::from_le_bytes(*id.as_array().unwrap())
        })
    }
}

#[derive(Clone)]
pub enum MatchMaking2GameInfo {
    SkySn(SkySnMatchMaking2Info)
}

pub struct MatchMaking2Info {
    pub common_addr: BdCommonAddr,
    pub game_mode: u32,
    pub max_players: u32,

    pub session_id: LobbySessionId,
    pub num_players: u32,

    pub game_specific: MatchMaking2GameInfo
}

impl Clone for MatchMaking2Info {
    fn clone(&self) -> Self {
        MatchMaking2Info {
            common_addr: self.common_addr,
            game_mode: self.game_mode,
            max_players: self.max_players,
            session_id: self.session_id,
            num_players: self.num_players,
            game_specific: self.game_specific.clone()
        }
    }
}

impl BdDeserialize for MatchMaking2Info {
    fn deserialize(reader: &mut BdReader) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized
    {
        let common_addr = BdCommonAddr::deserialize(reader)?;

        let game_mode   = reader.read_u32()?;
        let max_players = reader.read_u32()?;

        let game_data = reader.read_blob()?;
        let mut game_data_reader = BdReader::new(game_data);
        game_data_reader.set_mode(StreamMode::ByteMode);
        game_data_reader.set_type_checked(true);

        // hardcoded = bad
        let bad_idea = MatchMaking2GameInfo::SkySn(SkySnMatchMaking2Info::deserialize(&mut game_data_reader).expect("Failed to deserialize skysn matchmaking2 info"));

        Ok(MatchMaking2Info {
            common_addr,
            game_mode,
            max_players,
            num_players: 0,
            session_id: LobbySessionId::new(0),
            game_specific: bad_idea
        })
    }
}

impl BdSerialize for MatchMaking2Info {
    fn serialize(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>>
    {
        self.common_addr.serialize(writer)?;

        self.session_id.serialize(writer)?;

        writer.write_u32(self.game_mode)?;
        writer.write_u32(self.max_players)?;
        writer.write_u32(self.num_players)?;

        match &self.game_specific {
            SkySn(game_specific) => game_specific.serialize(writer)?
        };

        Ok(())
    }
}

#[derive(Clone)]
pub struct SkySnMatchMaking2Info {
    pub security_id: [u8; 0x08],
    pub security_key: [u8; 0x10],
    pub debug_game_name: String,
    pub user_id: u64,
    pub zone_handle: u64,
    pub missing_players: u32,
    pub in_matchmaking_lobby: bool,
    pub has_action_pack_for_race_type: u32,
    pub session_type: u32,
    pub race_type: u32,
    pub matchmaking_title_id: u32,
    pub block_coop_friend_joins: bool,
    pub nat_type: u32,
    pub tier0: u32,
    pub tier1: u32,
    pub tier2: u32,
    pub tier3: u32,
    pub skill_level: f32
}

impl BdDeserialize for SkySnMatchMaking2Info {
    fn deserialize(reader: &mut BdReader) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized
    {
        let security_id = reader.read_blob()?;
        let security_key = reader.read_blob()?;
        let debug_game_name = reader.read_str()?;
        let user_id = reader.read_u64()?;
        let zone_handle = reader.read_u64()?;
        let missing_players = reader.read_u32()?;
        let in_matchmaking_lobby = reader.read_u32()? == 0xFFFFFFFE;
        let has_action_pack_for_race_type = reader.read_u32()?;
        let session_type = reader.read_u32()?;
        let race_type = reader.read_u32()?;
        let matchmaking_title_id = reader.read_u32()?;
        let block_coop_friend_joins = reader.read_u32()? == 1;
        let nat_type = reader.read_u32()?;
        let tier0 = reader.read_u32()?;
        let tier1 = reader.read_u32()?;
        let tier2 = reader.read_u32()?;
        let tier3 = reader.read_u32()?;
        let skill_level = reader.read_f32()?;

        ensure!(security_id.len()  == 0x08,  InvalidSecurityIdSnafu { len:  security_id.len() });
        ensure!(security_key.len() == 0x10, InvalidSecurityKeySnafu { len: security_key.len() });

        Ok(SkySnMatchMaking2Info {
            security_id: *security_id.as_array().unwrap(),
            security_key: *security_key.as_array().unwrap(),
            debug_game_name,
            user_id,
            zone_handle,
            missing_players,
            in_matchmaking_lobby,
            has_action_pack_for_race_type,
            session_type,
            race_type,
            matchmaking_title_id,
            block_coop_friend_joins,
            nat_type,
            tier0,
            tier1,
            tier2,
            tier3,
            skill_level
        })
    }
}

impl BdSerialize for SkySnMatchMaking2Info {
    fn serialize(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>>
    {
        writer.write_blob(&self.security_id)?;
        writer.write_blob(&self.security_key)?;
        writer.write_str(&self.debug_game_name)?;
        writer.write_u64(self.user_id)?;
        writer.write_u64(self.zone_handle)?;
        writer.write_u32(self.missing_players)?;
        writer.write_u32((self.in_matchmaking_lobby as u32) * 0xFFFFFFFE)?;
        writer.write_u32(self.has_action_pack_for_race_type)?;
        writer.write_u32(self.session_type)?;
        writer.write_u32(self.race_type)?;
        writer.write_u32(self.matchmaking_title_id)?;
        writer.write_u32(self.block_coop_friend_joins as u32)?;
        writer.write_u32(self.nat_type)?;
        writer.write_u32(self.tier0)?;
        writer.write_u32(self.tier1)?;
        writer.write_u32(self.tier2)?;
        writer.write_u32(self.tier3)?;
        writer.write_f32(self.skill_level)?;

        Ok(())
    }
}
