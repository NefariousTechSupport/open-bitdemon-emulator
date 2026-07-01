use std::error::Error;

use base64::Engine;
use base64::{engine::general_purpose::STANDARD as base64_encoder};
use num_traits::ToPrimitive;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use serde_aux::prelude::deserialize_number_from_string;
use snafu::Snafu;

use crate::auth::auth_handler::AuthMessageType::{self, CreateAccountRequest};
use crate::auth::result::auth_ticket::AuthTicket;
use crate::auth::result::auth_ticket::BdAuthTicketType::UserToService;
use crate::domain::title::Title::SuperNovaPS3;
use crate::messaging::bd_serialization::BdSerialize;
use crate::messaging::bd_writer::BdWriter;

pub fn serialize_u32_to_string<S>(field: &u32, serializer: S) -> Result<S::Ok, S::Error> where S : Serializer {
    serializer.serialize_str(field.to_string().as_str())
}
pub fn serialize_u64_to_string<S>(field: &u64, serializer: S) -> Result<S::Ok, S::Error> where S : Serializer {
    serializer.serialize_str(field.to_string().as_str())
}
pub fn serialize_auth_ticket<S>(field: &AuthTicket, serializer: S) -> Result<S::Ok, S::Error> where S : Serializer {
    let mut ticket_buf = Vec::new();
    {
        let mut ticket_writer = BdWriter::new(&mut ticket_buf);
        let _ = field.serialize(&mut ticket_writer);

    }

    println!("auth ticket size is {}", ticket_buf.len());
    // It must be exactly 0xCC bytes long excluding the null byte
    let mut ticket_base64: String = base64_encoder.encode(ticket_buf);
    ticket_base64.reserve(0xCC - ticket_base64.len());
    for _ in ticket_base64.len()..0xCC {
        ticket_base64 += "=";
    }

    serializer.serialize_str(&ticket_base64)
}

#[derive(Deserialize, Serialize)]
pub struct Auth3Request {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub auth_task: u64,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub iv_seed: u64,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub title_id: u64,
    pub extra_data: Option<String>,
}

#[derive(Serialize)]
pub struct Auth3Response {
    #[serde(serialize_with = "serialize_u64_to_string")]
    pub auth_task: u64,
    #[serde(serialize_with = "serialize_u32_to_string")]
    pub code: u32,
    #[serde(serialize_with = "serialize_u64_to_string")]
    pub iv_seed: u64,
    #[serde(serialize_with = "serialize_auth_ticket")]
    pub client_ticket: AuthTicket,
    #[serde(serialize_with = "serialize_auth_ticket")]
    pub server_ticket: AuthTicket,
    pub client_id: String,
    pub account_type: String,
    pub crossplay_enabled: bool,
    pub loginqueue_enabled: bool,
    pub lsg_endpoint: Option<String>,
    pub extra_data: String,
}

impl Default for Auth3Response {
    fn default() -> Self {
        return Auth3Response {
            auth_task: CreateAccountRequest.to_u64().unwrap(),
            code: 0,
            iv_seed: 0,
            client_ticket: AuthTicket { ticket_type: UserToService, title: SuperNovaPS3, time_issued: 0, time_expires: 0, license_id: 0, user_id: 0, username: String::new(), session_key: [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ] },
            server_ticket: AuthTicket { ticket_type: UserToService, title: SuperNovaPS3, time_issued: 0, time_expires: 0, license_id: 0, user_id: 0, username: String::new(), session_key: [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ] },
            client_id: String::new(),
            account_type: String::new(),
            crossplay_enabled: false,
            loginqueue_enabled: false,
            lsg_endpoint: Option::None,
            extra_data: String::new(),
        };
    }
}

#[derive(Debug, Snafu)]
pub enum Auth3RequestDeserializationError {
    #[snafu(display("The title id is unknown (value={title_id})"))]
    UnknownTitleError { title_id: u64 },

    #[snafu(display("Missing extra_data field"))]
    MissingExtraDataError,
}

pub trait Auth3MessageHandler {
    fn handle_auth3_message(
        &self,
        
        task: Auth3Request,
    ) -> Result<Auth3Response, Box<dyn Error>>;
}
