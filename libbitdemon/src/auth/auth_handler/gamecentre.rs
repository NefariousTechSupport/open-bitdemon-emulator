use chrono::Utc;
use num_traits::ToPrimitive;
use serde::Deserialize;
use serde_aux::prelude::deserialize_number_from_string;

use crate::auth::auth_handler::AuthMessageType::GameCentreForMmpReply;
use crate::auth::auth_handler::{AuthHandler, AuthMessageType};
use crate::auth::auth3_server::{Auth3Request, Auth3Response};
use crate::auth::key_store::ThreadSafeBackendPrivateKeyStorage;
use crate::auth::response::AuthResponse;
use crate::auth::result::auth_ticket::{AuthTicket, BdAuthTicketType};
use crate::crypto::generate_iv_seed;
use crate::domain::title::Title;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_writer::BdWriter;
use crate::messaging::BdErrorCode;
use crate::networking::bd_session::BdSession;
use std::error::Error;
use std::sync::Arc;

#[derive(Deserialize)]
struct Auth3GameCentreRequest {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    version: u64,
    game_center_id: String,
    bundle_id: String,
    public_key_url: String,
    signature: String,
    salt: String,
    fingerprint: String,
    timestamp: u64,
    game_center_display_name: String,
}

pub struct GameCentreAuthHandler {
    key_store: Arc<ThreadSafeBackendPrivateKeyStorage>,
}

const TICKET_ISSUE_LENGTH: i64 = 5 * 60 * 1000;

struct GameCentreAuthResponse {
    ticket: AuthTicket
}

impl AuthResponse for GameCentreAuthResponse {
    fn message_type(&self) -> AuthMessageType {
        AuthMessageType::GameCentreForMmpReply
    }

    fn error_code(&self) -> BdErrorCode {
        BdErrorCode::AuthNoError
    }

    fn write_auth_data(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}

impl GameCentreAuthHandler {
    pub fn new(key_store: Arc<ThreadSafeBackendPrivateKeyStorage>) -> Self {
        GameCentreAuthHandler { key_store }
    }
}

impl AuthHandler for GameCentreAuthHandler {
    fn handle_message(
        &self,
        _session: &mut BdSession,
        mut _message: BdMessage,
    ) -> Result<Box<dyn AuthResponse>, Box<dyn Error>> {
        todo!()
    }

    fn handle_auth3_message(
        &self,
        title: Title,
        task: Auth3Request,
    ) -> Result<Auth3Response, Box<dyn Error>> {
        let mut response: Auth3Response = Default::default();
        // assume failure
        response.code = 800;

        println!("Processing gamecentre auth");

        if task.extra_data.is_some() {
            let extra_data = task.extra_data.unwrap();
            let gc_auth_request: Auth3GameCentreRequest = serde_json::from_str(&extra_data.as_str())?;

            // game_center_id seems to be G:<number>
            let user_id_str = gc_auth_request.game_center_id.replace("G:", "");
            let user_id: u64 = user_id_str.parse()?;

            let now = Utc::now();
            let issued = (now.timestamp() % (u32::MAX as i64)) as u32;
            let expires_i64 = now.timestamp() + TICKET_ISSUE_LENGTH;
            let expires = ((expires_i64) % (u32::MAX as i64)) as u32;

            let ticket = AuthTicket {
                ticket_type: BdAuthTicketType::UserToService,
                title: title,
                time_issued: issued,
                time_expires: expires,
                license_id: 1234u64, // test data
                user_id: user_id,
                username: gc_auth_request.game_center_display_name,
                session_key: [0x42; 24], // test data
            };

            // TODO: Verify the signature provided by the client
            // Read the discussion on the following https://developer.apple.com/documentation/gamekit/gklocalplayer/fetchitems(foridentityverificationsignature:)

            response.code = 700;
            response.auth_task = GameCentreForMmpReply.to_u64().unwrap();
            response.iv_seed = generate_iv_seed().to_u64().unwrap();
            response.client_ticket = ticket;
            //response.server_ticket = ;
            response.client_id = gc_auth_request.game_center_id;
            response.account_type = String::from("gamecentre"); // unconfirmed
            response.crossplay_enabled = false;
            response.loginqueue_enabled = false;
            response.lsg_endpoint = Option::None;
            // there is no extra data for gamecentre
            response.extra_data = String::new();
        }

        Ok(response)
    }
}
