use base64::Engine;
use base64::{engine::general_purpose::STANDARD as base64_decoder};
use chrono::Utc;
use log::debug;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

use crate::auth::auth_handler::AuthMessageType::Ps3ForMmpReply;
use crate::auth::auth_handler::{AuthHandler, AuthMessageType};
use crate::auth::auth3_server::{Auth3Request, Auth3Response};
use crate::auth::response::AuthResponse;
use crate::auth::result::auth_ticket::{AuthTicket, BdAuthTicketType};
use crate::crypto::{generate_iv_seed, generate_iv_from_seed, encrypt_buffer_in_place};
use crate::domain::title::Title;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_serialization::BdSerialize;
use crate::messaging::bd_writer::BdWriter;
use crate::messaging::BdErrorCode;
use crate::networking::bd_session::BdSession;
use std::error::Error;

#[derive(Deserialize)]
struct Auth3RPCNRequest {
    token: String,
    extended_data: bool
}

#[derive(Serialize)]
struct Auth3RPCNReply {
    extended_data: String
}

pub struct RPCNAuthHandler {
}

const TICKET_ISSUE_LENGTH: i64 = 5 * 60 * 1000;

impl AuthResponse for RPCNAuthHandler {
    fn message_type(&self) -> AuthMessageType {
        AuthMessageType::Ps3ForMmpReply
    }

    fn error_code(&self) -> BdErrorCode {
        BdErrorCode::AuthNoError
    }

    fn write_auth_data(&self, _writer: &mut BdWriter) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}

impl AuthHandler for RPCNAuthHandler {
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

        debug!("Processing rpcn auth");

        if task.extra_data.is_some() {
            let extra_data = task.extra_data.unwrap();
            let rpcn_auth_request: Auth3RPCNRequest = serde_json::from_str(&extra_data.as_str())?;

            let psn_token_b = base64_decoder.decode(rpcn_auth_request.token)?;
            let mut client_cookie = [0x0u8; 0x18];
            client_cookie.copy_from_slice(&psn_token_b[0xAC..0xC4]);
            //let psn_ticket = npticket::Ticket::from_bytes(&mut psn_token_b)?;

            let now = Utc::now();
            let issued = (now.timestamp() % (u32::MAX as i64)) as u32;
            let expires_i64 = now.timestamp() + TICKET_ISSUE_LENGTH;
            let expires = ((expires_i64) % (u32::MAX as i64)) as u32;

            let client_ticket = AuthTicket {
                ticket_type: BdAuthTicketType::UserToService,
                title: title,
                time_issued: issued,
                time_expires: expires,
                license_id: 1234u64, // test data
                user_id: 1,
                username: String::from("gay"),
                session_key: [0x42; 24], // test data
            };
            let server_ticket = AuthTicket {
                ticket_type: BdAuthTicketType::HostToService,
                title: title,
                time_issued: issued,
                time_expires: expires,
                license_id: 1234u64, // test data
                user_id: 1,
                username: String::from("gay"),
                session_key: [0x42; 24], // test data
            };

            let mut client_ticket_buf = Vec::new();
            {
                let mut ticket_writer = BdWriter::new(&mut client_ticket_buf);
                client_ticket.serialize(&mut ticket_writer)?;
                // I don't know what this means either
                ticket_writer.write_bytes(&[0x67, 0x62, 0x00, 0x01, 0x62, 0x36, 0x00, 0x00, 0x00, 0x01, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;
            }
            let mut server_ticket_buf = Vec::new();
            {
                let mut ticket_writer = BdWriter::new(&mut server_ticket_buf);
                server_ticket.serialize(&mut ticket_writer)?;
            }
            let iv_seed = generate_iv_seed();
            let auth_iv = generate_iv_from_seed(iv_seed);
            encrypt_buffer_in_place(&mut client_ticket_buf, &client_cookie, &auth_iv);

            let extra_data = Auth3RPCNReply {
                // this is meant to be a JWE, I'm not sure what for
                extended_data: String::from("eyJlbmMiOiAiQTEyOENCQy1IUzI1NiIsICJhbGciOiAiUlNBLU9BRVAifQ.eyJlbmMiOiAiQTEyOENCQy1IUzI1NiIsICJhbGciOiAiUlNBLU9BRVAifQ.eyJlbmMiOiAiQTEyOENCQy1IUzI1NiIsICJhbGciOiAiUlNBLU9BRVAifQ.eyJlbmMiOiAiQTEyOENCQy1IUzI1NiIsICJhbGciOiAiUlNBLU9BRVAifQ.eyJlbmMiOiAiQTEyOENCQy1IUzI1NiIsICJhbGciOiAiUlNBLU9BRVAifQ")
            };

            response.code = 700;
            response.auth_task = Ps3ForMmpReply.to_u64().unwrap();
            response.iv_seed = iv_seed as u64;
            response.client_ticket = client_ticket_buf;
            response.server_ticket = server_ticket_buf;
            response.client_id = 1.to_string();
            response.account_type = String::from("ps3");
            response.crossplay_enabled = false;
            response.loginqueue_enabled = false;
            response.lsg_endpoint = Option::None;
            response.extra_data = serde_json::to_string_pretty(&extra_data).unwrap();
        }

        Ok(response)
    }
}
