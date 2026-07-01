use crate::auth::auth_handler::gamecentre::GameCentreAuthHandler;
use crate::auth::auth_handler::steam::SteamAuthHandler;
use crate::auth::auth_handler::AuthMessageType;
use crate::auth::auth_handler::ThreadSafeAuthHandler;
use crate::auth::auth3_server::Auth3MessageHandler;
use crate::auth::auth3_server::Auth3Request;
use crate::auth::auth3_server::Auth3Response;
use crate::auth::key_store::ThreadSafeBackendPrivateKeyStorage;
use crate::auth::response::{AuthResponse, AuthResponseWithOnlyCode};
use crate::domain::title::Title;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_response::ResponseCreator;
use crate::messaging::BdErrorCode::AuthIllegalOperation;
use crate::networking::bd_session::BdSession;
use crate::networking::bd_socket::BdMessageHandler;
use log::{info, warn};
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;
use snafu::OptionExt;
use snafu::Snafu;
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, RwLock};

pub struct AuthServer {
    auth_handlers: RwLock<HashMap<AuthMessageType, Arc<ThreadSafeAuthHandler>>>,
}

impl AuthServer {
    pub fn new(key_store: Arc<ThreadSafeBackendPrivateKeyStorage>) -> Self {
        let auth_server = AuthServer {
            auth_handlers: RwLock::new(HashMap::new()),
        };

        auth_server.add_handler(
            AuthMessageType::SteamForMmpRequest,
            Arc::new(SteamAuthHandler::new(key_store.clone())),
        );

        auth_server.add_handler(
            AuthMessageType::GameCentreForMmpRequest,
            Arc::new(GameCentreAuthHandler::new(key_store.clone())),
        );

        auth_server
    }

    pub fn add_handler(&self, message_type: AuthMessageType, handler: Arc<ThreadSafeAuthHandler>) {
        info!("Adding {message_type:?} auth handler");
        self.auth_handlers
            .write()
            .unwrap()
            .insert(message_type, handler);
    }
}

#[derive(Debug, Snafu)]
enum AuthServerError {
    #[snafu(display("The client specified an illegal message type: {message_type_input}"))]
    IllegalMessageTypeError { message_type_input: u8 },
    #[snafu(display("The title id is unknown (value={title_id})"))]
    UnknownTitleError { title_id: u64 },

}

impl BdMessageHandler for AuthServer {
    fn handle_message(
        &self,
        session: &mut BdSession,
        mut message: BdMessage,
    ) -> Result<(), Box<dyn Error>> {
        let message_type_input = message.reader.read_u8()?;

        let handler_type = AuthMessageType::from_u8(message_type_input)
            .ok_or_else(|| IllegalMessageTypeSnafu { message_type_input }.build())?;

        let handlers = self.auth_handlers.read().unwrap();
        let maybe_handler = handlers.get(&handler_type);

        match maybe_handler {
            Some(handler) => {
                let auth_response = handler.handle_message(session, message)?;
                auth_response.to_response()?.send(session)?;

                Ok(())
            }
            None => {
                warn!("Tried to request unavailable auth handler {handler_type:?}");
                let only: Box<dyn AuthResponse> = Box::from(AuthResponseWithOnlyCode::new(
                    handler_type.reply_code(),
                    AuthIllegalOperation,
                ));

                only.to_response()?.send(session)?;

                Ok(())
            }
        }
    }
}

impl Auth3MessageHandler for AuthServer {
    fn handle_auth3_message(
        &self,
        task: Auth3Request,
    ) -> Result<Auth3Response, Box<dyn Error>> {
        let message_type_input = task.auth_task.to_u8().unwrap_or(0);

        let title = Title::from_u32(task.title_id.to_u32().unwrap_or(0)).with_context(|| UnknownTitleSnafu { title_id: task.title_id })?;

        let handler_type = AuthMessageType::from_u8(message_type_input)
            .ok_or_else(|| IllegalMessageTypeSnafu { message_type_input }.build())?;

        let handlers = self.auth_handlers.read().unwrap();
        let maybe_handler = handlers.get(&handler_type);

        match maybe_handler {
            Some(handler) => {
                let auth_response = handler.handle_auth3_message(title, task)?;

                Ok(auth_response)
            }
            None => {
                warn!("Tried to request unavailable auth handler {handler_type:?}");

                Ok(Auth3Response {
                    code: 800, // it just has to not be 700
                    ..Default::default()
                })
            }
        }
    }
}
