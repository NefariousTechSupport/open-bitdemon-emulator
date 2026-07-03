use crate::auth::authentication::SessionAuthentication;
use crate::auth::result::auth_ticket::{self, AuthTicket};
use crate::domain::title::Title;
use crate::messaging::StreamMode;
use crate::messaging::bd_message::BdMessage;
use crate::messaging::bd_reader::BdReader;
use crate::messaging::bd_serialization::BdDeserialize;
use crate::messaging::bd_writer::BdWriter;
use crate::networking::bd_session::{BdSession, SessionVersion};
use crate::networking::session_manager::SessionManager;
use aes::cipher::block_padding::{NoPadding, Padding};
use aes::{Aes128, Aes128Dec};
use aes::cipher::{BlockCipherDecrypt, BlockModeDecrypt, KeyIvInit, SetIvState};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use cbc::Decryptor;
use hmac::{Hmac, KeyInit, Mac};
use log::{debug, error, info};
use num_traits::{FromPrimitive, ToPrimitive};
use rand::random;
use sha1::{Digest, Sha1};
use snafu::{ensure, Snafu};
use std::error::Error;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::{io, thread};

const MAX_MESSAGE_SIZE: u32 = 0x4000000;
type HmacSha1 = Hmac<Sha1>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Debug, Snafu)]
enum BdSocketError {
    #[snafu(display("Message was too large (size={msg_size}, max={MAX_MESSAGE_SIZE})"))]
    MessageTooLargeError { msg_size: u32 },
    #[snafu(display("The client sent an incomplete message header"))]
    IncompleteMessageHeaderError {},
    #[snafu(display("The client sent an auth packet that had an incorrect bit buffer magic number. (magic={magic})"))]
    InvalidBitBufferError { magic: u8 },
    #[snafu(display("The client sent an auth packet that was not correct. (details={details})"))]
    IncorrectAuthError { details: String },
    #[snafu(display("The client sent an auth packet that contained an invalid title id. (title={title})"))]
    InvalidTitleError { title: u32 },
}

pub trait BdMessageHandler {
    fn handle_message(
        &self,
        session: &mut BdSession,
        message: BdMessage,
    ) -> Result<(), Box<dyn Error>>;
}

pub struct BdSocket {
    session_manager: Arc<SessionManager>,
    listener: Option<TcpListener>,
}

impl BdSocket {
    /// Creates a new BdSocket instance and binds it to the specified port.
    pub fn new(port: u16) -> Result<BdSocket, io::Error> {
        Self::new_with_session_manager(port, Arc::new(SessionManager::new()))
    }

    /// Creates a new BdSocket instance and binds it to the specified port.
    pub fn new_with_session_manager(
        port: u16,
        session_manager: Arc<SessionManager>,
    ) -> Result<BdSocket, io::Error> {
        let listener = TcpListener::bind(format!("0.0.0.0:{port}"))?;

        info!("Opened bitdemon socket on port {port}");

        Ok(BdSocket {
            listener: Some(listener),
            session_manager,
        })
    }

    fn listen(
        listener: &TcpListener,
        session_manager: &Arc<SessionManager>,
        message_handler: Arc<dyn BdMessageHandler + Send + Sync>,
    ) -> Result<(), io::Error> {
        for stream in listener.incoming() {
            let stream = stream?;

            let session_manager = Arc::clone(session_manager);
            let message_handler = Arc::clone(&message_handler);
            thread::spawn(move || {
                let mut session = BdSession::new(stream);
                session_manager.register_session(&mut session);
                BdSocket::handle_connection(&mut session, message_handler.as_ref());
                session_manager.unregister_session(&session);
            });
        }

        Ok(())
    }

    pub fn run_sync(
        &mut self,
        message_handler: Arc<dyn BdMessageHandler + Send + Sync>,
    ) -> Result<(), io::Error> {
        Self::listen(
            self.listener.as_ref().unwrap(),
            &self.session_manager,
            message_handler,
        )
    }

    pub fn run_async(
        &mut self,
        message_handler: Arc<dyn BdMessageHandler + Send + Sync>,
    ) -> JoinHandle<Result<(), io::Error>> {
        let message_handler = Arc::clone(&message_handler);
        let listener = self.listener.take();
        let session_manager = self.session_manager.clone();
        thread::spawn(move || -> Result<(), io::Error> {
            let session_manager = session_manager;
            Self::listen(
                listener.as_ref().unwrap(),
                &session_manager,
                message_handler,
            )
        })
    }

    fn handle_connection(session: &mut BdSession, message_handler: &dyn BdMessageHandler) {
        let connection_loop = |session: &mut BdSession| -> Result<(), Box<dyn Error>> {
            loop {
                let mut b: [u8; 4] = [0; 4];
                let len = session.read(&mut b)?;
                if len == 0 {
                    return Ok(());
                }

                ensure!(len == 4, IncompleteMessageHeaderSnafu {});
                let header = u32::from_le_bytes(b);

                match header {
                    0 => {
                        debug!("Ping");
                        session.write_u32::<LittleEndian>(0)?;
                    }
                    200 => {
                        let available_buffer_size = session.read_u32::<LittleEndian>()?;
                        debug!("Buffer available: {available_buffer_size}");
                    }
                    210 => {
                        session.set_version(SessionVersion::Dw210);

                        let the_number_210 = session.read_u32::<LittleEndian>()?;
                        let client_window = session.read_u32::<LittleEndian>()?;
                        let client_random = session.read_u64::<LittleEndian>()?;
                        session.set_client_window(client_window);
                        session.set_client_random(client_random);
                        session.set_server_random(random::<u64>());
                        debug!("210 number is: {the_number_210}");
                        debug!("client window is: {}", session.client_window());
                        debug!("client random is: {}", session.client_random());
                        debug!("server random is: {}", session.server_random());

                        session.write_u32::<LittleEndian>(0x16)?;
                        session.write_u8(0xAB)?;
                        session.write_u8(0x81)?; // command type
                        session.write_u32::<LittleEndian>(210)?;
                        session.write_u64::<LittleEndian>(session.id)?;
                        session.write_u64::<LittleEndian>(session.server_random())?;
                    }
                    _ => {
                        ensure!(
                            header <= MAX_MESSAGE_SIZE,
                            MessageTooLargeSnafu { msg_size: header }
                        );

                        let mut msg = vec![0; header as usize];
                        session.read_exact(msg.as_mut_slice())?;
                        debug!("Message with size {header} {msg:x?}");

                        if msg[0] == 0xAB {
                            let command_type = msg[1];
                            match command_type {
                                0x82 => {
                                    let client_bit_buffer = &msg[2..2+0x8B];

                                    {
                                        // interpret client bit buffer to read auth
                                        let mut bit_reader = BdReader::new(client_bit_buffer.to_vec());
                                        bit_reader.set_mode(StreamMode::BitMode);
                                        bit_reader.set_type_checked(false);

                                        let bit_buffer_magic = bit_reader.read_u8()?;
                                        ensure!(bit_buffer_magic == 7, InvalidBitBufferSnafu { magic: bit_buffer_magic });

                                        // this is an assumption
                                        let type_checked = bit_reader.read_bool()?;

                                        bit_reader.set_type_checked(type_checked);
                                        let title_id = bit_reader.read_u32()?;

                                        let maybe_title_id = Title::from_u32(title_id);
                                        ensure!(maybe_title_id.is_some(), InvalidTitleSnafu { title: title_id });

                                        let _iv_seed = bit_reader.read_u32()?;
                                        let mut server_ticket_bytes = [0u8; 0x80];
                                        bit_reader.read_bits(&mut server_ticket_bytes, 0x400)?;
                                        let server_ticket;
                                        {
                                            let mut server_ticket_reader = BdReader::new(server_ticket_bytes.to_vec());
                                            server_ticket = AuthTicket::deserialize(&mut server_ticket_reader)?
                                        }

                                        let auth = SessionAuthentication {
                                            session_key: server_ticket.session_key,
                                            title: maybe_title_id.unwrap(),
                                            user_id: server_ticket.user_id,
                                            username: server_ticket.username
                                        };
                                        session.set_authentication(auth);
                                    }

                                    let mut clientchalb = [0u8; 8];
                                    clientchalb.copy_from_slice(&msg[0x8D..0x95]);
                                    let received_clientchal = u64::from_le_bytes(clientchalb);
                                    let mut hash_data = Vec::new();
                                    {
                                        let mut hash_data_writer = BdWriter::new(&mut hash_data);
                                        hash_data_writer.set_type_checked(false);
                                        hash_data_writer.set_mode(StreamMode::ByteMode);
                                        // initial 210 packet
                                        let _ = hash_data_writer.write_u32(210);
                                        let _ = hash_data_writer.write_u32(210);
                                        let _ = hash_data_writer.write_u32(session.client_window());
                                        let _ = hash_data_writer.write_u64(session.client_random());
                                        // server response to initial 210 packet
                                        let _ = hash_data_writer.write_u32(0x16);
                                        let _ = hash_data_writer.write_u8(0xAB);
                                        let _ = hash_data_writer.write_u8(0x81);
                                        let _ = hash_data_writer.write_u32(210);
                                        let _ = hash_data_writer.write_u64(session.id);
                                        let _ = hash_data_writer.write_u64(session.server_random());
                                        // the packet we're responding to right now
                                        let _ = hash_data_writer.write_u32(client_bit_buffer.len().to_u32().unwrap_or_default() + 10);
                                        let _ = hash_data_writer.write_u8(0xAB);
                                        let _ = hash_data_writer.write_u8(0x82);
                                        let _ = hash_data_writer.write_bytes(&client_bit_buffer);
                                    }
                                    info!("0xAB 0x82 (0/4) hash data: {hash_data:x?}");
                                    let hmac_key = Sha1::digest(hash_data);
                                    let mut hmac_algo = HmacSha1::new_from_slice(&hmac_key).unwrap();
                                    hmac_algo.update(&[0x42; 24]); // session key
                                    let hmac_res = hmac_algo.finalize();
                                    let auth_tag = hmac_res.into_bytes();

                                    info!("0xAB 0x82 (1/4) auth_tag: {auth_tag:x?}");
                                    let mut computed_clientchal = [0u8; 0x10];
                                    let mut bddata = [0u8; 0x48];
                                    Self::derive_key(&auth_tag, "CLIENTCHAL", &mut computed_clientchal);
                                    Self::derive_key(&auth_tag, "BDDATA",     &mut bddata);

                                    info!("0xAB 0x82 (2/4) computed client challenge: {computed_clientchal:x?}");
                                    info!("0xAB 0x82 (3/4) client challenge received: {received_clientchal:x?}");
                                    info!("0xAB 0x82 (4/4) bd cryptography data:      {bddata:x?}");

                                    let mut computed_clientchal_copy = [0u8; 8];
                                    computed_clientchal_copy.copy_from_slice(&computed_clientchal[0..8]);
                                    assert_eq!(u64::from_le_bytes(computed_clientchal_copy), received_clientchal);

                                    let mut hmac_key             = [0u8;   20];
                                    let mut client_to_server_key = [0u8; 0x10];
                                    let mut server_to_client_key = [0u8; 0x10];
                                    hmac_key.copy_from_slice(&bddata[20..40]);
                                    client_to_server_key.copy_from_slice(&bddata[40..56]);
                                    server_to_client_key.copy_from_slice(&bddata[56..72]);
                                    session.set_client_to_server_key(&client_to_server_key);
                                    session.set_server_to_client_key(&server_to_client_key);

                                    // Response
                                    session.write_u32::<LittleEndian>(0x0A)?;
                                    session.write_u8(0xAB)?;
                                    session.write_u8(0x83)?; // command type
                                    session.write_all(&computed_clientchal[8..16])?;
                                }
                                0x85 => {
                                    let mut u32_buffer = [0u8; 4];

                                    u32_buffer.copy_from_slice(&msg[2..6]);
                                    let msg_count = u32::from_le_bytes(u32_buffer);

                                    let mut iv = [0u8; 0x10];
                                    iv.copy_from_slice(&msg[6..0x16]);

                                    let enc_size = msg.len() - 0x1E;
                                    let mut encrypted = vec![0u8; enc_size];
                                    encrypted.copy_from_slice(&msg[0x16..msg.len() - 8]);

                                    let mut hash = [0u8; 0x08];
                                    hash.copy_from_slice(&msg[0x16+enc_size..msg.len()]);

                                    let decrypted = Aes128CbcDec::new_from_slices(session.client_to_server_key(), &iv)?
                                        .decrypt_padded::<NoPadding>(&mut encrypted).unwrap();

                                    debug!("Decrypted Message with size {enc_size} {hash:x?} {decrypted:x?}");
                                }
                                _ => {
                                    debug!("Ecountered command type {command_type} and don't know what to do");
                                }
                            }
                        }
                        else {
                            let message = BdMessage::new(session, msg)?;
                            message_handler.handle_message(session, message)?;
                        }
                    }
                }
            }
        };

        let connection_result = connection_loop(session);
        if let Err(e) = connection_result {
            if let Some(e0) = e.downcast_ref::<io::Error>() {
                match e0.kind() {
                    ErrorKind::Interrupted | ErrorKind::ConnectionReset => {}
                    _ => error!("Connection terminated: {}: {e}", e0.kind()),
                }
            } else {
                error!("Session terminated with error: {e}")
            }
        }
    }

    fn derive_key(auth_tag: &[u8], salt: &str, out: &mut [u8]) {
        let out_len = out.len();
        let mut out_offset = 0;
        let mut prev_key = [0u8; 20];

        let mut iteration = 1;
        while out_offset < out_len {
            let mut buffer = Vec::new();
            {
                let mut writer = BdWriter::new(&mut buffer);

                if out_offset > 0 {
                    let _ = writer.write_bytes(&prev_key);
                }

                let _ = writer.write_bytes(&salt.as_bytes());

                let _ = writer.write_u8(iteration);
            }

            let mut hmac_algo = HmacSha1::new_from_slice(&auth_tag).unwrap();
            hmac_algo.update(&buffer);

            let hmac_res = hmac_algo.finalize();
            prev_key.copy_from_slice(&hmac_res.into_bytes());
            let remaining_out = std::cmp::min(20, out_len - out_offset);
            out[out_offset..out_offset+remaining_out].copy_from_slice(&prev_key[..remaining_out]);

            out_offset += 20;
            iteration += 1;
        }
    }
}
