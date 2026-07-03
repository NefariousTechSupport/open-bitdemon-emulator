use crate::crypto::{calculate_hmac, decrypt_buffer_in_place, generate_iv_from_seed};
use crate::messaging::bd_reader::BdReader;
use crate::networking::bd_session::BdSession;
use crate::networking::bd_session::SessionVersion::Dw210;
use log::warn;
use snafu::{ensure, Snafu};
use std::error::Error;

pub struct BdMessage {
    pub reader: BdReader,
}

#[derive(Debug, Snafu)]
enum BdMessageError {
    #[snafu(display("Received encrypted message but no session key was set"))]
    NoSessionKeyError,
    #[snafu(display("Message Hmac mismatch, expected={expected} actual={actual}"))]
    InvalidHmacError { expected: u32, actual: u32 },
    #[snafu(display("Message was too short"))]
    MessageTooShortError,
}

impl BdMessage {
    pub fn new(session: &BdSession, mut buf: Vec<u8>) -> Result<Self, Box<dyn Error>> {
        if session.version() != Dw210 {
            let encrypted = buf.first().unwrap();
            if *encrypted > 0 {
                ensure!(session.authentication().is_some(), NoSessionKeySnafu {});
                let seed = u32::from_le_bytes(buf[1..5].try_into().unwrap());

                let iv = generate_iv_from_seed(seed);
                let buf_len = buf.len();
                decrypt_buffer_in_place(
                    &mut buf[5..buf_len],
                    &session.authentication().unwrap().session_key,
                    &iv,
                )?;

                let hmac = u32::from_le_bytes(buf[5..9].try_into().unwrap());

                // Hmac does not include the message type byte that follows so skip that.
                let expected_hmac = calculate_hmac(
                    &buf[10..buf.len()],
                    &session.authentication().unwrap().session_key,
                );

                ensure!(
                    hmac == expected_hmac,
                    InvalidHmacSnafu {
                        expected: expected_hmac,
                        actual: hmac
                    }
                );

                Ok(BdMessage {
                    reader: BdReader::new(Vec::from(&buf[9..buf.len()])),
                })
            } else {
                Ok(BdMessage {
                    reader: BdReader::new(Vec::from(&buf[1..buf.len()])),
                })
            }
        }
        else {
            let mut message_size_buf = [0u8; 4];
            message_size_buf.copy_from_slice(&buf[0..4]);

            let message_size = u32::from_le_bytes(message_size_buf);
            ensure!(message_size > 0, MessageTooShortSnafu {});

            let mut start = 4;
            if buf[4] == 0x86 {
                start = 5;
            }
            else {
                warn!("a decrypted message didn't start with 0x86");
            }

            // It'd have been decrypted beforehand
            Ok(BdMessage {
                reader: BdReader::new(Vec::from(&buf[start..buf.len()])),
            })
        }
    }
}
