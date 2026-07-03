use crate::crypto::{encrypt_buffer_in_place, generate_iv_from_seed, generate_iv_seed};
use crate::messaging::StreamMode::ByteMode;
use crate::messaging::bd_writer::BdWriter;
use crate::networking::bd_session::BdSession;
use crate::networking::bd_session::SessionVersion::Dw200;
use aes::cipher::{BlockModeEncrypt, KeyIvInit};
use aes::cipher::block_padding::NoPadding;
use byteorder::{LittleEndian, WriteBytesExt};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use std::error::Error;
use std::io::Write;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type HmacSha1 = Hmac<Sha1>;

pub struct BdResponse {
    should_encrypt: bool,
    data: Vec<u8>,
}

pub trait ResponseCreator {
    fn to_response(&self) -> Result<BdResponse, Box<dyn Error>>;
}

const RESPONSE_SIGNATURE: u32 = 0xDEADBEEF;

impl BdResponse {
    pub fn unencrypted(data: Vec<u8>) -> Self {
        BdResponse {
            should_encrypt: false,
            data,
        }
    }
    pub fn encrypted_if_available(data: Vec<u8>) -> Self {
        BdResponse {
            should_encrypt: true,
            data,
        }
    }

    pub fn send(&mut self, session: &mut BdSession) -> Result<(), Box<dyn Error>> {
        if session.version() == Dw200 {
            if self.should_encrypt && session.authentication().is_some() {
                let seed = generate_iv_seed();
                let iv = generate_iv_from_seed(seed);

                self.data
                    .splice(0..0, RESPONSE_SIGNATURE.to_le_bytes().iter().cloned());
                encrypt_buffer_in_place(
                    &mut self.data,
                    &session.authentication().unwrap().session_key,
                    &iv,
                );

                // Written length minus length field itself
                // 1 byte (encrypted) + 4 byte (seed)
                let message_length = self.data.len() + 5;
                session.write_u32::<LittleEndian>(message_length as u32)?;
                session.write_u8(1u8)?; // Encrypted
                session.write_u32::<LittleEndian>(seed)?;
                session.write_all(self.data.as_slice())?;
            } else {
                // Written length minus length field itself
                let message_length = self.data.len() + 1;
                session.write_u32::<LittleEndian>(message_length as u32)?;
                session.write_u8(0u8)?; // Encrypted
                session.write_all(self.data.as_slice())?;
            }
        }
        else {
            let iv: [u8; 0x10] = rand::random();

            let padded_len = (5 + self.data.len() + 0x0F) & !0x0F;
            let mut padded_data = vec![0u8; padded_len];
            padded_data[0..4].copy_from_slice(&u32::to_le_bytes(self.data.len() as u32));
            padded_data[4] = 5;
            padded_data[5..self.data.len()+5].copy_from_slice(&self.data);
            let encrypted = Aes128CbcEnc::new_from_slices(session.server_to_client_key(), &iv)?
                .encrypt_padded::<NoPadding>(&mut padded_data, padded_len).unwrap();

            let mut response_buf = Vec::new();
            {
                let mut response_writer = BdWriter::new(&mut response_buf);
                response_writer.set_type_checked(false);
                response_writer.set_mode(ByteMode);

                response_writer.write_u32(0x1E + (encrypted.len() as u32))?;
                response_writer.write_u8(0xAB)?;
                response_writer.write_u8(0x85)?;
                response_writer.write_u32(session.next_recv())?; // recv counter, always increments
                response_writer.write_bytes(&iv)?;
                response_writer.write_bytes(&encrypted)?;
            }

            let mut hmac_algo = HmacSha1::new_from_slice(session.server_to_client_hmac()).unwrap();
            hmac_algo.update(&response_buf); // session key
            let hash = hmac_algo.finalize().into_bytes();

            session.write_all(&response_buf)?;
            session.write_all(&hash[0..8])?;
        }

        Ok(())
    }
}
