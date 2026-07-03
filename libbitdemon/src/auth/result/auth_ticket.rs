use crate::{domain::title::Title, messaging::bd_serialization::BdDeserialize};
use crate::messaging::bd_serialization::BdSerialize;
use crate::messaging::bd_writer::BdWriter;
use crate::messaging::StreamMode;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use snafu::{ensure, Snafu};
use std::error::Error;

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum BdAuthTicketType {
    UserToService = 0x0,
    HostToService = 0x1,
    UserToHost = 0x2,
}

pub struct AuthTicket {
    pub ticket_type: BdAuthTicketType,
    pub title: Title,
    pub time_issued: u32,
    pub time_expires: u32,
    pub license_id: u64,
    pub user_id: u64,
    pub username: String,
    pub session_key: [u8; 24],
}

const MAGIC_NUMBER: u32 = 0xEFBDADDE;
const NAME_MAX_LEN: usize = 64;

#[derive(Debug, Snafu)]
enum AuthTicketSerializeError {
    #[snafu(display("Name too long when serializing auth ticket (len={name_len} max={NAME_MAX_LEN})"))]
    UsernameTooLongError { name_len: usize },
    #[snafu(display("Magic number invalid for auth ticket (magic number={magic_number})"))]
    InvalidMagicNumberError { magic_number: u32 },
    #[snafu(display("Ticket type invalid for auth ticket (ticket type={ticket_type})"))]
    InvalidTicketTypeError { ticket_type: u8 },
    #[snafu(display("Title invalid for auth ticket (title={title})"))]
    InvalidTitleError { title: u32 },
}

impl BdSerialize for AuthTicket {
    fn serialize(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>> {
        writer.set_type_checked(false);
        writer.set_mode(StreamMode::ByteMode);

        writer.write_u32(MAGIC_NUMBER)?;
        writer.write_u8(self.ticket_type.to_u8().unwrap())?;
        writer.write_u32(self.title.to_u32().unwrap())?;
        writer.write_u32(self.time_issued)?;
        writer.write_u32(self.time_expires)?;
        writer.write_u64(self.license_id)?;
        writer.write_u64(self.user_id)?;

        ensure!(
            self.username.len() <= NAME_MAX_LEN,
            UsernameTooLongSnafu {
                name_len: self.username.len()
            }
        );

        writer.write_bytes(self.username.as_ref())?;
        for _ in self.username.len()..64 {
            writer.write_bytes(&[0])?;
        }

        writer.write_bytes(self.session_key.as_ref())?;

        // Random hash stuff that is unused?
        writer.write_bytes(&[0, 0, 0, 0, 0, 0, 0])?;
        Ok(())
    }
}
impl BdDeserialize for AuthTicket {
    fn deserialize(reader: &mut crate::messaging::bd_reader::BdReader) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized
    {
        reader.set_type_checked(false);
        reader.set_mode(StreamMode::ByteMode);

        let magic_number = reader.read_u32()?;
        ensure!(
            magic_number == MAGIC_NUMBER,
            InvalidMagicNumberSnafu {
                magic_number
            }
        );
        let ticket_type = reader.read_u8()?;
        let title = reader.read_u32()?;
        let time_issued = reader.read_u32()?;
        let time_expires = reader.read_u32()?;
        let license_id = reader.read_u64()?;
        let user_id = reader.read_u64()?;

        let mut username_buf = [0u8; 0x40];
        reader.read_bytes(&mut username_buf);

        let mut username_len = username_buf.len();
        for i in 0..username_buf.len() {
            if username_buf[i] == 0 {
                username_len = i;
                break;
            }
        }
        let username = str::from_utf8(&username_buf[0..username_len])?;

        let mut session_key_buf = [0u8; 24];
        reader.read_bytes(&mut session_key_buf);

        let maybe_ticket_type = BdAuthTicketType::from_u8(ticket_type);
        ensure!(
            maybe_ticket_type.is_some(),
            InvalidTicketTypeSnafu {
                ticket_type
            }
        );
        let maybe_title = Title::from_u32(title);
        ensure!(
            maybe_title.is_some(),
            InvalidTitleSnafu {
                title
            }
        );

        Ok(AuthTicket {
            ticket_type: maybe_ticket_type.unwrap(),
            title: maybe_title.unwrap(),
            time_issued,
            time_expires,
            license_id,
            user_id,
            username: String::from(username),
            session_key: session_key_buf
        })
    }
}
