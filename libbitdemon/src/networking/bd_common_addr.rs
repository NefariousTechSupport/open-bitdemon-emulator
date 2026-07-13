use std::{error::Error, net::Ipv4Addr};

use snafu::{Snafu, ensure};

use crate::messaging::{StreamMode::ByteMode, bd_reader::BdReader, bd_serialization::{BdDeserialize, BdSerialize}, bd_writer::BdWriter};

#[derive(Debug, Snafu)]
enum AuthenticationRequestDeserializationError {
    #[snafu(display("The BdCommonAddr request data is too short (len={data_len} expected=0x25)"))]
    BlobDataTooSmallError { data_len: usize },
}


#[derive(Copy, Clone)]
pub struct BdCommonAddr {
    pub local_addrs: [Ipv4Addr; 5],
    pub local_ports: [u16; 5],
    pub public_addr: Ipv4Addr,
    pub public_port: u16,
    pub nat_type: u8
}

impl BdCommonAddr {
    pub fn new() -> BdCommonAddr {
        BdCommonAddr {
            local_addrs: [ Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0) ],
            local_ports: [ 0, 0, 0, 0, 0 ],
            public_addr: Ipv4Addr::new(0, 0, 0, 0),
            public_port: 0,
            nat_type: 1
        }
    }
}

impl BdDeserialize for BdCommonAddr {
    fn deserialize(reader: &mut BdReader) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized
    {
        let blob = reader.read_blob()?;

        ensure!(
            blob.len() <= 0x25,
            BlobDataTooSmallSnafu { data_len: blob.len() }
        );

        let mut common_addr = BdCommonAddr::new();

        for i in 0..6 {
            let offset = i * 6;
            let ip_addr = Ipv4Addr::new(blob[offset + 0], blob[offset + 1], blob[offset + 2], blob[offset + 3]);
            let port    = u16::from_le_bytes(*(blob[offset+4..offset+6].as_array::<2>().unwrap()));
            if i < common_addr.local_addrs.len() {
                common_addr.local_addrs[i] = ip_addr;
                common_addr.local_ports[i] = port;
            }
            else {
                common_addr.public_addr = ip_addr;
                common_addr.public_port = port;
            }
        }
        common_addr.nat_type = blob[0x24];

        Ok(common_addr)
    }
}

impl BdSerialize for BdCommonAddr {
    fn serialize(&self, writer: &mut BdWriter) -> Result<(), Box<dyn Error>>
    {
        let mut blob = Vec::new();
        {
            let mut blob_writer = BdWriter::new(&mut blob);
            blob_writer.set_mode(ByteMode);
            blob_writer.set_type_checked(false);

            for i in 0..6 {
                let mut ip_addr;
                let mut port;
                if i < self.local_addrs.len() {
                    ip_addr = self.local_addrs[i];
                    port    = self.local_ports[i];
                }
                else {
                    ip_addr = self.public_addr;
                    port    = self.public_port;
                }

                blob_writer.write_bytes(&ip_addr.octets());
                blob_writer.write_u16(port);
            }
            blob_writer.write_u8(self.nat_type);
        }
        writer.write_blob(&blob);

        Ok(())
    }
}