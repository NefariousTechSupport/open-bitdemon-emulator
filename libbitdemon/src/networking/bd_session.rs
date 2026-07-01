use crate::auth::authentication::SessionAuthentication;
use std::io;
use std::io::BufReader;
use std::net::{SocketAddr, TcpStream};

pub type SessionId = u64;

pub struct BdSession {
    pub id: SessionId,
    authentication: Option<SessionAuthentication>,
    stream: BufReader<TcpStream>,
    client_window: u32,
    client_random: u64,
    server_random: u64,
    client_to_server_key: [u8; 0x10],
    server_to_client_key: [u8; 0x10],
}

impl io::Read for BdSession {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl io::Write for BdSession {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.get_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.get_mut().flush()
    }
}

impl BdSession {
    pub fn new(stream: TcpStream) -> Self {
        let reader = BufReader::new(stream);

        BdSession {
            id: 0,
            authentication: None,
            stream: reader,
            client_window: 0,
            client_random: 0,
            server_random: 0,
            client_to_server_key: [0u8; 0x10],
            server_to_client_key: [0u8; 0x10],
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.get_ref().peer_addr()
    }

    pub fn authentication(&self) -> Option<&SessionAuthentication> {
        self.authentication.as_ref()
    }

    pub fn set_authentication(&mut self, authentication: SessionAuthentication) {
        debug_assert!(self.authentication.is_none());
        self.authentication = Some(authentication);
    }

    pub fn client_window(&self) -> u32 {
        self.client_window
    }

    pub fn set_client_window(&mut self, client_window: u32) {
        self.client_window = client_window;
    }

    pub fn client_random(&self) -> u64 {
        self.client_random
    }

    pub fn set_client_random(&mut self, client_random: u64) {
        self.client_random = client_random;
    }

    pub fn server_random(&self) -> u64 {
        self.server_random
    }

    pub fn set_server_random(&mut self, server_random: u64) {
        self.server_random = server_random;
    }

    pub fn client_to_server_key(&self) -> &[u8; 0x10] {
        &self.client_to_server_key
    }

    pub fn set_client_to_server_key(&mut self, client_to_server_key: &[u8; 0x10]) {
        self.client_to_server_key.copy_from_slice(client_to_server_key);
    }

    pub fn server_to_client_key(&self) -> &[u8; 0x10] {
        &self.server_to_client_key
    }

    pub fn set_server_to_client_key(&mut self, server_to_client_key: &[u8; 0x10]) {
        self.server_to_client_key.copy_from_slice(server_to_client_key);
    }
}
