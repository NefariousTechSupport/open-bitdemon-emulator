use serde::{Deserialize, Serialize};

const DEFAULT_CONTENT_PORT: u16 = 3076;
const DEFAULT_HOSTNAME: &str = "localhost";
const DEFAULT_AUTH3_ENABLED: bool = false;
const DEFAULT_AUTH3_TLS: bool = true;
const DEFAULT_AUTH3_PUBLIC_CERT_PATH: &str = "certs/skysn.pem";
const DEFAULT_AUTH3_PRIVATE_KEY_PATH: &str = "certs/skysn.key";

#[derive(Serialize, Deserialize, Default)]
pub struct DwServerConfig {
    content_port: Option<u16>,
    /// The hostname under which the server can be reached
    hostname: Option<String>,
    auth3_enabled: Option<bool>,
    auth3_tls: Option<bool>,
    auth3_public_cert_path: Option<String>,
    auth3_private_key_path: Option<String>,
}

impl DwServerConfig {
    pub fn content_port(&self) -> u16 {
        self.content_port.unwrap_or(DEFAULT_CONTENT_PORT)
    }

    pub fn hostname(&self) -> &str {
        self.hostname.as_deref().unwrap_or(DEFAULT_HOSTNAME)
    }

    pub fn auth3_enabled(&self) -> bool {
        self.auth3_enabled.unwrap_or(DEFAULT_AUTH3_ENABLED)
    }

    pub fn auth3_tls(&self) -> bool {
        self.auth3_tls.unwrap_or(DEFAULT_AUTH3_TLS)
    }

    pub fn auth3_public_cert_path(&self) -> &str {
        self.auth3_public_cert_path.as_deref().unwrap_or(DEFAULT_AUTH3_PUBLIC_CERT_PATH)
    }

    pub fn auth3_private_key_path(&self) -> &str {
        self.auth3_private_key_path.as_deref().unwrap_or(DEFAULT_AUTH3_PRIVATE_KEY_PATH)
    }
}
