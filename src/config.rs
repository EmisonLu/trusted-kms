// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use config::File;
use serde::Deserialize;

const SYNC_ADDR: &str = "0.0.0.0:9991";
const KMS_API_ADDR: &str = "0.0.0.0:9992";
const KMS_REGISTRATION_ADDR: &str = "0.0.0.0:9993";

#[derive(Deserialize, Default)]
pub struct Config {
    pub peers: Vec<String>,
    pub sync_socket: String,
    // KMS API. That will be covered by TLS
    pub kms_api_socket: String,

    // KMS registration API. That will not be covered by TLS
    pub kms_registration_socket: String,
    pub https_cert: String,
    pub https_private_key: String,
    pub client_root_ca_cert: String,

    // CA configurations
    pub ca_private_key: String,
    pub ca_public_key_cert: String,
}

impl Config {
    /// Load `CdhConfig` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate.
    pub fn from_file(config_path: &str) -> Result<Self> {
        let c = config::Config::builder()
            .set_default("sync_socket", SYNC_ADDR)?
            .set_default("kms_api_socket", KMS_API_ADDR)?
            .set_default("kms_registration_socket", KMS_REGISTRATION_ADDR)?
            .add_source(File::with_name(config_path))
            .build()?;

        let res = c.try_deserialize().context("invalid config")?;
        Ok(res)
    }
}
