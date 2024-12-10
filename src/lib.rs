// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use config::Config;
use kms::Kms;
use storage::InMemory;

pub mod config;
pub mod kms;
pub mod storage;

pub fn new_instance(config: &Config) -> Kms {
    let storage = InMemory::new(config.peers.clone());
    Kms::new(
        Arc::new(storage),
        config.ca_private_key.clone(),
        config.ca_public_key_cert.clone(),
    )
}

// #[cfg(test)]
// mod test {
//     use rstest::rstest;

//     use crate::{config::Config, kms::KmsApi};

//     #[rstest]
//     #[case(b"this is a test data bytes to be encrypted")]
//     #[case(b"")]
//     #[tokio::test]
//     async fn kms_api(#[case] plaintext: &[u8]) {
//         use crate::new_instance;

//         let config = Config::default();
//         let kms = new_instance(&config);

//         let uid = kms.register(upk)
//         let cmk = kms.generate_cmk().await.unwrap();

//         let datakey = kms.generate_data_key(&cmk).await.unwrap();

//         let cipher = kms.encrypt(&cmk, &datakey, plaintext).await.unwrap();
//         let plaintext = kms.decrypt(&cmk, &datakey, &cipher).await.unwrap();

//         assert_eq!(plaintext, plaintext);
//     }
// }
