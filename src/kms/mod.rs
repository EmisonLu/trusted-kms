// SPDX-License-Identifier: Apache-2.0

mod ca;

use std::{collections::BTreeSet, sync::Arc};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rcgen::{CertificateSigningRequest, SanType};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};

use crate::storage::Storage;

use self::ca::CA;

#[async_trait]
pub trait KmsApi {
    /// Input the user public key, return the cert(upk, uid)
    async fn register(&self, upk: &str) -> Result<String>;

    /// return the cmk id
    async fn generate_cmk(&self, uid: &str) -> Result<String>;

    /// return the data key
    async fn generate_data_key(&self, cmk_id: &str, uid: &str) -> Result<String>;

    /// return the encrypted blob
    async fn encrypt(
        &self,
        cmk_id: &str,
        data_key: &str,
        plaintext: &[u8],
        uid: &str,
    ) -> Result<Vec<u8>>;

    /// return the plaintext
    async fn decrypt(
        &self,
        cmk_id: &str,
        data_key: &str,
        ciphertext: &[u8],
        uid: &str,
    ) -> Result<Vec<u8>>;
}

pub struct Kms {
    pub storage: Arc<dyn Storage>,
    pub ca: CA,
    pub users: BTreeSet<String>,
}

impl Kms {
    pub fn new(storage: Arc<dyn Storage>, private_key: String, public_key_cert: String) -> Self {
        let ca = CA::new(private_key, public_key_cert).expect("CA initialize failed");
        Self {
            storage,
            ca,
            users: BTreeSet::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedBlob {
    cipher: Vec<u8>,
    nonce: [u8; 12],
}

const AAD: &[u8] = b"TEE-KMS AAD";
const TAG_LEN: usize = 16;

#[async_trait]
impl KmsApi for Kms {
    /// Input the user public key, return the cert(upk, uid)
    async fn register(&self, upk_csr: &str) -> Result<String> {
        let uid = format!("kms://{}", uuid::Uuid::new_v4());
        let mut csr = CertificateSigningRequest::from_pem(upk_csr)?;
        csr.params.subject_alt_names = vec![SanType::URI(uid)];
        let cert = self.ca.issue_cert(csr)?;
        Ok(cert)
    }

    async fn generate_cmk(&self, uid: &str) -> Result<String> {
        let rand = SystemRandom::new();

        let mut cmk = [0u8; 32];
        rand.fill(&mut cmk).map_err(|_| anyhow!("generate cmk"))?;
        let id = uuid::Uuid::new_v4();
        let key = id.to_string();
        let key = format!("{uid}::{key}");
        self.storage.set(key.as_str(), cmk.as_slice()).await?;
        Ok(key)
    }

    async fn generate_data_key(&self, cmk_id: &str, uid: &str) -> Result<String> {
        let key = format!("{uid}::{cmk_id}");
        let cmk = self.storage.get(&key).await?;
        let rand = SystemRandom::new();
        let mut datakey = vec![0u8; 32];
        rand.fill(&mut datakey)
            .map_err(|_| anyhow!("generate data key"))?;

        let key = UnboundKey::new(&AES_256_GCM, &cmk).map_err(|_| anyhow!("initialize cmk"))?;
        let key = LessSafeKey::new(key);
        let mut nonce_bytes = [0u8; 12];
        rand.fill(&mut nonce_bytes)
            .map_err(|_| anyhow!("generate AEAD nonce"))?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let additional_data = Aad::from(AAD);

        key.seal_in_place_append_tag(nonce, additional_data, &mut datakey)
            .map_err(|_| anyhow!("encrypt datakey"))?;

        let datakey = EncryptedBlob {
            cipher: datakey,
            nonce: nonce_bytes,
        };
        let datakey = bincode::serialize(&datakey)?;
        let datakey = URL_SAFE_NO_PAD.encode(datakey);
        Ok(datakey)
    }

    async fn encrypt(
        &self,
        cmk_id: &str,
        data_key: &str,
        plaintext: &[u8],
        uid: &str,
    ) -> Result<Vec<u8>> {
        let key = format!("{uid}::{cmk_id}");
        let cmk = self.storage.get(&key).await?;

        let rand = SystemRandom::new();
        let algorithm = &AES_256_GCM;
        let key = UnboundKey::new(algorithm, &cmk).map_err(|_| anyhow!("initialize cmk"))?;
        let key = LessSafeKey::new(key);

        let datakey = URL_SAFE_NO_PAD.decode(data_key)?;
        let datakey: EncryptedBlob = bincode::deserialize(&datakey)?;

        let mut datakey_plaintext = Vec::new();
        datakey_plaintext.extend_from_slice(&datakey.cipher);
        let nonce = Nonce::assume_unique_for_key(datakey.nonce);
        let additional_data = Aad::from(AAD);

        key.open_in_place(nonce, additional_data, &mut datakey_plaintext)
            .map_err(|_| anyhow!("initialize cmk"))?;

        let encryption_key = UnboundKey::new(algorithm, &datakey_plaintext[..32])
            .map_err(|_| anyhow!("initialize datakey"))?;
        let encryption_key = LessSafeKey::new(encryption_key);
        let mut ciphertext = plaintext.to_vec();

        let mut nonce_bytes = [0u8; 12];
        rand.fill(&mut nonce_bytes)
            .map_err(|_| anyhow!("generate AEAD nonce"))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let additional_data = Aad::from(AAD);

        encryption_key
            .seal_in_place_append_tag(nonce, additional_data, &mut ciphertext)
            .map_err(|_| anyhow!("encrypt"))?;

        let blob = EncryptedBlob {
            cipher: ciphertext,
            nonce: nonce_bytes,
        };

        let res = bincode::serialize(&blob)?;
        Ok(res)
    }

    async fn decrypt(
        &self,
        cmk_id: &str,
        data_key: &str,
        ciphertext: &[u8],
        uid: &str,
    ) -> Result<Vec<u8>> {
        let key = format!("{uid}::{cmk_id}");
        let cmk = self.storage.get(&key).await?;

        let datakey = URL_SAFE_NO_PAD.decode(data_key)?;
        let datakey: EncryptedBlob = bincode::deserialize(&datakey)?;

        let mut datakey_plaintext = Vec::new();
        datakey_plaintext.extend_from_slice(&datakey.cipher);
        let nonce = Nonce::assume_unique_for_key(datakey.nonce);
        let additional_data = Aad::from(AAD);

        let algorithm = &AES_256_GCM;
        let key = UnboundKey::new(algorithm, &cmk).map_err(|_| anyhow!("initialize cmk"))?;
        let key = LessSafeKey::new(key);

        key.open_in_place(nonce, additional_data, &mut datakey_plaintext)
            .map_err(|_| anyhow!("decrypt cmk"))?;

        let decryption_key = UnboundKey::new(algorithm, &datakey_plaintext[..32])
            .map_err(|_| anyhow!("initialize datakey"))?;
        let decryption_key = LessSafeKey::new(decryption_key);

        let cipherblob: EncryptedBlob = bincode::deserialize(ciphertext)?;
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&cipherblob.cipher);

        let nonce = Nonce::assume_unique_for_key(cipherblob.nonce);
        let additional_data = Aad::from(AAD);
        decryption_key
            .open_in_place(nonce, additional_data, &mut plaintext)
            .map_err(|_| anyhow!("decrypt"))?;

        let new_len = plaintext.len() - TAG_LEN;
        plaintext.truncate(new_len);
        Ok(plaintext)
    }
}
