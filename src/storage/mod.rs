// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use async_trait::async_trait;
use log::{info, warn};
use tokio::sync::RwLock;

use self::rpc::{sync_service_client::SyncServiceClient, SyncCmkRequest};

mod rpc {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    #![allow(clippy::redundant_async_block)]
    tonic::include_proto!("api");
}

/// This storage is to store the CMK depending on synchoronization between
/// different tee instances
#[async_trait]
pub trait Storage: Sync + Send {
    async fn get(&self, key: &str) -> Result<Vec<u8>>;
    async fn set(&self, key: &str, value: &[u8]) -> Result<()>;
}

pub struct InMemory {
    map: RwLock<BTreeMap<String, Vec<u8>>>,
    clients: Vec<String>,
}

impl InMemory {
    pub fn new(clients: Vec<String>) -> Self {
        Self {
            map: RwLock::new(BTreeMap::new()),
            clients,
        }
    }
}

#[async_trait]
impl Storage for InMemory {
    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let reader = self.map.read().await;
        if let Some(local) = reader.get(key).cloned() {
            return Ok(local);
        }

        for peer in &self.clients {
            let endpoint = peer.clone();
            let mut client = SyncServiceClient::connect(endpoint).await?;
            let req = tonic::Request::new(SyncCmkRequest {
                cmk_id: key.to_string(),
            });

            match client.sync_cmk(req).await {
                std::result::Result::Ok(res) => {
                    info!("Sync cmk {key} from peer {peer}");
                    let cmk = res.into_inner().cmk;
                    self.map.write().await.insert(key.to_string(), cmk.clone());
                    return Ok(cmk);
                }
                Err(e) => warn!("Peer {peer} sync failed: {e}"),
            }
        }

        bail!("Failed to sync. No peer has this!");
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut writer = self.map.write().await;
        writer.insert(key.to_string(), value.to_vec());
        Ok(())
    }
}
