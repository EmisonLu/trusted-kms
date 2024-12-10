// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, sync::Arc};

use anyhow::*;
use log::{debug, error};
use rpc::{
    sync_service_server::{SyncService, SyncServiceServer},
    SyncCmkRequest, SyncCmkResponse,
};
use tee_kms::kms::Kms;
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};

mod rpc {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    #![allow(clippy::redundant_async_block)]
    tonic::include_proto!("api");
}

pub struct GrpcKms {
    inner: RwLock<Arc<Kms>>,
}

#[tonic::async_trait]
impl SyncService for GrpcKms {
    async fn sync_cmk(
        &self,
        request: Request<SyncCmkRequest>,
    ) -> Result<Response<SyncCmkResponse>, Status> {
        debug!("SyncCmkRequest request");
        let request = request.into_inner();

        let kms = self.inner.read().await;

        let cmk = kms.storage.get(&request.cmk_id).await.map_err(|e| {
            error!("Failed to get cmk from storage.");
            Status::internal(format!("Failed to get cmk from storage: {e}"))
        })?;

        debug!("Get cmk successfully!");

        let reply = SyncCmkResponse {
            cmk_id: request.cmk_id,
            cmk,
        };

        Result::Ok(Response::new(reply))
    }
}

pub async fn start_grpc_service(socket: SocketAddr, kms: Arc<Kms>) -> Result<()> {
    let service = GrpcKms {
        inner: RwLock::new(kms),
    };
    Server::builder()
        .add_service(SyncServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}
