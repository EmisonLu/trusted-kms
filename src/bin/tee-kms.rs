// SPDX-License-Identifier: Apache-2.0

mod kms_api;
mod sync;

use std::{net::SocketAddr, sync::Arc};

use anyhow::*;
use clap::Parser;

use log::{error, info};
use tee_kms::{config::Config, new_instance};
use tokio::signal::unix::{signal, SignalKind};

use crate::{kms_api::start_restful_service, sync::start_grpc_service};

#[derive(Debug, Parser)]
#[command(author)]
struct Cli {
    /// Path to the config  file
    ///
    /// `--config /etc/kms.conf`
    #[arg(short, default_value_t = default_config_path())]
    config: String,
}

fn default_config_path() -> String {
    "/etc/tee-kms.conf".into()
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();
    info!("Use configuration file {}", cli.config);

    let config = Config::from_file(&cli.config)?;

    let sync_socket = config.sync_socket.parse::<SocketAddr>()?;
    let kms_api_socket = config.kms_api_socket.parse::<SocketAddr>()?;
    let kms_registration_socket = config.kms_registration_socket.parse::<SocketAddr>()?;

    info!(
        "KMS instance starts to listen to KMS request: https://{}",
        config.kms_api_socket,
    );

    info!(
        "KMS instance starts to listen to Registration requests: http://{}",
        config.kms_registration_socket,
    );

    info!(
        "KMS instance starts to listen to Sync server: {}",
        config.sync_socket,
    );

    let kms = Arc::new(new_instance(&config));

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;

    tokio::select! {
        _ = hangup.recv() => info!("Client terminal disconnected."),
        _ = interrupt.recv() => info!("SIGINT received, gracefully shutdown."),
        _ = start_grpc_service(sync_socket, kms.clone()) => info!("KMS sync channel exits."),
        _ = async { match start_restful_service(kms, config.https_cert, config.https_private_key, config.client_root_ca_cert,kms_api_socket, kms_registration_socket).await {
            std::result::Result::Ok(_) => {}
            Err(e) => error!("{e:?}"),
        } } => info!("KMS exits."),
    }

    Ok(())
}
