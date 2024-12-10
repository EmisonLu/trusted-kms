// SPDX-License-Identifier: Apache-2.0

use std::{any::Any, io::Cursor, net::SocketAddr, sync::Arc};

use actix_tls::accept::rustls_0_21::TlsStream;
use actix_web::{
    body::BoxBody, dev::Extensions, web, App, HttpRequest, HttpResponse, HttpServer, ResponseError,
};
use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use log::{error, info};
use rustls::{
    server::AllowAnyAnonymousOrAuthenticatedClient, Certificate, PrivateKey, RootCertStore,
    ServerConfig,
};
use rustls_pemfile::pkcs8_private_keys;
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumString};
use tee_kms::kms::{Kms, KmsApi};
use thiserror::Error;
use tokio::{net::TcpStream, sync::RwLock};

#[derive(Error, Debug, AsRefStr)]
pub enum Error {
    #[error("An internal error occured: {0}")]
    InternalError(#[from] anyhow::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let body = format!("{self:#?}");

        let mut res = match self {
            Error::InternalError(_) => HttpResponse::InternalServerError(),
            // _ => HttpResponse::NotImplemented(),
        };

        res.body(BoxBody::new(body))
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(EnumString, AsRefStr)]
#[strum(serialize_all = "lowercase")]
enum WebApi {
    #[strum(serialize = "/register")]
    Register,

    #[strum(serialize = "/generate-datakey")]
    GenerateDataKey,

    #[strum(serialize = "/generate-cmk")]
    GenerateCmk,

    #[strum(serialize = "/encrypt")]
    Encrypt,

    #[strum(serialize = "/decrypt")]
    Decrypt,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterRequest {
    pub crt: String,
}

pub async fn register(
    request_json: web::Json<RegisterRequest>,
    kms: web::Data<Arc<RwLock<Arc<Kms>>>>,
) -> Result<HttpResponse> {
    info!("register client");

    let client_cert = kms.read().await.register(&request_json.crt).await?;
    Ok(HttpResponse::Ok().body(client_cert))
}

pub async fn generate_cmk(
    request: HttpRequest,
    kms: web::Data<Arc<RwLock<Arc<Kms>>>>,
) -> Result<HttpResponse> {
    info!("generate cmk.");

    let Some(uid) = request.conn_data::<String>() else {
        Err(anyhow!("No UID found"))?
    };

    let cmk_id = kms.read().await.generate_cmk(uid).await?;
    Ok(HttpResponse::Ok().body(cmk_id))
}

#[derive(Serialize, Deserialize)]
pub struct GenerateDatakeyRequest {
    pub cmk_id: String,
}

pub async fn generate_datakey(
    request_json: web::Json<GenerateDatakeyRequest>,
    request: HttpRequest,
    kms: web::Data<Arc<RwLock<Arc<Kms>>>>,
) -> Result<HttpResponse> {
    info!("generate datakey.");

    let Some(uid) = request.conn_data::<String>() else {
        Err(anyhow!("No UID found"))?
    };

    let datakey = kms
        .read()
        .await
        .generate_data_key(&request_json.cmk_id, uid)
        .await?;
    Ok(HttpResponse::Ok().body(datakey))
}

#[derive(Serialize, Deserialize)]
pub struct EncryptRequest {
    pub cmk_id: String,
    pub datakey: String,
    pub plaintext: String,
}

pub async fn encrypt(
    request_json: web::Json<EncryptRequest>,
    request: HttpRequest,
    kms: web::Data<Arc<RwLock<Arc<Kms>>>>,
) -> Result<HttpResponse> {
    info!("encrypt.");
    let Some(uid) = request.conn_data::<String>() else {
        Err(anyhow!("No UID found"))?
    };

    let plaintext = URL_SAFE_NO_PAD
        .decode(&request_json.plaintext)
        .context("base64 decode plaintext (URL SAFE NO PAD)")?;
    let ciphertext = kms
        .read()
        .await
        .encrypt(&request_json.cmk_id, &request_json.datakey, &plaintext, uid)
        .await?;

    let ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    Ok(HttpResponse::Ok().body(ciphertext))
}

#[derive(Serialize, Deserialize)]
pub struct DecryptRequest {
    pub cmk_id: String,
    pub datakey: String,
    pub ciphertext: String,
}

pub async fn decrypt(
    request_json: web::Json<DecryptRequest>,
    request: HttpRequest,
    kms: web::Data<Arc<RwLock<Arc<Kms>>>>,
) -> Result<HttpResponse> {
    info!("decrypt.");

    let Some(uid) = request.conn_data::<String>() else {
        Err(anyhow!("No UID found"))?
    };

    let ciphertext = URL_SAFE_NO_PAD
        .decode(&request_json.ciphertext)
        .context("base64 decode ciphertext (URL SAFE NO PAD)")?;

    let plaintext = kms
        .read()
        .await
        .decrypt(
            &request_json.cmk_id,
            &request_json.datakey,
            &ciphertext,
            uid,
        )
        .await?;
    Ok(HttpResponse::Ok().body(plaintext))
}

fn get_client_cert(connection: &dyn Any, data: &mut Extensions) {
    info!("new connection");
    if let Some(tls_socket) = connection.downcast_ref::<TlsStream<TcpStream>>() {
        let (_, tls_session) = tls_socket.get_ref();

        if let Some(certs) = tls_session.peer_certificates() {
            info!("client certificate found");
            let client_cert = certs.first().unwrap().clone();
            let (_, client_cert) = x509_parser::parse_x509_certificate(client_cert.as_ref())
                .expect("Parse mTLS client cert failed");
            if let x509_parser::extensions::GeneralName::URI(id) = client_cert
                .subject_alternative_name()
                .expect("get SAN extension")
                .expect("get SAN extension")
                .value
                .general_names
                .iter()
                .find(|it| matches!(it, x509_parser::extensions::GeneralName::URI(_)))
                .expect("No SAN extension as URI")
            {
                let id = id.to_string();
                data.insert(id);
            }
        } else if connection.downcast_ref::<TcpStream>().is_some() {
            info!("plaintext on_connect");
        } else {
            unreachable!("socket should be TLS or plaintext");
        }
    }
}

pub async fn start_restful_service(
    kms: Arc<Kms>,
    https_cert: String,
    https_private_key: String,
    client_root_ca_cert: String,
    kms_api: SocketAddr,
    registration_api: SocketAddr,
) -> anyhow::Result<()> {
    let kms_inner = Arc::new(RwLock::new(kms));
    let kms_registration_server = web::Data::new(kms_inner.clone());
    let kms_api_server = web::Data::new(kms_inner);

    // Initialize TLS set-ups
    // HTTPS public key cert
    let mut cursor = Cursor::new(https_cert);
    let https_cert_chain = rustls_pemfile::certs(&mut cursor)?
        .into_iter()
        .map(Certificate)
        .collect();

    // HTTPS private key
    let mut cursor = Cursor::new(https_private_key);

    let mut https_key: Vec<PrivateKey> = pkcs8_private_keys(&mut cursor)?
        .into_iter()
        .map(PrivateKey)
        .collect();

    // mTLS client key root cert
    let mut cursor = Cursor::new(client_root_ca_cert);
    let mtls_cert_chain = rustls_pemfile::certs(&mut cursor)?;

    let mut client_root_cert_store = RootCertStore::empty();
    let (_, _skip) = client_root_cert_store.add_parsable_certificates(&mtls_cert_chain);
    let mtls_verifier = Arc::new(AllowAnyAnonymousOrAuthenticatedClient::new(
        client_root_cert_store,
    ));
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(mtls_verifier)
        .with_single_cert_with_ocsp_and_sct(
            https_cert_chain,
            https_key.remove(0),
            Vec::new(),
            Vec::new(),
        )?;

    // KMS API's that will use cert
    let kms_api_server = HttpServer::new(move || {
        App::new()
            .service(web::resource(WebApi::GenerateCmk.as_ref()).route(web::get().to(generate_cmk)))
            .service(
                web::resource(WebApi::GenerateDataKey.as_ref())
                    .route(web::post().to(generate_datakey)),
            )
            .service(web::resource(WebApi::Encrypt.as_ref()).route(web::post().to(encrypt)))
            .service(web::resource(WebApi::Decrypt.as_ref()).route(web::post().to(decrypt)))
            .app_data(web::Data::clone(&kms_api_server))
    })
    .on_connect(get_client_cert)
    .bind_rustls_021(kms_api, tls_config)?
    .run();

    // Registration API's that will not use cert
    let registration_server = HttpServer::new(move || {
        App::new()
            .service(web::resource(WebApi::Register.as_ref()).route(web::post().to(register)))
            .app_data(web::Data::clone(&kms_registration_server))
    })
    .bind(registration_api)?
    .run();

    tokio::select! {
        _ = async { match kms_api_server.await {
            std::result::Result::Ok(_) => {}
            Err(e) => error!("{e:?}"),
        } } => info!("KMS API exits."),
        _ = async { match registration_server.await {
            std::result::Result::Ok(_) => {}
            Err(e) => error!("{e:?}"),
        } } => info!("KMS Registration Server exits."),
    }

    Ok(())
}
