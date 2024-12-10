// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::{read, read_to_string},
    io::Cursor,
    time::{Duration, SystemTime},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Args, Parser, Subcommand};
use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256};
use reqwest::{header::CONTENT_TYPE, Identity};
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    Certificate, ClientConfig, RootCertStore, ServerName,
};

use crate::kms_api::{DecryptRequest, EncryptRequest, GenerateDatakeyRequest, RegisterRequest};

mod kms_api;

#[derive(Parser)]
#[command(name = "tee_kms_client")]
#[command(bin_name = "tee_kms_client")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    address: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[command(author, version, about, long_about = None)]
enum Command {
    /// Register the client
    Register(RegisterArgs),

    /// Generate a CMK
    GenerateCmk(GenerateCmkArgs),

    /// Generate a Datakey
    GenerateDatakey(GenerateDatakeyArgs),

    /// Encrypt using datakey
    Encrypt(EncryptArgs),

    /// Decrypt using datakey
    Decrypt(DecryptArgs),
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct RegisterArgs {
    /// Path to the user's private key
    private_key: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct GenerateCmkArgs {
    /// Path to the user's private key
    private_key: String,

    /// Path to the user's public key cert provisioned by tee-kms
    user_public_key_cert: String,

    /// Path to the server's public key cert
    server_public_key_cert: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct GenerateDatakeyArgs {
    /// Path to the user's private key
    private_key: String,

    /// Path to the user's public key cert provisioned by tee-kms
    user_public_key_cert: String,

    /// Path to the server's public key cert
    server_public_key_cert: String,

    /// cmk id
    cmk_id: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct EncryptArgs {
    /// Path to the user's private key
    private_key: String,

    /// Path to the user's public key cert provisioned by tee-kms
    user_public_key_cert: String,

    /// Path to the server's public key cert
    server_public_key_cert: String,

    /// cmk id
    cmk_id: String,

    /// datakey
    datakey: String,

    /// path to the file whose content will be encrypted
    plaintext_file: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct DecryptArgs {
    /// Path to the user's private key
    private_key: String,

    /// Path to the user's public key cert provisioned by tee-kms
    user_public_key_cert: String,

    /// Path to the server's public key cert
    server_public_key_cert: String,

    /// cmk id
    cmk_id: String,

    /// datakey
    datakey: String,

    /// path to the file whose content will be decrypt
    ciphertext_file: String,
}

struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

fn new_tls_client(
    client_key_path: &str,
    client_key_cert_path: &str,
    server_public_key_cert_path: &str,
) -> reqwest::Client {
    let client_key = read_to_string(client_key_path).unwrap();
    let client_key_cert = read_to_string(client_key_cert_path).unwrap();
    let server_public_key_cert = read_to_string(server_public_key_cert_path).unwrap();

    let identity_cert = format!("{client_key}\n{client_key_cert}");
    let identity = Identity::from_pem(identity_cert.as_bytes()).unwrap();

    let mut cursor = Cursor::new(&server_public_key_cert);
    let server_public_key_cert_chain = rustls_pemfile::certs(&mut cursor).unwrap();

    let mut cursor = Cursor::new(client_key_cert);
    let client_key_cert_chain: Vec<_> = rustls_pemfile::certs(&mut cursor)
        .unwrap()
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    let mut kms_cert_chain_store = RootCertStore::empty();
    kms_cert_chain_store.add_parsable_certificates(&server_public_key_cert_chain);

    let mut cursor = Cursor::new(client_key);
    let private_key = rustls_pemfile::rsa_private_keys(&mut cursor)
        .unwrap()
        .remove(0);
    let private_key = rustls::PrivateKey(private_key);

    let tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(kms_cert_chain_store)
        .with_client_auth_cert(client_key_cert_chain, private_key)
        .unwrap();

    let mut http_client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .use_rustls_tls()
        .use_preconfigured_tls(tls_config);

    let cert = reqwest::Certificate::from_pem(server_public_key_cert.as_bytes()).unwrap();
    http_client_builder = http_client_builder.add_root_certificate(cert);

    http_client_builder.identity(identity).build().unwrap()
}

#[tokio::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let args = Cli::parse();
    let url = args.address.trim_end_matches('/');

    match args.command {
        Command::Register(r) => {
            let mut params = CertificateParams::default();
            let client_key = read_to_string(r.private_key).unwrap();
            params.key_pair = Some(KeyPair::from_pem(&client_key).unwrap());
            params.alg = &PKCS_RSA_SHA256;

            let cert = rcgen::Certificate::from_params(params).unwrap();
            let csr = cert.serialize_request_pem().unwrap();
            let url = format!("{url}/register");
            let body = RegisterRequest { crt: csr };
            let body = serde_json::to_string(&body).unwrap();

            let client_cert = reqwest::Client::new()
                .post(url)
                .header(CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            println!("{client_cert}")
        }
        Command::GenerateCmk(r) => {
            let client = new_tls_client(
                &r.private_key,
                &r.user_public_key_cert,
                &r.server_public_key_cert,
            );
            let url = format!("{url}/generate-cmk");
            let res = client.get(url).send().await.unwrap();
            let cmk_id = res.text().await.unwrap();
            println!("{cmk_id}")
        }
        Command::GenerateDatakey(r) => {
            let client = new_tls_client(
                &r.private_key,
                &r.user_public_key_cert,
                &r.server_public_key_cert,
            );
            let url = format!("{url}/generate-datakey");
            let body = GenerateDatakeyRequest { cmk_id: r.cmk_id };
            let body = serde_json::to_string(&body).unwrap();
            let res = client
                .post(url)
                .header(CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .unwrap();
            let datakey = res.text().await.unwrap();
            println!("{datakey}")
        }
        Command::Encrypt(r) => {
            let plaintext = read(r.plaintext_file).unwrap();
            let plaintext = URL_SAFE_NO_PAD.encode(plaintext);
            let client = new_tls_client(
                &r.private_key,
                &r.user_public_key_cert,
                &r.server_public_key_cert,
            );
            let url = format!("{url}/encrypt");
            let body = EncryptRequest {
                cmk_id: r.cmk_id,
                datakey: r.datakey,
                plaintext,
            };
            let body = serde_json::to_string(&body).unwrap();
            let res = client
                .post(url)
                .header(CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .unwrap();
            let cipher = res.text().await.unwrap();
            println!("{cipher}")
        }
        Command::Decrypt(r) => {
            let ciphertext = read(r.ciphertext_file).unwrap();
            let ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
            let client = new_tls_client(
                &r.private_key,
                &r.user_public_key_cert,
                &r.server_public_key_cert,
            );
            let url = format!("{url}/encrypt");
            let body = DecryptRequest {
                cmk_id: r.cmk_id,
                datakey: r.datakey,
                ciphertext,
            };
            let body = serde_json::to_string(&body).unwrap();
            let res = client
                .post(url)
                .header(CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .unwrap();
            let datakey = res.text().await.unwrap();
            println!("{datakey}")
        }
    }
}
