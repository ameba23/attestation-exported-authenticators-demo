use std::{fs::File, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{anyhow, bail};
use attestation_exported_authenticators::{
    attestation::{AttestationGenerator, AttestationType, AttestationValidator},
    quic::{AttestedQuic, TlsServer},
};
use clap::Parser;
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    ClientConfig, ServerConfig,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};

/// Create a self-signed certificate and keypair
pub fn generate_certificate_chain() -> TlsCertAndKey {
    let subject_alt_names = vec!["localhost".to_string()];
    let cert_key = rcgen::generate_simple_self_signed(subject_alt_names)
        .expect("Failed to generate self-signed certificate");

    let cert_chain = vec![CertificateDer::from(cert_key.cert)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        cert_key.signing_key.serialize_der(),
    ));

    let cert_chain_pem = certs_to_pem_string(&cert_chain).unwrap();

    if let Err(err) = std::fs::write("cert_chain.pem", &cert_chain_pem) {
        println!("Failed to write certs to file: {err}");
    }

    let key_pem = private_key_to_pem_string(&key).unwrap();

    if let Err(err) = std::fs::write("key.pem", &key_pem) {
        println!("Failed to write key to file: {err}");
    }

    TlsCertAndKey { cert_chain, key }
}

/// Create a TLS configuration, optionally specifying a remote certificate chain and client authentication
fn create_tls_config(
    certificate_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    remote_cert_chain: Option<&Vec<CertificateDer<'static>>>,
    client_auth: bool,
) -> (rustls::ServerConfig, Option<rustls::ClientConfig>) {
    let (tls_server_config_builder, tls_client_config) =
        if let Some(remote_cert_chain) = remote_cert_chain {
            let (client_verifier, root_store) =
                client_verifier_from_remote_cert(remote_cert_chain[0].clone());

            let server_config_builder = if client_auth {
                rustls::ServerConfig::builder().with_client_cert_verifier(client_verifier)
            } else {
                rustls::ServerConfig::builder().with_no_client_auth()
            };

            let client_config = if client_auth {
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_client_auth_cert(certificate_chain.clone(), key.clone_key())
                    .unwrap()
            } else {
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            };

            (server_config_builder, Some(client_config))
        } else {
            (rustls::ServerConfig::builder().with_no_client_auth(), None)
        };

    let tls_server_config = tls_server_config_builder
        .with_single_cert(certificate_chain.clone(), key)
        .expect("Failed to create rustls server config");

    (tls_server_config, tls_client_config)
}

/// Given a server ceritificate, return a client verifier which will accept it
fn client_verifier_from_remote_cert(
    cert: CertificateDer<'static>,
) -> (
    Arc<dyn rustls::server::danger::ClientCertVerifier>,
    rustls::RootCertStore,
) {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert).unwrap();

    (
        WebPkiClientVerifier::builder(Arc::new(root_store.clone()))
            .build()
            .unwrap(),
        root_store,
    )
}

/// Setup a quinn server, with optional remote ceritifcate and client authentication
pub fn create_quinn_server(
    port: u16,
    certificate_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    remote_cert_chain: Option<&Vec<CertificateDer<'static>>>,
    client_auth: bool,
) -> quinn::Endpoint {
    let (tls_server_config, tls_client_config) =
        create_tls_config(certificate_chain, key, remote_cert_chain, client_auth);

    let server_config = ServerConfig::with_crypto(Arc::<QuicServerConfig>::new(
        tls_server_config.try_into().unwrap(),
    ));
    let mut quic_server =
        quinn::Endpoint::server(server_config, format!("127.0.0.1:{port}").parse().unwrap())
            .unwrap();

    if let Some(tls_client_config) = tls_client_config {
        let client_config = ClientConfig::new(Arc::<QuicClientConfig>::new(
            tls_client_config.try_into().unwrap(),
        ));
        quic_server.set_default_client_config(client_config);
    }
    quic_server
}

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    connect: Option<SocketAddr>,
    #[arg(long)]
    cert_file: Option<PathBuf>,
    #[arg(long)]
    private_key: Option<PathBuf>,
    #[arg(long)]
    remote_cert_chain: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install aws-lc-rs provider");

    let TlsCertAndKey { cert_chain, key } = if let Some(cert_file) = cli.cert_file {
        if let Some(key_file) = cli.private_key {
            load_tls_cert_and_key(cert_file, key_file)?
        } else {
            bail!("certificate file given but no private key");
        }
    } else {
        generate_certificate_chain()
    };

    let remote_cert_chain = if let Some(path) = cli.remote_cert_chain {
        Some(load_certs_pem(path)?)
    } else {
        None
    };

    let quinn_server = create_quinn_server(
        cli.port.unwrap_or_default(),
        cert_chain.clone(),
        key.clone_key(),
        remote_cert_chain.as_ref(),
        false,
    );
    let endpoint = AttestedQuic {
        provider: rustls::crypto::aws_lc_rs::default_provider().into(),
        attestation_validator: AttestationValidator::new_mock_tdx(),
        attestation_generator: AttestationGenerator {
            attestation_type: AttestationType::DcapTdx,
        },
        endpoint: quinn_server,
        tls_server: Some(TlsServer {
            certificate_chain: cert_chain.clone(),
            private_key: key,
        }),
    };

    let server_addr = endpoint.endpoint.local_addr().unwrap();
    println!("Listening on {server_addr:?}");

    let endpoint_c = endpoint.clone();
    tokio::spawn(async move {
        if let Some(addr) = cli.connect {
            let (_connection, measurements) = endpoint_c.connect(addr, "localhost").await.unwrap();

            println!("Validated remote attestation with measurements: {measurements:?}");
        }
    });

    loop {
        let connection_result = endpoint.accept().await;
        match connection_result {
            Ok(conn) => {
                println!("Accepted connection");
                // conn.close(0u32.into(), b"");
            }
            Err(err) => {
                println!("Incoming connection failed: {err}");
                break;
            }
        }
    }

    Ok(())
}

/// Load TLS details from storage
fn load_tls_cert_and_key(
    cert_chain: PathBuf,
    private_key: PathBuf,
) -> anyhow::Result<TlsCertAndKey> {
    let key = load_private_key_pem(private_key)?;
    let cert_chain = load_certs_pem(cert_chain)?;
    Ok(TlsCertAndKey { key, cert_chain })
}

/// load certificates from a PEM-encoded file
fn load_certs_pem(path: PathBuf) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(File::open(path)?))
        .collect::<Result<Vec<_>, _>>()
}

/// load TLS private key from a PEM-encoded file
fn load_private_key_pem(path: PathBuf) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(File::open(path)?);

    // Tries to read the key as PKCS#8, PKCS#1, or SEC1
    let pks8_key = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .next()
        .ok_or(anyhow!("No PKS8 Key"))??;

    Ok(PrivateKeyDer::Pkcs8(pks8_key))
}

/// Given a certificate chain, convert it to a PEM encoded string
fn certs_to_pem_string(certs: &[CertificateDer<'_>]) -> Result<String, pem_rfc7468::Error> {
    let mut out = String::new();
    for cert in certs {
        let block =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, cert.as_ref())?;
        out.push_str(&block);
        out.push('\n');
    }
    Ok(out)
}

fn private_key_to_pem_string(key: &PrivateKeyDer<'_>) -> Result<String, pem_rfc7468::Error> {
    match key {
        PrivateKeyDer::Pkcs8(k) => {
            let pem = pem_rfc7468::encode_string(
                "PRIVATE KEY",
                pem_rfc7468::LineEnding::LF,
                k.secret_pkcs8_der(),
            )?;
            Ok(pem)
        }
        _ => panic!("Key not PKCS8"),
    }
}

/// TLS Credentials
pub struct TlsCertAndKey {
    /// Der-encoded TLS certificate chain
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Der-encoded TLS private key
    pub key: PrivateKeyDer<'static>,
}
