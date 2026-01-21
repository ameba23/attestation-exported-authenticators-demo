use std::{net::SocketAddr, path::PathBuf};

use anyhow::bail;
use attestation_exported_authenticators::{
    attestation::{AttestationGenerator, AttestationType, AttestationValidator},
    quic::{AttestedQuic, TlsServer},
};
use clap::Parser;
mod config;
mod ui;

use crate::config::{
    create_quinn_server, generate_certificate_chain, load_certs_pem, load_tls_cert_and_key,
    TlsCertAndKey,
};
use crate::ui::{
    add_connection, format_measurements, handle_chat_commands, handle_incoming_streams,
    run_http_server, send_status, AppState,
};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    socket_address: Option<SocketAddr>,
    #[arg(long)]
    connect: Option<SocketAddr>,
    #[arg(long)]
    http_port: Option<u16>,
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
        cli.socket_address
            .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()),
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
    let (state, cmd_rx) = AppState::new();
    send_status(&state, format!("quic listening on {server_addr}"));

    let http_port = cli.http_port.unwrap_or(8080);
    let http_state = state.clone();
    tokio::spawn(async move {
        if let Err(err) = run_http_server(http_state, http_port).await {
            eprintln!("HTTP server error: {err}");
        }
    });
    send_status(&state, format!("web UI on http://127.0.0.1:{http_port}"));

    let command_state = state.clone();
    tokio::spawn(async move {
        handle_chat_commands(cmd_rx, command_state).await;
    });

    let endpoint_c = endpoint.clone();
    let client_state = state.clone();
    tokio::spawn(async move {
        if let Some(addr) = cli.connect {
            let (connection, measurements) = endpoint_c.connect(addr, "localhost").await.unwrap();

            println!("Validated remote attestation with measurements: {measurements:?}");
            send_status(
                &client_state,
                format!("made connection to {addr} and validated attestation"),
            );
            send_status(&client_state, format_measurements(&measurements));
            add_connection(&client_state, connection.clone()).await;
            let incoming_state = client_state.clone();
            tokio::spawn(async move {
                handle_incoming_streams(connection, incoming_state).await;
            });
        }
    });

    loop {
        let connection_result = endpoint.accept().await;
        match connection_result {
            Ok(conn) => {
                let peer = conn.remote_address();
                println!("Accepted connection from {peer}");
                send_status(&state, format!("accepted connection from {peer}"));
                add_connection(&state, conn.clone()).await;
                let incoming_state = state.clone();
                tokio::spawn(async move {
                    handle_incoming_streams(conn, incoming_state).await;
                });
                // conn.close(0u32.into(), b"");
            }
            Err(err) => {
                println!("Incoming connection failed: {err}");
                send_status(&state, format!("incoming connection failed: {err}"));
                break;
            }
        }
    }

    Ok(())
}
