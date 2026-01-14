use std::{collections::VecDeque, net::SocketAddr, sync::Arc};

use anyhow::Result;
use attestation_exported_authenticators::attestation::MultiMeasurements;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, Mutex};

static INDEX_HTML: &[u8] = include_bytes!("index.html");

#[derive(Clone)]
pub struct AppState {
    event_tx: broadcast::Sender<ServerEvent>,
    cmd_tx: mpsc::Sender<ClientCommand>,
    connections: Arc<Mutex<Vec<quinn::Connection>>>,
    history: Arc<Mutex<VecDeque<ServerEvent>>>,
}

impl AppState {
    pub fn new() -> (Arc<Self>, mpsc::Receiver<ClientCommand>) {
        let (event_tx, _) = broadcast::channel(100);
        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        let state = Arc::new(Self {
            event_tx,
            cmd_tx,
            connections: Arc::new(Mutex::new(Vec::new())),
            history: Arc::new(Mutex::new(VecDeque::new())),
        });
        (state, cmd_rx)
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    Chat { text: String },
}

#[derive(Debug)]
pub(crate) enum ClientCommand {
    SendChat { text: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerEvent {
    Status { text: String },
    Chat { text: String, from: String },
}

async fn index_handler() -> Html<&'static str> {
    let html = std::str::from_utf8(INDEX_HTML).unwrap_or("");
    Html(html)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut event_rx = state.event_tx.subscribe();

    let history = {
        let history_guard = state.history.lock().await;
        history_guard.iter().cloned().collect::<Vec<_>>()
    };
    for event in history {
        if let Ok(payload) = serde_json::to_string(&event) {
            if sender.send(Message::Text(payload)).await.is_err() {
                return;
            }
        }
    }

    let send_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            if let Ok(payload) = serde_json::to_string(&event) {
                if sender.send(Message::Text(payload)).await.is_err() {
                    break;
                }
            }
        }
    });

    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(text) => {
                if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(&text) {
                    match client_msg {
                        ClientMessage::Chat { text } => {
                            let _ = state.cmd_tx.send(ClientCommand::SendChat { text }).await;
                        }
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    send_task.abort();
}

pub async fn run_http_server(state: Arc<AppState>, port: u16) -> Result<()> {
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/ws", get(ws_handler))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn send_status(state: &AppState, text: impl Into<String>) {
    emit_event(
        state,
        ServerEvent::Status {
            text: text.into(),
        },
    );
}

pub async fn add_connection(state: &Arc<AppState>, conn: quinn::Connection) {
    let mut connections = state.connections.lock().await;
    connections.push(conn);
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

pub fn format_measurements(measurements: &MultiMeasurements) -> String {
    match measurements {
        MultiMeasurements::DcapTdx {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        } => format!(
            "measurements (DCAP TDX)<br>mrtd: {}<br>rtmr0: {}<br>rtmr1: {}<br>rtmr2: {}<br>rtmr3: {}",
            bytes_to_hex(mrtd),
            bytes_to_hex(rtmr0),
            bytes_to_hex(rtmr1),
            bytes_to_hex(rtmr2),
            bytes_to_hex(rtmr3),
        ),
        MultiMeasurements::None => "measurements: none".to_string(),
    }
}

pub async fn handle_incoming_streams(conn: quinn::Connection, state: Arc<AppState>) {
    let peer = conn.remote_address();
    loop {
        match conn.accept_bi().await {
            Ok((_send, mut recv)) => match recv.read_to_end(65_535).await {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).trim().to_string();
                    if !text.is_empty() {
                        emit_event(
                            &state,
                            ServerEvent::Chat {
                                text,
                                from: format!("peer {}", peer),
                            },
                        );
                    }
                }
                Err(err) => {
                    send_status(&state, format!("stream read failed: {err}"));
                    break;
                }
            },
            Err(err) => {
                send_status(&state, format!("connection closed: {err}"));
                break;
            }
        }
    }
}

async fn send_chat_to_peers(state: &AppState, text: &str) {
    let mut connections = state.connections.lock().await;
    let mut keep = Vec::with_capacity(connections.len());
    for conn in connections.iter() {
        if let Ok((mut send, _recv)) = conn.open_bi().await {
            if send.write_all(text.as_bytes()).await.is_ok() {
                let _ = send.finish();
                keep.push(conn.clone());
                continue;
            }
        }
        send_status(state, "failed to send chat message to a peer");
    }
    *connections = keep;
}

pub async fn handle_chat_commands(mut cmd_rx: mpsc::Receiver<ClientCommand>, state: Arc<AppState>) {
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            ClientCommand::SendChat { text } => {
                send_chat_to_peers(&state, &text).await;
                emit_event(
                    &state,
                    ServerEvent::Chat {
                        text,
                        from: "local".to_string(),
                    },
                );
            }
        }
    }
}

fn emit_event(state: &AppState, event: ServerEvent) {
    let _ = state.event_tx.send(event.clone());
    let history = state.history.clone();
    tokio::spawn(async move {
        const MAX_HISTORY: usize = 200;
        let mut history_guard = history.lock().await;
        history_guard.push_back(event);
        if history_guard.len() > MAX_HISTORY {
            history_guard.pop_front();
        }
    });
}
