
use std::{sync::Arc, time::Duration};

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;
use tokio::{net::TcpListener, sync::RwLock, time::sleep};
use std::net::{IpAddr, SocketAddr};
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Clone, Serialize, Hash, PartialEq, Eq)]
pub struct Connection {
    pub proto: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub state: String,
}

type SharedConnections = Arc<RwLock<Vec<Connection>>>;

#[derive(Clone)]
struct AppState {
    connections: SharedConnections,
    node_name: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let conntrack_path =
        std::env::var("CONNTRACK_PATH").unwrap_or_else(|_| "/proc/net/nf_conntrack".into());

    let verbose = std::env::var("KFLOW_DEBUG").is_ok();
    if verbose {
        println!("kflow daemon starting; CONNTRACK_PATH={}", conntrack_path);
    }

    let state: SharedConnections = Arc::new(RwLock::new(Vec::new()));
    let node_name = std::env::var("KUBE_NODE_NAME").ok();
    
    {
        let state = state.clone();
        let path = conntrack_path.clone();
        tokio::spawn(async move {
            use std::collections::HashSet;
            let mut prev_set: HashSet<Connection> = HashSet::new();
            loop {
                let flows = read_conntrack(&path);
                // detect added / removed
                let new_set: HashSet<Connection> = flows.iter().cloned().collect();
                for added in new_set.difference(&prev_set) {
                    println!("Added connection: {:?}", added);
                }
                for removed in prev_set.difference(&new_set) {
                    println!("Removed connection: {:?}", removed);
                }
                prev_set = new_set;

                {
                    let mut w = state.write().await;
                    *w = flows;
                }
                sleep(Duration::from_secs(2)).await;
            }
        });
    }

    let app_state = AppState { connections: state, node_name };
    let app = Router::new()
        .route("/connections", get(list_connections))
        .with_state(app_state);

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    println!("Listening on {addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Debug, Serialize)]
struct ConnectionsResponse {
    node_name: Option<String>,
    connections: Vec<Connection>,
}

async fn list_connections(
    State(state): State<AppState>,
) -> Json<ConnectionsResponse> {
    let snapshot = state.connections.read().await;
    Json(ConnectionsResponse {
        node_name: state.node_name.clone(),
        connections: snapshot.clone(),
    })
}

fn read_conntrack(path: &str) -> Vec<Connection> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open conntrack file {path}: {e}");
            return vec![];
        }
    };
    let reader = BufReader::new(file);
    // read all lines so we can optionally print debug info
    let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();
    // if debug enabled, print a small sample
    if std::env::var("KFLOW_DEBUG").is_ok() {
        eprintln!("read_conntrack: read {} lines from {}", lines.len(), path);
        for (i, ln) in lines.iter().enumerate().take(5) {
            eprintln!("  [{}] {}", i, ln);
        }
    }

    lines
        .into_iter()
        .filter_map(|l| parse_conntrack_line(&l))
        .collect()
}

fn parse_conntrack_line(line: &str) -> Option<Connection> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    let mut proto: Option<String> = None;
    let mut state: Option<String> = None;
    let mut src_ip: Option<IpAddr> = None;
    let mut dst_ip: Option<IpAddr> = None;
    let mut src_port: Option<u16> = None;
    let mut dst_port: Option<u16> = None;

    for p in &parts {
        if proto.is_none() && (*p == "tcp" || *p == "udp") {
            proto = Some((*p).to_string());
        } else if p.starts_with("src=") && src_ip.is_none() {
            src_ip = p["src=".len()..].parse().ok();
        } else if p.starts_with("dst=") && dst_ip.is_none() {
            dst_ip = p["dst=".len()..].parse().ok();
        } else if p.starts_with("sport=") && src_port.is_none() {
            src_port = p["sport=".len()..].parse().ok();
        } else if p.starts_with("dport=") && dst_port.is_none() {
            dst_port = p["dport=".len()..].parse().ok();
        } else if state.is_none()
            && (*p == "ESTABLISHED"
                || *p == "SYN_SENT"
                || *p == "SYN_RECV"
                || *p == "FIN_WAIT"
                || *p == "TIME_WAIT")
        {
            state = Some((*p).to_string());
        }
    }

    Some(Connection {
        proto: proto?,
        src_ip: src_ip?,
        src_port: src_port?,
        dst_ip: dst_ip?,
        dst_port: dst_port?,
        state: state.unwrap_or_else(|| "UNKNOWN".into()),
    })
}