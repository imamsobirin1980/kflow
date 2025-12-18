use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;

pub const DEFAULT_DAEMONSET: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/k8s/daemonset.yaml"));

pub mod types;
pub mod kubectl;
pub mod fetch;
pub mod tui;

use types::Connection;
use kubectl::{run_kubectl_apply, run_kubectl_delete, discover_pods};
use fetch::{fetch_url, fetch_via_portforward};
use tui::run_tui;

#[derive(Parser, Debug)]
#[command(name = "kflow-cli")]
struct Args {
    #[arg(long)]
    kube: bool,

    #[arg(long)]
    local: bool,

    #[arg(long)]
    endpoints: Option<String>,

    #[arg(long, default_value_t = 18080)]
    start_port: u16,

    #[command(subcommand)]
    cmd: Option<CommandSub>,
}

#[derive(clap::Subcommand, Debug)]
enum CommandSub {
    Install {
        #[arg(long)]
        file: Option<String>,
        #[arg(short = 'n', long)]
        namespace: Option<String>,
        #[arg(long)]
        conntrack: Option<String>,
    },
    Uninstall {
        #[arg(long)]
        file: Option<String>,
        #[arg(short = 'n', long)]
        namespace: Option<String>,
        #[arg(long)]
        conntrack: Option<String>,
    },
}

pub async fn run_cli() -> anyhow::Result<()> {
    let _ = color_eyre::install();
    let args = Args::parse();

    if let Some(cmd) = &args.cmd {
        match cmd {
            CommandSub::Install { file, namespace, conntrack } => {
                let file_ref = file.as_deref();
                let conn_ref = conntrack.as_deref();
                run_kubectl_apply(file_ref, namespace.as_deref(), conn_ref).await?;
                return Ok(());
            }
            CommandSub::Uninstall { file, namespace, conntrack } => {
                let file_ref = file.as_deref();
                let conn_ref = conntrack.as_deref();
                run_kubectl_delete(file_ref, namespace.as_deref(), conn_ref).await?;
                return Ok(());
            }
        }
    }

    let state: Arc<RwLock<HashMap<String, Vec<Connection>>>> = Arc::new(RwLock::new(HashMap::new()));

    let endpoints_list: Vec<String> = if args.local {
        vec!["http://localhost:8080".to_string()]
    } else if let Some(s) = args.endpoints.clone() {
        s.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        discover_pods().await?
    };

    let did_fetch_once = Arc::new(AtomicBool::new(false));
    let is_kube_mode = args.kube || (!args.local && args.endpoints.is_none());
    if !endpoints_list.is_empty() {
        let state_clone = state.clone();
        let endpoints_clone = endpoints_list.clone();
        let start_port = args.start_port;
        let kube_mode = is_kube_mode;
        let local_mode = args.local;
        let did_fetch = did_fetch_once.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            loop {
                tick.tick().await;
                let mut map = HashMap::new();
                if kube_mode {
                    for (i, pod) in endpoints_clone.iter().enumerate() {
                        let port = start_port + (i as u16);
                        if let Ok(resp) = fetch_via_portforward(pod, port).await {
                            let node = resp.node_name.unwrap_or_else(|| pod.clone());
                            map.insert(node, resp.connections);
                        }
                    }
                } else if local_mode {
                    if let Ok(resp) = fetch_url("http://localhost:8080/connections").await {
                        let node = resp.node_name.unwrap_or_else(|| "localhost".to_string());
                        map.insert(node, resp.connections);
                    }
                } else {
                    for ep in &endpoints_clone {
                        if let Ok(resp) = fetch_url(&format!("{}/connections", ep)).await {
                            let node = resp.node_name.unwrap_or_else(|| ep.clone());
                            map.insert(node, resp.connections);
                        }
                    }
                }
                let mut w = state_clone.write().await;
                *w = map;
                did_fetch.store(true, Ordering::SeqCst);
            }
        });
    }

    run_tui(state, is_kube_mode, did_fetch_once).await?;
    Ok(())
}
