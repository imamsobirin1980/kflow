use crate::cli::types::ConnectionsResponse;
use reqwest;
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::Duration;

pub async fn fetch_via_portforward(pod: &str, local_port: u16) -> anyhow::Result<ConnectionsResponse> {
    let mut child = Command::new("kubectl")
        .args(["port-forward", &format!("pod/{pod}"), &format!("{local_port}:8080")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    tokio::time::sleep(Duration::from_millis(300)).await;

    let url = format!("http://127.0.0.1:{}/connections", local_port);
    let mut last_err = None;
    for _ in 0..6 {
        match fetch_url(&url).await {
            Ok(r) => {
                let _ = child.kill().await;
                return Ok(r);
            }
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }

    let _ = child.kill().await;
    Err(anyhow::anyhow!("failed to fetch {}: {:?}", pod, last_err))
}

pub async fn fetch_url(url: &str) -> anyhow::Result<ConnectionsResponse> {
    let client = reqwest::Client::new();
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("status {}", resp.status());
    }
    let v: ConnectionsResponse = resp.json().await?;
    Ok(v)
}
