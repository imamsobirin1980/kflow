use std::process::Stdio;
use tokio::process::Command;

use crate::cli::DEFAULT_DAEMONSET;

pub async fn discover_pods() -> anyhow::Result<Vec<String>> {
    let output = Command::new("kubectl")
        .args(["get", "pods", "-l", "app=kflow-daemon", "-o", "jsonpath={.items[*].metadata.name}"])
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!("kubectl failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let out = String::from_utf8_lossy(&output.stdout);
    let names: Vec<String> = out.split_whitespace().map(|s| s.to_string()).collect();
    Ok(names)
}

pub async fn run_kubectl_apply(file: Option<&str>, namespace: Option<&str>, conntrack: Option<&str>) -> anyhow::Result<()> {
    if let Some(path) = file {
        if let Some(ct) = conntrack {
            let ct_repl = if ct.starts_with("/proc/") { format!("/host{}", ct) } else { ct.to_string() };
            let content = std::fs::read_to_string(path)?;
            let replaced = content.replace("/host/proc/net/nf_conntrack", &ct_repl);

            let mut args: Vec<String> = vec!["apply".into(), "-f".into(), "-".into()];
            if let Some(ns) = namespace {
                args.push("-n".into());
                args.push(ns.to_string());
            }

            let mut child = Command::new("kubectl").args(args).stdin(Stdio::piped()).spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(replaced.as_bytes()).await?;
            }
            let output = child.wait_with_output().await?;
            if output.status.success() {
                println!("{}", String::from_utf8_lossy(&output.stdout));
                Ok(())
            } else {
                anyhow::bail!("kubectl apply failed: {}", String::from_utf8_lossy(&output.stderr));
            }
        } else {
            let mut args: Vec<String> = vec!["apply".into(), "-f".into(), path.to_string()];
            if let Some(ns) = namespace {
                args.push("-n".into());
                args.push(ns.to_string());
            }

            let output = Command::new("kubectl").args(args).output().await?;
            if output.status.success() {
                println!("{}", String::from_utf8_lossy(&output.stdout));
                Ok(())
            } else {
                anyhow::bail!("kubectl apply failed: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
    } else {
        let mut manifest = DEFAULT_DAEMONSET.to_string();
        if let Some(ct) = conntrack {
            let ct_repl = if ct.starts_with("/proc/") { format!("/host{}", ct) } else { ct.to_string() };
            manifest = manifest.replace("/host/proc/net/nf_conntrack", &ct_repl);
        }

        let mut args: Vec<String> = vec!["apply".into(), "-f".into(), "-".into()];
        if let Some(ns) = namespace {
            args.push("-n".into());
            args.push(ns.to_string());
        }

        let mut child = Command::new("kubectl").args(args).stdin(Stdio::piped()).spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(manifest.as_bytes()).await?;
        }
        let output = child.wait_with_output().await?;
        if output.status.success() {
            println!("{}", String::from_utf8_lossy(&output.stdout));
            Ok(())
        } else {
            anyhow::bail!("kubectl apply failed: {}", String::from_utf8_lossy(&output.stderr));
        }
    }
}

pub async fn run_kubectl_delete(file: Option<&str>, namespace: Option<&str>, conntrack: Option<&str>) -> anyhow::Result<()> {
    if let Some(path) = file {
        if let Some(ct) = conntrack {
            let ct_repl = if ct.starts_with("/proc/") { format!("/host{}", ct) } else { ct.to_string() };
            let content = std::fs::read_to_string(path)?;
            let replaced = content.replace("/host/proc/net/nf_conntrack", &ct_repl);

            let mut args: Vec<String> = vec!["delete".into(), "-f".into(), "-".into()];
            if let Some(ns) = namespace {
                args.push("-n".into());
                args.push(ns.to_string());
            }

            let mut child = Command::new("kubectl").args(args).stdin(Stdio::piped()).spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(replaced.as_bytes()).await?;
            }
            let output = child.wait_with_output().await?;
            if output.status.success() {
                println!("{}", String::from_utf8_lossy(&output.stdout));
                Ok(())
            } else {
                anyhow::bail!("kubectl delete failed: {}", String::from_utf8_lossy(&output.stderr));
            }
        } else {
            let mut args: Vec<String> = vec!["delete".into(), "-f".into(), path.to_string()];
            if let Some(ns) = namespace {
                args.push("-n".into());
                args.push(ns.to_string());
            }

            let output = Command::new("kubectl").args(args).output().await?;
            if output.status.success() {
                println!("{}", String::from_utf8_lossy(&output.stdout));
                Ok(())
            } else {
                anyhow::bail!("kubectl delete failed: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
    } else {
        let mut manifest = DEFAULT_DAEMONSET.to_string();
        if let Some(ct) = conntrack {
            let ct_repl = if ct.starts_with("/proc/") { format!("/host{}", ct) } else { ct.to_string() };
            manifest = manifest.replace("/host/proc/net/nf_conntrack", &ct_repl);
        }

        let mut args: Vec<String> = vec!["delete".into(), "-f".into(), "-".into()];
        if let Some(ns) = namespace {
            args.push("-n".into());
            args.push(ns.to_string());
        }

        let mut child = Command::new("kubectl").args(args).stdin(Stdio::piped()).spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(manifest.as_bytes()).await?;
        }
        let output = child.wait_with_output().await?;
        if output.status.success() {
            println!("{}", String::from_utf8_lossy(&output.stdout));
            Ok(())
        } else {
            anyhow::bail!("kubectl delete failed: {}", String::from_utf8_lossy(&output.stderr));
        }
    }
}
