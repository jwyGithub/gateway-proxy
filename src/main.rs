//! gateway-proxy：跑在家里 Windows 上的轻量反向代理 / 端口转发网关。
//!
//! - L7：多个 HTTPS 子域名共用 443，按 `Host` 反向代理到内网上游（Phase 2 接入）。
//! - L4：每条 `[[tcp]]` 独占一个端口做裸 TCP 透传（如 SSH 2222→22）。
//!
//! 对外入口是 IPv6 公网；所有监听器都是双栈，方便本地用 IPv4 联调。
//! 路由全部来自 `config.toml`，改路由不用改代码。

mod config;
mod ddns;
mod http_proxy;
mod net;
mod tcp_proxy;
mod tls;

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    // 统一进程默认加密后端为 ring（与各 TLS 配置一致，避免 provider 歧义）。
    // 已安装则忽略。
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 支持 `gateway-proxy [config.toml]`，默认读当前目录的 config.toml。
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    let cfg = Config::load(&config_path).with_context(|| format!("加载配置失败: {config_path}"))?;
    info!(
        http_routes = cfg.http.len(),
        tcp_routes = cfg.tcp.len(),
        https_listen = cfg.https_listen,
        "配置加载完成"
    );

    // 所有 task（监听循环 + 连接处理）统一挂到 tracker；token 用于通知停止接入。
    let tracker = TaskTracker::new();
    let token = CancellationToken::new();

    // L4 TCP 路由：每条一个独立 task 持续 accept。
    for route in cfg.tcp.clone() {
        let listen = route.listen;
        let token = token.clone();
        let run_tracker = tracker.clone();
        tracker.spawn(async move {
            if let Err(e) = tcp_proxy::run(route, token, run_tracker).await {
                error!(listen, error = %format!("{e:#}"), "TCP 路由退出");
            }
        });
    }

    // L7 HTTPS 反向代理：所有 [[http]] 域名共用 https_listen 端口，按 Host 分发。
    if !cfg.http.is_empty() {
        let routes: HashMap<String, String> = cfg
            .http
            .iter()
            .map(|h| (h.domain.to_lowercase(), h.upstream.clone()))
            .collect();
        let proxy = http_proxy::Proxy::new(routes, tracker.clone());
        let tls_front = tls::TlsFront::start(&cfg).context("启动 HTTPS 前置失败")?;
        let port = cfg.https_listen;
        let token = token.clone();
        tracker.spawn(async move {
            if let Err(e) = http_proxy::serve_https(port, tls_front, proxy, token).await {
                error!(port, error = %format!("{e:#}"), "HTTPS 服务退出");
            }
        });
    }

    // DDNS：IPv6 前缀漂移时自动更新 Cloudflare AAAA 记录（可选）。
    if let Some(ddns) = cfg.ddns.clone() {
        let token = ddns::read_token(&ddns).context("读取 DDNS API Token 失败")?;
        tracker.spawn(ddns::run(ddns, token));
    }

    if cfg.http.is_empty() && cfg.tcp.is_empty() {
        anyhow::bail!("没有任何可运行的路由，请检查 config.toml（[[http]] 或 [[tcp]] 至少一条）");
    }

    info!("网关已启动，按 Ctrl-C 退出");
    tokio::signal::ctrl_c().await.context("监听 Ctrl-C 失败")?;

    // 优雅退出：先停 accept，再给存量连接最多 10 秒收尾；到点强退
    // （长连接如 WebSocket/SSH 本就没有"优雅"可言，进程退出即关闭）。
    // ponytail: 不做 hyper 连接级 graceful_shutdown（watch 通道逐连接通知），
    // 家用规模下 10 秒超时兜底足够；连接数大了再加。
    info!("收到关闭信号，停止接入新连接…");
    token.cancel();
    tracker.close();
    let _ = timeout(Duration::from_secs(10), tracker.wait()).await;
    info!("网关已退出");

    Ok(())
}

/// 初始化日志：默认 `info`，可用环境变量 `RUST_LOG` 覆盖（如 `RUST_LOG=debug`）。
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
