//! Cloudflare DDNS：IPv6 前缀漂移的兜底。
//!
//! 家宽公网 IPv6 的前缀会不定期变化。网关本身绑 `[::]`，漂移不影响本机监听，
//! 唯一会断的是 Cloudflare 上指向旧地址的 AAAA 记录。本模块定时做两件事：
//! 1. 访问 IPv6-only 的回显服务，拿到当前出站公网地址；
//! 2. 地址变了才调 Cloudflare API v4，把所有 `records` 的 AAAA 记录改过去。
//!
//! Token 权限：Zone / DNS / Edit；不配 `zone_id`（按名称查 zone）还需要 Zone 读取。
//! 记录必须先在控制台手工创建——不自动创建，避免误建。

use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Method;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::crypto::ring;
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use crate::config::DdnsConfig;

/// Cloudflare API v4 根地址。
const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";
/// IPv6-only 回显服务：连上它就说明出站在走 IPv6，返回的文本即公网地址。
/// 两个互为备份，任一可用即可。
const ECHO_URLS: [&str; 2] = ["https://api6.ipify.org/", "https://ipv6.icanhazip.com/"];

type DdnsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// DDNS 主循环：轮询公网 IPv6，变化时同步 Cloudflare。正常不返回。
pub async fn run(cfg: DdnsConfig, token: String) {
    // 下限 10 秒，防止误配成 1 秒之类去锤 Cloudflare。
    let interval = Duration::from_secs(cfg.interval_secs.max(10));
    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %format!("{e:#}"), "DDNS 客户端初始化失败，DDNS 不生效");
            return;
        }
    };
    info!(
        zone = %cfg.zone,
        records = ?cfg.records,
        interval_secs = interval.as_secs(),
        "DDNS 已启动"
    );

    // last 只是为了少调 API：与上次成功同步的地址相同就不发请求。
    // 重启后为 None，首轮必对账一次（顺带自愈 Cloudflare 侧被手改的情况）。
    let mut last: Option<Ipv6Addr> = None;
    loop {
        match fetch_public_ipv6(&client, &ECHO_URLS).await {
            Ok(ip) if last != Some(ip) => match sync_all(&client, CF_API_BASE, &cfg, &token, ip).await {
                Ok(()) => {
                    info!(%ip, "DDNS 同步完成");
                    last = Some(ip);
                }
                Err(e) => warn!(error = %format!("{e:#}"), "DDNS 同步失败，下轮重试"),
            },
            Ok(_) => {}
            Err(e) => debug!(
                error = %format!("{e:#}"),
                "获取公网 IPv6 失败（本机 IPv6 可能暂时不可用）"
            ),
        }
        tokio::time::sleep(interval).await;
    }
}

/// 读取 Cloudflare API Token：环境变量优先，其次文件。
pub fn read_token(cfg: &DdnsConfig) -> anyhow::Result<String> {
    if let Some(env) = &cfg.api_token_env {
        let token = std::env::var(env)
            .with_context(|| format!("读取环境变量 {env} 失败"))?
            .trim()
            .to_owned();
        anyhow::ensure!(!token.is_empty(), "环境变量 {env} 为空");
        return Ok(token);
    }
    if let Some(file) = &cfg.api_token_file {
        let token = std::fs::read_to_string(file)
            .with_context(|| format!("读取 token 文件失败: {file}"))?
            .trim()
            .to_owned();
        anyhow::ensure!(!token.is_empty(), "token 文件 {file} 内容为空");
        return Ok(token);
    }
    bail!("[ddns] 需要 api_token_env 或 api_token_file 之一");
}

/// 出站 HTTPS 客户端（Cloudflare API / IP 回显共用）。
/// `https_or_http`：生产全走 https，本地测试用 http 假服务。
fn build_client() -> anyhow::Result<DdnsClient> {
    let https = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(Arc::new(ring::default_provider()))
        .context("初始化 DDNS TLS 配置失败")?
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(https))
}

/// 依次尝试回显服务，返回当前公网 IPv6。
async fn fetch_public_ipv6(client: &DdnsClient, urls: &[&str]) -> anyhow::Result<Ipv6Addr> {
    let mut last_err = String::new();
    for url in urls {
        let resp = match client.request(get(url)).await {
            Ok(r) => r,
            Err(e) => {
                last_err = format!("{e}");
                continue;
            }
        };
        let status = resp.status();
        let text = resp
            .into_body()
            .collect()
            .await
            .context("读取回显响应失败")?
            .to_bytes();
        match std::str::from_utf8(&text).context("回显响应不是 UTF-8")?.trim().parse::<Ipv6Addr>() {
            Ok(ip) => return Ok(ip),
            Err(_) => last_err = format!("HTTP {status}: 非 IPv6 地址文本"),
        }
    }
    bail!("所有回显服务都失败: {last_err}")
}

/// 把当前公网 IPv6 同步到所有 `records`。
/// `api_base` 可注入（测试指向本地假服务）。
async fn sync_all(
    client: &DdnsClient,
    api_base: &str,
    cfg: &DdnsConfig,
    token: &str,
    ip: Ipv6Addr,
) -> anyhow::Result<()> {
    let zone_id = resolve_zone_id(client, api_base, cfg, token).await?;
    for name in &cfg.records {
        let url = format!(
            "{api_base}/zones/{zone_id}/dns_records?type=AAAA&name={}",
            encode_query_value(name)
        );
        let result = cf_request(client, Method::GET, &url, token, None).await?;
        let record = result
            .as_array()
            .and_then(|a| a.first())
            .with_context(|| format!("Cloudflare 上没有 {name} 的 AAAA 记录，请先在控制台手工创建"))?;
        let record_id = record["id"]
            .as_str()
            .with_context(|| format!("{name} 记录响应缺少 id"))?;

        // 已一致就跳过，不发 PUT。
        if record["content"].as_str() == Some(ip.to_string().as_str()) {
            debug!(%name, "AAAA 记录已是最新，跳过");
            continue;
        }

        // 只改 content，其余字段（ttl / proxied）原样带回，不覆盖用户的其它设置。
        let body = json!({
            "type": "AAAA",
            "name": name,
            "content": ip.to_string(),
            "ttl": record.get("ttl").cloned().unwrap_or(json!(1)),
            "proxied": record.get("proxied").cloned().unwrap_or(json!(false)),
        });
        let url = format!("{api_base}/zones/{zone_id}/dns_records/{record_id}");
        cf_request(client, Method::PUT, &url, token, Some(body.to_string())).await?;
        info!(%name, %ip, "DDNS 记录已更新");
    }
    Ok(())
}

/// zone id：配置里直接给了就用；否则按名称查（需要 Zone 读取权限）。
async fn resolve_zone_id(
    client: &DdnsClient,
    api_base: &str,
    cfg: &DdnsConfig,
    token: &str,
) -> anyhow::Result<String> {
    if let Some(id) = &cfg.zone_id {
        return Ok(id.clone());
    }
    let url = format!("{api_base}/zones?name={}", encode_query_value(&cfg.zone));
    let result = cf_request(client, Method::GET, &url, token, None).await?;
    result
        .as_array()
        .and_then(|a| a.first())
        .and_then(|z| z["id"].as_str())
        .map(str::to_owned)
        .with_context(|| {
            format!(
                "按名称 {} 找不到 zone：检查 Token 是否有 Zone 读取权限，或在配置里直接填 zone_id",
                cfg.zone
            )
        })
}

/// 调一次 Cloudflare API：带 Bearer token，校验 HTTP 状态与响应里的 success 标志，
/// 返回 `result` 字段。
async fn cf_request(
    client: &DdnsClient,
    method: Method,
    url: &str,
    token: &str,
    body: Option<String>,
) -> anyhow::Result<Value> {
    let builder = Request::builder()
        .method(method)
        .uri(url)
        .header(AUTHORIZATION, format!("Bearer {token}"));
    let req = match body {
        Some(json) => builder
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .context("构造 Cloudflare 请求失败")?,
        None => builder.body(Full::default()).context("构造 Cloudflare 请求失败")?,
    };
    let resp = client.request(req).await.context("请求 Cloudflare API 失败")?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .context("读取 Cloudflare 响应失败")?
        .to_bytes();
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("解析 Cloudflare 响应失败（HTTP {status}）"))?;
    if !status.is_success() || value["success"] != json!(true) {
        bail!(
            "Cloudflare API 拒绝（HTTP {status}）: {}",
            serde_json::to_string(&value["errors"]).unwrap_or_else(|_| "未知错误".to_owned())
        );
    }
    Ok(value["result"].clone())
}

fn get(url: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(url)
        .body(Full::default())
        .expect("构造回显 GET 请求不应失败")
}

/// 查询串里唯一需要转义的字符是通配符 `*`（域名其余字符都在 URI 安全集内）。
fn encode_query_value(s: &str) -> String {
    s.replace('*', "%2A")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use hyper_util::server::conn::auto;
    use serde_json::json;

    /// 假 Cloudflare + 假回显服务的可变状态。
    #[derive(Default)]
    struct MockState {
        /// 当前 AAAA 记录内容（模拟 Cloudflare 侧的真实值）。
        content: Option<String>,
        /// 收到的 PUT 请求体。
        puts: Vec<Value>,
        /// 收到的 dns_records 查询串（验证通配符被编码）。
        list_query: Option<String>,
    }

    /// 在 127.0.0.1 随机端口起假服务，返回 (回显地址, api_base, 状态)。
    async fn start_mock(initial_content: &str) -> (String, String, Arc<Mutex<MockState>>) {
        let state = Arc::new(Mutex::new(MockState {
            content: Some(initial_content.to_owned()),
            puts: Vec::new(),
            list_query: None,
        }));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_state = state.clone();

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let state = server_state.clone();
                let svc = service_fn(move |req: Request<Incoming>| {
                    let state = state.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let path = parts.uri.path().to_owned();
                        let query = parts.uri.query().unwrap_or_default().to_owned();
                        let method = parts.method.clone();
                        let body = body.collect().await.unwrap().to_bytes();

                        let resp = match (method, path.as_str()) {
                            // 假回显服务。
                            (Method::GET, "/echo") => text_response("2001:db8::25"),
                            // 假 Cloudflare：按名称查 zone。
                            (Method::GET, "/zones") => json_response(json!({
                                "result": [{"id": "zone123"}], "success": true
                            })),
                            // 假 Cloudflare：列 AAAA 记录（真实路径 /zones/{id}/dns_records）。
                            (Method::GET, p) if p.starts_with("/zones/") && p.ends_with("/dns_records") => {
                                let content = {
                                    let mut s = state.lock().unwrap();
                                    s.list_query = Some(query);
                                    s.content.clone().unwrap_or_default()
                                };
                                json_response(json!({
                                    "result": [{
                                        "id": "rec1",
                                        "type": "AAAA",
                                        "name": "*.test.zone",
                                        "content": content,
                                        "ttl": 300,
                                        "proxied": false,
                                    }],
                                    "success": true
                                }))
                            }
                            // 假 Cloudflare：更新记录（真实路径 /zones/{id}/dns_records/{id}）。
                            (Method::PUT, p) if p.starts_with("/zones/") && p.contains("/dns_records/") => {
                                let body: Value = serde_json::from_slice(&body).unwrap();
                                let mut s = state.lock().unwrap();
                                s.puts.push(body.clone());
                                s.content = body["content"].as_str().map(str::to_owned);
                                json_response(json!({"result": body, "success": true}))
                            }
                            _ => text_response("not found"),
                        };
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                tokio::spawn(async move {
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tcp), svc)
                        .await;
                });
            }
        });

        (
            format!("http://{addr}/echo"),
            format!("http://{addr}"),
            state,
        )
    }

    fn text_response(body: &str) -> hyper::Response<Full<Bytes>> {
        hyper::Response::builder()
            .body(Full::new(Bytes::from(body.to_owned())))
            .unwrap()
    }

    fn json_response(v: Value) -> hyper::Response<Full<Bytes>> {
        hyper::Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(v.to_string())))
            .unwrap()
    }

    fn test_cfg() -> DdnsConfig {
        DdnsConfig {
            zone: "test.zone".to_owned(),
            zone_id: None,
            records: vec!["*.test.zone".to_owned()],
            api_token_env: None,
            api_token_file: None,
            interval_secs: 60,
        }
    }

    #[tokio::test]
    async fn echo_fetches_ipv6() {
        let _ = ring::default_provider().install_default();
        let client = build_client().unwrap();
        let ip = fetch_public_ipv6(&client, &["http://127.0.0.1:1/echo"]).await;
        assert!(ip.is_err(), "连不上的回显服务应报错");
    }

    #[tokio::test]
    async fn updates_record_and_skips_when_unchanged() {
        let _ = ring::default_provider().install_default();
        let client = build_client().unwrap();
        let (echo_url, api_base, state) = start_mock("2001:db8::dead").await;

        // 回显服务返回固定地址。
        let ip = fetch_public_ipv6(&client, &[&echo_url]).await.unwrap();
        assert_eq!(ip.to_string(), "2001:db8::25");

        let cfg = test_cfg();
        let token = "test-token";

        // 第一次同步：旧地址不同，应 PUT 且只改 content、保留 ttl。
        sync_all(&client, &api_base, &cfg, token, ip).await.unwrap();
        {
            let s = state.lock().unwrap();
            assert_eq!(s.puts.len(), 1, "应恰好一次 PUT");
            let put = &s.puts[0];
            assert_eq!(put["type"], "AAAA");
            assert_eq!(put["name"], "*.test.zone");
            assert_eq!(put["content"], "2001:db8::25");
            assert_eq!(put["ttl"], 300, "ttl 应保留原值");
            assert_eq!(put["proxied"], false, "proxied 应保留原值");
            // 通配符在查询串里被编码成 %2A（否则 Uri 解析直接失败）。
            assert_eq!(s.list_query.as_deref(), Some("type=AAAA&name=%2A.test.zone"));
        }

        // 第二次同步同地址：记录已一致，不应再 PUT。
        sync_all(&client, &api_base, &cfg, token, ip).await.unwrap();
        assert_eq!(state.lock().unwrap().puts.len(), 1, "地址未变不应重复 PUT");
    }
}
