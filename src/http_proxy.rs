//! L7 HTTP 反向代理。
//!
//! 每条 TLS 连接交给 hyper 的 auto(h1/h2) server 处理。对每个请求：
//! 1. 取 Host（去端口、小写），在 `[[http]]` 路由表里查上游 origin；
//! 2. 普通请求走连接池转发（补 `X-Forwarded-*`、去逐跳头）；
//! 3. 带 `Upgrade` 头的请求（WebSocket 等）单开一条 h1 连接转发，
//!    双方 101 之后在两个升级连接之间双向对拷字节；
//! 4. 未命中返回 404，上游出错返回 502。
//!
//! h2 的 RFC 8441（WebSocket over HTTP/2）不用管：hyper 服务端默认不宣告
//! ENABLE_CONNECT_PROTOCOL，浏览器会自动回落到 h1 + Upgrade，正好走上面的路径 3。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::{CONNECTION, HOST, UPGRADE, HeaderMap, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use crate::net::bind_dual_stack;
use crate::tls::TlsFront;

/// 代理响应统一用 `BoxBody`（上游响应体与自造错误页两种来源归一）。
type ResBody = BoxBody<Bytes, hyper::Error>;
type ProxyClient = Client<HttpConnector, Incoming>;

/// 普通请求要删除的逐跳（hop-by-hop）头。
/// WebSocket 升级路径单独处理（见 `strip_hop_by_hop` 的 `keep_upgrade` 分支）。
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

#[derive(Clone)]
pub struct Proxy {
    /// 域名(小写) -> 上游 origin（如 `http://192.168.10.103:8080`）。
    routes: Arc<HashMap<String, String>>,
    client: ProxyClient,
    /// 所有连接级 task 都挂到 tracker，配合 token 做优雅退出。
    tracker: TaskTracker,
}

impl Proxy {
    pub fn new(routes: HashMap<String, String>, tracker: TaskTracker) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            routes: Arc::new(routes),
            client,
            tracker,
        }
    }

    /// 处理单个请求。`peer` 为客户端 IP，用于 `X-Forwarded-For`。
    pub async fn handle(
        &self,
        peer: IpAddr,
        req: Request<Incoming>,
    ) -> Result<Response<ResBody>, hyper::Error> {
        let Some(host) = extract_host(&req) else {
            return Ok(text_response(StatusCode::BAD_REQUEST, "missing Host"));
        };

        let Some(upstream) = self.routes.get(&host).cloned() else {
            debug!(%host, "无匹配路由，返回 404");
            return Ok(text_response(StatusCode::NOT_FOUND, "no route for host"));
        };

        // 带 Upgrade 头（WebSocket、h2c 等）走升级透传，其余走普通代理。
        let is_upgrade = req.headers().contains_key(UPGRADE);
        let result = if is_upgrade {
            self.forward_upgrade(peer, &host, &upstream, req).await
        } else {
            self.forward(peer, &host, &upstream, req).await
        };
        match result {
            Ok(resp) => Ok(resp),
            Err(e) => {
                warn!(%host, %upstream, error = %format!("{e:#}"), "转发上游失败");
                Ok(text_response(StatusCode::BAD_GATEWAY, "upstream error"))
            }
        }
    }

    /// 普通请求：复用连接池转发，并记一条请求日志（方法/域名/状态/耗时）。
    async fn forward(
        &self,
        peer: IpAddr,
        host: &str,
        upstream: &str,
        req: Request<Incoming>,
    ) -> anyhow::Result<Response<ResBody>> {
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        let start = Instant::now();

        let (mut parts, body) = req.into_parts();
        parts.uri = rewrite_for_upstream(&mut parts.headers, &parts.uri, peer, host, upstream, false)?;
        // 客户端到网关走 h2 时请求 version 是 HTTP_2；上游是明文 h1，
        // 必须改回 1.1，否则上游客户端按 h2 语义处理（池化连接直接拒绝）。
        parts.version = Version::HTTP_11;

        let resp = self
            .client
            .request(Request::from_parts(parts, body))
            .await
            .context("请求上游失败")?;

        let (mut rparts, rbody) = resp.into_parts();
        strip_hop_by_hop(&mut rparts.headers, false);
        info!(
            %method,
            %host,
            path,
            status = rparts.status.as_u16(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "代理请求"
        );
        Ok(Response::from_parts(rparts, rbody.boxed()))
    }

    /// 升级请求（WebSocket 等）：单开一条 h1 连接，双方 101 后双向对拷。
    async fn forward_upgrade(
        &self,
        peer: IpAddr,
        host: &str,
        upstream: &str,
        mut req: Request<Incoming>,
    ) -> anyhow::Result<Response<ResBody>> {
        // 客户端侧升级句柄，必须在消费 req 之前取出。
        let on_client = hyper::upgrade::on(&mut req);

        let (mut parts, body) = req.into_parts();
        parts.uri = rewrite_for_upstream(&mut parts.headers, &parts.uri, peer, host, upstream, true)?;
        // h1 裸连接 + 1.1 版本，Upgrade 协商只定义在 HTTP/1.1 上。
        parts.version = Version::HTTP_11;

        // 升级后的连接无法归还连接池，因此不复用池子，单独拨一条上游连接。
        let (up_host, up_port) = upstream_socket_addr(&parts.uri).context("上游地址非法")?;
        let tcp = TcpStream::connect((up_host, up_port))
            .await
            .with_context(|| format!("连接上游 {up_host}:{up_port} 失败"))?;
        let _ = tcp.set_nodelay(true);

        let (mut sender, conn) = http1::handshake(TokioIo::new(tcp))
            .await
            .context("与上游 HTTP 握手失败")?;
        // with_upgrades：没有它，上游 101 响应不会附带 OnUpgrade。
        self.tracker.spawn(conn.with_upgrades());

        let resp = sender
            .send_request(Request::from_parts(parts, body))
            .await
            .context("向上游发送升级请求失败")?;

        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let (mut rparts, _) = resp.into_parts();
            // 101 的 Connection/Upgrade 等头原样转回客户端，去掉会破坏升级协商。
            let Some(on_upstream) = rparts.extensions.remove::<OnUpgrade>() else {
                anyhow::bail!("上游返回 101 但未提供升级句柄");
            };
            info!(%host, "升级隧道建立");
            self.tracker.spawn(async move {
                // 两端的 OnUpgrade 都完成后，才各自拿到可读写的裸连接。
                match tokio::try_join!(on_client, on_upstream) {
                    Ok((client_io, upstream_io)) => {
                        let mut client_io = TokioIo::new(client_io);
                        let mut upstream_io = TokioIo::new(upstream_io);
                        if let Err(e) = copy_bidirectional(&mut client_io, &mut upstream_io).await {
                            debug!(error = %e, "升级隧道结束");
                        }
                    }
                    Err(e) => warn!(error = %e, "升级隧道握手失败"),
                }
            });
            Ok(Response::from_parts(rparts, empty_body()))
        } else {
            // 上游拒绝升级（如按普通请求返回 200）：当普通响应转回。
            let (mut rparts, rbody) = resp.into_parts();
            strip_hop_by_hop(&mut rparts.headers, false);
            Ok(Response::from_parts(rparts, rbody.boxed()))
        }
    }
}

/// 在 `port` 上启动 HTTPS 服务：双栈监听 → TLS 握手 → auto(h1/h2) 反代。
///
/// 正常不返回（一直 accept）；`token` 取消后停止接入并返回。单连接错误只记日志。
pub async fn serve_https(
    port: u16,
    tls: TlsFront,
    proxy: Proxy,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let listener = bind_dual_stack(port).with_context(|| format!("HTTPS 绑定端口 {port} 失败"))?;
    info!(port, "HTTPS 反向代理已启动");

    loop {
        let (tcp, peer) = tokio::select! {
            _ = token.cancelled() => {
                info!(port, "HTTPS 服务停止接入");
                return Ok(());
            }
            res = listener.accept() => match res {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = %e, "HTTPS accept 失败");
                    continue;
                }
            },
        };
        let tls = tls.clone();
        let proxy = proxy.clone();
        let tracker = proxy.tracker.clone();
        tracker.spawn(async move {
            let stream = match tls.accept(tcp).await {
                Ok(Some(stream)) => stream, // 正常 TLS 连接
                Ok(None) => return,         // ACME TLS-ALPN-01 挑战，已处理
                Err(e) => {
                    debug!(error = %format!("{e:#}"), "TLS 握手失败");
                    return;
                }
            };

            let peer_ip = client_ip(peer);
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let proxy = proxy.clone();
                async move { proxy.handle(peer_ip, req).await }
            });

            // with_upgrades：101 响应后连接才能被 hyper::upgrade::on 取走。
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, svc)
                .await
            {
                debug!(%peer, error = %e, "HTTP 连接结束");
            }
        });
    }
}

/// 把请求改写为指向 `upstream`，返回新的 URI：
/// - origin + 原 path?query；
/// - 去逐跳头（`keep_upgrade=true` 时保留 connection/upgrade）；
/// - 补 `X-Forwarded-*`，Host 改写为上游 authority（不把对外域名透给内网）。
fn rewrite_for_upstream(
    headers: &mut HeaderMap,
    uri: &Uri,
    peer: IpAddr,
    host: &str,
    upstream: &str,
    keep_upgrade: bool,
) -> anyhow::Result<Uri> {
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let new_uri: Uri = format!("{}{}", upstream.trim_end_matches('/'), pq)
        .parse()
        .with_context(|| format!("拼接上游 URI 失败: {upstream}{pq}"))?;
    let up_authority = new_uri.authority().map(|a| a.as_str().to_owned());

    strip_hop_by_hop(headers, keep_upgrade);
    append_forwarded(headers, peer, host);
    if let Some(auth) = up_authority {
        headers.insert(HOST, HeaderValue::from_str(&auth).context("上游 Host 头非法")?);
    }
    Ok(new_uri)
}

/// 从上游 URI 取 socket 地址（缺端口默认 80；仅支持明文 http 上游）。
fn upstream_socket_addr(uri: &Uri) -> Option<(&str, u16)> {
    let auth = uri.authority()?;
    Some((auth.host(), auth.port_u16().unwrap_or(80)))
}

/// 取请求的目标域名：h2 优先用 URI authority，h1 用 Host 头；去端口、转小写。
fn extract_host(req: &Request<Incoming>) -> Option<String> {
    if let Some(auth) = req.uri().authority() {
        return Some(auth.host().trim().to_ascii_lowercase());
    }
    let raw = req.headers().get(HOST)?.to_str().ok()?;
    Some(strip_port(raw).trim().to_ascii_lowercase())
}

/// 去掉 Host 头里的端口。兼容 IPv6 字面量（`[::1]:8080`）。
fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        // IPv6 字面量：取到 ']' 为止（不含端口）。
        return rest.split(']').next().unwrap_or(rest);
    }
    host.split(':').next().unwrap_or(host)
}

/// 把 IPv4-mapped IPv6（双栈下 IPv4 客户端的形态）还原成 IPv4，日志/XFF 更干净。
fn client_ip(addr: SocketAddr) -> IpAddr {
    match addr.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        ip => ip,
    }
}

/// 删除逐跳头，包括 `Connection` 头里逐个列出的头名。
///
/// `keep_upgrade=true`（升级协商路径）：`connection`/`upgrade` 是 101 语义的一部分，
/// 必须原样转发，只删其余逐跳头。
fn strip_hop_by_hop(headers: &mut HeaderMap, keep_upgrade: bool) {
    if keep_upgrade {
        for name in ["te", "trailers", "transfer-encoding", "proxy-authenticate", "proxy-authorization"] {
            headers.remove(name);
        }
        return;
    }

    // 先收集 Connection 头里列出的 token（如 `Connection: upgrade, X-Foo`）。
    let listed: Vec<HeaderName> = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
                .collect()
        })
        .unwrap_or_default();

    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    for name in listed {
        headers.remove(name);
    }
}

/// 追加反向代理标准头：`X-Forwarded-For/Proto/Host`。
fn append_forwarded(headers: &mut HeaderMap, peer: IpAddr, host: &str) {
    let xff = HeaderName::from_static("x-forwarded-for");
    let peer_s = peer.to_string();
    let value = match headers.get(&xff).and_then(|v| v.to_str().ok()) {
        Some(existing) => format!("{existing}, {peer_s}"),
        None => peer_s,
    };
    if let Ok(v) = HeaderValue::from_str(&value) {
        headers.insert(xff, v);
    }
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    if let Ok(v) = HeaderValue::from_str(host) {
        headers.insert(HeaderName::from_static("x-forwarded-host"), v);
    }
}

/// 101 升级响应的空响应体。
fn empty_body() -> ResBody {
    Full::new(Bytes::new())
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed()
}

/// 构造纯文本响应（错误页/兜底）。
fn text_response(status: StatusCode, msg: &str) -> Response<ResBody> {
    let body = Full::new(Bytes::from(msg.to_owned()))
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(body)
        .expect("构造静态响应不应失败")
}
