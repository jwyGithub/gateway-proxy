//! L7 HTTPS 的 TLS 前置。证书来源二选一（由配置决定）：
//! - `[tls]`：自定义 PEM 证书/私钥（如已购证书），启动时一次性加载；
//! - `[acme]`：`rustls-acme` 自动签发 / 续期 Let's Encrypt 证书（TLS-ALPN-01 校验）。
//!
//! 多个子域名共用同一个 443 端口。ACME 模式证书按 SNI 动态解析；
//! 自定义模式同一张证书服务所有 SNI（配通配符或多 SAN 证书即可）。
//! `TlsFront` 可克隆（内部都是 `Arc`），每条连接一份句柄。

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::Context as _;
use rustls::ServerConfig;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeConfig, is_tls_alpn_challenge};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

use crate::config::{Config, TlsCertConfig};

/// TLS 握手所需的共享句柄。
#[derive(Clone)]
pub struct TlsFront {
    /// TLS-ALPN-01 挑战用配置（`is_tls_alpn_challenge` 为真时使用）。
    /// 自定义证书模式下没有 ACME，此字段不会被触发，用默认配置占位。
    challenge: Arc<ServerConfig>,
    /// 正常连接用配置：已设置 ALPN(h2 + http/1.1)。
    default: Arc<ServerConfig>,
}

impl TlsFront {
    /// 构建 TLS 前置：`[tls]` 自定义证书优先；否则按 `[acme]` 自动签发。
    ///
    /// 前置条件：`cfg` 至少有一条 `[[http]]` 路由（否则 HTTPS 服务根本不会启动）。
    /// ACME 模式会 spawn 后台驱动 task（签发/续期/缓存）。
    pub fn start(cfg: &Config) -> anyhow::Result<Self> {
        let provider = Arc::new(ring::default_provider());
        let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let (default, challenge) = match &cfg.tls {
            Some(tls_cfg) => {
                let (certs, key) = load_custom_cert(tls_cfg)?;
                let mut default = ServerConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .context("初始化 rustls 协议版本失败")?
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .context("自定义证书与私钥不匹配（或证书无法使用）")?;
                default.alpn_protocols = alpn;
                let default = Arc::new(default);
                info!(cert = %tls_cfg.cert, key = %tls_cfg.key, "TLS 使用自定义证书");
                (default.clone(), default)
            }
            None => {
                let acme = cfg
                    .acme
                    .as_ref()
                    .context("既没有 [tls] 自定义证书也没有 [acme] 配置")?;
                Self::start_acme(cfg, acme, provider, alpn)?
            }
        };

        Ok(Self { challenge, default })
    }

    /// ACME 模式：构建状态机并 spawn 后台驱动 task。
    fn start_acme(
        cfg: &Config,
        acme: &crate::config::AcmeConfig,
        provider: Arc<rustls::crypto::CryptoProvider>,
        alpn: Vec<Vec<u8>>,
    ) -> anyhow::Result<(Arc<ServerConfig>, Arc<ServerConfig>)> {
        let domains = cfg.acme_domains();
        anyhow::ensure!(!domains.is_empty(), "没有 [[http]] 路由，无法启动 HTTPS 前置");

        // staging=true → Let's Encrypt 测试环境（production=false）。
        let production = !acme.staging;
        let mut state = AcmeConfig::new(domains.clone())
            .contact([format!("mailto:{}", acme.email)])
            .cache_option(Some(DirCache::new(acme.cache_dir.clone())))
            .directory_lets_encrypt(production)
            .state();

        let challenge = state.challenge_rustls_config();

        // 正常连接自建 ServerConfig：显式用 ring provider，并设 ALPN 让 h2 可协商。
        let mut default = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("初始化 rustls 协议版本失败")?
            .with_no_client_auth()
            .with_cert_resolver(state.resolver());
        default.alpn_protocols = alpn;

        info!(
            ?domains,
            staging = acme.staging,
            cache_dir = %acme.cache_dir,
            "ACME 已初始化（{}）",
            if acme.staging { "staging 测试环境" } else { "生产环境" }
        );

        // 后台驱动状态机：拉取账户、下单、完成校验、缓存与续期都在这里推进。
        tokio::spawn(async move {
            loop {
                match state.next().await {
                    Some(Ok(ok)) => info!(event = ?ok, "ACME 事件"),
                    Some(Err(err)) => error!(error = ?err, "ACME 错误"),
                    None => {
                        warn!("ACME 状态流结束，证书将不再自动续期");
                        break;
                    }
                }
            }
        });

        Ok((Arc::new(default), challenge))
    }

    /// 对一条已 accept 的 TCP 连接完成 TLS 握手。
    ///
    /// - `Ok(Some(tls))`：正常连接，交给 HTTP 层处理。
    /// - `Ok(None)`：这是 ACME TLS-ALPN-01 挑战握手，已在此完成并关闭。
    /// - `Err(_)`：握手失败。
    pub async fn accept(&self, tcp: TcpStream) -> anyhow::Result<Option<TlsStream<TcpStream>>> {
        let handshake = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp)
            .await
            .context("读取 TLS ClientHello 失败")?;

        if is_tls_alpn_challenge(&handshake.client_hello()) {
            // ACME 校验握手：用挑战证书完成握手后立即关闭即可。
            let mut tls = handshake
                .into_stream(self.challenge.clone())
                .await
                .context("完成 ACME 挑战握手失败")?;
            let _ = tls.shutdown().await;
            Ok(None)
        } else {
            let tls = handshake
                .into_stream(self.default.clone())
                .await
                .context("TLS 握手失败")?;
            Ok(Some(tls))
        }
    }
}

/// 从 PEM 文件加载自定义证书链与私钥。
fn load_custom_cert(t: &TlsCertConfig) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_file =
        File::open(&t.cert).with_context(|| format!("打开证书文件失败: {}", t.cert))?;
    let certs: Vec<CertificateDer<'static>> = certs(&mut BufReader::new(cert_file))
        .collect::<Result<_, _>>()
        .with_context(|| format!("解析证书 PEM 失败: {}", t.cert))?;
    anyhow::ensure!(!certs.is_empty(), "证书文件里没有任何证书: {}", t.cert);

    let key_file =
        File::open(&t.key).with_context(|| format!("打开私钥文件失败: {}", t.key))?;
    let key = private_key(&mut BufReader::new(key_file))
        .with_context(|| format!("解析私钥 PEM 失败: {}", t.key))?
        .with_context(|| format!("私钥文件里没有找到私钥: {}", t.key))?;

    Ok((certs, key))
}
