//! 配置加载与校验。
//!
//! 所有路由都来自 `config.toml`，改配置不用改代码。配置分四部分：
//! - `[acme]`：Let's Encrypt 自动签发（与 `[tls]` 二选一）。
//! - `[tls]`：自定义 PEM 证书（与 `[acme]` 二选一）。
//! - `[[http]]`：L7 HTTPS 路由，全部共用同一个 443 端口，按 `domain` 分发。
//! - `[[tcp]]`：L4 TCP 转发，每个服务独占一个监听端口（SSH 等裸 TCP 协议）。

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, bail, ensure};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// ACME 自动签发（与 `tls` 二选一；有 `[[http]]` 路由时必填其一）。
    #[serde(default)]
    pub acme: Option<AcmeConfig>,

    /// 自定义 PEM 证书（与 `acme` 二选一；有 `[[http]]` 路由时必填其一）。
    #[serde(default)]
    pub tls: Option<TlsCertConfig>,

    /// HTTPS 监听端口，默认 443。
    #[serde(default = "default_https_listen")]
    pub https_listen: u16,

    #[serde(default)]
    pub http: Vec<HttpRoute>,

    #[serde(default)]
    pub tcp: Vec<TcpRoute>,

    /// Cloudflare DDNS（IPv6 前缀漂移兜底），可选。
    #[serde(default)]
    pub ddns: Option<DdnsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    /// Let's Encrypt 联系邮箱（证书到期提醒等）。
    pub email: String,
    /// 证书与账户缓存目录，务必持久化，避免重启后重复签发触发速率限制。
    #[serde(default = "default_cache_dir")]
    pub cache_dir: String,
    /// true 使用 LE staging（联调用，不受正式速率限制但证书不被浏览器信任）；
    /// 联调通过后改成 false 取正式证书。
    #[serde(default = "default_true")]
    pub staging: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsCertConfig {
    /// PEM 证书链路径（fullchain，可含服务器证书 + 中间证书）。
    pub cert: String,
    /// PEM 私钥路径（PKCS8 / PKCS1 RSA / SEC1 EC 均可）。
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRoute {
    /// 对外域名，如 `relay.example.com`。
    pub domain: String,
    /// 内网上游，如 `http://192.168.10.103:8080`。
    pub upstream: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpRoute {
    /// 本机监听端口，如 2222。
    pub listen: u16,
    /// 内网上游 `host:port`，如 `192.168.10.103:22`。
    pub upstream: String,
}

/// Cloudflare DDNS：IPv6 前缀漂移时自动更新 AAAA 记录。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DdnsConfig {
    /// Cloudflare 上的 zone（主域名），如 `example.com`。
    pub zone: String,
    /// 直接指定 zone id（Cloudflare 仪表盘 URL 里能看到）。
    /// 不填则按 `zone` 名查询，这需要 Token 有 Zone 读取权限。
    #[serde(default)]
    pub zone_id: Option<String>,
    /// 要同步公网 IPv6 的 AAAA 记录名，如 `["example.com", "*.example.com"]`，
    /// 必须先在 Cloudflare 控制台手工创建。
    pub records: Vec<String>,
    /// 存 Cloudflare API Token 的环境变量名（推荐，token 不落盘）。
    #[serde(default)]
    pub api_token_env: Option<String>,
    /// 存 Cloudflare API Token 的文件路径（Windows 服务不便传环境变量时用）。
    #[serde(default)]
    pub api_token_file: Option<String>,
    /// 轮询间隔（秒）。
    #[serde(default = "default_ddns_interval")]
    pub interval_secs: u64,
}

fn default_https_listen() -> u16 {
    443
}
fn default_cache_dir() -> String {
    "./acme-cache".to_string()
}
fn default_true() -> bool {
    true
}
fn default_ddns_interval() -> u64 {
    60
}

impl Config {
    /// 从 TOML 文件加载并做基础校验。
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置文件失败: {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).context("解析 TOML 配置失败")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        // 证书来源二选一：[acme] 与 [tls] 不能同时出现。
        ensure!(
            self.acme.is_none() || self.tls.is_none(),
            "[acme] 与 [tls] 只能二选一"
        );
        if let Some(acme) = &self.acme {
            ensure!(!acme.email.trim().is_empty(), "acme.email 不能为空");
        }
        // 有 HTTP 路由就必须有证书来源；纯 TCP 转发则都不需要。
        ensure!(
            self.http.is_empty() || self.acme.is_some() || self.tls.is_some(),
            "有 [[http]] 路由时必须配置 [acme]（自动签发）或 [tls]（自定义证书）之一"
        );
        ensure!(
            !self.http.is_empty() || !self.tcp.is_empty(),
            "至少要配置一个 [[http]] 或 [[tcp]] 路由"
        );

        // HTTP 域名唯一性
        let mut domains = HashSet::new();
        for r in &self.http {
            ensure!(!r.domain.trim().is_empty(), "[[http]] domain 不能为空");
            ensure!(
                !r.upstream.trim().is_empty(),
                "[[http]] upstream 不能为空 (domain={})",
                r.domain
            );
            let d = r.domain.to_lowercase();
            if !domains.insert(d.clone()) {
                bail!("[[http]] domain 重复: {d}");
            }
        }

        // TCP 监听端口唯一性，且不能撞 HTTPS 端口
        let mut ports = HashSet::new();
        for r in &self.tcp {
            ensure!(
                !r.upstream.trim().is_empty(),
                "[[tcp]] upstream 不能为空 (listen={})",
                r.listen
            );
            if r.listen == self.https_listen {
                bail!(
                    "[[tcp]] listen={} 与 https_listen 冲突，L4 服务必须使用独立端口",
                    r.listen
                );
            }
            if !ports.insert(r.listen) {
                bail!("[[tcp]] listen 端口重复: {}", r.listen);
            }
        }

        // DDNS 段校验：token 来源至少一个，records 非空。
        if let Some(ddns) = &self.ddns {
            ensure!(!ddns.zone.trim().is_empty(), "[ddns] zone 不能为空");
            ensure!(!ddns.records.is_empty(), "[ddns] records 不能为空");
            ensure!(
                ddns.api_token_env.is_some() || ddns.api_token_file.is_some(),
                "[ddns] 需要 api_token_env 或 api_token_file 之一"
            );
        }

        Ok(())
    }

    /// ACME 需要申请证书的所有域名（小写）。
    pub fn acme_domains(&self) -> Vec<String> {
        self.http.iter().map(|h| h.domain.to_lowercase()).collect()
    }
}
