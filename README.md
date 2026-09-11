# gateway-proxy

跑在家里 Windows 上的轻量反向代理 / 端口转发网关，用 Rust 编写。

一台只有 IPv6 公网的机器，把内网服务安全地暴露到公网：

- **L7 HTTPS 反向代理**：多个子域名共用 443 端口，按 `Host` 分发到内网上游，支持 WebSocket 透传
- **L4 TCP 透传**：SSH 等裸 TCP 协议按端口转发，每条路由独占监听端口
- **证书全自动**：Let's Encrypt 自动签发与续期（TLS-ALPN-01），或使用自定义 PEM 证书
- **DDNS 兜底**：IPv6 前缀漂移时自动更新 Cloudflare AAAA 记录

```
外网客户端 ──IPv6──> Windows 网关 (gateway-proxy)
                        │
                        ├─ https://relay.example.com   ──> http://192.168.10.103:8080
                        ├─ https://web.example.com     ──> http://192.168.10.103:3000
                        └─ develop.example.com:2222    ──> 192.168.10.103:22 (SSH)
```

## 特性

- **多域名路由**：所有 HTTPS 子域共用一个 443，无需为每个服务开端口
- **证书二选一**
  - `[acme]`：`rustls-acme` 自动签发 / 续期 / 缓存，支持 staging 联调
  - `[tls]`：加载已有 PEM 证书（通配符 / 多 SAN），PKCS8 / PKCS1 / SEC1 私钥均可
- **HTTP/2 + HTTP/1.1**：客户端到网关自动协商，上游明文 h1 转发，连接池复用
- **WebSocket 透传**：`Upgrade` 请求单独建连，双方 101 后双向对拷，`h2` 客户端自动回落
- **标准代理头**：自动注入 `X-Forwarded-For / Proto / Host`，剥离逐跳头
- **优雅退出**：Ctrl-C 停止接入新连接，存量连接 10 秒收尾后退出
- **DDNS**：定时检测公网 IPv6，变化时更新 Cloudflare AAAA 记录（`[ddns]` 段可选）
- **双栈监听**：入口为 IPv6，本地 IPv4 联调也直接可用
- **零重载改路由**：所有路由来自 `config.toml`，改配置不改代码

## 安装

### 从 Release 下载

推送 `v*` tag 时 CI 自动构建六个平台的二进制（见 [Actions](.github/workflows/release.yml)）：

| 平台 | 产物 |
|---|---|
| Linux x64 / arm64 | `gateway-proxy-*-linux-*.tar.gz` |
| Windows x64 / arm64 | `gateway-proxy-*-windows-*.zip` |
| macOS x64 / arm64 | `gateway-proxy-*-apple-darwin.tar.gz` |

到 [Releases](https://github.com/jwyGithub/gateway-proxy/releases) 下载解压即可，无运行时依赖。

### 从源码构建

```bash
git clone https://github.com/jwyGithub/gateway-proxy.git
cd gateway-proxy
cargo build --release
# 产物在 target/release/gateway-proxy
```

TLS 后端统一使用 ring：Windows 上仅需 MSVC 自带的 C 编译器，不需要 cmake / NASM。

## 快速开始

```bash
cp config.example.toml config.toml
$EDITOR config.toml
./gateway-proxy config.toml   # 不带参数则读当前目录 config.toml
```

最小配置示例：

```toml
https_listen = 443

[acme]
email = "you@example.com"
cache_dir = "./acme-cache"
staging = true   # 联调通过后改 false 取正式证书

[[http]]
domain = "relay.example.com"
upstream = "http://192.168.10.103:8080"

[[tcp]]
listen = 2222
upstream = "192.168.10.103:22"
```

已有证书？删掉 `[acme]` 段，换成 `[tls]`：

```toml
[tls]
cert = "/path/to/fullchain.pem"
key = "/path/to/private.key"
```

## 配置说明

| 段 / 字段 | 必填 | 说明 |
|---|---|---|
| `https_listen` | 否 | HTTPS 监听端口，默认 `443`。**必须写在所有表头之前** |
| `[acme]` | 二选一 | Let's Encrypt 自动签发。有 `[[http]]` 路由时必须提供 `[acme]` 或 `[tls]` 之一 |
| `[acme].email` | 是 | 联系邮箱（到期提醒） |
| `[acme].cache_dir` | 否 | 证书缓存目录，默认 `./acme-cache`，务必持久化 |
| `[acme].staging` | 否 | 默认 `true`，联调用；改 `false` 取正式受信证书 |
| `[tls].cert` | 二选一 | PEM 证书链（fullchain） |
| `[tls].key` | 二选一 | PEM 私钥（PKCS8 / PKCS1 RSA / SEC1 EC） |
| `[[http]].domain` | 是 | 对外域名，按它分发（全局唯一） |
| `[[http]].upstream` | 是 | 内网上游，如 `http://192.168.10.103:8080` |
| `[[tcp]].listen` | 是 | 本机监听端口（唯一、不与 `https_listen` 冲突） |
| `[[tcp]].upstream` | 是 | 内网 `host:port` |
| `[ddns]` | 否 | Cloudflare DDNS，IPv6 前缀漂移兜底 |
| `[ddns].zone` | 是* | Cloudflare 上的主域名，如 `example.com` |
| `[ddns].zone_id` | 否 | zone id（仪表盘 URL 可见）；不填则按名称查，需 Token 有 Zone 读取权限 |
| `[ddns].records` | 是* | 要同步的 AAAA 记录名（需先手工创建），支持通配符 `*` |
| `[ddns].api_token_env` | 二选一* | 存 API Token 的环境变量名（推荐） |
| `[ddns].api_token_file` | 二选一* | 存 API Token 的文件路径（Windows 服务场景） |
| `[ddns].interval_secs` | 否 | 轮询间隔，默认 `60`，下限 10 |

校验失败的配置会在启动时直接报错并指出原因（`deny_unknown_fields`，写错键名不会静默忽略）。

## 部署要点（IPv6 + DNS-only 场景）

1. **DNS**：在 Cloudflare 添加 AAAA 记录指向机器 IPv6，使用灰云（DNS-only）——代理模式无法转发非标端口
2. **防火墙**：放行入站 443 与所有 `[[tcp]]` 监听端口
3. **ACME 联调**：先 `staging = true` 验证 `DeployedNewCert` 事件，再切正式
4. **SSH 路由**：L4 无域名概念，`develop.example.com` 仅用于 DNS 解析，实际按 2222 端口路由
5. **DDNS**：家宽 IPv6 前缀漂移时开启 `[ddns]` 段自动更新 AAAA 记录。
   Token 权限只需 Zone / DNS / Edit（配 `zone_id` 时连 Zone 读取都不用）。
   提示：Windows 默认用临时隐私地址出站，回显地址会一天一换、记录跟着日更；
   想稳定可在管理员 PowerShell 执行
   `netsh interface ipv6 set privacy "以太网" state=disabled`，
   出站即改用固定接口标识的稳定地址

## 日志

默认 `info` 级别，`RUST_LOG=debug` 可看握手失败等细节：

```
INFO 代理请求 method=GET host=relay.example.com path=/ status=200 elapsed_ms=3
INFO 升级隧道建立 host=ws.example.com
```

## 开发

```bash
cargo build
cargo run -- config.toml
```

模块划分：

| 模块 | 职责 |
|---|---|
| `src/main.rs` | 启动流程、优雅退出 |
| `src/config.rs` | TOML 加载与校验 |
| `src/tls.rs` | TLS 前置：自定义证书 / ACME 二选一 |
| `src/http_proxy.rs` | L7 反代：路由、转发、WebSocket 透传 |
| `src/tcp_proxy.rs` | L4 裸 TCP 双向对拷 |
| `src/ddns.rs` | Cloudflare DDNS：公网 IPv6 检测与记录更新 |
| `src/net.rs` | 双栈监听 |

## License

MIT
