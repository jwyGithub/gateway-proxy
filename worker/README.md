# gateway-proxy-relay (Cloudflare Worker)

让**纯 IPv4 客户端**也能访问只有**公网 IPv6** 的自建服务。一个 Worker 靠 `HOST_MAP`
带多个服务。

```
IPv4 客户端 ──► relay4.nicoo.eu.cc        (Worker 自定义域, CF 双栈边缘, IPv4 可进)
                    │  fetch()  Host+SNI=relay.nicoo.eu.cc, 走 IPv6 回源 :8443
                    ▼
             relay.nicoo.eu.cc:8443        (灰云 DNS-only AAAA → 你家公网 IPv6)
                    │
                    ▼  gateway-proxy 按 Host 命中 [[http]] 路由 → 内网上游
```

> 仅适用于 **HTTP / HTTPS / WebSocket**。SSH 等裸 TCP 走不了 Worker。

## 本例映射（改成你的真实值）

| 客户端入口(IPv4 走这里)        | 源站(保持不变, IPv6 直连)      |
| ------------------------------ | ------------------------------ |
| `https://relay4.nicoo.eu.cc`   | `relay.nicoo.eu.cc:8443`       |
| `https://postman4.nicoo.eu.cc` | `postman.nicoo.eu.cc:8443`     |

**这个方案对网关/证书/DDNS 零改动**：`relay.nicoo.eu.cc` / `postman.nicoo.eu.cc`
继续作为源站(灰云 AAAA、原证书、原 8443)对 IPv6 直连；只是给 IPv4 客户端新增
`relay4` / `postman4` 两个走 CF 的入口名。

## 前置检查（决定成败）

Worker 的 `fetch()` 会校验源站 TLS。**用浏览器直接打开
`https://relay.nicoo.eu.cc:8443` 和 `https://postman.nicoo.eu.cc:8443`，
若地址栏是正常小锁、无证书警告，就能用。** 若有警告(staging / 自签)，先解决证书：

- 你现在服务在 **8443**，而 Let's Encrypt 的 **TLS-ALPN-01 校验固定走 443**，
  只监听 8443 拿不到正式证书。二选一：
  1. 让网关**同时监听 443** 专供 ACME 校验；或
  2. 改用 **DNS-01 挑战**(用 Cloudflare API 加 TXT，端口无关，还能签泛域名)——
     当前 `rustls-acme` 走的是 TLS-ALPN-01，切 DNS-01 需要改代码，可让我帮你加。

## 部署步骤

1. **DNS**：确认 `relay.nicoo.eu.cc` / `postman.nicoo.eu.cc` 是 **AAAA + 灰云(DNS-only)**
   指向你家 IPv6（你现有的 DDNS 已在维护）。`relay4` / `postman4` 不用手建，
   `wrangler deploy` 绑定自定义域时会自动创建。
2. **改 `wrangler.toml`**：把 `routes` 和 `HOST_MAP` 里的域名/端口换成你的真实值。
3. **部署**：
   ```bash
   cd worker
   npx wrangler deploy
   ```

## 验证

```bash
# 强制 IPv4 打入口，应拿到与源站一致的响应
curl -4 -I https://relay4.nicoo.eu.cc/
curl -4 -I https://postman4.nicoo.eu.cc/

# 源站仍是 IPv6-only 直连(灰云)
curl -6 -I https://relay.nicoo.eu.cc:8443/
```

## 常见坑

- **502 bad gateway via worker**：源站证书不受信(改证书方案) / 源站 IPv6 当前不可达。
- **502 no origin mapping for host**：`HOST_MAP` 少了这个入口域名。
- **404 no route for host**：源站 host 与网关 `[[http]].domain` 不一致(注意去端口后比较)。
- **回源到 8443 失败**：`wrangler.toml` 缺 `compatibility_flags = ["allow_custom_ports"]`。
- **想让客户端也用 :8443**：Cloudflare 支持 8443，可给入口域名也用 8443 访问；
  默认走标准 443 更省事。

## 想保留原域名(不加 relay4/postman4)？

那就得反过来：把 `relay.nicoo.eu.cc` / `postman.nicoo.eu.cc` 绑到 Worker(对外),
另起 `relay-origin` / `postman-origin` 作源站(灰云 AAAA)。代价是要改网关
`[[http]].domain`、重签这些名字的证书、并更新 `[ddns].records`——改动较大，按需选择。
