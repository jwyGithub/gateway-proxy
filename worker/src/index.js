/**
 * Cloudflare Worker：让公网 IPv4 客户端也能访问只有公网 IPv6 的自建服务
 * （gateway-proxy）。支持多个服务，靠 HOST_MAP 映射表分发。
 *
 * 链路：
 *   IPv4 客户端 -> Worker 入口域名(CF 双栈边缘) -> fetch() 走 IPv6 回源到源站 host:port
 *
 * 为什么可行：Cloudflare 边缘是双栈(IPv4+IPv6)，Worker 的 fetch() 由边缘发起，
 * 边缘能用 IPv6 直连只有 AAAA 记录的源站。
 *
 * 关键约束（务必满足，否则必挂）：
 *   1. 入口域名 与 源站域名 必须【不同】，否则 Worker 会 fetch 到自己（死循环）。
 *   2. 映射到的源站 host 必须与网关 config.toml 里某条 [[http]].domain 一致
 *      —— 网关取 Host(去端口、小写)查路由表，不匹配直接 404。
 *   3. 源站证书必须“公开受信”：浏览器直接打开 https://源站:端口 不报证书警告。
 *      Worker 的 fetch() 会校验 TLS，staging / 自签证书会握手失败(502)。
 *   4. 回源用了非标端口(如 8443)时，wrangler.toml 里要开 allow_custom_ports 标志。
 */

/** 逐跳(hop-by-hop)头：不透传给源站；注意保留 upgrade，WebSocket 要用。 */
const HOP_BY_HOP = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
];

export default {
  /**
   * @param {Request} request
   * @param {{ HOST_MAP?: string }} env  HOST_MAP 是 JSON：{ 入口host: "源站host[:port]" }
   */
  async fetch(request, env) {
    let map;
    try {
      map = JSON.parse(env.HOST_MAP || "{}");
    } catch {
      return new Response("worker misconfigured: HOST_MAP 不是合法 JSON", { status: 500 });
    }

    const inUrl = new URL(request.url);
    const origin = map[inUrl.hostname.toLowerCase()];
    if (!origin) {
      return new Response(`no origin mapping for host: ${inUrl.hostname}`, { status: 502 });
    }

    // origin 形如 "relay.nicoo.eu.cc:8443"；协议固定 https(网关只收 HTTPS)。
    const outUrl = new URL(inUrl.pathname + inUrl.search, `https://${origin}`);

    // 复制请求头，删掉 Host —— 让 fetch 按目标 URL 自动把 Host / SNI 设成源站，
    // 网关才能按 Host 命中路由，TLS 才能用对证书握手。
    const headers = new Headers(request.headers);
    headers.delete("host");
    for (const h of HOP_BY_HOP) headers.delete(h);

    // 透传真实客户端 IP(否则网关的 X-Forwarded-For 记的是 CF 出口 IP)。
    const clientIp = request.headers.get("CF-Connecting-IP");
    if (clientIp) headers.set("X-Forwarded-For", clientIp);
    headers.set("X-Forwarded-Proto", "https");
    headers.set("X-Forwarded-Host", inUrl.host);

    const outReq = new Request(outUrl, {
      method: request.method,
      headers,
      body: request.body,
      redirect: "manual", // 3xx 交给客户端处理，别让 Worker 吞掉跳转
    });

    try {
      // WebSocket 升级请求也走这里：Workers 原生识别 Upgrade 头，
      // 源站回 101 后 CF 自动把双向隧道接起来，无需额外代码。
      return await fetch(outReq);
    } catch (err) {
      return new Response(`bad gateway via worker: ${err}`, { status: 502 });
    }
  },
};
