//! 网络监听辅助。
//!
//! 对外入口是 IPv6 公网，但我们把监听 socket 建成"双栈"（绑定 `[::]` 且关闭
//! `IPV6_V6ONLY`），这样同一个 socket 既能接受 IPv6 公网连接，也能接受 IPv4
//! 的本机 / 局域网连接（方便本地联调）。这对 Windows 尤其重要：Windows 默认
//! `IPV6_V6ONLY=1`，若不显式关闭则纯 IPv6 socket 收不到 IPv4 连接。

use std::net::{Ipv6Addr, SocketAddr};

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

/// 在 `[::]:port` 上建立一个双栈 TCP 监听器。
pub fn bind_dual_stack(port: u16) -> anyhow::Result<TcpListener> {
    let addr: SocketAddr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));

    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
        .context("创建 IPv6 socket 失败")?;

    // 关键：关闭 v6only，接受 IPv4-mapped 地址（双栈）。
    socket
        .set_only_v6(false)
        .context("关闭 IPV6_V6ONLY 失败")?;

    socket.set_nonblocking(true)?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("绑定 [::]:{port} 失败（端口被占用或权限不足？）"))?;
    socket.listen(1024).context("listen 失败")?;

    let std_listener: std::net::TcpListener = socket.into();
    let listener = TcpListener::from_std(std_listener).context("转换为 tokio TcpListener 失败")?;
    Ok(listener)
}
