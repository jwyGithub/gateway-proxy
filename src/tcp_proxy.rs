//! L4 TCP 透传转发。
//!
//! 每条 `[[tcp]]` 路由对应一个独立的监听端口，收到连接后连上游、双向对拷字节，
//! 不理解也不修改任何应用层协议。SSH（2222→22）只是其中一例。
//!
//! 监听 socket 走 [`crate::net::bind_dual_stack`]，因此同一端口同时接受 IPv6
//! 公网连接与 IPv4 本地/局域网连接。

use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::config::TcpRoute;
use crate::net::bind_dual_stack;

/// 运行一条 TCP 路由：在 `route.listen` 上监听并把每条连接透传到 `route.upstream`。
///
/// 正常情况下该函数不返回（一直 `accept`）；只有监听器初始化失败才返回 `Err`。
/// `token` 取消后停止接入并正常返回；连接级 task 挂在 `tracker` 上配合优雅退出。
/// 单条连接的错误只记日志、不影响其它连接，因此适合直接放进独立 task。
pub async fn run(route: TcpRoute, token: CancellationToken, tracker: TaskTracker) -> anyhow::Result<()> {
    let listener = bind_dual_stack(route.listen)
        .with_context(|| format!("TCP 路由绑定端口 {} 失败", route.listen))?;
    info!(listen = route.listen, upstream = %route.upstream, "TCP 路由已启动");

    // upstream 在每条连接里共享只读，用 Arc<str> 避免每次 accept 都 clone String。
    let upstream: Arc<str> = Arc::from(route.upstream.as_str());
    let listen = route.listen;

    loop {
        let (inbound, peer) = tokio::select! {
            _ = token.cancelled() => {
                info!(listen, "TCP 路由停止接入");
                return Ok(());
            }
            res = listener.accept() => match res {
                Ok(pair) => pair,
                Err(e) => {
                    // accept 出错通常是瞬时的（fd 耗尽等），记日志后继续。
                    error!(listen, error = %e, "accept 失败");
                    continue;
                }
            },
        };

        let upstream = upstream.clone();
        tracker.spawn(async move {
            if let Err(e) = handle_conn(inbound, &upstream).await {
                warn!(listen, %peer, upstream = %*upstream, error = %e, "TCP 连接结束（异常）");
            }
        });
    }
}

/// 处理单条 TCP 连接：连上游后在两端之间双向拷贝，直到任意一端关闭。
async fn handle_conn(mut inbound: TcpStream, upstream: &str) -> anyhow::Result<()> {
    let mut outbound = TcpStream::connect(upstream)
        .await
        .with_context(|| format!("连接上游 {upstream} 失败"))?;

    // 交互式协议（SSH 等）关掉 Nagle 更跟手；失败不致命，忽略即可。
    let _ = inbound.set_nodelay(true);
    let _ = outbound.set_nodelay(true);

    let (to_upstream, to_client) = tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .context("双向拷贝出错")?;

    debug!(to_upstream, to_client, "TCP 连接正常关闭");
    Ok(())
}
