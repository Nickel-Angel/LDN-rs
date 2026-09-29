//! 异步 netlink socket：按序号把回复分发给等待中的请求，序号为 0 的通知放进事件队列。
//!
//! 对应 python-netlink 的 `NetlinkSocket`。一个后台读任务独占接收方向；
//! 发送方向由各请求直接写 socket（netlink 数据报的写入是原子的，不需要锁）。

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ldn_netlink::message::{ErrorMessage, NLMSG_DONE, NLMSG_ERROR, parse_messages};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::sys;

/// 收到的一条 netlink 消息（拥有所有权的版本）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// 消息类型。
    pub kind: u16,
    /// 标志位。
    pub flags: u16,
    /// 序号，通知为 0。
    pub seq: u32,
    /// 头部之后的载荷。
    pub payload: Vec<u8>,
}

type Reply = Result<Vec<Message>>;

struct Pending {
    parts: Vec<Message>,
    done: oneshot::Sender<Reply>,
}

struct Inner {
    fd: AsyncFd<OwnedFd>,
    pid: u32,
    next_seq: AtomicU32,
    pending: Mutex<HashMap<u32, Pending>>,
}

/// 异步 netlink socket。
///
/// 必须在 tokio 运行时内创建（构造时会 spawn 读任务）；drop 时读任务被取消，
/// 仍在等待的请求收到 [`Error::Closed`]。
pub struct NetlinkSocket {
    inner: Arc<Inner>,
    events: tokio::sync::Mutex<mpsc::UnboundedReceiver<Message>>,
    reader: JoinHandle<()>,
}

impl NetlinkSocket {
    /// 打开给定协议（`libc::NETLINK_GENERIC` / `libc::NETLINK_ROUTE`）的 socket。
    pub fn open(protocol: libc::c_int) -> Result<Self> {
        let (fd, pid) = sys::netlink_socket(protocol)?;
        let inner = Arc::new(Inner {
            fd: AsyncFd::new(fd)?,
            pid,
            // 与 python-netlink 一样从 1 开始；0 留给内核通知。
            next_seq: AtomicU32::new(1),
            pending: Mutex::new(HashMap::new()),
        });
        let (tx, rx) = mpsc::unbounded_channel();
        let reader = tokio::spawn(read_loop(Arc::clone(&inner), tx));
        Ok(Self {
            inner,
            events: tokio::sync::Mutex::new(rx),
            reader,
        })
    }

    /// 内核分配的端口号，写进请求头的 `nlmsg_pid`。
    pub fn pid(&self) -> u32 {
        self.inner.pid
    }

    /// 加入组播组，之后该组的通知会进入 [`next_event`](Self::next_event)。
    pub fn add_membership(&self, group: u32) -> Result<()> {
        Ok(sys::add_membership(self.inner.fd.as_raw_fd(), group)?)
    }

    /// 发送一条请求并等待 ACK / dump 结束，返回期间收到的所有回复消息。
    ///
    /// `encode` 接收分配好的序号和端口号，返回完整消息字节。请求必须带
    /// `NLM_F_ACK`，否则永远等不到结束标志。内核返回错误时得到 [`Error::Kernel`]。
    pub async fn request(
        &self,
        encode: impl FnOnce(u32, u32) -> ldn_netlink::Result<Vec<u8>>,
    ) -> Reply {
        let seq = self.inner.next_seq.fetch_add(1, Ordering::Relaxed);
        let data = encode(seq, self.inner.pid)?;
        let (done, rx) = oneshot::channel();
        // 先登记再发送，避免回复先于登记到达。
        self.inner.pending.lock().unwrap().insert(
            seq,
            Pending {
                parts: Vec::new(),
                done,
            },
        );
        if let Err(e) = self.send(&data).await {
            self.inner.pending.lock().unwrap().remove(&seq);
            return Err(e);
        }
        rx.await.unwrap_or(Err(Error::Closed))
    }

    /// 发送一条请求但不等待回复；只能尝试一次，socket 忙时直接放弃。
    ///
    /// 供 `Drop` 里的尽力清理使用（例如删除接口），那里不能 await。
    /// 内核的 ACK 会作为“无人等待的回复”被读任务丢弃。
    pub fn send_nowait(&self, encode: impl FnOnce(u32, u32) -> ldn_netlink::Result<Vec<u8>>) {
        let seq = self.inner.next_seq.fetch_add(1, Ordering::Relaxed);
        match encode(seq, self.inner.pid) {
            Ok(data) => {
                if let Err(e) = sys::write(self.inner.fd.as_raw_fd(), &data) {
                    log::warn!("best-effort netlink request {seq} failed: {e}");
                }
            }
            Err(e) => log::warn!("could not encode best-effort netlink request: {e}"),
        }
    }

    /// 等待下一条内核通知（序号为 0 的消息）。
    ///
    /// 读任务退出后返回 [`Error::Closed`]。同一时刻只应有一个任务在等待事件。
    pub async fn next_event(&self) -> Result<Message> {
        self.events.lock().await.recv().await.ok_or(Error::Closed)
    }

    async fn send(&self, data: &[u8]) -> Result<()> {
        let fd = &self.inner.fd;
        let n = fd
            .async_io(Interest::WRITABLE, |fd| sys::write(fd.as_raw_fd(), data))
            .await?;
        if n != data.len() {
            return Err(Error::Protocol(format!(
                "short netlink write: {n} of {} bytes",
                data.len()
            )));
        }
        Ok(())
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// 后台读循环：解析每个数据报，按序号分发。socket 读错误时让所有等待者失败并退出。
async fn read_loop(inner: Arc<Inner>, events: mpsc::UnboundedSender<Message>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match inner
            .fd
            .async_io(Interest::READABLE, |fd| sys::read(fd.as_raw_fd(), &mut buf))
            .await
        {
            Ok(n) => n,
            Err(e) => {
                log::error!("netlink socket read failed: {e}");
                break;
            }
        };
        let messages = match parse_messages(&buf[..n]) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("dropping malformed netlink datagram: {e}");
                continue;
            }
        };
        for m in messages {
            dispatch(
                &inner,
                &events,
                Message {
                    kind: m.kind,
                    flags: m.flags,
                    seq: m.seq,
                    payload: m.payload.to_vec(),
                },
            );
        }
    }
    // 退出时唤醒所有等待者，而不是让它们永远挂起。
    for (_, p) in inner.pending.lock().unwrap().drain() {
        let _ = p.done.send(Err(Error::Closed));
    }
}

fn dispatch(inner: &Inner, events: &mpsc::UnboundedSender<Message>, msg: Message) {
    if msg.kind == NLMSG_ERROR || msg.kind == NLMSG_DONE {
        let Some(p) = inner.pending.lock().unwrap().remove(&msg.seq) else {
            // 新内核会在 dump 的 DONE 之后再补一个 ACK；send_nowait 的 ACK 也走到这里。
            log::debug!("ignoring ack for unknown sequence {}", msg.seq);
            return;
        };
        let reply = match ErrorMessage::parse(msg.flags, &msg.payload) {
            Ok(e) if e.code != 0 && msg.kind == NLMSG_ERROR => Err(Error::Kernel {
                errno: -e.code,
                message: e.message,
            }),
            Ok(_) => Ok(p.parts),
            Err(e) => Err(e.into()),
        };
        let _ = p.done.send(reply);
    } else if msg.seq == 0 {
        let _ = events.send(msg);
    } else if let Some(p) = inner.pending.lock().unwrap().get_mut(&msg.seq) {
        p.parts.push(msg);
    } else {
        log::warn!(
            "received netlink message with unexpected sequence {}",
            msg.seq
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldn_netlink::rtnl;

    // 以下测试只用 NETLINK_ROUTE 上不需要特权的只读/必失败请求，与真实内核交互。

    #[tokio::test]
    async fn kernel_error_is_reported() {
        let sock = NetlinkSocket::open(libc::NETLINK_ROUTE).unwrap();
        // 删除一个不存在的邻居：普通用户得到 EPERM，root 得到 ENOENT 等，总之是内核错误。
        let req = rtnl::remove_neighbor(
            u32::MAX,
            "169.254.0.1".parse().unwrap(),
            ldn_wire::MacAddress::ZERO,
        );
        let err = sock
            .request(|seq, pid| req.encode(seq, pid))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Kernel { .. }), "{err:?}");
        assert!(err.errno().is_some());
    }

    #[tokio::test]
    async fn sequences_are_independent() {
        let sock = NetlinkSocket::open(libc::NETLINK_ROUTE).unwrap();
        let req = rtnl::remove_neighbor(
            u32::MAX,
            "169.254.0.1".parse().unwrap(),
            ldn_wire::MacAddress::ZERO,
        );
        let (a, b) = tokio::join!(
            sock.request(|seq, pid| req.encode(seq, pid)),
            sock.request(|seq, pid| req.encode(seq, pid)),
        );
        assert!(a.is_err() && b.is_err());
        assert!(sock.inner.pending.lock().unwrap().is_empty());
    }
}
