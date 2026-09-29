//! nl80211 与 rtnetlink 客户端：在 [`NetlinkSocket`] 之上加上 family 解析和消息解码。

use ldn_netlink::genl::{self, Family, GenlMessage};
use ldn_netlink::nl80211::{Event, Request};
use ldn_netlink::rtnl::RouteRequest;

use crate::error::{Error, Result};
use crate::netlink::NetlinkSocket;

/// nl80211 客户端。
///
/// 构造时加入 `mlme` 组播组，之后连接结果、收到的管理帧、control port 帧等
/// 都通过 [`next_event`](Self::next_event) 取得。事件只有一个消费者：同一个
/// `Nl80211` 上同时只应有一个 STA 或 AP 在读事件。
pub struct Nl80211 {
    sock: NetlinkSocket,
    family: Family,
}

impl Nl80211 {
    /// 打开 generic netlink socket，查询 nl80211 family 并订阅 `mlme` 组。
    ///
    /// 内核没有加载 cfg80211（没有无线网卡）时返回 `ENOENT` 内核错误。
    pub async fn connect() -> Result<Self> {
        let sock = NetlinkSocket::open(libc::NETLINK_GENERIC)?;
        let replies = sock
            .request(|seq, pid| genl::get_family_request("nl80211", seq, pid))
            .await?;
        let reply = replies
            .first()
            .ok_or_else(|| Error::Protocol("empty nlctrl reply".into()))?;
        let family = Family::parse(&reply.payload)?;
        let mlme = *family
            .mcast_groups
            .get("mlme")
            .ok_or_else(|| Error::Protocol("nl80211 has no mlme multicast group".into()))?;
        sock.add_membership(mlme)?;
        Ok(Self { sock, family })
    }

    /// 发送请求并等待 ACK，返回回复消息的 genl 载荷（dump 时有多条）。
    pub async fn request(&self, req: &Request) -> Result<Vec<Vec<u8>>> {
        let replies = self
            .sock
            .request(|seq, pid| req.encode(&self.family, seq, pid))
            .await?;
        Ok(replies
            .into_iter()
            .filter(|m| m.kind == self.family.id)
            .map(|m| m.payload)
            .collect())
    }

    /// 尽力发送、不等回复，供 `Drop` 清理使用。
    pub fn send_nowait(&self, req: &Request) {
        self.sock
            .send_nowait(|seq, pid| req.encode(&self.family, seq, pid));
    }

    /// 等待下一个 nl80211 事件；格式有误的通知记日志后跳过。
    pub async fn next_event(&self) -> Result<Event> {
        loop {
            let msg = self.sock.next_event().await?;
            if msg.kind != self.family.id {
                continue;
            }
            match GenlMessage::parse(&msg.payload).and_then(|g| Event::parse(&g)) {
                Ok(event) => return Ok(event),
                Err(e) => log::debug!("ignoring malformed nl80211 event: {e}"),
            }
        }
    }
}

/// rtnetlink 客户端。
pub struct Route {
    sock: NetlinkSocket,
}

impl Route {
    /// 打开 rtnetlink socket。
    pub fn connect() -> Result<Self> {
        Ok(Self {
            sock: NetlinkSocket::open(libc::NETLINK_ROUTE)?,
        })
    }

    /// 发送请求并等待 ACK。
    pub async fn request(&self, req: &RouteRequest) -> Result<()> {
        self.sock
            .request(|seq, pid| req.encode(seq, pid))
            .await
            .map(drop)
    }
}
