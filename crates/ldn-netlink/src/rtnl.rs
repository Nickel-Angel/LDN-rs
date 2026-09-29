//! rtnetlink 请求：拉起接口、改 MAC、加 IPv4 地址、加删静态邻居。
//!
//! 对应 python-netlink 的 `route.RouteController` 与 wlan.py `Interface` 里的调用。

use std::net::Ipv4Addr;

use ldn_wire::MacAddress;

use crate::error::Result;
use crate::message::{self, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use crate::nla::Attrs;

/// 新建/修改链路。
pub const RTM_NEWLINK: u16 = 16;
/// 新增地址。
pub const RTM_NEWADDR: u16 = 20;
/// 新增邻居。
pub const RTM_NEWNEIGH: u16 = 28;
/// 删除邻居。
pub const RTM_DELNEIGH: u16 = 29;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const IFF_UP: u32 = 1;
const IFLA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_BROADCAST: u16 = 4;
const IFA_F_PERMANENT: u8 = 0x80;
const RT_SCOPE_UNIVERSE: u8 = 0;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NUD_PERMANENT: u16 = 0x80;

/// 一条 rtnetlink 请求：消息类型、额外标志和已编码的载荷（固定头 + 属性）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRequest {
    /// 消息类型（`RTM_*`）。
    pub kind: u16,
    /// 除 `NLM_F_REQUEST | NLM_F_ACK` 以外的标志。
    pub flags: u16,
    header: Vec<u8>,
    attrs: Attrs,
}

impl RouteRequest {
    /// 编码成完整的 netlink 消息，自动加上 `NLM_F_REQUEST | NLM_F_ACK`。
    pub fn encode(&self, seq: u32, pid: u32) -> Result<Vec<u8>> {
        let mut payload = self.header.clone();
        payload.extend(self.attrs.clone().finish()?);
        Ok(message::encode(
            self.kind,
            self.flags | NLM_F_REQUEST | NLM_F_ACK,
            seq,
            pid,
            &payload,
        ))
    }
}

/// `ifinfomsg`：family, pad, type, index, flags, change。
fn link_request(ifindex: u32, flags: u32, change: u32, attrs: Attrs) -> RouteRequest {
    let mut header = vec![AF_UNSPEC, 0, 0, 0];
    header.extend_from_slice(&ifindex.to_ne_bytes());
    header.extend_from_slice(&flags.to_ne_bytes());
    header.extend_from_slice(&change.to_ne_bytes());
    RouteRequest {
        kind: RTM_NEWLINK,
        flags: 0,
        header,
        attrs,
    }
}

/// 把接口置为 up。
pub fn set_link_up(ifindex: u32) -> RouteRequest {
    link_request(ifindex, IFF_UP, IFF_UP, Attrs::new())
}

/// 修改接口 MAC 地址（TAP 口要与 monitor 口地址一致）。
pub fn set_link_address(ifindex: u32, mac: MacAddress) -> RouteRequest {
    let mut attrs = Attrs::new();
    attrs.bytes(IFLA_ADDRESS, &mac.octets());
    link_request(ifindex, 0, 0, attrs)
}

/// 给接口添加永久 IPv4 地址；地址已存在时内核返回 `EEXIST`。
pub fn add_ipv4_address(
    ifindex: u32,
    local: Ipv4Addr,
    broadcast: Ipv4Addr,
    prefix: u8,
) -> RouteRequest {
    let mut header = vec![AF_INET, prefix, IFA_F_PERMANENT, RT_SCOPE_UNIVERSE];
    header.extend_from_slice(&ifindex.to_ne_bytes());
    let mut attrs = Attrs::new();
    attrs
        .bytes(IFA_LOCAL, &local.octets())
        .bytes(IFA_BROADCAST, &broadcast.octets());
    RouteRequest {
        kind: RTM_NEWADDR,
        flags: NLM_F_CREATE | NLM_F_EXCL,
        header,
        attrs,
    }
}

/// `ndmsg`：family, pad×3, ifindex, state, flags, type。
fn neighbor_request(
    kind: u16,
    flags: u16,
    ifindex: u32,
    ip: Ipv4Addr,
    mac: MacAddress,
) -> RouteRequest {
    let mut header = vec![AF_INET, 0, 0, 0];
    header.extend_from_slice(&ifindex.to_ne_bytes());
    header.extend_from_slice(&NUD_PERMANENT.to_ne_bytes());
    header.extend_from_slice(&[0, 0]);
    let mut attrs = Attrs::new();
    attrs
        .bytes(NDA_DST, &ip.octets())
        .bytes(NDA_LLADDR, &mac.octets());
    RouteRequest {
        kind,
        flags,
        header,
        attrs,
    }
}

/// 添加永久 ARP 邻居（成员加入时，省去 ARP 解析）。
pub fn add_neighbor(ifindex: u32, ip: Ipv4Addr, mac: MacAddress) -> RouteRequest {
    neighbor_request(RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, ifindex, ip, mac)
}

/// 删除邻居（成员离开时）。
pub fn remove_neighbor(ifindex: u32, ip: Ipv4Addr, mac: MacAddress) -> RouteRequest {
    neighbor_request(RTM_DELNEIGH, 0, ifindex, ip, mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_sizes() {
        // ifinfomsg 16、ifaddrmsg 8、ndmsg 12 字节。
        assert_eq!(set_link_up(1).header.len(), 16);
        let ip = Ipv4Addr::new(169, 254, 1, 1);
        assert_eq!(add_ipv4_address(1, ip, ip, 24).header.len(), 8);
        assert_eq!(add_neighbor(1, ip, MacAddress::ZERO).header.len(), 12);
    }
}
