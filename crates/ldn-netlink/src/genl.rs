//! generic netlink 头部与 nlctrl（按名字查询 family id 和组播组）。

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::message::{self, NLM_F_ACK, NLM_F_REQUEST};
use crate::nla::{AttrMap, Attrs};

/// nlctrl 自身固定的 family id。
pub const GENL_ID_CTRL: u16 = 16;
/// nlctrl 的协议版本。
pub const CTRL_VERSION: u8 = 2;

/// nlctrl 命令：新 family（查询的回复）。
pub const CTRL_CMD_NEWFAMILY: u8 = 1;
/// nlctrl 命令：查询 family。
pub const CTRL_CMD_GETFAMILY: u8 = 3;

/// family id（u16）。
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
/// family 名字（字符串）。
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
/// 协议版本（u32）。
pub const CTRL_ATTR_VERSION: u16 = 3;
/// 用户头长度（u32）。
pub const CTRL_ATTR_HDRSIZE: u16 = 4;
/// 最大属性号（u32）。
pub const CTRL_ATTR_MAXATTR: u16 = 5;
/// 组播组数组。
pub const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
/// 组播组名字。
pub const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
/// 组播组 id。
pub const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

/// generic netlink 头长度（`cmd u8 | version u8 | reserved u16`）。
pub const GENL_HEADER_LEN: usize = 4;

/// 编码 generic netlink 载荷（genl 头 + 属性）。
///
/// 只支持用户头长度为 0 的 family；nl80211 和 nlctrl 都是如此。
pub fn encode_payload(cmd: u8, version: u8, attrs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(GENL_HEADER_LEN + attrs.len());
    out.extend_from_slice(&[cmd, version, 0, 0]);
    out.extend_from_slice(attrs);
    out
}

/// 解析出的 generic netlink 消息，属性借用自原缓冲区。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenlMessage<'a> {
    /// 命令号。
    pub cmd: u8,
    /// 协议版本。
    pub version: u8,
    /// 属性表。
    pub attrs: AttrMap<'a>,
}

impl<'a> GenlMessage<'a> {
    /// 解析 netlink 消息载荷（用户头长度为 0）。
    pub fn parse(payload: &'a [u8]) -> Result<Self> {
        let header = payload.get(..GENL_HEADER_LEN).ok_or(Error::Truncated)?;
        Ok(Self {
            cmd: header[0],
            version: header[1],
            attrs: AttrMap::parse(&payload[GENL_HEADER_LEN..])?,
        })
    }
}

/// 编码“按名字查询 family”的完整请求消息。
pub fn get_family_request(name: &str, seq: u32, pid: u32) -> Result<Vec<u8>> {
    let mut attrs = Attrs::new();
    attrs.string(CTRL_ATTR_FAMILY_NAME, name);
    let payload = encode_payload(CTRL_CMD_GETFAMILY, CTRL_VERSION, &attrs.finish()?);
    Ok(message::encode(
        GENL_ID_CTRL,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        pid,
        &payload,
    ))
}

/// 一个 generic netlink family 的运行时信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Family {
    /// 内核动态分配的 family id，用作消息类型。
    pub id: u16,
    /// 名字。
    pub name: String,
    /// 协议版本，请求的 genl 头里要带上。
    pub version: u8,
    /// 用户头长度。
    pub hdrsize: u32,
    /// 组播组：名字 -> 组 id。
    pub mcast_groups: BTreeMap<String, u32>,
}

impl Family {
    /// 解析 nlctrl 回复（`CTRL_CMD_NEWFAMILY`）的 genl 载荷。
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let msg = GenlMessage::parse(payload)?;
        let a = &msg.attrs;
        let version = a.u32(CTRL_ATTR_VERSION)?;
        let mut mcast_groups = BTreeMap::new();
        for group in a.nested_array(CTRL_ATTR_MCAST_GROUPS)? {
            mcast_groups.insert(
                group.string(CTRL_ATTR_MCAST_GRP_NAME)?,
                group.u32(CTRL_ATTR_MCAST_GRP_ID)?,
            );
        }
        Ok(Self {
            id: a.u16(CTRL_ATTR_FAMILY_ID)?,
            name: a.string(CTRL_ATTR_FAMILY_NAME)?,
            version: u8::try_from(version)
                .map_err(|_| Error::InvalidAttribute(CTRL_ATTR_VERSION))?,
            hdrsize: a.u32(CTRL_ATTR_HDRSIZE)?,
            mcast_groups,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genl_payload_roundtrip() {
        let mut attrs = Attrs::new();
        attrs.u32(3, 7);
        let payload = encode_payload(65, 1, &attrs.finish().unwrap());
        let msg = GenlMessage::parse(&payload).unwrap();
        assert_eq!((msg.cmd, msg.version), (65, 1));
        assert_eq!(msg.attrs.u32(3), Ok(7));
        assert_eq!(GenlMessage::parse(&[1, 2]), Err(Error::Truncated));
    }

    #[test]
    fn family_requires_id() {
        let mut attrs = Attrs::new();
        attrs
            .string(CTRL_ATTR_FAMILY_NAME, "x")
            .u32(CTRL_ATTR_VERSION, 1)
            .u32(CTRL_ATTR_HDRSIZE, 0);
        let payload = encode_payload(CTRL_CMD_NEWFAMILY, 2, &attrs.finish().unwrap());
        assert_eq!(
            Family::parse(&payload),
            Err(Error::MissingAttribute(CTRL_ATTR_FAMILY_ID))
        );
    }
}
