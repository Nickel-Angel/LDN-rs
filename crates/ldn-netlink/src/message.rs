//! netlink 消息帧：16 字节 `nlmsghdr` + 载荷，以及内核的 ACK/错误消息。

use crate::error::{Error, Result};
use crate::nla::{AttrMap, align4};

/// 这是一条请求。
pub const NLM_F_REQUEST: u16 = 0x1;
/// 多部分消息（dump 回复）。
pub const NLM_F_MULTI: u16 = 0x2;
/// 要求内核回 ACK。
pub const NLM_F_ACK: u16 = 0x4;
/// dump 请求（`NLM_F_ROOT | NLM_F_MATCH`）。
pub const NLM_F_DUMP: u16 = 0x300;
/// 新建对象（rtnetlink）。
pub const NLM_F_CREATE: u16 = 0x400;
/// 对象已存在时报错（rtnetlink）。
pub const NLM_F_EXCL: u16 = 0x200;
/// 错误消息里回显的原请求被截成了只有头部（设置了 `NETLINK_CAP_ACK`）。
pub const NLM_F_CAPPED: u16 = 0x100;
/// 错误消息后面附带扩展 ACK 属性（设置了 `NETLINK_EXT_ACK`）。
pub const NLM_F_ACK_TLVS: u16 = 0x200;

/// 空操作消息类型。
pub const NLMSG_NOOP: u16 = 1;
/// ACK / 错误消息类型。
pub const NLMSG_ERROR: u16 = 2;
/// dump 结束消息类型。
pub const NLMSG_DONE: u16 = 3;

/// 扩展 ACK 属性：人类可读的错误说明。
pub const NLMSGERR_ATTR_MSG: u16 = 1;

/// `nlmsghdr` 的长度。
pub const HEADER_LEN: usize = 16;

/// 编码一条 netlink 消息。
///
/// `flags` 原样写入，调用方负责加上 [`NLM_F_REQUEST`] / [`NLM_F_ACK`]。
/// 载荷超过 u32 可表示的长度时 panic（netlink 消息远到不了这个量级）。
pub fn encode(kind: u16, flags: u16, seq: u32, pid: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(HEADER_LEN + payload.len()).expect("netlink message too large");
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&pid.to_ne_bytes());
    out.extend_from_slice(payload);
    out
}

/// 从缓冲区中拆出的一条消息，载荷借用自原缓冲区。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawMessage<'a> {
    /// 消息类型（generic netlink 下是 family id）。
    pub kind: u16,
    /// 标志位。
    pub flags: u16,
    /// 序号；内核主动推送的通知为 0。
    pub seq: u32,
    /// 端口号。
    pub pid: u32,
    /// 头部之后的载荷。
    pub payload: &'a [u8],
}

/// 把一次 `recv` 得到的数据拆成若干条消息。
///
/// 任何一条的长度字段越界都返回 [`Error::Truncated`]，调用方应丢弃整个数据报。
pub fn parse_messages(data: &[u8]) -> Result<Vec<RawMessage<'_>>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let header = data.get(pos..pos + HEADER_LEN).ok_or(Error::Truncated)?;
        let word = |i: usize| u32::from_ne_bytes(header[i..i + 4].try_into().unwrap());
        let half = |i: usize| u16::from_ne_bytes(header[i..i + 2].try_into().unwrap());
        let len = word(0) as usize;
        if len < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let payload = data
            .get(pos + HEADER_LEN..pos + len)
            .ok_or(Error::Truncated)?;
        out.push(RawMessage {
            kind: half(4),
            flags: half(6),
            seq: word(8),
            pid: word(12),
            payload,
        });
        pos += align4(len);
    }
    Ok(out)
}

/// `NLMSG_ERROR` / `NLMSG_DONE` 消息的内容。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMessage {
    /// 0 表示成功（即 ACK），否则是负的 errno。
    pub code: i32,
    /// 扩展 ACK 附带的错误说明，内核没给时为 `None`。
    pub message: Option<String>,
}

impl ErrorMessage {
    /// 解析 `NLMSG_ERROR`（或 dump 结束时的 `NLMSG_DONE`）消息的载荷。
    ///
    /// 载荷格式为 `i32 错误码 | 原请求（设置 CAP_ACK 时只有 16 字节头）| 扩展 ACK 属性`。
    /// 扩展属性本身格式有误时忽略它，不影响错误码。
    pub fn parse(flags: u16, payload: &[u8]) -> Result<Self> {
        let code_bytes: [u8; 4] = payload
            .get(..4)
            .ok_or(Error::Truncated)?
            .try_into()
            .unwrap();
        let code = i32::from_ne_bytes(code_bytes);
        let mut message = None;
        if flags & NLM_F_ACK_TLVS != 0 {
            let echoed = if flags & NLM_F_CAPPED != 0 {
                HEADER_LEN
            } else {
                // 未截断时原请求整条回显，长度在它自己的头部里。
                payload
                    .get(4..8)
                    .map(|b| align4(u32::from_ne_bytes(b.try_into().unwrap()) as usize))
                    .unwrap_or(HEADER_LEN)
            };
            if let Some(tlvs) = payload.get(4 + echoed..) {
                message = AttrMap::parse(tlvs)
                    .ok()
                    .and_then(|m| m.string(NLMSGERR_ATTR_MSG).ok());
            }
        }
        Ok(Self { code, message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nla::Attrs;

    #[test]
    fn encode_and_parse_roundtrip() {
        let mut data = encode(0x22, NLM_F_REQUEST | NLM_F_ACK, 3, 4242, &[1, 2, 3]);
        data.push(0); // 第一条消息补齐到 4 字节
        data.extend(encode(NLMSG_DONE, NLM_F_MULTI, 3, 4242, &[0; 4]));
        let msgs = parse_messages(&data).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(
            msgs[0],
            RawMessage {
                kind: 0x22,
                flags: 5,
                seq: 3,
                pid: 4242,
                payload: &[1, 2, 3]
            }
        );
        assert_eq!(msgs[1].kind, NLMSG_DONE);
    }

    #[test]
    fn bad_length_is_rejected() {
        let mut data = encode(1, 0, 0, 0, &[]);
        data[0] = 40;
        assert_eq!(parse_messages(&data), Err(Error::Truncated));
        data[0] = 8;
        assert_eq!(parse_messages(&data), Err(Error::Truncated));
        assert_eq!(parse_messages(&[0; 10]), Err(Error::Truncated));
    }

    #[test]
    fn error_with_extended_ack_message() {
        let mut tlvs = Attrs::new();
        tlvs.string(NLMSGERR_ATTR_MSG, "invalid frequency");
        let mut payload = (-22i32).to_ne_bytes().to_vec();
        payload.extend(encode(0x22, 5, 9, 1, &[])); // 被截断的原请求头
        payload.extend(tlvs.finish().unwrap());

        let err = ErrorMessage::parse(NLM_F_CAPPED | NLM_F_ACK_TLVS, &payload).unwrap();
        assert_eq!(
            err,
            ErrorMessage {
                code: -22,
                message: Some("invalid frequency".into())
            }
        );
    }

    #[test]
    fn uncapped_error_skips_full_echo() {
        let mut tlvs = Attrs::new();
        tlvs.string(NLMSGERR_ATTR_MSG, "busy");
        let mut payload = (-16i32).to_ne_bytes().to_vec();
        payload.extend(encode(0x22, 5, 9, 1, &[0xAA; 8])); // 完整回显 24 字节
        payload.extend(tlvs.finish().unwrap());
        let err = ErrorMessage::parse(NLM_F_ACK_TLVS, &payload).unwrap();
        assert_eq!(err.message.as_deref(), Some("busy"));
    }

    #[test]
    fn plain_ack() {
        let err = ErrorMessage::parse(0, &0i32.to_ne_bytes()).unwrap();
        assert_eq!(
            err,
            ErrorMessage {
                code: 0,
                message: None
            }
        );
        assert_eq!(ErrorMessage::parse(0, &[0, 0]), Err(Error::Truncated));
    }
}
