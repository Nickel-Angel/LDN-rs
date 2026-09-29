//! LDN 用到的 netlink 协议的纯编解码层：netlink 消息帧、属性（NLA）、generic netlink
//! 与 nlctrl、nl80211 和 rtnetlink 请求。
//!
//! 本 crate 不做任何 I/O：请求构造成 [`nl80211::Request`] / [`rtnl::RouteRequest`]，
//! 由调用方给定序号和端口号后编码成字节；收到的字节用 [`message::parse_messages`]
//! 拆开再按协议解码。这样它可以不接内核、逐字节与 Python 版（python-netlink）对拍，
//! 见 `tests/python_parity.rs`。
//!
//! 属性值按本机字节序编码，与内核和 python-netlink 一致；目前只在 Linux 小端机上验证过。

#![forbid(unsafe_code)]

pub mod error;
pub mod genl;
pub mod message;
pub mod nl80211;
pub mod nla;
pub mod rtnl;

pub use error::{Error, Result};
