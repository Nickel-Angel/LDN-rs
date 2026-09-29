//! LDN 的 WLAN 接口层（tokio）：nl80211 / rtnetlink 客户端、monitor 口、TAP 口、
//! STA 与 AP 接口。对应 Python 版 `ldn/wlan.py` 里 `Interface` 及其子类和 `Factory`。
//!
//! - [`ap`]：AP 管理帧状态机，纯逻辑，可不接网卡测试。
//! - [`client`]：nl80211 / rtnetlink 请求-应答与事件。
//! - [`interface`]：各类接口与 [`Factory`]，真正创建网卡接口，需要 root。
//! - [`netlink`]：底层异步 netlink socket。
//!
//! 所有系统调用集中在私有的 `sys` 模块，它是整个 workspace 唯一含 `unsafe` 的地方。

pub mod ap;
pub mod client;
pub mod error;
pub mod interface;
pub mod netlink;
mod sys;

pub use error::{Error, Result};
pub use interface::{AccessPoint, AccessPointEvent, Factory, Monitor, Station, StationEvent, Tap};
