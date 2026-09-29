//! LDN 协议消息：广播帧、挑战请求/应答、LDN 认证帧、断开帧，以及扫描/建房共用的 [`NetworkInfo`]。
//!
//! 对应 Python 版 `ldn/__init__.py` 中 `NetworkId` 到 `NetworkInfo` 的部分。
//! 本 crate 只做格式与加解密的组合，不做 I/O：广播帧是 802.11 Action 帧的帧体，
//! 认证帧和断开帧经 nl80211 control port（EtherType 0x88B7）收发，挑战请求/应答
//! 嵌在认证帧里。与 Python 的逐字节一致由 `tests/python_parity.rs` 保证。

#![forbid(unsafe_code)]

pub mod advertisement;
pub mod auth;
pub mod common;
pub mod error;
pub mod network;

pub use advertisement::{AdvertiseFormat, AdvertisementFrame, AdvertisementInfo};
pub use auth::{
    AuthPayload, AuthenticationFrame, AuthenticationRequest, AuthenticationResponse,
    ChallengeRequest, ChallengeResponse, DisconnectFrame,
};
pub use common::{NetworkId, ParticipantInfo};
pub use error::{Error, Result};
pub use network::NetworkInfo;
