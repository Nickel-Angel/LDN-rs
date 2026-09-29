//! ldn 高层 API 的错误类型。

use std::fmt;

/// 扫描、加入、建房过程中的错误。
#[derive(Debug)]
pub enum Error {
    /// 网卡/内核操作失败。
    Wlan(ldn_wlan::Error),
    /// LDN 帧编解码失败。
    Proto(ldn_proto::Error),
    /// 密钥派生失败（通常是 prod.keys 缺少所需密钥）。
    Crypto(ldn_crypto::Error),
    /// 802.11 帧编解码失败。
    Wire(ldn_wire::Error),
    /// 参数不合法，附带说明。
    InvalidParam(&'static str),
    /// 主机拒绝了认证，附带 LDN 认证状态码（见 `ldn_proto::auth::status`）。
    AuthenticationRejected(u8),
    /// 三次认证请求都没有收到应答（常见原因：房间密码不对）。
    AuthenticationTimeout,
    /// 连接过程中或连接后出现的异常，例如被主机解除关联、收到不兼容的广播帧。
    Connection(String),
}

/// 本 crate 统一使用的 `Result` 别名。
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wlan(e) => write!(f, "{e}"),
            Self::Proto(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::InvalidParam(what) => write!(f, "invalid parameter: {what}"),
            Self::AuthenticationRejected(status) => {
                write!(f, "authentication failed with status {status}")
            }
            Self::AuthenticationTimeout => {
                write!(f, "authentication timeout (password may be wrong)")
            }
            Self::Connection(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

macro_rules! from_error {
    ($variant:ident, $ty:ty) => {
        impl From<$ty> for Error {
            fn from(e: $ty) -> Self {
                Self::$variant(e)
            }
        }
    };
}

from_error!(Wlan, ldn_wlan::Error);
from_error!(Proto, ldn_proto::Error);
from_error!(Crypto, ldn_crypto::Error);
from_error!(Wire, ldn_wire::Error);
