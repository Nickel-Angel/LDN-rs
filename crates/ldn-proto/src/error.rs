//! ldn-proto 的错误类型。

use std::fmt;

/// 协议消息编解码错误。
///
/// 解码错误意味着收到了畸形、不属于 LDN 或密钥不对的帧，调用方（扫描循环、认证流程）
/// 一般丢弃该帧继续；编码错误意味着调用方给了超出协议字段范围的值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 底层读写越界、填充不为 0 等。
    Wire(ldn_wire::Error),
    /// 密钥派生或加解密失败（包括认证标签不匹配）。
    Crypto(ldn_crypto::Error),
    /// 帧头标识不对：不是 Nintendo 的 vendor-specific 帧或帧类型不符。
    NotLdnFrame(&'static str),
    /// 字段取值不合法（版本号、格式、长度字段等），附带说明。
    Invalid(&'static str),
    /// 编码时字段超出协议允许的长度，例如名字超过 32 字节。
    TooLong {
        /// 字段名。
        field: &'static str,
        /// 实际长度。
        len: usize,
        /// 上限。
        max: usize,
    },
    /// 广播帧 SHA-256 校验失败，或挑战 HMAC 不对。
    IntegrityCheckFailed,
}

/// 本 crate 统一使用的 `Result` 别名。
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::NotLdnFrame(what) => write!(f, "not an LDN {what}"),
            Self::Invalid(what) => write!(f, "invalid LDN frame: {what}"),
            Self::TooLong { field, len, max } => {
                write!(f, "field `{field}` is too long ({len} > {max})")
            }
            Self::IntegrityCheckFailed => write!(f, "integrity check failed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ldn_wire::Error> for Error {
    fn from(e: ldn_wire::Error) -> Self {
        Self::Wire(e)
    }
}

impl From<ldn_crypto::Error> for Error {
    fn from(e: ldn_crypto::Error) -> Self {
        // 标签不匹配归入完整性错误，调用方不必区分是 GCM tag 还是 SHA/HMAC。
        match e {
            ldn_crypto::Error::AuthenticationFailed => Self::IntegrityCheckFailed,
            other => Self::Crypto(other),
        }
    }
}
