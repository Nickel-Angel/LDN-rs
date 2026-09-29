//! netlink 编解码错误。

use std::fmt;

/// 编解码 netlink 消息时的错误。
///
/// 这些都是“字节不合格式”的错误；内核返回的 `NLMSG_ERROR` 不在这里，
/// 而是由 [`crate::message::ErrorMessage`] 表示，交给 I/O 层转换成调用方的错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 消息头或属性头声明的长度超出了缓冲区，或短于头部本身。
    Truncated,
    /// 单个属性的值超过 65531 字节，放不进 16 位长度字段。
    AttributeTooLong {
        /// 属性类型。
        kind: u16,
        /// 值的长度。
        len: usize,
    },
    /// 必需的属性不存在。
    MissingAttribute(u16),
    /// 属性值长度与期望的类型不符（例如 u32 属性不是 4 字节）。
    InvalidAttribute(u16),
}

/// 本 crate 统一使用的 `Result` 别名。
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated netlink message or attribute"),
            Self::AttributeTooLong { kind, len } => {
                write!(f, "netlink attribute {kind} is too long ({len} bytes)")
            }
            Self::MissingAttribute(kind) => write!(f, "missing netlink attribute {kind}"),
            Self::InvalidAttribute(kind) => write!(f, "invalid value for netlink attribute {kind}"),
        }
    }
}

impl std::error::Error for Error {}
