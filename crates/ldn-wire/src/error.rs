//! 编解码错误类型。

use std::fmt;

/// 编解码过程中可能出现的所有错误。
///
/// 解码错误一般意味着收到了畸形或不认识的帧，调用方（例如监听循环）通常应丢弃该帧继续处理，
/// 而不是中止整个网络会话；编码错误意味着调用方给了超出协议字段范围的值，属于调用方 bug。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 读取或定位越过了输入缓冲区末尾。
    UnexpectedEof,
    /// 填充字节不是预期的 0。
    InvalidPadding,
    /// MAC 地址文本或字节长度不合法，附带原始输入便于排查。
    InvalidMacAddress(String),
    /// Frame Control 里的协议版本号不是 0。
    UnsupportedMacVersion,
    /// 帧类型/子类型与要解码的结构体不符。
    UnexpectedFrameType {
        /// 期望的帧名称，例如 `"beacon"`。
        expected: &'static str,
    },
    /// Radiotap 头不合法，附带具体原因。
    InvalidRadiotap(&'static str),
    /// 单个 IE 的内容超过 255 字节，无法放进 1 字节长度字段。
    ElementTooLong {
        /// 元素 ID。
        id: u8,
        /// 实际内容长度。
        len: usize,
    },
    /// 数据帧载荷缺少 `AA AA 03` 开头的 SNAP/LLC 头。
    MissingSnapHeader,
    /// 受保护的数据帧没有置 Ext IV 位，不是 CCMP 格式。
    MissingExtIv,
    /// 编码时字段值超出了协议字段的位宽。
    FieldOutOfRange {
        /// 字段名。
        field: &'static str,
    },
}

/// 本 crate 统一使用的 `Result` 别名。
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of buffer"),
            Self::InvalidPadding => write!(f, "incorrect padding"),
            Self::InvalidMacAddress(s) => write!(f, "invalid MAC address: {s}"),
            Self::UnsupportedMacVersion => write!(f, "frame has unsupported MAC version number"),
            Self::UnexpectedFrameType { expected } => write!(f, "frame is not a {expected} frame"),
            Self::InvalidRadiotap(why) => write!(f, "invalid radiotap header: {why}"),
            Self::ElementTooLong { id, len } => {
                write!(
                    f,
                    "information element {id} is too long ({len} > 255 bytes)"
                )
            }
            Self::MissingSnapHeader => write!(f, "SNAP extension is required"),
            Self::MissingExtIv => write!(f, "Ext IV was expected in protected frame"),
            Self::FieldOutOfRange { field } => {
                write!(f, "value of field `{field}` is out of range")
            }
        }
    }
}

impl std::error::Error for Error {}
