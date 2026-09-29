//! ldn-crypto 的错误类型。

use std::fmt;

/// 密钥加载、派生和加解密的错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 密钥文件第 `line` 行（从 1 开始）不是 `名字 = 十六进制` 格式。
    InvalidKeyFile {
        /// 出错的行号。
        line: usize,
    },
    /// 派生所需的系统密钥不在密钥表里。
    MissingKey(&'static str),
    /// 密钥长度不对（AES-128 需要 16 字节）。
    InvalidKeyLength {
        /// 密钥名或用途。
        name: &'static str,
        /// 实际长度。
        len: usize,
    },
    /// 协议版本没有对应的主密钥（只支持 1 和 3）。
    UnsupportedProtocol(u8),
    /// 认证标签（GCM tag / CCMP MIC / HMAC）校验失败：密钥不对或数据被篡改。
    AuthenticationFailed,
    /// 输入长度不合法，例如 CCMP 帧体短于 8 字节 MIC。
    InvalidLength(&'static str),
    /// 对已加密的数据帧再次加密。
    AlreadyProtected,
    /// 数据帧编码字段越界（例如 48 位包序号溢出）。
    Wire(ldn_wire::Error),
}

/// 本 crate 统一使用的 `Result` 别名。
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyFile { line } => write!(f, "invalid key file syntax on line {line}"),
            Self::MissingKey(name) => write!(f, "required key '{name}' is missing"),
            Self::InvalidKeyLength { name, len } => {
                write!(f, "key '{name}' has invalid length {len}")
            }
            Self::UnsupportedProtocol(p) => {
                write!(
                    f,
                    "key derivation for protocol version {p} is not supported"
                )
            }
            Self::AuthenticationFailed => write!(f, "authentication tag mismatch"),
            Self::InvalidLength(what) => write!(f, "invalid length: {what}"),
            Self::AlreadyProtected => write!(f, "data frame is already protected"),
            Self::Wire(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ldn_wire::Error> for Error {
    fn from(e: ldn_wire::Error) -> Self {
        Self::Wire(e)
    }
}
