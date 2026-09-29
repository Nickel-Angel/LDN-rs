//! ldn-wlan 的错误类型。

use std::{fmt, io};

/// WLAN 层的错误。
#[derive(Debug)]
pub enum Error {
    /// 系统调用失败（socket、ioctl、读写等）。
    Io(io::Error),
    /// 内核对 netlink 请求返回了错误。
    Kernel {
        /// 正的 errno。
        errno: i32,
        /// 扩展 ACK 附带的说明。
        message: Option<String>,
    },
    /// netlink 消息格式错误。
    Netlink(ldn_netlink::Error),
    /// 802.11 帧格式错误。
    Wire(ldn_wire::Error),
    /// 内核或对端的行为不符合预期，例如连接失败、找不到 wiphy。
    Protocol(String),
    /// netlink 读循环已退出（socket 出错或已关闭），请求无法完成。
    Closed,
}

/// 本 crate 统一使用的 `Result` 别名。
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// 内核错误时返回 errno，便于调用方判断 `EEXIST` 之类的可忽略错误。
    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::Kernel { errno, .. } => Some(*errno),
            Self::Io(e) => e.raw_os_error(),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Kernel { errno, message } => {
                write!(
                    f,
                    "netlink request failed: {}",
                    io::Error::from_raw_os_error(*errno)
                )?;
                if let Some(m) = message {
                    write!(f, ": {m}")?;
                }
                Ok(())
            }
            Self::Netlink(e) => write!(f, "{e}"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::Protocol(m) => write!(f, "{m}"),
            Self::Closed => write!(f, "netlink socket is closed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Netlink(e) => Some(e),
            Self::Wire(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ldn_netlink::Error> for Error {
    fn from(e: ldn_netlink::Error) -> Self {
        Self::Netlink(e)
    }
}

impl From<ldn_wire::Error> for Error {
    fn from(e: ldn_wire::Error) -> Self {
        Self::Wire(e)
    }
}
