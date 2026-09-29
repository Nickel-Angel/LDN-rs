//! LDN 协议的密码学部分：系统密钥加载、密钥派生，以及各类帧用到的加解密原语。
//!
//! 对应 Python 版 `ldn/__init__.py` 的 `load_keys`、`KeyDerivation`，以及
//! `AdvertisementFrame` / `AuthenticationFrame` / `Challenge*` / `wlan.DataFrame`
//! 里内联的 AES、SHA-256、HMAC 调用。帧格式本身不在这里（属于 ldn-proto），
//! 这里只提供“给定字节做加解密”的函数，所以能直接与 Python 的同名方法逐字节对拍
//! （见 `tests/python_parity.rs`）。
//!
//! 所有密码学实现来自 RustCrypto，本 crate 不含 `unsafe`。

#![forbid(unsafe_code)]

pub mod cipher;
pub mod error;
pub mod keys;

pub use error::{Error, Result};
pub use keys::{KeyDerivation, Keys, Protocol};
