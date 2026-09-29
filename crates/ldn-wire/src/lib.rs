//! LDN 协议的纯编解码层：802.11 管理帧/数据帧、Radiotap 头、信息元素（IE）。
//!
//! 本 crate 不做任何 I/O，也不依赖异步运行时或第三方库，输入输出都是字节切片，
//! 所以在没有无线网卡的机器上也能完整测试。编码结果与 Python 版
//! `ldn/wlan.py` 逐字节一致，这一点由 `tests/python_parity.rs` 用
//! Python 实现生成的黄金向量验证。
//!
//! 与 Python 版有意不同的地方都在对应类型的文档里标了“与 Python 版的差异”。

#![forbid(unsafe_code)]

pub mod channel;
pub mod data;
pub mod element;
pub mod error;
pub mod frame;
pub mod mac;
pub mod radiotap;
pub mod stream;

pub use error::{Error, Result};
pub use mac::MacAddress;
