//! 在 Linux 上与任天堂 Switch 进行本地无线通信（LDN）：扫描附近的房间、加入房间、建房。
//!
//! 这是 Python 包 [kinnay/LDN](https://github.com/kinnay/LDN) 的 Rust 重写，对外 API 与之对应：
//!
//! | Python | Rust |
//! |---|---|
//! | `ldn.scan(keys, ...)` | [`scan()`]`(&`[`ScanParam`]`)` |
//! | `async with ldn.connect(param) as network` | [`connect`]`(`[`ConnectParam`]`)` -> [`StaNetwork`]，用完 `close().await` |
//! | `async with ldn.create_network(param) as network` | [`create_network`]`(`[`CreateNetworkParam`]`)` -> [`HostNetwork`]，用完 `close().await` |
//! | `network.next_event()` | `next_event().await` -> [`Event`] |
//!
//! 协议决策集中在两个不做 I/O 的状态机 [`host_core::HostCore`] 和 [`station_core::StationCore`]，
//! 可以不接网卡测试，并与 Python 版逐字节对拍（`tests/python_parity.rs`）；
//! [`host`] 和 [`station`] 只负责把它们接到 `ldn-wlan` 的接口上。
//!
//! 需要 root（或 `CAP_NET_ADMIN` + `CAP_NET_RAW`），并建议先停掉 NetworkManager。

#![forbid(unsafe_code)]

pub mod error;
pub mod event;
pub mod host;
pub mod host_core;
pub mod scan;
pub mod station;
pub mod station_core;

pub use error::{Error, Result};
pub use event::Event;
pub use host::{CreateNetworkParam, HostNetwork, create_network};
pub use host_core::HostConfig;
pub use ldn_crypto::{Keys, Protocol};
pub use ldn_proto::{NetworkInfo, ParticipantInfo};
pub use scan::{ScanParam, scan};
pub use station::{ConnectParam, StaNetwork, connect};
pub use station_core::JoinConfig;
