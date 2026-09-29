//! 加入或建立网络后上报给应用的事件，以及两侧共用的小工具。

use std::net::Ipv4Addr;

use ldn_proto::ParticipantInfo;

/// 网络事件。STA 侧会收到全部种类，主机侧只会收到 `Join` / `Leave`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// 被主机断开（STA 侧），`reason` 见 `ldn_proto::auth::disconnect`。
    Disconnected {
        /// 断开原因。
        reason: u8,
    },
    /// 有参与者加入。
    Join {
        /// 槽位号（0 是主机）。
        index: usize,
        /// 参与者信息。
        participant: ParticipantInfo,
    },
    /// 有参与者离开；`participant.connected` 已为 `false`。
    Leave {
        /// 槽位号。
        index: usize,
        /// 离开前的参与者信息。
        participant: ParticipantInfo,
    },
    /// 主机修改了应用数据（STA 侧）。
    ApplicationDataChanged {
        /// 旧数据。
        old: Vec<u8>,
        /// 新数据。
        new: Vec<u8>,
    },
    /// 主机修改了接纳策略（STA 侧）。
    AcceptPolicyChanged {
        /// 旧策略。
        old: u8,
        /// 新策略。
        new: u8,
    },
}

/// 信道所在频段：2.4GHz 信道记为 2，5GHz 记为 5（与 Python 版 `ChannelBands` 一致）。
pub fn channel_band(channel: u8) -> u8 {
    if channel >= 36 { 5 } else { 2 }
}

/// LDN 网络的 IP 规划：`169.254.<network_id>.<槽位号 + 1>`，广播地址 `.255`。
pub fn participant_ip(network_id: u8, index: usize) -> Ipv4Addr {
    Ipv4Addr::new(169, 254, network_id, index as u8 + 1)
}

/// 网络的广播地址。
pub fn broadcast_ip(network_id: u8) -> Ipv4Addr {
    Ipv4Addr::new(169, 254, network_id, 255)
}

/// 从系统熵源读取随机字节。
///
/// 直接读 `/dev/urandom`（本项目只支持 Linux），不为此引入随机数库。
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use std::io::Read;
    let mut out = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut out))
        .expect("reading /dev/urandom must not fail on Linux");
    out
}

/// 随机 u64。
pub fn random_u64() -> u64 {
    u64::from_ne_bytes(random_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_plan() {
        assert_eq!(participant_ip(42, 0).to_string(), "169.254.42.1");
        assert_eq!(participant_ip(42, 7).to_string(), "169.254.42.8");
        assert_eq!(broadcast_ip(42).to_string(), "169.254.42.255");
        assert_eq!((channel_band(6), channel_band(36)), (2, 5));
    }

    #[test]
    fn randomness_differs() {
        assert_ne!(random_bytes::<16>(), random_bytes::<16>());
    }
}
