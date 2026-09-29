//! LDN 使用的 2.4GHz / 5GHz 信道与中心频率的对应关系。
//!
//! 只列出 Python 版支持的 7 个信道：Switch 本地通信实际只用 1/6/11，
//! 36~48 是 Python 版保留的 5GHz 条目。

const CHANNELS: [(u8, u16); 7] = [
    (1, 2412),
    (6, 2437),
    (11, 2462),
    (36, 5180),
    (40, 5200),
    (44, 5220),
    (48, 5240),
];

/// 信道号对应的中心频率（MHz）；不支持的信道返回 `None`。
pub fn channel_to_frequency(channel: u8) -> Option<u16> {
    CHANNELS
        .iter()
        .find(|&&(c, _)| c == channel)
        .map(|&(_, f)| f)
}

/// 中心频率（MHz）对应的信道号；不支持的频率返回 `None`。
///
/// 扫描时用它把 Radiotap 里的频率换算成广播帧所在信道。
pub fn frequency_to_channel(frequency: u16) -> Option<u8> {
    CHANNELS
        .iter()
        .find(|&&(_, f)| f == frequency)
        .map(|&(c, _)| c)
}

/// 是否为支持的信道号，对应 Python 版 `is_valid_channel`。
pub fn is_valid_channel(channel: u8) -> bool {
    channel_to_frequency(channel).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_is_bidirectional() {
        for &(c, f) in &CHANNELS {
            assert_eq!(channel_to_frequency(c), Some(f));
            assert_eq!(frequency_to_channel(f), Some(c));
        }
    }

    #[test]
    fn unsupported_values() {
        assert!(!is_valid_channel(2));
        assert!(is_valid_channel(6));
        assert_eq!(frequency_to_channel(2417), None);
    }
}
