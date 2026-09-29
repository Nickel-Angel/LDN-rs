//! 48 位 MAC 地址。

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// 48 位 MAC 地址，按线上顺序存储 6 个字节。
///
/// 文本形式为冒号分隔的大写十六进制（`02:00:00:00:00:01`），解析时大小写都接受，
/// 但每段必须恰好 2 位，与 Python 版的严格程度一致。
///
/// 与 Python 版的差异：Python 版的 `MACAddress` 是可变对象且被用作 dataclass
/// 默认值（所有实例共享同一个对象）；这里是 `Copy` 值类型，不存在共享可变状态。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// 全 0 地址，Python 版 `MACAddress()` 的默认值。
    pub const ZERO: Self = Self([0; 6]);
    /// 广播地址 `FF:FF:FF:FF:FF:FF`。
    pub const BROADCAST: Self = Self([0xFF; 6]);

    /// 由 6 个字节构造。
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// 返回线上顺序的 6 个字节。
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// 由整数构造，最高有效字节在前；超过 48 位返回错误。
    pub fn from_u64(value: u64) -> Result<Self> {
        if value > 0xFFFF_FFFF_FFFF {
            return Err(Error::InvalidMacAddress(format!("{value:#x}")));
        }
        let b = value.to_be_bytes();
        Ok(Self([b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// 是否为广播地址。
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl TryFrom<&[u8]> for MacAddress {
    type Error = Error;

    /// 切片长度必须恰好为 6。
    fn try_from(bytes: &[u8]) -> Result<Self> {
        <[u8; 6]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidMacAddress(hex(bytes)))
    }
}

impl FromStr for MacAddress {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        let invalid = || Error::InvalidMacAddress(text.to_owned());
        let mut out = [0u8; 6];
        let mut fields = text.split(':');
        for byte in &mut out {
            let field = fields.next().ok_or_else(invalid)?;
            // from_str_radix 会接受 "+f" 这种写法，所以先逐字符校验。
            if field.len() != 2 || !field.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(invalid());
            }
            *byte = u8::from_str_radix(field, 16).map_err(|_| invalid())?;
        }
        if fields.next().is_some() {
            return Err(invalid());
        }
        Ok(Self(out))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{g:02X}")
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddress(\"{self}\")")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display_roundtrip() {
        let mac: MacAddress = "02:ab:CD:00:00:ff".parse().unwrap();
        assert_eq!(mac.octets(), [0x02, 0xAB, 0xCD, 0x00, 0x00, 0xFF]);
        assert_eq!(mac.to_string(), "02:AB:CD:00:00:FF");
        assert_eq!(format!("{mac:?}"), "MacAddress(\"02:AB:CD:00:00:FF\")");
    }

    #[test]
    fn parse_rejects_malformed_text() {
        for bad in [
            "",
            "02:00:00:00:00",
            "02:00:00:00:00:00:00",
            "2:00:00:00:00:00",
            "002:00:00:00:00:00",
            "0g:00:00:00:00:00",
            "+f:00:00:00:00:00",
            "02-00-00-00-00-00",
        ] {
            assert!(
                bad.parse::<MacAddress>().is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn from_u64_is_big_endian_and_range_checked() {
        let mac = MacAddress::from_u64(0x0200_0000_0001).unwrap();
        assert_eq!(mac.to_string(), "02:00:00:00:00:01");
        assert!(MacAddress::from_u64(0x1_0000_0000_0000).is_err());
    }

    #[test]
    fn try_from_slice_checks_length() {
        assert_eq!(
            MacAddress::try_from(&[0xFF; 6][..]),
            Ok(MacAddress::BROADCAST)
        );
        assert_eq!(
            MacAddress::try_from(&[1, 2, 3][..]),
            Err(Error::InvalidMacAddress("010203".into()))
        );
    }

    #[test]
    fn default_is_zero_and_broadcast_detection() {
        assert_eq!(MacAddress::default(), MacAddress::ZERO);
        assert!(MacAddress::BROADCAST.is_broadcast());
        assert!(!MacAddress::ZERO.is_broadcast());
    }
}
