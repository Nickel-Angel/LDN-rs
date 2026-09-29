//! 802.11 信息元素（IE，TLV 格式）的编解码，以及 LDN 用到的几种元素。

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::stream::{Endian, Reader, Writer};

/// 帧里的信息元素集合：元素 ID -> 元素内容（不含 ID 和长度字节）。
///
/// 用有序 map 是为了与 Python 版保持一致：编码按 ID 升序输出。
///
/// 与 802.11 标准的差异（继承自 Python 版，暂不修改以保证对拍一致）：同一 ID
/// 出现多次时（常见于 221 Vendor Specific）解码只保留最后一个。
pub type Elements = BTreeMap<u8, Vec<u8>>;

/// 常用元素 ID。
pub mod eid {
    /// SSID。
    pub const SSID: u8 = 0;
    /// Supported Rates。
    pub const SUPP_RATES: u8 = 1;
    /// DS Parameter Set（当前信道）。
    pub const DS_PARAMS: u8 = 3;
    /// Supported Channels。
    pub const SUPPORTED_CHANNELS: u8 = 36;
    /// HT Capabilities。
    pub const HT_CAPABILITY: u8 = 45;
    /// RSN。
    pub const RSN: u8 = 48;
    /// Extended Supported Rates。
    pub const EXT_SUPP_RATES: u8 = 50;
    /// Extended Capabilities。
    pub const EXT_CAPABILITY: u8 = 127;
    /// Vendor Specific。
    pub const VENDOR_SPECIFIC: u8 = 221;
}

/// 由 OUI 和类型号拼出 32 位套件编号（Python 版的 `SUITE`）。
pub const fn suite(oui: u32, id: u8) -> u32 {
    (oui << 8) | id as u32
}

/// 成对/组播密码套件：CCMP-128。
pub const WLAN_CIPHER_SUITE_CCMP: u32 = suite(0x000FAC, 4);
/// AKM 套件：PSK。
pub const WLAN_AKM_SUITE_PSK: u32 = suite(0x000FAC, 2);

/// 把元素集合编码成连续的 TLV 字节流。
///
/// 任一元素内容超过 255 字节时返回 [`Error::ElementTooLong`]。
pub fn encode_elements(elements: &Elements) -> Result<Vec<u8>> {
    let mut w = Writer::new(Endian::Little);
    for (&id, value) in elements {
        let len = u8::try_from(value.len()).map_err(|_| Error::ElementTooLong {
            id,
            len: value.len(),
        })?;
        w.u8(id);
        w.u8(len);
        w.write(value);
    }
    Ok(w.into_vec())
}

/// 把 TLV 字节流解码成元素集合；长度字段越界时返回 [`Error::UnexpectedEof`]。
pub fn decode_elements(data: &[u8]) -> Result<Elements> {
    let mut r = Reader::new(data, Endian::Little);
    let mut elements = Elements::new();
    while !r.is_eof() {
        let id = r.u8()?;
        let len = r.u8()?;
        elements.insert(id, r.read(len.into())?.to_vec());
    }
    Ok(elements)
}

/// RSN 元素（ID 48）的内容，AP 在 Beacon/Probe Response 里用它声明 CCMP+PSK。
///
/// 只实现编码：LDN 只需要作为 AP 发出这个元素，不需要解析对方的。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsnElement {
    /// 组播密码套件。
    pub group_cipher_suite: u32,
    /// 成对密码套件列表。
    pub pairwise_cipher_suites: Vec<u32>,
    /// AKM 套件列表。
    pub akm_suites: Vec<u32>,
    /// RSN Capabilities 字段。
    pub capabilities: u16,
}

impl RsnElement {
    /// 编码为元素内容（不含 ID 和长度字节），版本号固定为 1。
    ///
    /// 列表长度超过 u16 时返回 [`Error::FieldOutOfRange`]；即使没超，元素整体
    /// 超过 255 字节也会在 [`encode_elements`] 阶段被拒绝。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let count = |list: &[u32], field| {
            u16::try_from(list.len()).map_err(|_| Error::FieldOutOfRange { field })
        };
        let mut w = Writer::new(Endian::Little);
        w.u16(1);
        w.u32_be(self.group_cipher_suite);
        w.u16(count(
            &self.pairwise_cipher_suites,
            "pairwise_cipher_suites",
        )?);
        for &s in &self.pairwise_cipher_suites {
            w.u32_be(s);
        }
        w.u16(count(&self.akm_suites, "akm_suites")?);
        for &s in &self.akm_suites {
            w.u32_be(s);
        }
        w.u16(self.capabilities);
        Ok(w.into_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_sorted_output() {
        let elements = Elements::from([(3, vec![6]), (0, b"ldn".to_vec())]);
        let encoded = encode_elements(&elements).unwrap();
        assert_eq!(encoded, [0, 3, b'l', b'd', b'n', 3, 1, 6]);
        assert_eq!(decode_elements(&encoded).unwrap(), elements);
    }

    #[test]
    fn empty_element_and_empty_input() {
        let elements = Elements::from([(0, vec![])]);
        assert_eq!(encode_elements(&elements).unwrap(), [0, 0]);
        assert!(decode_elements(&[]).unwrap().is_empty());
    }

    #[test]
    fn too_long_element_is_rejected() {
        let elements = Elements::from([(221, vec![0; 256])]);
        assert_eq!(
            encode_elements(&elements),
            Err(Error::ElementTooLong { id: 221, len: 256 })
        );
    }

    #[test]
    fn truncated_element_is_rejected() {
        assert_eq!(decode_elements(&[0, 5, 1, 2]), Err(Error::UnexpectedEof));
        assert_eq!(decode_elements(&[0]), Err(Error::UnexpectedEof));
    }

    #[test]
    fn duplicate_ids_keep_last_like_python() {
        let decoded = decode_elements(&[221, 1, 0xAA, 221, 1, 0xBB]).unwrap();
        assert_eq!(decoded[&221], [0xBB]);
    }

    #[test]
    fn suite_constants() {
        assert_eq!(WLAN_CIPHER_SUITE_CCMP, 0x000F_AC04);
        assert_eq!(WLAN_AKM_SUITE_PSK, 0x000F_AC02);
    }
}
