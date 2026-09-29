//! 各类 LDN 消息共用的结构与常量。

use std::net::Ipv4Addr;

use ldn_wire::MacAddress;
use ldn_wire::stream::{Endian, Reader, Writer};

use crate::error::{Error, Result};

/// 一个网络最多的参与者数（含主机）。广播帧里参与者表固定 8 个槽位。
pub const MAX_PARTICIPANTS: usize = 8;
/// 用户名、参与者名的最大字节数（定长字段，不足补 0）。
pub const NAME_LEN: usize = 32;
/// Nintendo 的 OUI，所有 LDN 自定义帧都以它开头。
pub const NINTENDO_OUI: u32 = 0x0022AA;

/// 接纳策略（`station_accept_policy`）。
pub mod accept {
    /// 全部接纳。
    pub const ALL: u8 = 0;
    /// 全部拒绝。
    pub const NONE: u8 = 1;
    /// 黑名单。
    pub const BLACKLIST: u8 = 2;
    /// 白名单。
    pub const WHITELIST: u8 = 3;
}

/// 安全模式。
pub mod security {
    /// 广播帧与数据帧都加密。
    pub const PROD: u16 = 1;
    /// 广播帧加密，数据帧不加密。
    pub const DEBUG: u16 = 2;
    /// 都不加密。
    pub const SYSTEM_DEBUG: u16 = 3;
}

/// 平台。
pub mod platform {
    /// Switch。
    pub const NX: u8 = 0;
    /// Switch 2。
    pub const OUNCE: u8 = 1;
}

/// 32 字节的网络标识：本地通信 ID（游戏）、场景（游戏模式）和 SSID。
///
/// 广播帧里按大端编码，LDN 认证帧里按小端编码，所以编解码都要指定字节序。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct NetworkId {
    /// 本地通信 ID，通常等于游戏的 title id。
    pub local_communication_id: u64,
    /// 场景 ID（游戏自定义的模式号）。
    pub scene_id: u16,
    /// 16 字节随机 SSID；802.11 层的 SSID 是它的十六进制文本。
    pub ssid: [u8; 16],
}

impl NetworkId {
    /// 编码后的长度。
    pub const LEN: usize = 32;

    /// 写入流（使用流自身的字节序）。
    pub(crate) fn write(&self, w: &mut Writer) {
        w.u64(self.local_communication_id);
        w.pad(2);
        w.u16(self.scene_id);
        w.pad(4);
        w.write(&self.ssid);
    }

    /// 从流读取；填充不为 0 时报错。
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let local_communication_id = r.u64()?;
        r.pad(2)?;
        let scene_id = r.u16()?;
        r.pad(4)?;
        Ok(Self {
            local_communication_id,
            scene_id,
            ssid: r.read_array()?,
        })
    }

    /// 按给定字节序编码为 32 字节。
    pub fn encode(&self, endian: Endian) -> [u8; Self::LEN] {
        let mut w = Writer::new(endian);
        self.write(&mut w);
        w.into_vec().try_into().expect("network id is 32 bytes")
    }

    /// 按给定字节序解码。
    pub fn decode(data: &[u8], endian: Endian) -> Result<Self> {
        Self::read(&mut Reader::new(data, endian))
    }

    /// 802.11 层使用的 SSID 文本（16 字节的小写十六进制）。
    pub fn ssid_text(&self) -> String {
        self.ssid.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// 网络中一个节点（主机或成员）的信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantInfo {
    /// 链路本地 IP，`169.254.<network>.<n>`。
    pub ip_address: Ipv4Addr,
    /// MAC 地址。
    pub mac_address: MacAddress,
    /// 槽位是否被占用。
    pub connected: bool,
    /// 用户名，最多 32 字节，不含结尾的 0。
    pub name: Vec<u8>,
    /// 应用版本。
    pub app_version: u16,
    /// 平台，见 [`platform`]。
    pub platform: u8,
}

impl Default for ParticipantInfo {
    fn default() -> Self {
        Self {
            ip_address: Ipv4Addr::UNSPECIFIED,
            mac_address: MacAddress::ZERO,
            connected: false,
            name: Vec::new(),
            app_version: 0,
            platform: platform::NX,
        }
    }
}

/// 写一个 32 字节定长名字；超长时报 [`Error::TooLong`]。
pub(crate) fn write_name(w: &mut Writer, field: &'static str, name: &[u8]) -> Result<()> {
    if name.len() > NAME_LEN {
        return Err(Error::TooLong {
            field,
            len: name.len(),
            max: NAME_LEN,
        });
    }
    w.write(name);
    w.pad(NAME_LEN - name.len());
    Ok(())
}

/// 读一个 32 字节定长名字并去掉末尾的 0（与 Python 的 `rstrip(b"\0")` 一致）。
pub(crate) fn read_name(r: &mut Reader<'_>) -> Result<Vec<u8>> {
    let raw = r.read(NAME_LEN)?;
    let end = raw.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    Ok(raw[..end].to_vec())
}

/// 写 LDN 自定义帧的 6 字节前缀：OUI、帧类型、1 字节填充。
pub(crate) fn write_custom_header(w: &mut Writer, kind: u16) {
    w.u24(NINTENDO_OUI, "oui").expect("OUI fits in 24 bits");
    w.u16(kind);
    w.pad(1);
}

/// 读取并校验 LDN 自定义帧前缀。
pub(crate) fn read_custom_header(r: &mut Reader<'_>, kind: u16, name: &'static str) -> Result<()> {
    if r.u24()? != NINTENDO_OUI {
        return Err(Error::NotLdnFrame(name));
    }
    if r.u16()? != kind {
        return Err(Error::NotLdnFrame(name));
    }
    r.pad(1)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_id_endianness_and_ssid_text() {
        let id = NetworkId {
            local_communication_id: 0x0102,
            scene_id: 3,
            ssid: [0xAB; 16],
        };
        let be = id.encode(Endian::Big);
        let le = id.encode(Endian::Little);
        assert_eq!(be[7], 0x02);
        assert_eq!(le[0], 0x02);
        assert_eq!(NetworkId::decode(&be, Endian::Big), Ok(id));
        assert_eq!(NetworkId::decode(&le, Endian::Little), Ok(id));
        assert_eq!(id.ssid_text(), "ab".repeat(16));

        let mut bad = be;
        bad[8] = 1; // 填充
        assert!(NetworkId::decode(&bad, Endian::Big).is_err());
    }

    #[test]
    fn names() {
        let mut w = Writer::new(Endian::Big);
        write_name(&mut w, "name", b"abc").unwrap();
        assert_eq!(
            write_name(&mut w, "name", &[1; 33]),
            Err(Error::TooLong {
                field: "name",
                len: 33,
                max: 32
            })
        );
        let data = w.into_vec();
        assert_eq!(data.len(), 32);
        assert_eq!(
            read_name(&mut Reader::new(&data, Endian::Big)).unwrap(),
            b"abc"
        );
    }
}
