//! 802.11 数据帧、LLC/SNAP 头和以太网帧，以及 CCMP 加密所需的 nonce/AAD 构造。
//!
//! 数据面的转换链路是：空口 802.11 数据帧 <-> SNAP 头 <-> TAP 口上的以太网帧。
//! 本模块只做格式转换；AES-CCM 加解密本身在后续的加密 crate 里实现，
//! 这里提供的 [`DataFrame::ccmp_nonce`] / [`DataFrame::ccmp_aad`] 就是它的输入。

use crate::error::{Error, Result};
use crate::frame::{MAC_HEADER_LEN, MacHeader, ftype};
use crate::mac::MacAddress;
use crate::stream::{Endian, Reader, Writer};

/// IPv4 的 EtherType。
pub const ETH_P_IP: u16 = 0x0800;
/// ARP 的 EtherType。
pub const ETH_P_ARP: u16 = 0x0806;
/// OUI 扩展的 EtherType。
pub const ETH_P_OUI: u16 = 0x88B7;

/// LLC 头 `DSAP=AA SSAP=AA Control=03`，表示后面跟着 SNAP 扩展。
pub const SNAP_PREFIX: [u8; 3] = [0xAA, 0xAA, 0x03];

const FLAG_TO_DS: u8 = 0x01;
const FLAG_FROM_DS: u8 = 0x02;
const FLAG_PROTECTED: u8 = 0x40;
/// CCMP 头第 4 字节里的 Ext IV 标志（在小端 u16 里是 0x2000）。
const CCMP_EXT_IV: u16 = 0x2000;
/// CCMP 的 PN 是 48 位。
const MAX_PACKET_NUMBER: u64 = (1 << 48) - 1;

/// 数据帧（subtype 0）。受保护时 `payload` 是 CCMP 密文加 8 字节 MIC，否则是明文 SNAP 载荷。
///
/// LDN 里主机发出的帧 FromDS=1，其他成员之间的帧 ToDS/FromDS 都为 0。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataFrame {
    /// Address 1（接收方）。
    pub target: MacAddress,
    /// Address 2（发送方）。
    pub source: MacAddress,
    /// Address 3（BSSID）。
    pub bssid: MacAddress,
    /// FromDS 标志。
    pub from_ds: bool,
    /// ToDS 标志。
    pub to_ds: bool,
    /// Protected 标志；为真时帧体前有 8 字节 CCMP 头。
    pub protected: bool,
    /// CCMP 包序号（PN），48 位；Python 版叫 `nonce`。
    pub packet_number: u64,
    /// CCMP 密钥 ID（0~3）。
    pub key_id: u8,
    /// 帧体（CCMP 头之后的部分）。
    pub payload: Vec<u8>,
}

impl DataFrame {
    /// 从完整帧解码。
    ///
    /// 某些驱动在 monitor 口交上来时已经解密了帧却没清 Protected 位，所以
    /// 帧体若以 [`SNAP_PREFIX`] 开头就按明文处理（沿用 Python 版的判断）。
    ///
    /// 类型不符、受保护帧没有 Ext IV、长度不足时报错。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = MacHeader::decode(data)?;
        if header.frame_type != ftype::DATA || header.subtype != 0 {
            return Err(Error::UnexpectedFrameType { expected: "data" });
        }
        let mut r = Reader::new(data, Endian::Little);
        r.skip(MAC_HEADER_LEN)?;

        let already_decrypted = r.peek(SNAP_PREFIX.len()).is_ok_and(|p| p == SNAP_PREFIX);
        let mut frame = Self {
            target: header.address1,
            source: header.address2,
            bssid: header.address3,
            to_ds: header.flags & FLAG_TO_DS != 0,
            from_ds: header.flags & FLAG_FROM_DS != 0,
            protected: header.flags & FLAG_PROTECTED != 0 && !already_decrypted,
            ..Self::default()
        };

        if frame.protected {
            // CCMP 头：PN0 PN1 | 保留 | ExtIV/KeyID | PN2..PN5
            let low = r.u16()?;
            let extra = r.u16()?;
            let high = r.u32()?;
            if extra & CCMP_EXT_IV == 0 {
                return Err(Error::MissingExtIv);
            }
            frame.packet_number = u64::from(low) | (u64::from(high) << 16);
            frame.key_id = ((extra >> 14) & 3) as u8;
        }
        frame.payload = r.rest().to_vec();
        Ok(frame)
    }

    /// 编码为完整帧。受保护时写入 CCMP 头，但不做加密，`payload` 须已是密文。
    ///
    /// `packet_number` 超过 48 位或 `key_id` 超过 3 时返回 [`Error::FieldOutOfRange`]。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut flags = 0;
        if self.to_ds {
            flags |= FLAG_TO_DS;
        }
        if self.from_ds {
            flags |= FLAG_FROM_DS;
        }
        if self.protected {
            flags |= FLAG_PROTECTED;
        }
        let header = MacHeader {
            frame_type: ftype::DATA,
            flags,
            address1: self.target,
            address2: self.source,
            address3: self.bssid,
            ..MacHeader::default()
        };
        let mut w = Writer::new(Endian::Little);
        w.write(&header.encode());

        if self.protected {
            if self.packet_number > MAX_PACKET_NUMBER {
                return Err(Error::FieldOutOfRange {
                    field: "packet_number",
                });
            }
            if self.key_id > 3 {
                return Err(Error::FieldOutOfRange { field: "key_id" });
            }
            w.u16(self.packet_number as u16);
            w.u16(CCMP_EXT_IV | (u16::from(self.key_id) << 14));
            w.u32((self.packet_number >> 16) as u32);
        }
        w.write(&self.payload);
        Ok(w.into_vec())
    }

    /// AES-CCM 的 13 字节 nonce：优先级(0) + 发送方地址 + 大端 48 位 PN。
    pub fn ccmp_nonce(&self) -> [u8; 13] {
        let mut nonce = [0u8; 13];
        nonce[1..7].copy_from_slice(&self.source.octets());
        nonce[7..].copy_from_slice(&self.packet_number.to_be_bytes()[2..]);
        nonce
    }

    /// AES-CCM 的 22 字节附加认证数据：Frame Control + 三个地址 + 清零的序号字段。
    ///
    /// Protected 位总是置 1：加密和解密时帧都处于受保护状态，Python 版取
    /// `self.protected` 在这两个调用点上恒为真，效果相同。
    pub fn ccmp_aad(&self) -> [u8; 22] {
        let mut frame_control = u16::from(ftype::DATA) << 2;
        frame_control |= u16::from(self.to_ds) << 8;
        frame_control |= u16::from(self.from_ds) << 9;
        frame_control |= 1 << 14;

        let mut aad = [0u8; 22];
        aad[..2].copy_from_slice(&frame_control.to_le_bytes());
        aad[2..8].copy_from_slice(&self.target.octets());
        aad[8..14].copy_from_slice(&self.source.octets());
        aad[14..20].copy_from_slice(&self.bssid.octets());
        aad
    }
}

/// LLC/SNAP 头：802.11 数据帧体用它标明上层协议（EtherType）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapHeader {
    /// 24 位 OUI，封装以太网帧时为 0。
    pub oui: u32,
    /// EtherType。
    pub protocol: u16,
    /// 上层载荷。
    pub payload: Vec<u8>,
}

impl SnapHeader {
    /// 编码；`oui` 超过 24 位时返回 [`Error::FieldOutOfRange`]。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new(Endian::Big);
        w.write(&SNAP_PREFIX);
        w.u24(self.oui, "oui")?;
        w.u16(self.protocol);
        w.write(&self.payload);
        Ok(w.into_vec())
    }

    /// 解码；不以 [`SNAP_PREFIX`] 开头时返回 [`Error::MissingSnapHeader`]。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data, Endian::Big);
        if r.read(SNAP_PREFIX.len())? != SNAP_PREFIX {
            return Err(Error::MissingSnapHeader);
        }
        Ok(Self {
            oui: r.u24()?,
            protocol: r.u16()?,
            payload: r.rest().to_vec(),
        })
    }
}

/// TAP 接口上的以太网 II 帧。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EthernetFrame {
    /// 目的地址。
    pub target: MacAddress,
    /// 源地址。
    pub source: MacAddress,
    /// EtherType。
    pub protocol: u16,
    /// 载荷。
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    /// 编码。
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new(Endian::Big);
        w.write(&self.target.octets());
        w.write(&self.source.octets());
        w.u16(self.protocol);
        w.write(&self.payload);
        w.into_vec()
    }

    /// 解码；不足 14 字节时报错。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data, Endian::Big);
        Ok(Self {
            target: MacAddress::new(r.read_array()?),
            source: MacAddress::new(r.read_array()?),
            protocol: r.u16()?,
            payload: r.rest().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 1]);

    fn protected_frame() -> DataFrame {
        DataFrame {
            target: MacAddress::BROADCAST,
            source: A,
            bssid: A,
            from_ds: true,
            protected: true,
            packet_number: 0x1234_5678_9ABC,
            key_id: 1,
            payload: (1..=9).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn protected_roundtrip() {
        let frame = protected_frame();
        assert_eq!(DataFrame::decode(&frame.encode().unwrap()), Ok(frame));
    }

    #[test]
    fn protected_bit_cleared_when_body_is_plain_snap() {
        let frame = DataFrame {
            protected: false,
            packet_number: 0,
            key_id: 0,
            payload: SNAP_PREFIX.to_vec(),
            ..protected_frame()
        };
        let mut bytes = frame.encode().unwrap();
        bytes[1] |= FLAG_PROTECTED; // 模拟驱动解密后没清 Protected 位
        assert_eq!(DataFrame::decode(&bytes), Ok(frame));
    }

    #[test]
    fn missing_ext_iv_is_rejected() {
        let mut bytes = protected_frame().encode().unwrap();
        bytes[MAC_HEADER_LEN + 3] &= !0x20;
        assert_eq!(DataFrame::decode(&bytes), Err(Error::MissingExtIv));
    }

    #[test]
    fn encode_range_checks() {
        let mut frame = protected_frame();
        frame.packet_number = 1 << 48;
        assert_eq!(
            frame.encode(),
            Err(Error::FieldOutOfRange {
                field: "packet_number"
            })
        );
        let mut frame = protected_frame();
        frame.key_id = 4;
        assert_eq!(
            frame.encode(),
            Err(Error::FieldOutOfRange { field: "key_id" })
        );
    }

    #[test]
    fn non_data_frame_is_rejected() {
        let mgmt = MacHeader::default().encode();
        assert_eq!(
            DataFrame::decode(&mgmt),
            Err(Error::UnexpectedFrameType { expected: "data" })
        );
    }

    #[test]
    fn snap_and_ethernet_roundtrip() {
        let snap = SnapHeader {
            oui: 0,
            protocol: ETH_P_IP,
            payload: b"hi".to_vec(),
        };
        assert_eq!(SnapHeader::decode(&snap.encode().unwrap()), Ok(snap));
        assert_eq!(
            SnapHeader::decode(&[0xAA, 0xAA, 0x00, 0, 0, 0, 8, 0]),
            Err(Error::MissingSnapHeader)
        );

        let eth = EthernetFrame {
            target: MacAddress::BROADCAST,
            source: A,
            protocol: ETH_P_ARP,
            payload: vec![1],
        };
        assert_eq!(EthernetFrame::decode(&eth.encode()), Ok(eth));
        assert_eq!(EthernetFrame::decode(&[0; 13]), Err(Error::UnexpectedEof));
    }
}
