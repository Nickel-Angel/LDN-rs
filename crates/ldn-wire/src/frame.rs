//! 802.11 MAC 头与管理帧（Beacon、Probe、Auth、Assoc、Action 等）。
//!
//! 每个管理帧结构体只保留 LDN 需要的字段，编码时按 Python 版的规则填充
//! 另外的地址字段（例如 Beacon 的 addr1 固定为广播地址）。

use crate::data::DataFrame;
use crate::element::{Elements, decode_elements, encode_elements};
use crate::error::{Error, Result};
use crate::mac::MacAddress;
use crate::stream::{Endian, Reader, Writer};

/// 帧类型（Frame Control 的 type 字段）。
pub mod ftype {
    /// 管理帧。
    pub const MGMT: u8 = 0;
    /// 控制帧。
    pub const CTL: u8 = 1;
    /// 数据帧。
    pub const DATA: u8 = 2;
    /// 扩展帧。
    pub const EXT: u8 = 3;
}

/// 管理帧子类型。
pub mod stype {
    /// Association Request。
    pub const ASSOC_REQ: u8 = 0;
    /// Association Response。
    pub const ASSOC_RESP: u8 = 1;
    /// Reassociation Request。
    pub const REASSOC_REQ: u8 = 2;
    /// Reassociation Response。
    pub const REASSOC_RESP: u8 = 3;
    /// Probe Request。
    pub const PROBE_REQ: u8 = 4;
    /// Probe Response。
    pub const PROBE_RESP: u8 = 5;
    /// Beacon。
    pub const BEACON: u8 = 8;
    /// ATIM。
    pub const ATIM: u8 = 9;
    /// Disassociation。
    pub const DISASSOC: u8 = 10;
    /// Authentication。
    pub const AUTH: u8 = 11;
    /// Deauthentication。
    pub const DEAUTH: u8 = 12;
    /// Action。
    pub const ACTION: u8 = 13;
}

/// 状态码（Status Code）。
pub mod status {
    /// 成功。
    pub const SUCCESS: u16 = 0;
    /// 未指明的失败。
    pub const UNSPECIFIED_FAILURE: u16 = 1;
    /// 关联被拒绝，原因未指明。
    pub const ASSOC_DENIED_UNSPEC: u16 = 12;
    /// AP 无法再接纳新 STA（人数已满）。
    pub const AP_UNABLE_TO_HANDLE_NEW_STA: u16 = 17;
}

/// 原因码（Reason Code）。
pub mod reason {
    /// 未指明。
    pub const UNSPECIFIED: u16 = 1;
    /// STA 主动离开。
    pub const DISASSOC_STA_HAS_LEFT: u16 = 8;
}

/// 认证算法：开放系统认证。
pub const WLAN_AUTH_OPEN: u16 = 0;

/// 3 地址格式 802.11 MAC 头的长度。
pub const MAC_HEADER_LEN: usize = 24;

/// 3 地址格式的 802.11 MAC 头（不含 QoS Control 和 addr4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MacHeader {
    /// 帧类型，见 [`ftype`]。
    pub frame_type: u8,
    /// 子类型，见 [`stype`]。
    pub subtype: u8,
    /// Frame Control 的高 8 位（ToDS/FromDS/Protected 等标志）。
    pub flags: u8,
    /// Duration/ID。
    pub duration: u16,
    /// Address 1（接收方）。
    pub address1: MacAddress,
    /// Address 2（发送方）。
    pub address2: MacAddress,
    /// Address 3（通常是 BSSID）。
    pub address3: MacAddress,
    /// Sequence Control。
    pub sequence_control: u16,
}

impl MacHeader {
    /// 编码为 24 字节。
    pub fn encode(&self) -> [u8; MAC_HEADER_LEN] {
        let frame_control = (u16::from(self.frame_type & 3) << 2)
            | (u16::from(self.subtype & 0xF) << 4)
            | (u16::from(self.flags) << 8);
        let mut w = Writer::new(Endian::Little);
        w.u16(frame_control);
        w.u16(self.duration);
        w.write(&self.address1.octets());
        w.write(&self.address2.octets());
        w.write(&self.address3.octets());
        w.u16(self.sequence_control);
        w.into_vec()
            .try_into()
            .expect("MAC header is always 24 bytes")
    }

    /// 从 `data` 开头解码 24 字节 MAC 头，后续字节不读取。
    ///
    /// 协议版本号不为 0 时返回 [`Error::UnsupportedMacVersion`]。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data, Endian::Little);
        let frame_control = r.u16()?;
        if frame_control & 3 != 0 {
            return Err(Error::UnsupportedMacVersion);
        }
        Ok(Self {
            frame_type: ((frame_control >> 2) & 3) as u8,
            subtype: ((frame_control >> 4) & 0xF) as u8,
            flags: (frame_control >> 8) as u8,
            duration: r.u16()?,
            address1: MacAddress::new(r.read_array()?),
            address2: MacAddress::new(r.read_array()?),
            address3: MacAddress::new(r.read_array()?),
            sequence_control: r.u16()?,
        })
    }
}

/// 开始编码一个管理帧：写好 MAC 头，返回可继续写帧体的流。
fn mgmt_writer(subtype: u8, a1: MacAddress, a2: MacAddress, a3: MacAddress) -> Writer {
    let header = MacHeader {
        frame_type: ftype::MGMT,
        subtype,
        address1: a1,
        address2: a2,
        address3: a3,
        ..MacHeader::default()
    };
    let mut w = Writer::new(Endian::Little);
    w.write(&header.encode());
    w
}

/// 开始解码一个管理帧：解析并校验 MAC 头的类型/子类型，返回头和指向帧体的流。
///
/// 类型不符时返回 [`Error::UnexpectedFrameType`]，`name` 写入错误信息。
fn mgmt_reader<'a>(
    data: &'a [u8],
    subtype: u8,
    name: &'static str,
) -> Result<(MacHeader, Reader<'a>)> {
    let header = MacHeader::decode(data)?;
    if header.frame_type != ftype::MGMT || header.subtype != subtype {
        return Err(Error::UnexpectedFrameType { expected: name });
    }
    let mut r = Reader::new(data, Endian::Little);
    r.skip(MAC_HEADER_LEN)?;
    Ok((header, r))
}

/// Association Request：STA 请求加入。编码时 addr3（BSSID）取 `target`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssociationRequest {
    /// 目标 AP。
    pub target: MacAddress,
    /// 请求方 STA。
    pub source: MacAddress,
    /// Capability Information。
    pub capability_information: u16,
    /// Listen Interval。
    pub listen_interval: u16,
    /// 信息元素。
    pub elements: Elements,
}

impl AssociationRequest {
    /// 编码为完整帧；元素过长时报错。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = mgmt_writer(stype::ASSOC_REQ, self.target, self.source, self.target);
        w.u16(self.capability_information);
        w.u16(self.listen_interval);
        w.write(&encode_elements(&self.elements)?);
        Ok(w.into_vec())
    }

    /// 从完整帧解码；帧类型不符或长度不足时报错。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (h, mut r) = mgmt_reader(data, stype::ASSOC_REQ, "association request")?;
        Ok(Self {
            target: h.address1,
            source: h.address2,
            capability_information: r.u16()?,
            listen_interval: r.u16()?,
            elements: decode_elements(r.rest())?,
        })
    }
}

/// Association Response：AP 对关联请求的答复。编码时 addr3（BSSID）取 `source`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssociationResponse {
    /// 接收方 STA。
    pub target: MacAddress,
    /// 应答方 AP。
    pub source: MacAddress,
    /// Capability Information。
    pub capability_information: u16,
    /// 状态码，见 [`status`]。
    pub status_code: u16,
    /// 分配给 STA 的 AID（最高两位按标准置 1）。
    pub aid: u16,
    /// 信息元素。
    pub elements: Elements,
}

impl AssociationResponse {
    /// 编码为完整帧；元素过长时报错。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = mgmt_writer(stype::ASSOC_RESP, self.target, self.source, self.source);
        w.u16(self.capability_information);
        w.u16(self.status_code);
        w.u16(self.aid);
        w.write(&encode_elements(&self.elements)?);
        Ok(w.into_vec())
    }

    /// 从完整帧解码；帧类型不符或长度不足时报错。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (h, mut r) = mgmt_reader(data, stype::ASSOC_RESP, "association response")?;
        Ok(Self {
            target: h.address1,
            source: h.address2,
            capability_information: r.u16()?,
            status_code: r.u16()?,
            aid: r.u16()?,
            elements: decode_elements(r.rest())?,
        })
    }
}

/// Probe Request：编码时 addr1 和 addr3 固定为广播地址。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeRequest {
    /// 发送方 STA。
    pub source: MacAddress,
    /// 信息元素。
    pub elements: Elements,
}

impl ProbeRequest {
    /// 编码为完整帧；元素过长时报错。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bc = MacAddress::BROADCAST;
        let mut w = mgmt_writer(stype::PROBE_REQ, bc, self.source, bc);
        w.write(&encode_elements(&self.elements)?);
        Ok(w.into_vec())
    }

    /// 从完整帧解码；帧类型不符或长度不足时报错。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (h, mut r) = mgmt_reader(data, stype::PROBE_REQ, "probe request")?;
        Ok(Self {
            source: h.address2,
            elements: decode_elements(r.rest())?,
        })
    }
}

/// Probe Response：编码时 addr3（BSSID）取 `source`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeResponse {
    /// 接收方 STA。
    pub target: MacAddress,
    /// 应答方 AP。
    pub source: MacAddress,
    /// TSF 时间戳。
    pub timestamp: u64,
    /// Beacon 间隔（TU）。
    pub beacon_interval: u16,
    /// Capability Information。
    pub capability_information: u16,
    /// 信息元素。
    pub elements: Elements,
}

impl ProbeResponse {
    /// 编码为完整帧；元素过长时报错。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = mgmt_writer(stype::PROBE_RESP, self.target, self.source, self.source);
        w.u64(self.timestamp);
        w.u16(self.beacon_interval);
        w.u16(self.capability_information);
        w.write(&encode_elements(&self.elements)?);
        Ok(w.into_vec())
    }

    /// 从完整帧解码；帧类型不符或长度不足时报错。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (h, mut r) = mgmt_reader(data, stype::PROBE_RESP, "probe response")?;
        Ok(Self {
            target: h.address1,
            source: h.address2,
            timestamp: r.u64()?,
            beacon_interval: r.u16()?,
            capability_information: r.u16()?,
            elements: decode_elements(r.rest())?,
        })
    }
}

/// Beacon：编码时 addr1 为广播地址，addr3（BSSID）取 `source`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BeaconFrame {
    /// 发送方 AP。
    pub source: MacAddress,
    /// TSF 时间戳（由驱动/固件发送时覆盖）。
    pub timestamp: u64,
    /// Beacon 间隔（TU）。
    pub beacon_interval: u16,
    /// Capability Information。
    pub capability_information: u16,
    /// 信息元素。
    pub elements: Elements,
}

impl BeaconFrame {
    /// 编码为完整帧；元素过长时报错。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = mgmt_writer(
            stype::BEACON,
            MacAddress::BROADCAST,
            self.source,
            self.source,
        );
        w.u64(self.timestamp);
        w.u16(self.beacon_interval);
        w.u16(self.capability_information);
        w.write(&encode_elements(&self.elements)?);
        Ok(w.into_vec())
    }

    /// 从完整帧解码；帧类型不符或长度不足时报错。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (h, mut r) = mgmt_reader(data, stype::BEACON, "beacon")?;
        Ok(Self {
            source: h.address2,
            timestamp: r.u64()?,
            beacon_interval: r.u16()?,
            capability_information: r.u16()?,
            elements: decode_elements(r.rest())?,
        })
    }
}

/// Disassociation。
///
/// 与 Python 版的差异：Python 版 `DisassociationFrame.encode` 误把子类型写成了
/// Authentication（11），这里按标准写 Disassociation（10）。Python 版只解码不编码
/// 这种帧，所以修正不影响与 Python 版的互通。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DisassociationFrame {
    /// 接收方。
    pub target: MacAddress,
    /// 发送方。
    pub source: MacAddress,
    /// BSSID。
    pub bssid: MacAddress,
    /// 原因码，见 [`reason`]。
    pub reason: u16,
    /// 信息元素。
    pub elements: Elements,
}

impl DisassociationFrame {
    /// 编码为完整帧；元素过长时报错。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = mgmt_writer(stype::DISASSOC, self.target, self.source, self.bssid);
        w.u16(self.reason);
        w.write(&encode_elements(&self.elements)?);
        Ok(w.into_vec())
    }

    /// 从完整帧解码；帧类型不符或长度不足时报错。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (h, mut r) = mgmt_reader(data, stype::DISASSOC, "disassociation")?;
        Ok(Self {
            target: h.address1,
            source: h.address2,
            bssid: h.address3,
            reason: r.u16()?,
            elements: decode_elements(r.rest())?,
        })
    }
}

/// Authentication（802.11 层的开放系统认证，不是 LDN 自己的认证握手）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticationFrame {
    /// 接收方。
    pub target: MacAddress,
    /// 发送方。
    pub source: MacAddress,
    /// BSSID。
    pub bssid: MacAddress,
    /// 认证算法，LDN 只用 [`WLAN_AUTH_OPEN`]。
    pub algorithm: u16,
    /// 认证事务序号（请求 1、应答 2）。
    pub sequence: u16,
    /// 状态码，见 [`status`]。
    pub status_code: u16,
    /// 信息元素。
    pub elements: Elements,
}

impl AuthenticationFrame {
    /// 编码为完整帧；元素过长时报错。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = mgmt_writer(stype::AUTH, self.target, self.source, self.bssid);
        w.u16(self.algorithm);
        w.u16(self.sequence);
        w.u16(self.status_code);
        w.write(&encode_elements(&self.elements)?);
        Ok(w.into_vec())
    }

    /// 从完整帧解码；帧类型不符或长度不足时报错。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (h, mut r) = mgmt_reader(data, stype::AUTH, "authentication")?;
        Ok(Self {
            target: h.address1,
            source: h.address2,
            bssid: h.address3,
            algorithm: r.u16()?,
            sequence: r.u16()?,
            status_code: r.u16()?,
            elements: decode_elements(r.rest())?,
        })
    }
}

/// Deauthentication。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeauthenticationFrame {
    /// 接收方。
    pub target: MacAddress,
    /// 发送方。
    pub source: MacAddress,
    /// BSSID。
    pub bssid: MacAddress,
    /// 原因码，见 [`reason`]。
    pub reason: u16,
    /// 信息元素。
    pub elements: Elements,
}

impl DeauthenticationFrame {
    /// 编码为完整帧；元素过长时报错。
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = mgmt_writer(stype::DEAUTH, self.target, self.source, self.bssid);
        w.u16(self.reason);
        w.write(&encode_elements(&self.elements)?);
        Ok(w.into_vec())
    }

    /// 从完整帧解码；帧类型不符或长度不足时报错。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (h, mut r) = mgmt_reader(data, stype::DEAUTH, "deauthentication")?;
        Ok(Self {
            target: h.address1,
            source: h.address2,
            bssid: h.address3,
            reason: r.u16()?,
            elements: decode_elements(r.rest())?,
        })
    }
}

/// Action 帧：LDN 房间广播的载体。编码时 addr1 和 addr3 固定为广播地址。
///
/// `action` 是 Category 起的整个帧体，LDN 广播帧的具体格式由上层解析。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionFrame {
    /// 发送方。
    pub source: MacAddress,
    /// 帧体（Category 字节起）。
    pub action: Vec<u8>,
}

impl ActionFrame {
    /// 编码为完整帧。
    pub fn encode(&self) -> Vec<u8> {
        let bc = MacAddress::BROADCAST;
        let mut w = mgmt_writer(stype::ACTION, bc, self.source, bc);
        w.write(&self.action);
        w.into_vec()
    }

    /// 从完整帧解码；帧类型不符或长度不足时报错。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let (h, mut r) = mgmt_reader(data, stype::ACTION, "action")?;
        Ok(Self {
            source: h.address2,
            action: r.rest().to_vec(),
        })
    }
}

/// monitor 接口上能识别的所有帧，对应 Python 版 `Monitor._parse_frame` 的返回值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Association Request。
    AssociationRequest(AssociationRequest),
    /// Association Response。
    AssociationResponse(AssociationResponse),
    /// Probe Request。
    ProbeRequest(ProbeRequest),
    /// Probe Response。
    ProbeResponse(ProbeResponse),
    /// Beacon。
    Beacon(BeaconFrame),
    /// Disassociation。
    Disassociation(DisassociationFrame),
    /// Authentication。
    Authentication(AuthenticationFrame),
    /// Deauthentication。
    Deauthentication(DeauthenticationFrame),
    /// Action。
    Action(ActionFrame),
    /// 数据帧（仅 subtype 0，不含 QoS Data）。
    Data(DataFrame),
}

impl Frame {
    /// 按 MAC 头分发解码。
    ///
    /// 控制帧、扩展帧和不认识的管理帧子类型返回 `Ok(None)`，调用方应忽略；
    /// 帧畸形时返回错误。BSSID 过滤属于接口层逻辑，不在这里做。
    ///
    /// 与 Python 版的差异：Python 版遇到不认识的管理子类型会抛 `KeyError`
    /// （随后被接收循环吞掉），这里显式返回 `None`，效果相同。
    pub fn parse(data: &[u8]) -> Result<Option<Self>> {
        let header = MacHeader::decode(data)?;
        let frame = match (header.frame_type, header.subtype) {
            (ftype::MGMT, stype::ASSOC_REQ) => {
                Self::AssociationRequest(AssociationRequest::decode(data)?)
            }
            (ftype::MGMT, stype::ASSOC_RESP) => {
                Self::AssociationResponse(AssociationResponse::decode(data)?)
            }
            (ftype::MGMT, stype::PROBE_REQ) => Self::ProbeRequest(ProbeRequest::decode(data)?),
            (ftype::MGMT, stype::PROBE_RESP) => Self::ProbeResponse(ProbeResponse::decode(data)?),
            (ftype::MGMT, stype::BEACON) => Self::Beacon(BeaconFrame::decode(data)?),
            (ftype::MGMT, stype::DISASSOC) => {
                Self::Disassociation(DisassociationFrame::decode(data)?)
            }
            (ftype::MGMT, stype::AUTH) => Self::Authentication(AuthenticationFrame::decode(data)?),
            (ftype::MGMT, stype::DEAUTH) => {
                Self::Deauthentication(DeauthenticationFrame::decode(data)?)
            }
            (ftype::MGMT, stype::ACTION) => Self::Action(ActionFrame::decode(data)?),
            (ftype::DATA, _) => Self::Data(DataFrame::decode(data)?),
            _ => return Ok(None),
        };
        Ok(Some(frame))
    }

    /// 编码为完整帧（不含 Radiotap 头）。
    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::AssociationRequest(f) => f.encode(),
            Self::AssociationResponse(f) => f.encode(),
            Self::ProbeRequest(f) => f.encode(),
            Self::ProbeResponse(f) => f.encode(),
            Self::Beacon(f) => f.encode(),
            Self::Disassociation(f) => f.encode(),
            Self::Authentication(f) => f.encode(),
            Self::Deauthentication(f) => f.encode(),
            Self::Action(f) => Ok(f.encode()),
            Self::Data(f) => f.encode(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 1]);
    const B: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 2]);

    #[test]
    fn mac_header_roundtrip_and_version_check() {
        let h = MacHeader {
            frame_type: ftype::DATA,
            subtype: 0,
            flags: 0x42,
            duration: 0x1234,
            address1: A,
            address2: B,
            address3: MacAddress::BROADCAST,
            sequence_control: 0x5670,
        };
        let bytes = h.encode();
        assert_eq!(MacHeader::decode(&bytes), Ok(h));

        let mut bad = bytes;
        bad[0] |= 1;
        assert_eq!(MacHeader::decode(&bad), Err(Error::UnsupportedMacVersion));
        assert_eq!(MacHeader::decode(&bytes[..23]), Err(Error::UnexpectedEof));
    }

    #[test]
    fn decode_rejects_wrong_subtype() {
        let beacon = BeaconFrame {
            source: A,
            ..Default::default()
        }
        .encode()
        .unwrap();
        assert_eq!(
            ProbeResponse::decode(&beacon),
            Err(Error::UnexpectedFrameType {
                expected: "probe response"
            })
        );
    }

    #[test]
    fn disassociation_uses_correct_subtype() {
        let frame = DisassociationFrame {
            target: A,
            source: B,
            bssid: A,
            reason: 8,
            ..Default::default()
        };
        let bytes = frame.encode().unwrap();
        assert_eq!(MacHeader::decode(&bytes).unwrap().subtype, stype::DISASSOC);
        assert_eq!(DisassociationFrame::decode(&bytes), Ok(frame));
    }

    #[test]
    fn parse_dispatches_and_ignores_unknown() {
        let action = ActionFrame {
            source: A,
            action: vec![0x7F, 1],
        };
        assert_eq!(
            Frame::parse(&action.encode()),
            Ok(Some(Frame::Action(action)))
        );

        // ATIM 管理帧与控制帧都不认识。
        let atim = MacHeader {
            subtype: stype::ATIM,
            ..Default::default()
        }
        .encode();
        assert_eq!(Frame::parse(&atim), Ok(None));
        let ctl = MacHeader {
            frame_type: ftype::CTL,
            ..Default::default()
        }
        .encode();
        assert_eq!(Frame::parse(&ctl), Ok(None));
    }

    #[test]
    fn frame_encode_matches_inner_encode() {
        let auth = AuthenticationFrame {
            target: A,
            source: B,
            bssid: A,
            sequence: 2,
            ..Default::default()
        };
        assert_eq!(Frame::Authentication(auth.clone()).encode(), auth.encode());
    }

    #[test]
    fn truncated_body_is_error() {
        let bytes = AssociationResponse {
            target: B,
            source: A,
            ..Default::default()
        }
        .encode()
        .unwrap();
        assert_eq!(
            AssociationResponse::decode(&bytes[..MAC_HEADER_LEN + 3]),
            Err(Error::UnexpectedEof)
        );
    }
}
