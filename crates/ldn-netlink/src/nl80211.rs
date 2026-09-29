//! nl80211 命令、属性常量、请求构造与事件解析。
//!
//! 每个构造函数对应 Python 版 `ldn/wlan.py` 里的一处 `self._wlan.request(...)`，
//! 属性顺序与之逐一一致（由 `tests/python_parity.rs` 保证），这样发给内核的字节与原项目相同。

use ldn_wire::MacAddress;
use ldn_wire::element::{WLAN_AKM_SUITE_PSK, WLAN_CIPHER_SUITE_CCMP};

use crate::error::{Error, Result};
use crate::genl::{self, Family, GenlMessage};
use crate::message::{self, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
use crate::nla::Attrs;

/// nl80211 命令号。
pub mod cmd {
    /// 查询 wiphy。
    pub const GET_WIPHY: u8 = 1;
    /// wiphy 信息（dump 回复）。
    pub const NEW_WIPHY: u8 = 3;
    /// 新建接口。
    pub const NEW_INTERFACE: u8 = 7;
    /// 删除接口。
    pub const DEL_INTERFACE: u8 = 8;
    /// 修改密钥属性。
    pub const SET_KEY: u8 = 10;
    /// 安装密钥。
    pub const NEW_KEY: u8 = 11;
    /// 启动 AP。
    pub const START_AP: u8 = 15;
    /// 停止 AP。
    pub const STOP_AP: u8 = 16;
    /// 修改 station。
    pub const SET_STATION: u8 = 18;
    /// 新增 station。
    pub const NEW_STATION: u8 = 19;
    /// 删除 station。
    pub const DEL_STATION: u8 = 20;
    /// 连接（STA）。
    pub const CONNECT: u8 = 46;
    /// 断开（STA）。
    pub const DISCONNECT: u8 = 48;
    /// 订阅管理帧。
    pub const REGISTER_FRAME: u8 = 58;
    /// 发送/收到管理帧。
    pub const FRAME: u8 = 59;
    /// 切信道（monitor）。
    pub const SET_CHANNEL: u8 = 65;
    /// 经 nl80211 收发 control port（EAPOL 类）帧。
    pub const CONTROL_PORT_FRAME: u8 = 129;
}

/// nl80211 属性号（`NL80211_ATTR_*`）。
pub mod attr {
    #![allow(missing_docs)]
    pub const WIPHY: u16 = 1;
    pub const WIPHY_NAME: u16 = 2;
    pub const IFINDEX: u16 = 3;
    pub const IFNAME: u16 = 4;
    pub const IFTYPE: u16 = 5;
    pub const MAC: u16 = 6;
    pub const BEACON_INTERVAL: u16 = 12;
    pub const DTIM_PERIOD: u16 = 13;
    pub const BEACON_HEAD: u16 = 14;
    pub const BEACON_TAIL: u16 = 15;
    pub const STA_AID: u16 = 16;
    pub const STA_LISTEN_INTERVAL: u16 = 18;
    pub const STA_SUPPORTED_RATES: u16 = 19;
    pub const MNTR_FLAGS: u16 = 23;
    pub const HT_CAPABILITY: u16 = 31;
    pub const WIPHY_FREQ: u16 = 38;
    pub const MGMT_SUBTYPE: u16 = 41;
    pub const IE: u16 = 42;
    pub const FRAME: u16 = 51;
    pub const SSID: u16 = 52;
    pub const AUTH_TYPE: u16 = 53;
    pub const REASON_CODE: u16 = 54;
    pub const STA_FLAGS2: u16 = 67;
    pub const CONTROL_PORT: u16 = 68;
    pub const PRIVACY: u16 = 70;
    pub const STATUS_CODE: u16 = 72;
    pub const CIPHER_SUITES_PAIRWISE: u16 = 73;
    pub const CIPHER_SUITE_GROUP: u16 = 74;
    pub const AKM_SUITES: u16 = 76;
    pub const KEY: u16 = 80;
    pub const FRAME_MATCH: u16 = 91;
    pub const FRAME_TYPE: u16 = 101;
    pub const CONTROL_PORT_ETHERTYPE: u16 = 102;
    pub const HIDDEN_SSID: u16 = 126;
    pub const STA_CAPABILITY: u16 = 171;
    pub const STA_EXT_CAPABILITY: u16 = 172;
    pub const STA_SUPPORTED_CHANNELS: u16 = 189;
    pub const SOCKET_OWNER: u16 = 204;
    pub const CONTROL_PORT_OVER_NL80211: u16 = 264;
}

/// `NL80211_ATTR_KEY` 内的嵌套属性。
pub mod key_attr {
    #![allow(missing_docs)]
    pub const DATA: u16 = 1;
    pub const IDX: u16 = 2;
    pub const CIPHER: u16 = 3;
    pub const DEFAULT: u16 = 5;
    pub const DEFAULT_TYPES: u16 = 8;
    pub const DEFAULT_TYPE_MULTICAST: u16 = 2;
}

/// 接口类型（`NL80211_IFTYPE_*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum InterfaceType {
    /// STA。
    Station = 2,
    /// AP。
    Ap = 3,
    /// monitor。
    Monitor = 6,
}

/// monitor 标志：接收发给其他 BSS 的帧。
pub const MNTR_FLAG_OTHER_BSS: u16 = 4;
/// 认证类型：开放系统。
pub const AUTHTYPE_OPEN_SYSTEM: u32 = 0;
/// 隐藏 SSID：Beacon 里 SSID 内容置零（长度保留）。
pub const HIDDEN_SSID_ZERO_CONTENTS: u32 = 2;
/// station 标志位号：已授权（可以收发数据帧）。是位号不是掩码。
pub const STA_FLAG_AUTHORIZED: u32 = 1;
/// LDN 自定义认证帧使用的 control port EtherType。
pub const ETH_P_OUI: u16 = 0x88B7;
/// 管理帧的 frame type 字段值（`ftype << 2`）。
const FTYPE_MGMT: u16 = 0;

/// 一条待发送的 nl80211 请求：命令、额外的 netlink 标志位和属性。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// nl80211 命令号，见 [`cmd`]。
    pub cmd: u8,
    /// 除 `NLM_F_REQUEST | NLM_F_ACK` 以外的标志（例如 dump）。
    pub flags: u16,
    /// 属性。
    pub attrs: Attrs,
}

impl Request {
    fn new(cmd: u8) -> Self {
        Self {
            cmd,
            flags: 0,
            attrs: Attrs::new(),
        }
    }

    fn with_ifindex(cmd: u8, ifindex: u32) -> Self {
        let mut r = Self::new(cmd);
        r.attrs.u32(attr::IFINDEX, ifindex);
        r
    }

    /// 编码成完整的 netlink 消息，自动加上 `NLM_F_REQUEST | NLM_F_ACK`。
    pub fn encode(&self, family: &Family, seq: u32, pid: u32) -> Result<Vec<u8>> {
        let attrs = self.attrs.clone().finish()?;
        let payload = genl::encode_payload(self.cmd, family.version, &attrs);
        let flags = self.flags | NLM_F_REQUEST | NLM_F_ACK;
        Ok(message::encode(family.id, flags, seq, pid, &payload))
    }
}

/// 列出所有 wiphy（dump）。
pub fn get_wiphy_dump() -> Request {
    let mut r = Request::new(cmd::GET_WIPHY);
    r.flags = NLM_F_DUMP;
    r
}

/// 在 `wiphy` 上新建接口；monitor 接口额外带 `OTHER_BSS` 标志，收发任意 BSS 的帧。
pub fn new_interface(wiphy: u32, ifname: &str, iftype: InterfaceType) -> Request {
    let mut r = Request::new(cmd::NEW_INTERFACE);
    r.attrs
        .u32(attr::WIPHY, wiphy)
        .string(attr::IFNAME, ifname)
        .u32(attr::IFTYPE, iftype as u32);
    if iftype == InterfaceType::Monitor {
        let mut flags = Attrs::new();
        flags.flag(MNTR_FLAG_OTHER_BSS);
        r.attrs.nested(attr::MNTR_FLAGS, flags);
    }
    r
}

/// 删除接口。
pub fn del_interface(ifindex: u32) -> Request {
    Request::with_ifindex(cmd::DEL_INTERFACE, ifindex)
}

/// 把接口（monitor）切到给定中心频率。
pub fn set_channel(ifindex: u32, frequency: u32) -> Request {
    let mut r = Request::with_ifindex(cmd::SET_CHANNEL, ifindex);
    r.attrs.u32(attr::WIPHY_FREQ, frequency);
    r
}

/// 让驱动把给定子类型的管理帧通过 `CMD_FRAME` 事件交给本 socket。
///
/// `subtype` 是 802.11 管理帧子类型（见 `ldn_wire::frame::stype`）。
pub fn register_frame(ifindex: u32, subtype: u8) -> Request {
    let mut r = Request::with_ifindex(cmd::REGISTER_FRAME, ifindex);
    r.attrs
        .u16(
            attr::FRAME_TYPE,
            (u16::from(subtype) << 4) | (FTYPE_MGMT << 2),
        )
        .bytes(attr::FRAME_MATCH, &[]);
    r
}

/// 通过驱动发送一个管理帧（AP 模式下的 Probe/Auth/Assoc 应答）。
pub fn frame(ifindex: u32, data: &[u8]) -> Request {
    let mut r = Request::with_ifindex(cmd::FRAME, ifindex);
    r.attrs.bytes(attr::FRAME, data);
    r
}

/// 经 control port 向 `mac` 发送 LDN 自定义帧（EtherType 0x88B7）。
pub fn control_port_frame(ifindex: u32, mac: MacAddress, data: &[u8]) -> Request {
    let mut r = Request::with_ifindex(cmd::CONTROL_PORT_FRAME, ifindex);
    r.attrs
        .bytes(attr::FRAME, data)
        .bytes(attr::MAC, &mac.octets())
        .bytes(attr::CONTROL_PORT_ETHERTYPE, &ETH_P_OUI.to_ne_bytes());
    r
}

/// 追加 control port 相关的四个属性：把 0x88B7 帧交给本 socket，并让接口随本 socket 关闭而撤销。
fn control_port_attrs(a: &mut Attrs) {
    a.flag(attr::CONTROL_PORT)
        .bytes(attr::CONTROL_PORT_ETHERTYPE, &ETH_P_OUI.to_ne_bytes())
        .flag(attr::CONTROL_PORT_OVER_NL80211)
        .flag(attr::SOCKET_OWNER);
}

/// 安装一个 CCMP 密钥。`mac` 为 `Some` 时是对端的成对密钥，`None` 时是组播密钥。
pub fn new_key(ifindex: u32, mac: Option<MacAddress>, index: u8, key: &[u8]) -> Request {
    let mut r = Request::with_ifindex(cmd::NEW_KEY, ifindex);
    if let Some(mac) = mac {
        r.attrs.bytes(attr::MAC, &mac.octets());
    }
    let mut k = Attrs::new();
    k.u8(key_attr::IDX, index)
        .bytes(key_attr::DATA, key)
        .u32(key_attr::CIPHER, WLAN_CIPHER_SUITE_CCMP);
    r.attrs.nested(attr::KEY, k);
    r
}

/// 把 `index` 号密钥设为默认组播密钥。
pub fn set_default_multicast_key(ifindex: u32, index: u8) -> Request {
    let mut r = Request::with_ifindex(cmd::SET_KEY, ifindex);
    let mut types = Attrs::new();
    types.flag(key_attr::DEFAULT_TYPE_MULTICAST);
    let mut k = Attrs::new();
    k.u8(key_attr::IDX, index)
        .flag(key_attr::DEFAULT)
        .nested(key_attr::DEFAULT_TYPES, types);
    r.attrs.nested(attr::KEY, k);
    r
}

/// STA 加入网络的参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectParams<'a> {
    /// 接口。
    pub ifindex: u32,
    /// SSID 原始字节（LDN 里是 16 字节随机数的十六进制文本）。
    pub ssid: &'a [u8],
    /// 中心频率（MHz）。
    pub frequency: u32,
    /// 网络是否加密（CCMP + PSK）。为真时附带 RSN IE 与密码套件。
    pub privacy: bool,
    /// 加密时放进关联请求的 IE（RSN 元素），`privacy` 为假时忽略。
    pub ie: &'a [u8],
}

/// STA 连接网络。
///
/// 与 Python 版的差异：Python 版在不加密时也会发出 `NL80211_ATTR_PRIVACY`
/// （python-netlink 的 flag 类型无论值真假都编码成“存在”），这里不加密就不发。
pub fn connect(p: &ConnectParams<'_>) -> Request {
    let mut r = Request::with_ifindex(cmd::CONNECT, p.ifindex);
    let a = &mut r.attrs;
    a.bytes(attr::SSID, p.ssid)
        .u32(attr::WIPHY_FREQ, p.frequency)
        .u32(attr::AUTH_TYPE, AUTHTYPE_OPEN_SYSTEM);
    control_port_attrs(a);
    if p.privacy {
        a.bytes(
            attr::CIPHER_SUITES_PAIRWISE,
            &WLAN_CIPHER_SUITE_CCMP.to_ne_bytes(),
        )
        .u32(attr::CIPHER_SUITE_GROUP, WLAN_CIPHER_SUITE_CCMP)
        .bytes(attr::AKM_SUITES, &WLAN_AKM_SUITE_PSK.to_ne_bytes())
        .bytes(attr::IE, p.ie)
        .flag(attr::PRIVACY);
    }
    r
}

/// STA 断开。
pub fn disconnect(ifindex: u32) -> Request {
    Request::with_ifindex(cmd::DISCONNECT, ifindex)
}

/// 把对端 station 标记为已授权（STA 侧对 AP 做）。
pub fn set_station_authorized(ifindex: u32, mac: MacAddress) -> Request {
    let mut r = Request::with_ifindex(cmd::SET_STATION, ifindex);
    // nl80211_sta_flag_update { mask, set }，两者都是按位号左移得到的位图。
    let bit = 1u32 << STA_FLAG_AUTHORIZED;
    let mut flags = bit.to_ne_bytes().to_vec();
    flags.extend_from_slice(&bit.to_ne_bytes());
    r.attrs
        .bytes(attr::MAC, &mac.octets())
        .bytes(attr::STA_FLAGS2, &flags);
    r
}

/// 启动 AP 的参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartApParams<'a> {
    /// 接口。
    pub ifindex: u32,
    /// SSID 原始字节。
    pub ssid: &'a [u8],
    /// AP 的 MAC 地址。
    pub mac: MacAddress,
    /// 中心频率（MHz）。
    pub frequency: u32,
    /// Beacon 帧中 TIM 元素之前的部分（MAC 头 + 固定字段 + IE）。
    pub beacon_head: &'a [u8],
    /// Beacon 帧中 TIM 元素之后的部分。
    pub beacon_tail: &'a [u8],
    /// Beacon 间隔（TU）。
    pub beacon_interval: u32,
    /// DTIM 周期。
    pub dtim_period: u32,
}

/// 启动 AP；SSID 以“内容置零”方式隐藏，与 Switch 的行为一致。
pub fn start_ap(p: &StartApParams<'_>) -> Request {
    let mut r = Request::with_ifindex(cmd::START_AP, p.ifindex);
    let a = &mut r.attrs;
    a.bytes(attr::SSID, p.ssid)
        .bytes(attr::MAC, &p.mac.octets())
        .u32(attr::WIPHY_FREQ, p.frequency)
        .bytes(attr::BEACON_HEAD, p.beacon_head)
        .bytes(attr::BEACON_TAIL, p.beacon_tail)
        .u32(attr::BEACON_INTERVAL, p.beacon_interval)
        .u32(attr::DTIM_PERIOD, p.dtim_period)
        .u32(attr::HIDDEN_SSID, HIDDEN_SSID_ZERO_CONTENTS);
    control_port_attrs(a);
    r
}

/// 停止 AP。
pub fn stop_ap(ifindex: u32) -> Request {
    Request::with_ifindex(cmd::STOP_AP, ifindex)
}

/// AP 接纳一个 station 时交给驱动的参数，取自对方的关联请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewStationParams<'a> {
    /// 接口。
    pub ifindex: u32,
    /// station 地址。
    pub mac: MacAddress,
    /// Listen Interval。
    pub listen_interval: u16,
    /// Supported Rates 元素内容。
    pub supported_rates: &'a [u8],
    /// Capability Information。
    pub capability: u16,
    /// 分配的 AID（不含最高两位）。
    pub aid: u16,
    /// Extended Capabilities 元素内容（可选）。
    pub ext_capability: Option<&'a [u8]>,
    /// HT Capabilities 元素内容（可选）。
    pub ht_capability: Option<&'a [u8]>,
    /// Supported Channels 元素内容（可选）。
    pub supported_channels: Option<&'a [u8]>,
}

/// AP 新增 station。
pub fn new_station(p: &NewStationParams<'_>) -> Request {
    let mut r = Request::with_ifindex(cmd::NEW_STATION, p.ifindex);
    let a = &mut r.attrs;
    a.bytes(attr::MAC, &p.mac.octets())
        .u16(attr::STA_LISTEN_INTERVAL, p.listen_interval)
        .bytes(attr::STA_SUPPORTED_RATES, p.supported_rates)
        .u16(attr::STA_CAPABILITY, p.capability)
        .u16(attr::STA_AID, p.aid);
    if let Some(v) = p.ext_capability {
        a.bytes(attr::STA_EXT_CAPABILITY, v);
    }
    if let Some(v) = p.ht_capability {
        a.bytes(attr::HT_CAPABILITY, v);
    }
    if let Some(v) = p.supported_channels {
        a.bytes(attr::STA_SUPPORTED_CHANNELS, v);
    }
    r
}

/// AP 删除 station。`subtype` 为 `Some` 时表示是对方发来的解除关联/认证帧触发的删除。
pub fn del_station(ifindex: u32, mac: MacAddress, subtype: Option<u8>, reason: u16) -> Request {
    let mut r = Request::with_ifindex(cmd::DEL_STATION, ifindex);
    r.attrs.bytes(attr::MAC, &mac.octets());
    if let Some(s) = subtype {
        r.attrs.u8(attr::MGMT_SUBTYPE, s);
    }
    r.attrs.u16(attr::REASON_CODE, reason);
    r
}

fn mac_attr(msg: &GenlMessage<'_>) -> Result<MacAddress> {
    MacAddress::try_from(msg.attrs.require(attr::MAC)?)
        .map_err(|_| Error::InvalidAttribute(attr::MAC))
}

/// wiphy dump 回复中的一项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wiphy {
    /// wiphy 索引。
    pub index: u32,
    /// 名字（例如 `phy0`）。
    pub name: String,
}

impl Wiphy {
    /// 从 genl 消息解析；拆分 dump 的后续分片可能不带名字，此时返回 `None`。
    pub fn parse(msg: &GenlMessage<'_>) -> Result<Option<Self>> {
        if !msg.attrs.contains(attr::WIPHY_NAME) {
            return Ok(None);
        }
        Ok(Some(Self {
            index: msg.attrs.u32(attr::WIPHY)?,
            name: msg.attrs.string(attr::WIPHY_NAME)?,
        }))
    }
}

/// `NEW_INTERFACE` 回复里 LDN 关心的字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewInterface {
    /// 新接口的 ifindex。
    pub ifindex: u32,
    /// 新接口的 MAC 地址。
    pub mac: MacAddress,
}

impl NewInterface {
    /// 从 `NEW_INTERFACE` 回复解析。
    pub fn parse(msg: &GenlMessage<'_>) -> Result<Self> {
        Ok(Self {
            ifindex: msg.attrs.u32(attr::IFINDEX)?,
            mac: mac_attr(msg)?,
        })
    }
}

/// 内核经 `mlme` 组播组或单播推送的、LDN 关心的 nl80211 事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// STA 连接结果。
    Connect {
        /// 802.11 状态码，0 为成功。
        status: u16,
        /// AP 地址；失败时可能缺失。
        bssid: Option<MacAddress>,
    },
    /// AP 已启动。
    StartAp,
    /// 收到订阅的管理帧。
    Frame {
        /// 完整 802.11 帧（MAC 头起）。
        frame: Vec<u8>,
        /// 所在频率（MHz）。
        frequency: Option<u32>,
    },
    /// 收到 control port 帧（LDN 自定义认证帧）。
    ControlPortFrame {
        /// 发送方。
        mac: MacAddress,
        /// 帧内容（EtherType 之后）。
        frame: Vec<u8>,
    },
    /// station 被删除（STA 侧：被 AP 踢出）。
    DelStation {
        /// station 地址。
        mac: MacAddress,
    },
    /// 其他命令，LDN 不处理。
    Other(u8),
}

impl Event {
    /// 从 genl 消息解析事件；LDN 关心的事件缺少必需属性时报错。
    pub fn parse(msg: &GenlMessage<'_>) -> Result<Self> {
        let a = &msg.attrs;
        Ok(match msg.cmd {
            cmd::CONNECT => Self::Connect {
                status: a.u16(attr::STATUS_CODE)?,
                bssid: if a.contains(attr::MAC) {
                    Some(mac_attr(msg)?)
                } else {
                    None
                },
            },
            cmd::START_AP => Self::StartAp,
            cmd::FRAME => Self::Frame {
                frame: a.require(attr::FRAME)?.to_vec(),
                frequency: a.opt_u32(attr::WIPHY_FREQ)?,
            },
            cmd::CONTROL_PORT_FRAME => Self::ControlPortFrame {
                mac: mac_attr(msg)?,
                frame: a.require(attr::FRAME)?.to_vec(),
            },
            cmd::DEL_STATION => Self::DelStation {
                mac: mac_attr(msg)?,
            },
            other => Self::Other(other),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genl::encode_payload;

    const MAC: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 1]);

    fn roundtrip(r: &Request) -> Vec<u8> {
        let attrs = r.attrs.clone().finish().unwrap();
        encode_payload(r.cmd, 1, &attrs)
    }

    #[test]
    fn events_parse() {
        let mut a = Attrs::new();
        a.bytes(attr::FRAME, &[0xD0, 0]).u32(attr::WIPHY_FREQ, 2437);
        let payload = encode_payload(cmd::FRAME, 1, &a.finish().unwrap());
        let ev = Event::parse(&GenlMessage::parse(&payload).unwrap()).unwrap();
        assert_eq!(
            ev,
            Event::Frame {
                frame: vec![0xD0, 0],
                frequency: Some(2437)
            }
        );

        let mut a = Attrs::new();
        a.u16(attr::STATUS_CODE, 17);
        let payload = encode_payload(cmd::CONNECT, 1, &a.finish().unwrap());
        let ev = Event::parse(&GenlMessage::parse(&payload).unwrap()).unwrap();
        assert_eq!(
            ev,
            Event::Connect {
                status: 17,
                bssid: None
            }
        );

        let payload = encode_payload(99, 1, &[]);
        assert_eq!(
            Event::parse(&GenlMessage::parse(&payload).unwrap()),
            Ok(Event::Other(99))
        );
    }

    #[test]
    fn event_missing_attribute_is_error() {
        let payload = encode_payload(cmd::DEL_STATION, 1, &[]);
        let msg = GenlMessage::parse(&payload).unwrap();
        assert_eq!(Event::parse(&msg), Err(Error::MissingAttribute(attr::MAC)));
    }

    #[test]
    fn unencrypted_connect_has_no_privacy() {
        let p = ConnectParams {
            ifindex: 1,
            ssid: b"x",
            frequency: 2412,
            privacy: false,
            ie: &[],
        };
        let payload = roundtrip(&connect(&p));
        let msg = GenlMessage::parse(&payload).unwrap();
        assert!(!msg.attrs.contains(attr::PRIVACY));
        assert!(!msg.attrs.contains(attr::IE));
        assert!(msg.attrs.contains(attr::SOCKET_OWNER));
    }

    #[test]
    fn non_monitor_interface_has_no_flags() {
        let payload = roundtrip(&new_interface(0, "ldn", InterfaceType::Ap));
        let msg = GenlMessage::parse(&payload).unwrap();
        assert!(!msg.attrs.contains(attr::MNTR_FLAGS));
        assert_eq!(msg.attrs.u32(attr::IFTYPE), Ok(3));
    }

    #[test]
    fn wiphy_fragment_without_name_is_skipped() {
        let mut a = Attrs::new();
        a.u32(attr::WIPHY, 0);
        let payload = encode_payload(cmd::NEW_WIPHY, 1, &a.finish().unwrap());
        assert_eq!(
            Wiphy::parse(&GenlMessage::parse(&payload).unwrap()),
            Ok(None)
        );
    }

    #[test]
    fn del_station_optional_subtype() {
        let payload = roundtrip(&del_station(1, MAC, None, 1));
        assert!(
            !GenlMessage::parse(&payload)
                .unwrap()
                .attrs
                .contains(attr::MGMT_SUBTYPE)
        );
    }
}
