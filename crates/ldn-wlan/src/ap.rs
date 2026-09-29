//! AP 接口的管理帧处理逻辑（sans-IO）。
//!
//! 对应 Python 版 `AccessPoint` 的 `_process_frame` 一族：驱动把订阅的管理帧交上来，
//! 这里决定回什么帧、要驱动做什么（加/删 station、装密钥），以及向上层报告什么事件。
//! 只产出“动作”，不做 I/O，由 [`crate::interface::AccessPoint`] 按顺序执行，
//! 所以认证、关联、人满、重复关联等分支都能不接网卡测试。

use std::collections::BTreeMap;

use ldn_netlink::nl80211::{self, NewStationParams, Request};
use ldn_wire::MacAddress;
use ldn_wire::element::{Elements, RsnElement, WLAN_AKM_SUITE_PSK, WLAN_CIPHER_SUITE_CCMP, eid};
use ldn_wire::frame::{
    AssociationRequest, AssociationResponse, AuthenticationFrame, BeaconFrame,
    DeauthenticationFrame, Frame, ProbeResponse, WLAN_AUTH_OPEN, reason, status, stype,
};

use crate::error::Result;

/// AP 声明的速率集：1/2/5.5/11 Mbps（基本速率）+ 18/24/36/54 Mbps。
const SUPPORTED_RATES: [u8; 8] = [0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C];
const BEACON_INTERVAL: u16 = 100;
/// Capability：ESS | Short Preamble | Short Slot Time，另含 Beacon 的 IBSS 位（0x511）。
const BEACON_CAPABILITY: u16 = 0x511;
const PROBE_CAPABILITY: u16 = 0x501;
const ASSOC_CAPABILITY: u16 = 0x411;
/// Capability 的 Privacy 位。
const CAPABILITY_PRIVACY: u16 = 0x10;
/// AID 字段最高两位按标准置 1。
const AID_FLAGS: u16 = 0xC000;

/// AP 配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApConfig {
    /// 接口 ifindex，写进 nl80211 请求。
    pub ifindex: u32,
    /// AP 的 MAC 地址（也是 BSSID）。
    pub mac: MacAddress,
    /// SSID 原始字节。
    pub ssid: Vec<u8>,
    /// 信道号。
    pub channel: u8,
    /// 数据帧 CCMP 密钥；`None` 表示不加密。
    pub key: Option<Vec<u8>>,
    /// 最多接纳的 station 数（不含主机自己）。
    pub max_stations: usize,
}

/// 需要上报给 LDN 层的事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApEvent {
    /// station 完成 802.11 关联（LDN 自己的认证还没做）。
    Associated(MacAddress),
    /// station 主动解除关联或认证。
    Disassociated(MacAddress),
}

/// 处理一个管理帧后要执行的动作，必须按顺序执行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApAction {
    /// 经 `NL80211_CMD_FRAME` 发送一个管理帧。
    SendFrame(Vec<u8>),
    /// 发一条 nl80211 请求（加/删 station、装密钥）。
    Request(Request),
    /// 上报事件。
    Event(ApEvent),
}

/// AP 的管理帧状态机：维护 AID 分配表。
#[derive(Debug, Clone)]
pub struct ApCore {
    config: ApConfig,
    stations: BTreeMap<MacAddress, u16>,
}

impl ApCore {
    /// 以给定配置创建，初始没有 station。
    pub fn new(config: ApConfig) -> Self {
        Self {
            config,
            stations: BTreeMap::new(),
        }
    }

    /// 配置。
    pub fn config(&self) -> &ApConfig {
        &self.config
    }

    /// 当前已关联的 station 及其 AID。
    pub fn stations(&self) -> &BTreeMap<MacAddress, u16> {
        &self.stations
    }

    /// `START_AP` 用的 Beacon 头：不带任何 IE（SSID 由驱动按隐藏方式补上）。
    pub fn beacon_head(&self) -> Result<Vec<u8>> {
        let beacon = BeaconFrame {
            source: self.config.mac,
            beacon_interval: BEACON_INTERVAL,
            capability_information: BEACON_CAPABILITY,
            ..Default::default()
        };
        Ok(beacon.encode()?)
    }

    /// 处理驱动交上来的一个管理帧。与本 AP 无关的帧返回空动作列表。
    pub fn handle_frame(&mut self, frame: &Frame) -> Result<Vec<ApAction>> {
        let ssid_matches = |e: &Elements| e.get(&eid::SSID).is_some_and(|s| *s == self.config.ssid);
        Ok(match frame {
            Frame::ProbeRequest(f) if ssid_matches(&f.elements) => {
                vec![ApAction::SendFrame(self.probe_response(f.source)?)]
            }
            Frame::Authentication(f)
                if f.bssid == self.config.mac
                    && f.algorithm == WLAN_AUTH_OPEN
                    && f.sequence == 1 =>
            {
                let response = AuthenticationFrame {
                    target: f.source,
                    source: self.config.mac,
                    bssid: self.config.mac,
                    algorithm: WLAN_AUTH_OPEN,
                    sequence: 2,
                    status_code: status::SUCCESS,
                    ..Default::default()
                };
                vec![ApAction::SendFrame(response.encode()?)]
            }
            Frame::AssociationRequest(f) if ssid_matches(&f.elements) => self.associate(f)?,
            Frame::Disassociation(f) => self.disassociate(f.source, stype::DISASSOC, f.reason),
            Frame::Deauthentication(f) => self.disassociate(f.source, stype::DEAUTH, f.reason),
            _ => Vec::new(),
        })
    }

    /// 主动踢出 station：发 Deauthentication 并让驱动删除它。未关联的地址返回空列表。
    pub fn remove_station(&mut self, mac: MacAddress) -> Result<Vec<ApAction>> {
        if self.stations.remove(&mac).is_none() {
            return Ok(Vec::new());
        }
        let deauth = DeauthenticationFrame {
            target: mac,
            source: self.config.mac,
            bssid: self.config.mac,
            reason: reason::UNSPECIFIED,
            ..Default::default()
        };
        Ok(vec![
            ApAction::SendFrame(deauth.encode()?),
            ApAction::Request(nl80211::del_station(
                self.config.ifindex,
                mac,
                None,
                reason::UNSPECIFIED,
            )),
        ])
    }

    fn probe_response(&self, target: MacAddress) -> Result<Vec<u8>> {
        let mut response = ProbeResponse {
            target,
            source: self.config.mac,
            beacon_interval: BEACON_INTERVAL,
            capability_information: PROBE_CAPABILITY,
            elements: Elements::from([
                (eid::SSID, self.config.ssid.clone()),
                (eid::SUPP_RATES, SUPPORTED_RATES.to_vec()),
                (eid::DS_PARAMS, vec![self.config.channel]),
            ]),
            ..Default::default()
        };
        if self.config.key.is_some() {
            response.capability_information |= CAPABILITY_PRIVACY;
            let rsn = RsnElement {
                group_cipher_suite: WLAN_CIPHER_SUITE_CCMP,
                pairwise_cipher_suites: vec![WLAN_CIPHER_SUITE_CCMP],
                akm_suites: vec![WLAN_AKM_SUITE_PSK],
                capabilities: 12,
            };
            response.elements.insert(eid::RSN, rsn.encode()?);
        }
        Ok(response.encode()?)
    }

    fn association_response(
        &self,
        target: MacAddress,
        status_code: u16,
        aid: u16,
    ) -> Result<Vec<u8>> {
        let success = status_code == status::SUCCESS;
        let response = AssociationResponse {
            target,
            source: self.config.mac,
            capability_information: ASSOC_CAPABILITY,
            status_code,
            aid: if success { aid | AID_FLAGS } else { 0 },
            elements: if success {
                Elements::from([(eid::SUPP_RATES, SUPPORTED_RATES.to_vec())])
            } else {
                Elements::new()
            },
        };
        Ok(response.encode()?)
    }

    fn associate(&mut self, f: &AssociationRequest) -> Result<Vec<ApAction>> {
        // 重复的关联请求（对方没收到应答而重发）：沿用已分配的 AID，不再通知驱动。
        if let Some(&aid) = self.stations.get(&f.source) {
            return Ok(vec![ApAction::SendFrame(self.association_response(
                f.source,
                status::SUCCESS,
                aid,
            )?)]);
        }
        if self.stations.len() >= self.config.max_stations {
            let error =
                self.association_response(f.source, status::AP_UNABLE_TO_HANDLE_NEW_STA, 0)?;
            return Ok(vec![ApAction::SendFrame(error)]);
        }
        let Some(rates) = f.elements.get(&eid::SUPP_RATES) else {
            let error = self.association_response(f.source, status::ASSOC_DENIED_UNSPEC, 0)?;
            return Ok(vec![ApAction::SendFrame(error)]);
        };

        // 分配最小的空闲 AID（从 1 开始）。
        let used: Vec<u16> = self.stations.values().copied().collect();
        let aid = (1..)
            .find(|a| !used.contains(a))
            .expect("AID space exhausted");
        self.stations.insert(f.source, aid);

        let params = NewStationParams {
            ifindex: self.config.ifindex,
            mac: f.source,
            listen_interval: f.listen_interval,
            supported_rates: rates,
            capability: f.capability_information,
            aid,
            ext_capability: f.elements.get(&eid::EXT_CAPABILITY).map(Vec::as_slice),
            ht_capability: f.elements.get(&eid::HT_CAPABILITY).map(Vec::as_slice),
            supported_channels: f.elements.get(&eid::SUPPORTED_CHANNELS).map(Vec::as_slice),
        };
        let mut actions = vec![ApAction::Request(nl80211::new_station(&params))];
        if let Some(key) = &self.config.key {
            actions.push(ApAction::Request(nl80211::new_key(
                self.config.ifindex,
                Some(f.source),
                0,
                key,
            )));
        }
        actions.push(ApAction::Event(ApEvent::Associated(f.source)));
        actions.push(ApAction::SendFrame(self.association_response(
            f.source,
            status::SUCCESS,
            aid,
        )?));
        Ok(actions)
    }

    fn disassociate(&mut self, mac: MacAddress, subtype: u8, reason: u16) -> Vec<ApAction> {
        if self.stations.remove(&mac).is_none() {
            return Vec::new();
        }
        vec![
            ApAction::Request(nl80211::del_station(
                self.config.ifindex,
                mac,
                Some(subtype),
                reason,
            )),
            ApAction::Event(ApEvent::Disassociated(mac)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldn_wire::frame::{DisassociationFrame, ProbeRequest};

    const AP: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 1]);

    fn sta(n: u8) -> MacAddress {
        MacAddress::new([2, 0, 0, 0, 1, n])
    }

    fn core(max: usize, key: bool) -> ApCore {
        ApCore::new(ApConfig {
            ifindex: 7,
            mac: AP,
            ssid: b"ssid".to_vec(),
            channel: 6,
            key: key.then(|| vec![0; 16]),
            max_stations: max,
        })
    }

    fn assoc(mac: MacAddress, rates: bool) -> Frame {
        let mut elements = Elements::from([(eid::SSID, b"ssid".to_vec())]);
        if rates {
            elements.insert(eid::SUPP_RATES, vec![0x82]);
        }
        Frame::AssociationRequest(AssociationRequest {
            target: AP,
            source: mac,
            elements,
            ..Default::default()
        })
    }

    fn sent_status(actions: &[ApAction]) -> (u16, u16) {
        let Some(ApAction::SendFrame(bytes)) = actions.last() else {
            panic!("no frame sent: {actions:?}")
        };
        let r = AssociationResponse::decode(bytes).unwrap();
        (r.status_code, r.aid)
    }

    #[test]
    fn probe_only_answers_own_ssid() {
        let mut c = core(4, true);
        let probe = |ssid: &[u8]| {
            Frame::ProbeRequest(ProbeRequest {
                source: sta(1),
                elements: Elements::from([(eid::SSID, ssid.to_vec())]),
            })
        };
        assert!(c.handle_frame(&probe(b"other")).unwrap().is_empty());
        let actions = c.handle_frame(&probe(b"ssid")).unwrap();
        let [ApAction::SendFrame(bytes)] = actions.as_slice() else {
            panic!()
        };
        let r = ProbeResponse::decode(bytes).unwrap();
        assert_eq!(r.capability_information, 0x511);
        assert!(r.elements.contains_key(&eid::RSN));

        let mut open = core(4, false);
        let actions = open.handle_frame(&probe(b"ssid")).unwrap();
        let [ApAction::SendFrame(bytes)] = actions.as_slice() else {
            panic!()
        };
        assert!(
            !ProbeResponse::decode(bytes)
                .unwrap()
                .elements
                .contains_key(&eid::RSN)
        );
    }

    #[test]
    fn auth_only_for_our_bssid_and_first_transaction() {
        let mut c = core(4, false);
        let auth = |bssid, sequence| {
            Frame::Authentication(AuthenticationFrame {
                target: AP,
                source: sta(1),
                bssid,
                sequence,
                ..Default::default()
            })
        };
        assert!(c.handle_frame(&auth(sta(9), 1)).unwrap().is_empty());
        assert!(c.handle_frame(&auth(AP, 3)).unwrap().is_empty());
        let actions = c.handle_frame(&auth(AP, 1)).unwrap();
        let [ApAction::SendFrame(bytes)] = actions.as_slice() else {
            panic!()
        };
        let r = AuthenticationFrame::decode(bytes).unwrap();
        assert_eq!((r.target, r.sequence, r.status_code), (sta(1), 2, 0));
    }

    #[test]
    fn association_allocates_lowest_free_aid() {
        let mut c = core(4, true);
        let a1 = c.handle_frame(&assoc(sta(1), true)).unwrap();
        assert_eq!(a1.len(), 4); // NEW_STATION, NEW_KEY, 事件, 应答
        assert_eq!(a1[2], ApAction::Event(ApEvent::Associated(sta(1))));
        assert_eq!(sent_status(&a1), (0, 0xC001));
        assert_eq!(
            sent_status(&c.handle_frame(&assoc(sta(2), true)).unwrap()),
            (0, 0xC002)
        );

        // 1 号离开后，新来的 station 复用 AID 1。
        c.remove_station(sta(1)).unwrap();
        assert_eq!(
            sent_status(&c.handle_frame(&assoc(sta(3), true)).unwrap()),
            (0, 0xC001)
        );
    }

    #[test]
    fn repeated_association_reuses_aid_without_driver_calls() {
        let mut c = core(4, false);
        c.handle_frame(&assoc(sta(1), true)).unwrap();
        let again = c.handle_frame(&assoc(sta(1), true)).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(sent_status(&again), (0, 0xC001));
    }

    #[test]
    fn association_rejections() {
        let mut c = core(1, false);
        assert_eq!(
            sent_status(&c.handle_frame(&assoc(sta(1), false)).unwrap()),
            (status::ASSOC_DENIED_UNSPEC, 0)
        );
        c.handle_frame(&assoc(sta(1), true)).unwrap();
        let full = c.handle_frame(&assoc(sta(2), true)).unwrap();
        assert_eq!(full.len(), 1);
        assert_eq!(sent_status(&full), (status::AP_UNABLE_TO_HANDLE_NEW_STA, 0));
    }

    #[test]
    fn disassociation_of_unknown_station_is_ignored() {
        let mut c = core(4, false);
        let disassoc = Frame::Disassociation(DisassociationFrame {
            source: sta(1),
            reason: 8,
            ..Default::default()
        });
        assert!(c.handle_frame(&disassoc).unwrap().is_empty());
        c.handle_frame(&assoc(sta(1), true)).unwrap();
        let actions = c.handle_frame(&disassoc).unwrap();
        assert_eq!(actions[1], ApAction::Event(ApEvent::Disassociated(sta(1))));
        assert!(c.stations().is_empty());
        assert!(c.remove_station(sta(1)).unwrap().is_empty());
    }
}
