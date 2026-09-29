//! 与 Python 版（wlan.py + python-netlink）发出的 netlink 消息逐字节对拍。
//!
//! 期望值由 `tools/gen_netlink_vectors.py` 驱动 Python 真实代码路径截获，
//! 场景和取值与脚本里的常量一一对应。管理帧的内容（Probe/Assoc 应答等）属于
//! ldn-wlan 的 AP 逻辑，这里直接取 Python 向量里的帧字节，只校验 netlink 封装；
//! 帧内容本身在 ldn-wlan 的对拍测试里校验。

#[allow(dead_code)]
mod vectors {
    include!("vectors/python_netlink_vectors.rs");
}

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ldn_netlink::genl::{self, Family, GenlMessage};
use ldn_netlink::message::{ErrorMessage, parse_messages};
use ldn_netlink::nl80211::{self as nl, InterfaceType, Request, attr};
use ldn_netlink::rtnl::{self, RouteRequest};
use ldn_wire::MacAddress;
use ldn_wire::element::{
    Elements, RsnElement, WLAN_AKM_SUITE_PSK, WLAN_CIPHER_SUITE_CCMP, eid, encode_elements,
};
use ldn_wire::frame::{BeaconFrame, stype};

const PID: u32 = 4242;
const IFINDEX: u32 = 7;
const WIPHY_INDEX: u32 = 3;
const AP: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 1]);
const STA: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 2]);
const STA2: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 3]);
const SSID: &[u8] = b"00112233445566778899aabbccddeeff";
const FREQ: u32 = 2437;
const KEY: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
const CUSTOM_FRAME: &[u8] = &[0x7f, 0x00, 0x22, 0xaa];

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn family() -> Family {
    Family {
        id: 0x22,
        name: "nl80211".into(),
        version: 1,
        hdrsize: 0,
        mcast_groups: BTreeMap::new(),
    }
}

/// 按顺序比对一组 nl80211 请求；序号从 1 开始，与 Python 场景一致。
fn assert_nl(vector: &[&str], requests: &[Request]) {
    assert_eq!(vector.len(), requests.len(), "message count");
    for (i, (hex, req)) in vector.iter().zip(requests).enumerate() {
        let seq = i as u32 + 1;
        assert_eq!(
            req.encode(&family(), seq, PID).unwrap(),
            unhex(hex),
            "nl80211 message #{seq}"
        );
    }
}

fn assert_route(vector: &[&str], requests: &[RouteRequest]) {
    assert_eq!(vector.len(), requests.len(), "message count");
    for (i, (hex, req)) in vector.iter().zip(requests).enumerate() {
        let seq = i as u32 + 1;
        assert_eq!(
            req.encode(seq, PID).unwrap(),
            unhex(hex),
            "rtnetlink message #{seq}"
        );
    }
}

/// 取出 Python 某条 `CMD_FRAME` 请求里的帧字节。
fn python_frame(hex: &str) -> Vec<u8> {
    let data = unhex(hex);
    let msg = &parse_messages(&data).unwrap()[0];
    GenlMessage::parse(msg.payload)
        .unwrap()
        .attrs
        .require(attr::FRAME)
        .unwrap()
        .to_vec()
}

fn rsn_ie() -> Vec<u8> {
    let rsn = RsnElement {
        group_cipher_suite: WLAN_CIPHER_SUITE_CCMP,
        pairwise_cipher_suites: vec![WLAN_CIPHER_SUITE_CCMP],
        akm_suites: vec![WLAN_AKM_SUITE_PSK],
        capabilities: 12,
    };
    encode_elements(&Elements::from([(eid::RSN, rsn.encode().unwrap())])).unwrap()
}

#[test]
fn ctrl_get_family() {
    assert_eq!(
        genl::get_family_request("nl80211", 1, PID).unwrap(),
        unhex(vectors::CTRL_GETFAMILY[0])
    );
    let family = Family::parse(&unhex(vectors::CTRL_FAMILY_REPLY[0])).unwrap();
    assert_eq!(family.id, 0x22);
    assert_eq!(family.version, 1);
    assert_eq!(family.mcast_groups.get("mlme"), Some(&7));
    assert_eq!(family.mcast_groups.get("config"), Some(&5));
}

#[test]
fn monitor() {
    assert_nl(
        vectors::MONITOR_NL80211,
        &[
            nl::get_wiphy_dump(),
            nl::new_interface(WIPHY_INDEX, "ldn-mon", InterfaceType::Monitor),
            nl::set_channel(IFINDEX, FREQ),
            nl::del_interface(IFINDEX),
        ],
    );
    assert_route(vectors::MONITOR_ROUTE, &[rtnl::set_link_up(IFINDEX)]);

    let reply = unhex(vectors::WIPHY_DUMP_REPLY[0]);
    let wiphy = nl::Wiphy::parse(&GenlMessage::parse(&reply).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        wiphy,
        nl::Wiphy {
            index: WIPHY_INDEX,
            name: "phy0".into()
        }
    );
}

#[test]
fn station() {
    let ie = rsn_ie();
    let connect = nl::ConnectParams {
        ifindex: IFINDEX,
        ssid: SSID,
        frequency: FREQ,
        privacy: true,
        ie: &ie,
    };
    assert_nl(
        vectors::STATION_NL80211,
        &[
            nl::connect(&connect),
            nl::new_key(IFINDEX, Some(AP), 0, &KEY),
            nl::new_key(IFINDEX, None, 1, &KEY),
            nl::register_frame(IFINDEX, stype::ACTION),
            nl::control_port_frame(IFINDEX, AP, CUSTOM_FRAME),
            nl::set_station_authorized(IFINDEX, AP),
            nl::disconnect(IFINDEX),
        ],
    );
    assert_route(vectors::STATION_ROUTE, &[rtnl::set_link_up(IFINDEX)]);

    let event = unhex(vectors::CONNECT_EVENT[0]);
    let ev = nl::Event::parse(&GenlMessage::parse(&event).unwrap()).unwrap();
    assert_eq!(
        ev,
        nl::Event::Connect {
            status: 0,
            bssid: Some(AP)
        }
    );
}

#[test]
fn access_point() {
    let v = vectors::AP_NL80211;
    let head = BeaconFrame {
        source: AP,
        beacon_interval: 100,
        capability_information: 0x511,
        ..Default::default()
    }
    .encode()
    .unwrap();
    let start = nl::StartApParams {
        ifindex: IFINDEX,
        ssid: SSID,
        mac: AP,
        frequency: FREQ,
        beacon_head: &head,
        beacon_tail: &[],
        beacon_interval: 100,
        dtim_period: 3,
    };
    let rates = [0x82, 0x84, 0x8b, 0x96];
    let sta1 = nl::NewStationParams {
        ifindex: IFINDEX,
        mac: STA,
        listen_interval: 10,
        supported_rates: &rates,
        capability: 0x0421,
        aid: 1,
        ext_capability: Some(&[0x04]),
        ht_capability: Some(&[0x2c, 0x01]),
        supported_channels: None,
    };
    let sta2 = nl::NewStationParams {
        mac: STA2,
        aid: 2,
        ext_capability: None,
        ht_capability: None,
        ..sta1
    };
    assert_nl(
        v,
        &[
            nl::start_ap(&start),
            nl::new_key(IFINDEX, None, 1, &KEY),
            nl::set_default_multicast_key(IFINDEX, 1),
            nl::register_frame(IFINDEX, stype::ASSOC_REQ),
            nl::register_frame(IFINDEX, stype::PROBE_REQ),
            nl::register_frame(IFINDEX, stype::DISASSOC),
            nl::register_frame(IFINDEX, stype::AUTH),
            nl::register_frame(IFINDEX, stype::DEAUTH),
            nl::frame(IFINDEX, &python_frame(v[8])),
            nl::frame(IFINDEX, &python_frame(v[9])),
            nl::new_station(&sta1),
            nl::new_key(IFINDEX, Some(STA), 0, &KEY),
            nl::frame(IFINDEX, &python_frame(v[12])),
            nl::new_station(&sta2),
            nl::new_key(IFINDEX, Some(STA2), 0, &KEY),
            nl::frame(IFINDEX, &python_frame(v[15])),
            nl::del_station(IFINDEX, STA, Some(stype::DISASSOC), 8),
            nl::frame(IFINDEX, &python_frame(v[17])),
            nl::del_station(IFINDEX, STA2, None, 1),
            nl::control_port_frame(IFINDEX, STA, CUSTOM_FRAME),
            nl::stop_ap(IFINDEX),
        ],
    );
    assert_route(vectors::AP_ROUTE, &[rtnl::set_link_up(IFINDEX)]);
}

#[test]
fn tap_route() {
    let ip = |d| Ipv4Addr::new(169, 254, 1, d);
    assert_route(
        vectors::TAP_ROUTE,
        &[
            rtnl::set_link_address(9, AP),
            rtnl::set_link_up(9),
            rtnl::add_ipv4_address(9, ip(1), ip(255), 24),
            rtnl::add_neighbor(9, ip(2), STA),
            rtnl::remove_neighbor(9, ip(2), STA),
        ],
    );
}

#[test]
fn python_ack_shape_parses() {
    // 生成脚本回的 ACK 与内核同构：错误码 0 + 原请求头。
    let mut ack = 0i32.to_ne_bytes().to_vec();
    ack.extend_from_slice(&unhex(vectors::CTRL_GETFAMILY[0])[..16]);
    assert_eq!(ErrorMessage::parse(0, &ack).unwrap().code, 0);
}
