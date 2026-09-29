//! ApCore 与 Python 版 `AccessPoint` 的对拍：重放 gen_netlink_vectors.py 的 AP 场景，
//! 要求产生的 nl80211 请求（含其中的管理帧字节）与 Python 截获的第 9~20 条消息逐字节一致。

#[allow(dead_code)]
mod vectors {
    include!("../../ldn-netlink/tests/vectors/python_netlink_vectors.rs");
}

use std::collections::BTreeMap;

use ldn_netlink::genl::Family;
use ldn_netlink::nl80211;
use ldn_wire::MacAddress;
use ldn_wire::element::{Elements, eid};
use ldn_wire::frame::{
    AssociationRequest, AuthenticationFrame, DisassociationFrame, Frame, ProbeRequest,
};
use ldn_wlan::ap::{ApAction, ApConfig, ApCore, ApEvent};

const AP: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 1]);
const STA: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 2]);
const STA2: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 3]);
const SSID: &[u8] = b"00112233445566778899aabbccddeeff";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn access_point_matches_python() {
    let mut core = ApCore::new(ApConfig {
        ifindex: 7,
        mac: AP,
        ssid: SSID.to_vec(),
        channel: 6,
        key: Some((0x20..0x30).collect()),
        max_stations: 2,
    });
    let rates = vec![0x82, 0x84, 0x8b, 0x96];
    let frames = [
        Frame::ProbeRequest(ProbeRequest {
            source: STA,
            elements: Elements::from([(eid::SSID, SSID.to_vec())]),
        }),
        Frame::Authentication(AuthenticationFrame {
            target: AP,
            source: STA,
            bssid: AP,
            sequence: 1,
            ..Default::default()
        }),
        Frame::AssociationRequest(AssociationRequest {
            target: AP,
            source: STA,
            capability_information: 0x0421,
            listen_interval: 10,
            elements: Elements::from([
                (eid::SSID, SSID.to_vec()),
                (eid::SUPP_RATES, rates.clone()),
                (eid::HT_CAPABILITY, vec![0x2c, 0x01]),
                (eid::EXT_CAPABILITY, vec![0x04]),
            ]),
        }),
        Frame::AssociationRequest(AssociationRequest {
            target: AP,
            source: STA2,
            capability_information: 0x0421,
            listen_interval: 10,
            elements: Elements::from([(eid::SSID, SSID.to_vec()), (eid::SUPP_RATES, rates)]),
        }),
        Frame::Disassociation(DisassociationFrame {
            target: AP,
            source: STA,
            bssid: AP,
            reason: 8,
            ..Default::default()
        }),
    ];

    let mut actions = Vec::new();
    for f in &frames {
        actions.extend(core.handle_frame(f).unwrap());
    }
    actions.extend(core.remove_station(STA2).unwrap());

    let events: Vec<ApEvent> = actions
        .iter()
        .filter_map(|a| {
            if let ApAction::Event(e) = a {
                Some(*e)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        events,
        [
            ApEvent::Associated(STA),
            ApEvent::Associated(STA2),
            ApEvent::Disassociated(STA)
        ]
    );

    // 事件不产生 netlink 消息；其余动作按顺序对应 Python 的第 9 条（seq 9）起。
    let family = Family {
        id: 0x22,
        name: "nl80211".into(),
        version: 1,
        hdrsize: 0,
        mcast_groups: BTreeMap::new(),
    };
    let requests: Vec<nl80211::Request> = actions
        .into_iter()
        .filter_map(|a| match a {
            ApAction::SendFrame(bytes) => Some(nl80211::frame(7, &bytes)),
            ApAction::Request(r) => Some(r),
            ApAction::Event(_) => None,
        })
        .collect();
    let expected = &vectors::AP_NL80211[8..19];
    assert_eq!(requests.len(), expected.len());
    for (i, (req, hex)) in requests.iter().zip(expected).enumerate() {
        let seq = i as u32 + 9;
        assert_eq!(
            req.encode(&family, seq, 4242).unwrap(),
            unhex(hex),
            "AP message seq {seq}"
        );
    }
}

#[test]
fn beacon_head_matches_python() {
    let core = ApCore::new(ApConfig {
        ifindex: 7,
        mac: AP,
        ssid: SSID.to_vec(),
        channel: 6,
        key: None,
        max_stations: 2,
    });
    // START_AP 是 AP 场景的第 1 条；从中取出 BEACON_HEAD 比对。
    let data = unhex(vectors::AP_NL80211[0]);
    let msg = &ldn_netlink::message::parse_messages(&data).unwrap()[0];
    let genl = ldn_netlink::genl::GenlMessage::parse(msg.payload).unwrap();
    assert_eq!(
        core.beacon_head().unwrap(),
        genl.attrs.require(nl80211::attr::BEACON_HEAD).unwrap()
    );
}
