//! 与 Python 版 LDN 的逐字节对拍测试。
//!
//! 期望值来自 `tools/gen_python_vectors.py` 调用 Python 实现生成的
//! `vectors/python_vectors.rs`。这里构造的每个结构体都必须与生成脚本里的输入逐字段一致。
//! 每条用例同时验证两个方向：Rust 编码 == Python 编码，Rust 解码 Python 字节后再编码不变。

#[allow(dead_code)]
mod vectors {
    include!("vectors/python_vectors.rs");
}

use ldn_wire::MacAddress;
use ldn_wire::data::{DataFrame, ETH_P_ARP, ETH_P_IP, EthernetFrame, SnapHeader};
use ldn_wire::element::{
    Elements, RsnElement, WLAN_AKM_SUITE_PSK, WLAN_CIPHER_SUITE_CCMP, decode_elements,
    encode_elements,
};
use ldn_wire::frame::*;
use ldn_wire::radiotap::{RadiotapChannel, RadiotapFrame};

const A: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 1]);
const B: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 2]);
const BC: MacAddress = MacAddress::BROADCAST;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn ies() -> Elements {
    Elements::from([(0, b"ldn".to_vec()), (3, vec![6])])
}

fn snap_payload() -> SnapHeader {
    SnapHeader {
        oui: 0,
        protocol: ETH_P_IP,
        payload: b"hello".to_vec(),
    }
}

#[test]
fn elements() {
    let elements = Elements::from([
        (3, vec![6]),
        (0, b"ldn".to_vec()),
        (1, vec![0x82, 0x84, 0x8B, 0x96]),
    ]);
    let expected = unhex(vectors::ELEMENTS);
    assert_eq!(encode_elements(&elements).unwrap(), expected);
    assert_eq!(decode_elements(&expected).unwrap(), elements);
}

#[test]
fn rsn_element() {
    let rsn = RsnElement {
        group_cipher_suite: WLAN_CIPHER_SUITE_CCMP,
        pairwise_cipher_suites: vec![WLAN_CIPHER_SUITE_CCMP],
        akm_suites: vec![WLAN_AKM_SUITE_PSK],
        capabilities: 0x000C,
    };
    assert_eq!(rsn.encode().unwrap(), unhex(vectors::RSN_ELEMENT));
}

#[test]
fn radiotap() {
    let basic = RadiotapFrame {
        data: vec![0xDE, 0xAD],
        flags: Some(0x10),
        rate: Some(2),
        channel: Some(RadiotapChannel {
            frequency: 2437,
            flags: 0x00A0,
        }),
        ..Default::default()
    };
    let mactime = RadiotapFrame {
        data: vec![1],
        mactime: Some(0x0102_0304_0506_0708),
        flags: Some(0),
        ..Default::default()
    };
    for (frame, hex) in [
        (basic, vectors::RADIOTAP_BASIC),
        (mactime, vectors::RADIOTAP_MACTIME),
    ] {
        let expected = unhex(hex);
        assert_eq!(frame.encode(), expected);
        assert_eq!(RadiotapFrame::decode(&expected).unwrap(), frame);
    }
}

#[test]
fn mac_header() {
    let header = MacHeader {
        frame_type: 2,
        subtype: 0,
        flags: 0x42,
        duration: 0x1234,
        address1: A,
        address2: B,
        address3: BC,
        sequence_control: 0x5670,
    };
    let expected = unhex(vectors::MAC_HEADER);
    assert_eq!(header.encode().as_slice(), expected);
    assert_eq!(MacHeader::decode(&expected).unwrap(), header);
}

/// 对管理帧做双向对拍：编码一致，且解码 Python 字节得到同一个结构体。
macro_rules! parity {
    ($name:ident, $ty:ty, $vector:expr, $value:expr) => {
        #[test]
        fn $name() {
            let value: $ty = $value;
            let expected = unhex($vector);
            assert_eq!(value.encode().unwrap(), expected);
            assert_eq!(<$ty>::decode(&expected).unwrap(), value);
        }
    };
}

parity!(
    association_request,
    AssociationRequest,
    vectors::ASSOCIATION_REQUEST,
    AssociationRequest {
        target: A,
        source: B,
        capability_information: 0x0421,
        listen_interval: 10,
        elements: Elements::from([(0, b"ldn".to_vec())]),
    }
);

parity!(
    association_response,
    AssociationResponse,
    vectors::ASSOCIATION_RESPONSE,
    AssociationResponse {
        target: B,
        source: A,
        capability_information: 0x0421,
        status_code: status::SUCCESS,
        aid: 0xC001,
        elements: Elements::from([(1, vec![0x82])]),
    }
);

parity!(
    probe_request,
    ProbeRequest,
    vectors::PROBE_REQUEST,
    ProbeRequest {
        source: B,
        elements: Elements::from([(0, vec![])]),
    }
);

parity!(
    probe_response,
    ProbeResponse,
    vectors::PROBE_RESPONSE,
    ProbeResponse {
        target: B,
        source: A,
        timestamp: 0x1122_3344_5566_7788,
        beacon_interval: 100,
        capability_information: 0x0421,
        elements: ies(),
    }
);

parity!(
    beacon,
    BeaconFrame,
    vectors::BEACON,
    BeaconFrame {
        source: A,
        timestamp: 0,
        beacon_interval: 100,
        capability_information: 0x0421,
        elements: ies(),
    }
);

parity!(
    authentication,
    AuthenticationFrame,
    vectors::AUTHENTICATION,
    AuthenticationFrame {
        target: A,
        source: B,
        bssid: A,
        algorithm: WLAN_AUTH_OPEN,
        sequence: 1,
        status_code: status::SUCCESS,
        elements: Elements::new(),
    }
);

parity!(
    deauthentication,
    DeauthenticationFrame,
    vectors::DEAUTHENTICATION,
    DeauthenticationFrame {
        target: A,
        source: B,
        bssid: A,
        reason: 3,
        elements: Elements::new(),
    }
);

parity!(
    data_plain,
    DataFrame,
    vectors::DATA_PLAIN,
    DataFrame {
        target: BC,
        source: A,
        bssid: A,
        from_ds: true,
        payload: snap_payload().encode().unwrap(),
        ..Default::default()
    }
);

parity!(
    data_protected,
    DataFrame,
    vectors::DATA_PROTECTED,
    protected_frame()
);

fn protected_frame() -> DataFrame {
    DataFrame {
        target: BC,
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

parity!(snap, SnapHeader, vectors::SNAP, snap_payload());

#[test]
fn action() {
    let frame = ActionFrame {
        source: A,
        action: vec![0x7F, 0x00, 0x22, 0xAA, 0x04, 0x01],
    };
    let expected = unhex(vectors::ACTION);
    assert_eq!(frame.encode(), expected);
    assert_eq!(ActionFrame::decode(&expected).unwrap(), frame);
}

#[test]
fn ethernet() {
    let frame = EthernetFrame {
        target: BC,
        source: A,
        protocol: ETH_P_ARP,
        payload: b"arp".to_vec(),
    };
    let expected = unhex(vectors::ETHERNET);
    assert_eq!(frame.encode(), expected);
    assert_eq!(EthernetFrame::decode(&expected).unwrap(), frame);
}

#[test]
fn ccmp_nonce_and_aad() {
    let frame = protected_frame();
    assert_eq!(frame.ccmp_nonce().as_slice(), unhex(vectors::CCMP_NONCE));
    assert_eq!(frame.ccmp_aad().as_slice(), unhex(vectors::CCMP_AAD));
}

/// Python 用真实 AES-CCM 加密的帧：阶段 1 只能校验 CCMP 头解析和帧体长度，
/// 接入加密 crate 后在那里用 `CCMP_TEST_KEY` 解出明文 `SNAP` 向量。
#[test]
fn ccmp_encrypted_header() {
    let frame = DataFrame::decode(&unhex(vectors::DATA_CCMP_ENCRYPTED)).unwrap();
    assert!(frame.protected);
    assert_eq!(frame.packet_number, 1);
    assert_eq!(frame.key_id, 1);
    assert_eq!(
        frame.payload.len(),
        unhex(vectors::SNAP).len() + 8,
        "ciphertext + 8-byte MIC"
    );
}

#[test]
fn parse_dispatch_on_python_bytes() {
    assert!(matches!(
        Frame::parse(&unhex(vectors::BEACON)),
        Ok(Some(Frame::Beacon(_)))
    ));
    assert!(matches!(
        Frame::parse(&unhex(vectors::ACTION)),
        Ok(Some(Frame::Action(_)))
    ));
    assert!(matches!(
        Frame::parse(&unhex(vectors::DATA_PLAIN)),
        Ok(Some(Frame::Data(_)))
    ));
}
