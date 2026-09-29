//! 与 Python 版协议类逐字节对拍。期望值由 `tools/gen_proto_vectors.py` 生成，
//! 这里的输入必须与脚本一致。每条用例双向验证：Rust 编码 == Python 编码，
//! Rust 解码 Python 字节得到同一个结构体。

#[allow(dead_code)]
mod vectors {
    include!("vectors/python_proto_vectors.rs");
}
#[allow(dead_code)]
mod crypto_vectors {
    include!("../../ldn-crypto/tests/vectors/python_crypto_vectors.rs");
}

use std::net::Ipv4Addr;

use ldn_crypto::keys::CHALLENGE_KEY;
use ldn_crypto::{KeyDerivation, Keys, Protocol};
use ldn_proto::auth::{disconnect, status};
use ldn_proto::common::{MAX_PARTICIPANTS, accept, security};
use ldn_proto::*;
use ldn_wire::MacAddress;
use ldn_wire::stream::Endian;

const SERVER_RANDOM: [u8; 16] = seq(0x50);
const CLIENT_RANDOM: [u8; 16] = seq(0x40);
const SSID: [u8; 16] = seq(0xA0);
const NONCE: [u8; 4] = [1, 2, 3, 4];
const APP_DATA: &[u8] = b"application data \x00\x01\x02";

const fn seq(start: u8) -> [u8; 16] {
    let mut out = [0; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = start + i as u8;
        i += 1;
    }
    out
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn kd(protocol: Protocol) -> KeyDerivation {
    let text = String::from_utf8(unhex(crypto_vectors::KEYS_FILE)).unwrap();
    KeyDerivation::new(Keys::parse(&text).unwrap(), protocol)
}

fn network_id() -> NetworkId {
    NetworkId {
        local_communication_id: 0x0100_9B90_006D_C000,
        scene_id: 0x1234,
        ssid: SSID,
    }
}

fn participants() -> [ParticipantInfo; MAX_PARTICIPANTS] {
    let mut out: [ParticipantInfo; MAX_PARTICIPANTS] = Default::default();
    out[0] = ParticipantInfo {
        ip_address: Ipv4Addr::new(169, 254, 9, 1),
        mac_address: MacAddress::new([2, 0, 0, 0, 0, 1]),
        connected: true,
        name: b"host".to_vec(),
        app_version: 7,
        platform: 0,
    };
    out[2] = ParticipantInfo {
        ip_address: Ipv4Addr::new(169, 254, 9, 3),
        mac_address: MacAddress::new([2, 0, 0, 0, 0, 3]),
        connected: true,
        name: b"player-two".to_vec(),
        app_version: 7,
        platform: 1,
    };
    out
}

fn adv_frame(format: AdvertiseFormat) -> AdvertisementFrame {
    AdvertisementFrame {
        network_id: network_id(),
        version: 3,
        format,
        nonce: NONCE,
        payload: AdvertisementInfo {
            server_random: SERVER_RANDOM,
            security_mode: security::PROD,
            station_accept_policy: accept::BLACKLIST,
            app_version: 7,
            band: 2,
            channel: 6,
            max_participants: 4,
            num_participants: 2,
            participants: participants(),
            application_data: APP_DATA.to_vec(),
            challenge: 0x1122_3344_5566_7788,
        },
    }
}

fn challenge_request() -> ChallengeRequest {
    ChallengeRequest {
        flags: 1,
        token: 0xAABB_CCDD,
        nonce: 0x0102_0304_0506_0708,
        device_id: 0x1111_2222_3333_4444,
        unk: seq(0xC0),
        params1: vec![1, 2],
        params2: vec![3, 4, 5],
    }
}

fn challenge_response() -> ChallengeResponse {
    ChallengeResponse {
        flags: 2,
        nonce: 0x0102_0304_0506_0708,
        device_id: 0x1111_2222_3333_4444,
        device_id_host: 0x5555_6666_7777_8888,
        unk: seq(0),
        unk_host: seq(16),
    }
}

#[test]
fn network_id_both_endians() {
    let id = network_id();
    assert_eq!(
        id.encode(Endian::Big).to_vec(),
        unhex(vectors::NETWORK_ID_BE)
    );
    assert_eq!(
        id.encode(Endian::Little).to_vec(),
        unhex(vectors::NETWORK_ID_LE)
    );
    assert_eq!(
        NetworkId::decode(&unhex(vectors::NETWORK_ID_LE), Endian::Little),
        Ok(id)
    );
}

#[test]
fn advertisements() {
    for (format, protocol, hex) in [
        (AdvertiseFormat::AesCtr, Protocol::V1, vectors::ADV_P1_CTR),
        (AdvertiseFormat::Plain, Protocol::V1, vectors::ADV_P1_PLAIN),
        (AdvertiseFormat::AesGcm, Protocol::V3, vectors::ADV_P3_GCM),
        (AdvertiseFormat::Plain, Protocol::V3, vectors::ADV_P3_PLAIN),
    ] {
        let kd = kd(protocol);
        let frame = adv_frame(format);
        let expected = unhex(hex);
        assert_eq!(
            frame.encode(&kd).unwrap(),
            expected,
            "{format:?} {protocol:?} encode"
        );
        assert_eq!(
            AdvertisementFrame::decode(&expected, &kd).unwrap(),
            frame,
            "{format:?} {protocol:?} decode"
        );
    }
}

#[test]
fn challenges() {
    let req = challenge_request();
    let expected = unhex(vectors::CHALLENGE_REQUEST);
    assert_eq!(req.encode(&CHALLENGE_KEY).unwrap(), expected);
    assert_eq!(
        ChallengeRequest::decode(&expected, &CHALLENGE_KEY).unwrap(),
        req
    );

    let resp = challenge_response();
    let expected = unhex(vectors::CHALLENGE_RESPONSE);
    assert_eq!(resp.encode(&CHALLENGE_KEY), expected);
    assert_eq!(
        ChallengeResponse::decode(&expected, &CHALLENGE_KEY).unwrap(),
        resp
    );
}

#[test]
fn authentication_frames() {
    use vectors::*;
    let cases = [
        (Protocol::V1, 2, false, AUTH_P1_V2_REQ),
        (Protocol::V1, 2, true, AUTH_P1_V2_RESP),
        (Protocol::V1, 3, false, AUTH_P1_V3_REQ),
        (Protocol::V1, 3, true, AUTH_P1_V3_RESP),
        (Protocol::V3, 2, false, AUTH_P3_V2_REQ),
        (Protocol::V3, 2, true, AUTH_P3_V2_RESP),
        (Protocol::V3, 3, false, AUTH_P3_V3_REQ),
        (Protocol::V3, 3, true, AUTH_P3_V3_RESP),
    ];
    for (protocol, version, is_response, hex) in cases {
        let payload = if is_response {
            AuthPayload::Response(AuthenticationResponse {
                platform: 1,
                challenge: if version >= 3 {
                    unhex(CHALLENGE_RESPONSE)
                } else {
                    Vec::new()
                },
            })
        } else {
            AuthPayload::Request(AuthenticationRequest {
                username: b"player-two".to_vec(),
                app_version: 7,
                platform: 1,
                challenge: if version >= 3 {
                    unhex(CHALLENGE_REQUEST)
                } else {
                    Vec::new()
                },
            })
        };
        let frame = AuthenticationFrame {
            version,
            status_code: if is_response {
                status::DENIED_BY_POLICY
            } else {
                status::SUCCESS
            },
            network_id: network_id(),
            server_random: SERVER_RANDOM,
            client_random: CLIENT_RANDOM,
            payload,
        };
        let kd = kd(protocol);
        let expected = unhex(hex);
        let label = format!("{protocol:?} v{version} response={is_response}");
        assert_eq!(frame.encode(&kd).unwrap(), expected, "{label} encode");

        // 版本 2 的应答载荷为空，解码后平台回到默认值。
        let mut want = frame.clone();
        if is_response && version < 3 {
            want.payload = AuthPayload::Response(AuthenticationResponse::default());
        }
        assert_eq!(
            AuthenticationFrame::decode(&expected, &kd).unwrap(),
            want,
            "{label} decode"
        );
    }
}

#[test]
fn disconnect_frame() {
    let frame = DisconnectFrame {
        reason: disconnect::STATION_REJECTED_BY_HOST,
    };
    let expected = unhex(vectors::DISCONNECT);
    assert_eq!(frame.encode(), expected);
    assert_eq!(DisconnectFrame::decode(&expected), Ok(frame));
}

#[test]
fn build_advertisement() {
    let mut net = NetworkInfo::new(Protocol::V3);
    net.band = 2;
    net.channel = 11;
    net.local_communication_id = network_id().local_communication_id;
    net.scene_id = network_id().scene_id;
    net.ssid = SSID;
    net.version = 4;
    net.server_random = SERVER_RANDOM;
    net.app_version = 7;
    net.accept_policy = accept::ALL;
    net.max_participants = 8;
    net.num_participants = 2;
    net.participants = participants();
    net.application_data = APP_DATA.to_vec();
    net.challenge = 42;
    net.nonce = NONCE;

    let kd = kd(Protocol::V3);
    let expected = unhex(vectors::BUILD_ADVERTISEMENT_P3);
    assert_eq!(net.to_advertisement().encode(&kd).unwrap(), expected);

    // 扫描方从同一帧还原（地址/频段/信道由扫描方设置）。
    let mut scanned = NetworkInfo::new(Protocol::V3);
    scanned.band = 2;
    scanned.channel = 11;
    scanned.update_from_advertisement(&AdvertisementFrame::decode(&expected, &kd).unwrap());
    assert_eq!(scanned, net);
}
