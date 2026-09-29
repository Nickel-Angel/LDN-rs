//! HostCore / StationCore 与 Python 版 APNetwork / STANetwork 的对拍。
//!
//! 重放 `tools/gen_ldn_vectors.py` 的场景：主机建房 -> 成员认证加入 -> 黑名单拒绝 ->
//! 收发各一个数据帧 -> 踢人。每一步产生的字节都必须与 Python 截获的一致；
//! 固定的“随机数”与脚本里的 FIXED_RANDINT 对应。

#[allow(dead_code)]
mod vectors {
    include!("vectors/python_ldn_vectors.rs");
}
#[allow(dead_code)]
mod crypto_vectors {
    include!("../../ldn-crypto/tests/vectors/python_crypto_vectors.rs");
}

use ldn::event::Event;
use ldn::host_core::{HostConfig, HostCore, HostRandom};
use ldn::station_core::{JoinConfig, StationCore};
use ldn_crypto::{KeyDerivation, Keys, Protocol};
use ldn_proto::common::{accept, platform, security};
use ldn_wire::MacAddress;
use ldn_wire::data::DataFrame;
use ldn_wire::frame::ActionFrame;

const HOST: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 1]);
const GUEST: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 2]);
const OTHER: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 9]);
const PASSWORD: &[u8] = b"LunchPack2DefaultPhrase";
const CHALLENGE_NONCE: u64 = 0x0102_0304_0506_0708;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn seq(start: u8) -> [u8; 16] {
    std::array::from_fn(|i| start + i as u8)
}

fn kd(protocol: Protocol) -> KeyDerivation {
    let text = String::from_utf8(unhex(crypto_vectors::KEYS_FILE)).unwrap();
    KeyDerivation::new(Keys::parse(&text).unwrap(), protocol)
}

fn host(protocol: Protocol) -> HostCore {
    let config = HostConfig {
        protocol,
        local_communication_id: 0x0100_9B90_006D_C000,
        scene_id: 7,
        max_participants: 4,
        application_data: b"room data".to_vec(),
        accept_policy: accept::ALL,
        accept_filter: Vec::new(),
        security_mode: security::PROD,
        ssid: seq(0xA0),
        name: b"host".to_vec(),
        app_version: 3,
        platform: platform::NX,
        channel: 6,
        server_random: seq(0x50),
        password: PASSWORD.to_vec(),
        version: 4,
        enable_challenge: true,
        device_id: 0x1111_2222_3333_4444,
        dev: false,
    };
    let random = HostRandom {
        network_id: 42,
        advert_nonce: 0x1122_3344,
        challenge: 0x0102_0304_0506_0708,
    };
    HostCore::new(config, kd(protocol), HOST, HOST, random).unwrap()
}

/// 取出 802.11 Action 帧的帧体。
fn action_body(frame: &[u8]) -> Vec<u8> {
    ActionFrame::decode(frame).unwrap().action
}

struct Vectors {
    adv_initial: &'static str,
    auth_request: &'static str,
    auth_response: &'static str,
    adv_after_join: &'static str,
    auth_denied: &'static str,
    tap_out: &'static str,
    data_tx: &'static str,
    data_rx: &'static str,
    tap_in: &'static str,
    kick: &'static str,
    adv_after_kick: &'static str,
    ap_iface_ops: &'static [&'static str],
    tap_ops: &'static [&'static str],
}

fn run(protocol: Protocol, v: Vectors) {
    let label = format!("{protocol:?}");
    let mut host = host(protocol);
    assert_eq!(
        host.advertisement_frame().unwrap(),
        unhex(v.adv_initial),
        "{label} initial advertisement"
    );
    assert_eq!(
        format!("address {} {}", host.host_ip(), host.broadcast_ip()),
        v.tap_ops[0]
    );

    // 成员从扫描结果（即主机当前状态）出发。
    let mut join = JoinConfig::new(host.network().clone());
    join.password = PASSWORD.to_vec();
    join.name = b"guest".to_vec();
    join.app_version = 3;
    join.platform = platform::OUNCE;
    join.device_id = 0x5555_6666_7777_8888;
    join.client_random = seq(0x40);
    let mut station = StationCore::new(join, kd(protocol), GUEST).unwrap();
    assert_eq!(station.data_key().unwrap().as_ref(), host.data_key());

    let request = station.authentication_request(CHALLENGE_NONCE).unwrap();
    assert_eq!(request, unhex(v.auth_request), "{label} auth request");

    let outcome = host.handle_auth_request(GUEST, &request).unwrap();
    assert_eq!(
        outcome.response,
        unhex(v.auth_response),
        "{label} auth response"
    );
    let (ip, mac, event) = outcome.joined.expect("guest should join");
    assert_eq!(format!("add {ip} {mac}").to_lowercase(), v.ap_iface_ops[0]);
    assert!(matches!(event, Event::Join { index: 1, .. }));
    assert!(
        station
            .check_authentication_response(HOST, &outcome.response)
            .unwrap()
    );

    // 重发同一请求：沿用原槽位，不再 Join。
    let again = host.handle_auth_request(GUEST, &request).unwrap();
    assert!(again.joined.is_none());
    assert_eq!(host.network().num_participants, 2);

    let adv = host.advertisement_frame().unwrap();
    assert_eq!(
        adv,
        unhex(v.adv_after_join),
        "{label} advertisement after join"
    );
    let network = station
        .parse_advertisement(HOST, &action_body(&adv), Some(2437))
        .unwrap()
        .unwrap();
    let plan = station
        .try_initialize(network)
        .expect("station finds itself");
    assert_eq!(plan.local_ip.to_string(), "169.254.42.2");
    assert_eq!(plan.broadcast_ip.to_string(), "169.254.42.255");
    assert_eq!(plan.neighbors.len(), 2);

    host.set_accept_policy(accept::BLACKLIST);
    host.set_accept_filter(vec![OTHER]);
    let denied = host.handle_auth_request(OTHER, &request).unwrap();
    assert_eq!(
        denied.response,
        unhex(v.auth_denied),
        "{label} denied response"
    );
    assert!(denied.joined.is_none());

    assert_eq!(
        host.build_data_frame(&unhex(v.tap_out)).unwrap(),
        unhex(v.data_tx),
        "{label} data tx"
    );
    let incoming = DataFrame::decode(&unhex(v.data_rx)).unwrap();
    assert_eq!(
        host.handle_data_frame(incoming).unwrap(),
        unhex(v.tap_in),
        "{label} data rx"
    );

    let (kicked, disconnect) = host.kick(1).unwrap();
    assert_eq!((kicked, disconnect), (GUEST, unhex(v.kick)));
    assert_eq!(
        format!("remove_station {kicked}").to_lowercase(),
        v.ap_iface_ops[1]
    );
    let (ip, mac, _) = host.handle_disassociation(GUEST).unwrap();
    assert_eq!(
        format!("remove {ip} {mac}").to_lowercase(),
        v.ap_iface_ops[2]
    );
    let adv = host.advertisement_frame().unwrap();
    assert_eq!(
        adv,
        unhex(v.adv_after_kick),
        "{label} advertisement after kick"
    );

    let network = station
        .parse_advertisement(HOST, &action_body(&adv), Some(2437))
        .unwrap()
        .unwrap();
    let update = station.update(network);
    assert_eq!(update.remove_neighbors, [(plan.local_ip, GUEST)]);
    assert!(matches!(
        update.events[0],
        Event::AcceptPolicyChanged {
            old: accept::ALL,
            new: accept::BLACKLIST
        }
    ));
    assert!(matches!(update.events[1], Event::Leave { index: 1, .. }));
}

#[test]
fn protocol_1_matches_python() {
    use vectors::*;
    run(
        Protocol::V1,
        Vectors {
            adv_initial: P1_ADV_INITIAL,
            auth_request: P1_AUTH_REQUEST,
            auth_response: P1_AUTH_RESPONSE,
            adv_after_join: P1_ADV_AFTER_JOIN,
            auth_denied: P1_AUTH_DENIED,
            tap_out: P1_TAP_OUT,
            data_tx: P1_DATA_TX,
            data_rx: P1_DATA_RX,
            tap_in: P1_TAP_IN,
            kick: P1_KICK_DISCONNECT,
            adv_after_kick: P1_ADV_AFTER_KICK,
            ap_iface_ops: P1_AP_IFACE_OPS,
            tap_ops: P1_TAP_OPS,
        },
    );
}

#[test]
fn protocol_3_matches_python() {
    use vectors::*;
    run(
        Protocol::V3,
        Vectors {
            adv_initial: P3_ADV_INITIAL,
            auth_request: P3_AUTH_REQUEST,
            auth_response: P3_AUTH_RESPONSE,
            adv_after_join: P3_ADV_AFTER_JOIN,
            auth_denied: P3_AUTH_DENIED,
            tap_out: P3_TAP_OUT,
            data_tx: P3_DATA_TX,
            data_rx: P3_DATA_RX,
            tap_in: P3_TAP_IN,
            kick: P3_KICK_DISCONNECT,
            adv_after_kick: P3_ADV_AFTER_KICK,
            ap_iface_ops: P3_AP_IFACE_OPS,
            tap_ops: P3_TAP_OPS,
        },
    );
}
