//! [`NetworkInfo`]：扫描得到或主机维护的房间完整状态，与广播帧互相转换。

use ldn_crypto::Protocol;
use ldn_wire::MacAddress;

use crate::advertisement::{AdvertiseFormat, AdvertisementFrame, AdvertisementInfo};
use crate::common::{MAX_PARTICIPANTS, NetworkId, ParticipantInfo, accept, security};

/// 一个 LDN 网络的状态。
///
/// 扫描方用 [`update_from_advertisement`](Self::update_from_advertisement) 从广播帧填充，
/// 地址、频段、信道由扫描方根据收到帧的 802.11 头和 Radiotap 另行设置；
/// 主机用 [`to_advertisement`](Self::to_advertisement) 生成要广播的帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    /// 协议版本，决定广播帧加密方式。
    pub protocol: Protocol,
    /// 主机 MAC 地址（BSSID）。
    pub address: MacAddress,
    /// 频段。
    pub band: u8,
    /// 信道。
    pub channel: u16,
    /// 本地通信 ID。
    pub local_communication_id: u64,
    /// 场景 ID。
    pub scene_id: u16,
    /// 16 字节 SSID。
    pub ssid: [u8; 16],
    /// 协议版本号（广播帧头里的 version）。
    pub version: u8,
    /// 主机随机数。
    pub server_random: [u8; 16],
    /// 安全模式。
    pub security_mode: u16,
    /// 应用版本。
    pub app_version: u16,
    /// 接纳策略。
    pub accept_policy: u8,
    /// 最大人数。
    pub max_participants: u8,
    /// 当前人数。
    pub num_participants: u8,
    /// 8 个参与者槽位。
    pub participants: [ParticipantInfo; MAX_PARTICIPANTS],
    /// 游戏自定义数据。
    pub application_data: Vec<u8>,
    /// 挑战值。
    pub challenge: u64,
    /// 广播帧 nonce。
    pub nonce: [u8; 4],
}

impl NetworkInfo {
    /// 给定协议下的空网络。
    pub fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            address: MacAddress::ZERO,
            band: 0,
            channel: 0,
            local_communication_id: 0,
            scene_id: 0,
            ssid: [0; 16],
            version: 0,
            server_random: [0; 16],
            security_mode: security::PROD,
            app_version: 0,
            accept_policy: accept::ALL,
            max_participants: 0,
            num_participants: 0,
            participants: Default::default(),
            application_data: Vec::new(),
            challenge: 0,
            nonce: [0; 4],
        }
    }

    /// 网络标识。
    pub fn network_id(&self) -> NetworkId {
        NetworkId {
            local_communication_id: self.local_communication_id,
            scene_id: self.scene_id,
            ssid: self.ssid,
        }
    }

    /// 两次扫描结果是否是同一个网络：只比较建网后不会变的字段（人数、应用数据等可变）。
    pub fn is_same_network(&self, other: &Self) -> bool {
        self.address == other.address
            && self.band == other.band
            && self.channel == other.channel
            && self.network_id() == other.network_id()
            && self.version == other.version
            && self.server_random == other.server_random
            && self.security_mode == other.security_mode
    }

    /// 用广播帧更新状态。地址、频段、信道不从帧里取（与 Python 版一致）。
    pub fn update_from_advertisement(&mut self, frame: &AdvertisementFrame) {
        let p = &frame.payload;
        self.local_communication_id = frame.network_id.local_communication_id;
        self.scene_id = frame.network_id.scene_id;
        self.ssid = frame.network_id.ssid;
        self.version = frame.version;
        self.server_random = p.server_random;
        self.security_mode = p.security_mode;
        self.app_version = p.app_version;
        self.accept_policy = p.station_accept_policy;
        self.max_participants = p.max_participants;
        self.num_participants = p.num_participants;
        self.participants = p.participants.clone();
        self.application_data = p.application_data.clone();
        self.challenge = p.challenge;
        self.nonce = frame.nonce;
    }

    /// 生成广播帧。`SYSTEM_DEBUG` 安全模式下不加密，否则按协议选择 CTR 或 GCM。
    pub fn to_advertisement(&self) -> AdvertisementFrame {
        let format = if self.security_mode == security::SYSTEM_DEBUG {
            AdvertiseFormat::Plain
        } else {
            AdvertiseFormat::encrypted_for(self.protocol)
        };
        AdvertisementFrame {
            network_id: self.network_id(),
            version: self.version,
            format,
            nonce: self.nonce,
            payload: AdvertisementInfo {
                server_random: self.server_random,
                security_mode: self.security_mode,
                station_accept_policy: self.accept_policy,
                app_version: self.app_version,
                band: self.band,
                channel: self.channel,
                max_participants: self.max_participants,
                num_participants: self.num_participants,
                participants: self.participants.clone(),
                application_data: self.application_data.clone(),
                challenge: self.challenge,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_through_advertisement() {
        let mut net = NetworkInfo::new(Protocol::V3);
        net.address = MacAddress::BROADCAST;
        net.channel = 6;
        net.version = 4;
        net.nonce = [1, 2, 3, 4];
        net.application_data = b"x".to_vec();

        let mut scanned = NetworkInfo::new(Protocol::V3);
        scanned.address = net.address;
        scanned.channel = 6;
        scanned.update_from_advertisement(&net.to_advertisement());
        assert_eq!(scanned, net);
        assert!(scanned.is_same_network(&net));

        // 人数等可变字段不影响“同一网络”判断；SSID 变了就不是。
        scanned.num_participants = 3;
        assert!(scanned.is_same_network(&net));
        scanned.ssid[0] = 1;
        assert!(!scanned.is_same_network(&net));
    }

    #[test]
    fn system_debug_is_plain() {
        let mut net = NetworkInfo::new(Protocol::V1);
        assert_eq!(net.to_advertisement().format, AdvertiseFormat::AesCtr);
        net.security_mode = security::SYSTEM_DEBUG;
        assert_eq!(net.to_advertisement().format, AdvertiseFormat::Plain);
    }
}
