//! 主机（建房）侧的协议状态机（sans-IO），对应 Python 版 `APNetwork` 的决策部分。
//!
//! 它不做任何 I/O：输入是收到的字节或事件，输出是要发的字节、要做的路由操作和要上报的
//! [`Event`]。[`crate::host::HostNetwork`] 负责把它接到 `ldn-wlan` 的 AP、monitor、TAP 口上。

use std::net::Ipv4Addr;

use ldn_crypto::cipher::{ccmp_decrypt, ccmp_encrypt};
use ldn_crypto::keys::Key;
use ldn_crypto::{KeyDerivation, Protocol};
use ldn_proto::auth::{disconnect, status};
use ldn_proto::common::{MAX_PARTICIPANTS, accept, security};
use ldn_proto::{
    AuthPayload, AuthenticationFrame, AuthenticationRequest, AuthenticationResponse,
    ChallengeRequest, ChallengeResponse, DisconnectFrame, NetworkInfo, ParticipantInfo,
};
use ldn_wire::MacAddress;
use ldn_wire::data::{DataFrame, EthernetFrame, SnapHeader};
use ldn_wire::frame::ActionFrame;

use crate::error::{Error, Result};
use crate::event::{Event, broadcast_ip, channel_band, participant_ip};

/// 应用数据的上限（与广播帧 V1 载荷一致）。
pub const MAX_APPLICATION_DATA: usize = 0x180;

/// 建房参数中与协议有关的部分，对应 Python 版 `CreateNetworkParam`（接口名另见
/// [`crate::host::CreateNetworkParam`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    /// 协议版本（1 或 3）。
    pub protocol: Protocol,
    /// 本地通信 ID（游戏）。
    pub local_communication_id: u64,
    /// 场景 ID。
    pub scene_id: u16,
    /// 最大人数（含主机），不超过 8。
    pub max_participants: u8,
    /// 游戏自定义数据，不超过 384 字节。
    pub application_data: Vec<u8>,
    /// 接纳策略，见 `ldn_proto::common::accept`。
    pub accept_policy: u8,
    /// 黑/白名单。
    pub accept_filter: Vec<MacAddress>,
    /// 安全模式，见 `ldn_proto::common::security`。
    pub security_mode: u16,
    /// 16 字节 SSID。
    pub ssid: [u8; 16],
    /// 主机用户名。
    pub name: Vec<u8>,
    /// 应用版本。
    pub app_version: u16,
    /// 主机平台。
    pub platform: u8,
    /// 信道（1/6/11/36/40/44/48）。
    pub channel: u8,
    /// 主机随机数。
    pub server_random: [u8; 16],
    /// 房间密码，参与数据帧密钥派生。
    pub password: Vec<u8>,
    /// 协议版本号（2~4）。
    pub version: u8,
    /// 是否启用认证挑战。
    pub enable_challenge: bool,
    /// 主机设备 ID，写进挑战应答。
    pub device_id: u64,
    /// 是否使用开发机挑战密钥。
    pub dev: bool,
}

impl HostConfig {
    /// 默认参数：SSID、主机随机数、设备 ID 随机生成，信道在 1/6/11 中随机选，
    /// 最多 8 人、版本号 4、启用挑战、全部接纳、`PROD` 安全模式。
    pub fn new(protocol: Protocol) -> Self {
        let channel = [1, 6, 11][usize::from(crate::event::random_bytes::<1>()[0] % 3)];
        Self {
            protocol,
            local_communication_id: 0,
            scene_id: 0,
            max_participants: MAX_PARTICIPANTS as u8,
            application_data: Vec::new(),
            accept_policy: accept::ALL,
            accept_filter: Vec::new(),
            security_mode: security::PROD,
            ssid: crate::event::random_bytes(),
            name: Vec::new(),
            app_version: 0,
            platform: ldn_proto::common::platform::NX,
            channel,
            server_random: crate::event::random_bytes(),
            password: Vec::new(),
            version: 4,
            enable_challenge: true,
            device_id: crate::event::random_u64(),
            dev: false,
        }
    }
    /// 检查参数范围，对应 Python 版 `CreateNetworkParam.check`。
    pub fn check(&self) -> Result<()> {
        if self.max_participants as usize > MAX_PARTICIPANTS {
            return Err(Error::InvalidParam("max_participants is too high"));
        }
        if self.application_data.len() > MAX_APPLICATION_DATA {
            return Err(Error::InvalidParam("application_data is too large"));
        }
        if !ldn_wire::channel::is_valid_channel(self.channel) {
            return Err(Error::InvalidParam("channel is invalid"));
        }
        if !(2..=4).contains(&self.version) {
            return Err(Error::InvalidParam("version is invalid"));
        }
        if self.protocol != Protocol::V1 && self.protocol != Protocol::V3 {
            return Err(Error::InvalidParam("protocol is not supported"));
        }
        Ok(())
    }
}

/// 主机状态机需要的随机值；由调用方提供，测试时可固定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostRandom {
    /// 网络号（IP 第三段），1~127。
    pub network_id: u8,
    /// 广播帧 nonce 初值。
    pub advert_nonce: u32,
    /// 挑战 token（未启用挑战时忽略）。
    pub challenge: u64,
}

impl HostRandom {
    /// 从系统熵源生成。
    pub fn generate() -> Self {
        let [a, b, c, d, n, ..] = crate::event::random_bytes::<8>();
        Self {
            network_id: n % 127 + 1,
            advert_nonce: u32::from_be_bytes([a, b, c, d]),
            challenge: crate::event::random_u64(),
        }
    }
}

/// 处理一个认证请求的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOutcome {
    /// 要经 control port 发回给请求方的认证应答。
    pub response: Vec<u8>,
    /// 认证成功且是新成员时：要加的邻居与要上报的 `Join` 事件。
    pub joined: Option<(Ipv4Addr, MacAddress, Event)>,
}

/// 主机状态机。
pub struct HostCore {
    kd: KeyDerivation,
    config: HostConfig,
    key: Option<Key>,
    data_address: MacAddress,
    network_id: u8,
    advert_nonce: u32,
    data_nonce: u64,
    network: NetworkInfo,
}

impl HostCore {
    /// 创建状态机。`host_mac` 是 AP 接口地址（BSSID），`data_mac` 是收发数据帧的 monitor 接口地址。
    ///
    /// 安全模式为 `PROD` 时在这里派生数据帧密钥，缺少系统密钥会立即报错。
    pub fn new(
        config: HostConfig,
        kd: KeyDerivation,
        host_mac: MacAddress,
        data_mac: MacAddress,
        random: HostRandom,
    ) -> Result<Self> {
        config.check()?;
        let key = if config.security_mode == security::PROD {
            Some(kd.derive_data_key(&config.server_random, &config.password)?)
        } else {
            None
        };

        let mut participants: [ParticipantInfo; MAX_PARTICIPANTS] = Default::default();
        participants[0] = ParticipantInfo {
            ip_address: participant_ip(random.network_id, 0),
            mac_address: host_mac,
            connected: true,
            name: config.name.clone(),
            app_version: config.app_version,
            platform: config.platform,
        };
        let mut network = NetworkInfo::new(config.protocol);
        network.address = host_mac;
        network.channel = config.channel.into();
        network.band = channel_band(config.channel);
        network.local_communication_id = config.local_communication_id;
        network.scene_id = config.scene_id;
        network.ssid = config.ssid;
        network.version = config.version;
        network.server_random = config.server_random;
        network.security_mode = config.security_mode;
        network.accept_policy = config.accept_policy;
        network.max_participants = config.max_participants;
        network.num_participants = 1;
        network.participants = participants;
        network.application_data = config.application_data.clone();
        network.app_version = config.app_version;
        network.challenge = if config.enable_challenge {
            random.challenge
        } else {
            0
        };
        network.nonce = random.advert_nonce.to_be_bytes();

        Ok(Self {
            kd,
            config,
            key,
            data_address: data_mac,
            network_id: random.network_id,
            advert_nonce: random.advert_nonce,
            data_nonce: 0,
            network,
        })
    }

    /// 当前网络状态。
    pub fn network(&self) -> &NetworkInfo {
        &self.network
    }

    /// 数据帧 CCMP 密钥（安全模式为 `PROD` 时才有），AP 接口启动时要装进驱动。
    pub fn data_key(&self) -> Option<&Key> {
        self.key.as_ref()
    }

    /// 主机自己的 IP。
    pub fn host_ip(&self) -> Ipv4Addr {
        participant_ip(self.network_id, 0)
    }

    /// 网络广播地址。
    pub fn broadcast_ip(&self) -> Ipv4Addr {
        broadcast_ip(self.network_id)
    }

    /// 广播帧内容每次变化都要换 nonce，让扫描方知道房间状态更新了。
    fn update_nonce(&mut self) {
        self.advert_nonce = self.advert_nonce.wrapping_add(1);
        self.network.nonce = self.advert_nonce.to_be_bytes();
    }

    /// 修改应用数据；超过 384 字节报错。
    pub fn set_application_data(&mut self, data: Vec<u8>) -> Result<()> {
        if data.len() > MAX_APPLICATION_DATA {
            return Err(Error::InvalidParam("application_data is too large"));
        }
        self.network.application_data = data;
        self.update_nonce();
        Ok(())
    }

    /// 修改接纳策略。
    pub fn set_accept_policy(&mut self, policy: u8) {
        self.network.accept_policy = policy;
        self.update_nonce();
    }

    /// 修改黑/白名单（不影响广播帧，所以不换 nonce）。
    pub fn set_accept_filter(&mut self, filter: Vec<MacAddress>) {
        self.config.accept_filter = filter;
    }

    /// 生成要从 monitor 口发出的完整 802.11 广播 Action 帧。
    pub fn advertisement_frame(&self) -> Result<Vec<u8>> {
        let body = self.network.to_advertisement().encode(&self.kd)?;
        Ok(ActionFrame {
            source: self.network.address,
            action: body,
        }
        .encode())
    }

    fn response(
        &self,
        status_code: u8,
        client_random: [u8; 16],
        challenge: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let frame = AuthenticationFrame {
            version: self.network.version,
            status_code,
            network_id: self.network.network_id(),
            server_random: self.network.server_random,
            client_random,
            payload: AuthPayload::Response(AuthenticationResponse {
                platform: self.config.platform,
                challenge,
            }),
        };
        Ok(frame.encode(&self.kd)?)
    }

    fn accepts(&self, address: MacAddress) -> bool {
        let listed = self.config.accept_filter.contains(&address);
        match self.network.accept_policy {
            accept::ALL => true,
            accept::BLACKLIST => !listed,
            accept::WHITELIST => listed,
            _ => false,
        }
    }

    fn check_request<'a>(
        &self,
        address: MacAddress,
        frame: &'a AuthenticationFrame,
    ) -> std::result::Result<&'a AuthenticationRequest, u8> {
        if !(2..=4).contains(&frame.version) {
            return Err(status::INVALID_VERSION);
        }
        let AuthPayload::Request(request) = &frame.payload else {
            return Err(status::MALFORMED_REQUEST);
        };
        if frame.status_code != 0
            || frame.network_id != self.network.network_id()
            || frame.server_random != self.network.server_random
        {
            return Err(status::MALFORMED_REQUEST);
        }
        if !self.accepts(address) {
            return Err(status::DENIED_BY_POLICY);
        }
        Ok(request)
    }

    /// 校验挑战并生成已签名的挑战应答；未启用挑战时返回空。
    fn answer_challenge(&self, challenge: &[u8]) -> Option<Vec<u8>> {
        if !self.config.enable_challenge {
            return Some(Vec::new());
        }
        let key = self.kd.challenge_key(self.config.dev);
        let request = match ChallengeRequest::decode(challenge, key) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("failed to parse authentication challenge: {e}");
                return None;
            }
        };
        if request.token != self.network.challenge {
            log::warn!("received authentication request with wrong token");
            return None;
        }
        let response = ChallengeResponse {
            flags: 2,
            nonce: request.nonce,
            device_id: request.device_id,
            device_id_host: self.config.device_id,
            unk: request.unk,
            unk_host: [0; 16],
        };
        Some(response.encode(key))
    }

    /// 处理成员经 control port 发来的认证请求。
    ///
    /// 与 Python 版的差异：
    /// - 已登记的地址重发请求（上次的应答丢了）时沿用原槽位，不重复登记、不重复上报 `Join`；
    /// - 8 个槽位都满时回 `DENIED_BY_POLICY`（Python 会覆盖 7 号槽位）。
    pub fn handle_auth_request(&mut self, address: MacAddress, data: &[u8]) -> Result<AuthOutcome> {
        let frame = match AuthenticationFrame::decode(data, &self.kd) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("failed to parse authentication request: {e}");
                let response = self.response(status::MALFORMED_REQUEST, [0; 16], Vec::new())?;
                return Ok(AuthOutcome {
                    response,
                    joined: None,
                });
            }
        };
        let request = match self.check_request(address, &frame) {
            Ok(r) => r.clone(),
            Err(code) => {
                return Ok(AuthOutcome {
                    response: self.response(code, frame.client_random, Vec::new())?,
                    joined: None,
                });
            }
        };
        let Some(challenge) = self.answer_challenge(&request.challenge) else {
            let response =
                self.response(status::CHALLENGE_FAILURE, frame.client_random, Vec::new())?;
            return Ok(AuthOutcome {
                response,
                joined: None,
            });
        };

        let existing = self
            .network
            .participants
            .iter()
            .position(|p| p.connected && p.mac_address == address);
        let joined = match existing {
            Some(_) => None,
            None => {
                let Some(index) = self.network.participants.iter().position(|p| !p.connected)
                else {
                    let response =
                        self.response(status::DENIED_BY_POLICY, frame.client_random, Vec::new())?;
                    return Ok(AuthOutcome {
                        response,
                        joined: None,
                    });
                };
                let participant = ParticipantInfo {
                    ip_address: participant_ip(self.network_id, index),
                    mac_address: address,
                    connected: true,
                    name: request.username,
                    app_version: request.app_version,
                    platform: request.platform,
                };
                self.network.participants[index] = participant.clone();
                self.network.num_participants += 1;
                self.update_nonce();
                Some((
                    participant.ip_address,
                    address,
                    Event::Join { index, participant },
                ))
            }
        };
        Ok(AuthOutcome {
            response: self.response(status::SUCCESS, frame.client_random, challenge)?,
            joined,
        })
    }

    /// 成员解除关联（主动离开、被踢或超时）。返回要删的邻居和 `Leave` 事件；不是成员时返回 `None`。
    ///
    /// 主机自己（0 号槽位）永远不会被移除。
    pub fn handle_disassociation(
        &mut self,
        address: MacAddress,
    ) -> Option<(Ipv4Addr, MacAddress, Event)> {
        let index = self
            .network
            .participants
            .iter()
            .skip(1)
            .position(|p| p.connected && p.mac_address == address)?
            + 1;
        let participant = &mut self.network.participants[index];
        participant.connected = false;
        let participant = participant.clone();
        self.network.num_participants -= 1;
        self.update_nonce();
        Some((
            participant.ip_address,
            address,
            Event::Leave { index, participant },
        ))
    }

    /// 准备踢出 `index` 号成员：返回其地址和要发给它的断开帧。空槽位或 0 号（主机）返回 `None`。
    ///
    /// 调用方随后应让 AP 删除该 station，再调用 [`handle_disassociation`](Self::handle_disassociation)。
    /// 与 Python 版的差异：Python 允许踢 0 号，会把主机自己从成员表里删掉。
    pub fn kick(&self, index: usize) -> Option<(MacAddress, Vec<u8>)> {
        let p = self
            .network
            .participants
            .get(index)
            .filter(|p| index != 0 && p.connected)?;
        Some((
            p.mac_address,
            DisconnectFrame {
                reason: disconnect::STATION_REJECTED_BY_HOST,
            }
            .encode(),
        ))
    }

    /// 解散网络时要发给每个成员的断开帧。
    pub fn destroy_frames(&self) -> Vec<(MacAddress, Vec<u8>)> {
        let frame = DisconnectFrame {
            reason: disconnect::NETWORK_DESTROYED,
        }
        .encode();
        self.network.participants[1..]
            .iter()
            .filter(|p| p.connected)
            .map(|p| (p.mac_address, frame.clone()))
            .collect()
    }

    /// 处理 monitor 口收到的数据帧：解密、过滤后返回要写进 TAP 的以太网帧。
    ///
    /// 只接受成员发来的、目标是本机或广播的帧；解密失败或无关的帧返回 `None`。
    pub fn handle_data_frame(&self, mut frame: DataFrame) -> Option<Vec<u8>> {
        if frame.protected {
            let key = self.key.as_ref().or_else(|| {
                log::warn!("received protected data frame but no key was registered");
                None
            })?;
            ccmp_decrypt(&mut frame, key).ok()?;
        }
        let is_peer = self.network.participants[1..]
            .iter()
            .any(|p| p.connected && p.mac_address == frame.source);
        if !is_peer || (frame.target != self.data_address && !frame.target.is_broadcast()) {
            return None;
        }
        let snap = SnapHeader::decode(&frame.payload).ok()?;
        let ethernet = EthernetFrame {
            target: frame.target,
            source: frame.source,
            protocol: snap.protocol,
            payload: snap.payload,
        };
        Some(ethernet.encode())
    }

    /// 把 TAP 读出的以太网帧封装成（加密的）802.11 数据帧，一律发往广播地址。
    ///
    /// 每调用一次包序号加 1，所以只能在单个发送循环里调用。
    pub fn build_data_frame(&mut self, ethernet: &[u8]) -> Result<Vec<u8>> {
        let eth = EthernetFrame::decode(ethernet)?;
        let snap = SnapHeader {
            oui: 0,
            protocol: eth.protocol,
            payload: eth.payload,
        };
        let mut frame = DataFrame {
            target: MacAddress::BROADCAST,
            source: self.data_address,
            bssid: self.data_address,
            from_ds: true,
            payload: snap.encode()?,
            ..Default::default()
        };
        if let Some(key) = &self.key {
            self.data_nonce += 1;
            ccmp_encrypt(&mut frame, key, self.data_nonce, 1)?;
        }
        Ok(frame.encode()?)
    }
}
