//! 成员（加入房间）侧的协议状态机（sans-IO），对应 Python 版 `STANetwork` 的决策部分。

use std::net::Ipv4Addr;

use ldn_crypto::KeyDerivation;
use ldn_crypto::keys::Key;
use ldn_proto::common::{MAX_PARTICIPANTS, platform, security};
use ldn_proto::{
    AdvertisementFrame, AuthPayload, AuthenticationFrame, AuthenticationRequest, ChallengeRequest,
    DisconnectFrame, NetworkInfo,
};
use ldn_wire::MacAddress;
use ldn_wire::channel::frequency_to_channel;

use crate::error::{Error, Result};
use crate::event::{Event, broadcast_ip, channel_band};

/// 加入网络的参数中与协议有关的部分，对应 Python 版 `ConnectNetworkParam`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinConfig {
    /// 扫描得到的目标网络。
    pub network: NetworkInfo,
    /// 房间密码。
    pub password: Vec<u8>,
    /// 用户名。
    pub name: Vec<u8>,
    /// 应用版本。
    pub app_version: u16,
    /// 平台。
    pub platform: u8,
    /// 是否在认证请求里带挑战。
    pub enable_challenge: bool,
    /// 本机设备 ID。
    pub device_id: u64,
    /// 客户端随机数，派生认证密钥。
    pub client_random: [u8; 16],
    /// 是否使用开发机挑战密钥。
    pub dev: bool,
}

impl JoinConfig {
    /// 以默认参数加入 `network`；设备 ID 与客户端随机数取自系统熵源。
    pub fn new(network: NetworkInfo) -> Self {
        Self {
            network,
            password: Vec::new(),
            name: Vec::new(),
            app_version: 0,
            platform: platform::NX,
            enable_challenge: true,
            device_id: crate::event::random_u64(),
            client_random: crate::event::random_bytes(),
            dev: false,
        }
    }
}

/// 加入后首次拿到自己的成员信息时要做的配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinPlan {
    /// 本机 IP。
    pub local_ip: Ipv4Addr,
    /// 网络广播地址。
    pub broadcast_ip: Ipv4Addr,
    /// 要添加的静态邻居（所有已连接的参与者，含自己，与 Python 版一致）。
    pub neighbors: Vec<(Ipv4Addr, MacAddress)>,
}

/// 收到新的广播帧后要做的更新。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkUpdate {
    /// 按顺序：接纳策略变化、应用数据变化、各 `Leave`、各 `Join`。
    pub events: Vec<Event>,
    /// 要删除的邻居。
    pub remove_neighbors: Vec<(Ipv4Addr, MacAddress)>,
    /// 要添加的邻居。
    pub add_neighbors: Vec<(Ipv4Addr, MacAddress)>,
}

/// 成员状态机。
pub struct StationCore {
    kd: KeyDerivation,
    config: JoinConfig,
    own_mac: MacAddress,
    network: NetworkInfo,
    network_id: u8,
    participant_index: Option<usize>,
}

impl StationCore {
    /// 创建状态机；目标网络地址为空或版本不支持时报错。
    pub fn new(config: JoinConfig, kd: KeyDerivation, own_mac: MacAddress) -> Result<Self> {
        if config.network.address == MacAddress::ZERO {
            return Err(Error::InvalidParam("network is invalid"));
        }
        if !(2..=4).contains(&config.network.version) {
            return Err(Error::InvalidParam("network version not supported"));
        }
        let network = config.network.clone();
        Ok(Self {
            kd,
            config,
            own_mac,
            network,
            network_id: 0,
            participant_index: None,
        })
    }

    /// 当前（最近一次广播帧里的）网络状态。
    pub fn network(&self) -> &NetworkInfo {
        &self.network
    }

    /// 本机在参与者表里的槽位；加入完成前为 `None`。
    pub fn participant_index(&self) -> Option<usize> {
        self.participant_index
    }

    /// 网络广播地址（加入完成后才有意义）。
    pub fn broadcast_ip(&self) -> Ipv4Addr {
        broadcast_ip(self.network_id)
    }

    /// 数据帧密钥：安全模式为 `PROD` 时由主机随机数和房间密码派生，STA 接口连接时装进驱动。
    pub fn data_key(&self) -> Result<Option<Key>> {
        if self.network.security_mode != security::PROD {
            return Ok(None);
        }
        Ok(Some(self.kd.derive_data_key(
            &self.network.server_random,
            &self.config.password,
        )?))
    }

    /// 生成认证请求；`challenge_nonce` 是挑战里的随机数（未启用挑战时忽略）。
    pub fn authentication_request(&self, challenge_nonce: u64) -> Result<Vec<u8>> {
        let challenge = if self.config.enable_challenge {
            let request = ChallengeRequest {
                token: self.network.challenge,
                nonce: challenge_nonce,
                device_id: self.config.device_id,
                ..Default::default()
            };
            request.encode(self.kd.challenge_key(self.config.dev))?
        } else {
            Vec::new()
        };
        let frame = AuthenticationFrame {
            version: self.network.version,
            status_code: 0,
            network_id: self.network.network_id(),
            server_random: self.network.server_random,
            client_random: self.config.client_random,
            payload: AuthPayload::Request(AuthenticationRequest {
                username: self.config.name.clone(),
                app_version: self.config.app_version,
                platform: self.config.platform,
                challenge,
            }),
        };
        Ok(frame.encode(&self.kd)?)
    }

    /// 判断一个 control port 帧是不是对本次认证的应答。
    ///
    /// 是且成功返回 `Ok(true)`；是但被拒绝返回 [`Error::AuthenticationRejected`]；
    /// 与本次认证无关（来源、网络、随机数不符或解析失败）返回 `Ok(false)`。
    pub fn check_authentication_response(&self, from: MacAddress, data: &[u8]) -> Result<bool> {
        if from != self.network.address {
            return Ok(false);
        }
        let frame = match AuthenticationFrame::decode(data, &self.kd) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("failed to parse authentication response: {e}");
                return Ok(false);
            }
        };
        if !matches!(frame.payload, AuthPayload::Response(_))
            || frame.network_id != self.network.network_id()
            || frame.server_random != self.network.server_random
            || frame.client_random != self.config.client_random
        {
            return Ok(false);
        }
        if frame.status_code != 0 {
            return Err(Error::AuthenticationRejected(frame.status_code));
        }
        Ok(true)
    }

    /// 解析 STA 接口收到的 Action 帧。不是主机发的或解析失败返回 `Ok(None)`；
    /// 是主机发的但与加入时的网络不兼容（主机重建了网络）返回错误。
    pub fn parse_advertisement(
        &self,
        source: MacAddress,
        action: &[u8],
        frequency: Option<u32>,
    ) -> Result<Option<NetworkInfo>> {
        if source != self.network.address {
            return Ok(None);
        }
        let Ok(frame) = AdvertisementFrame::decode(action, &self.kd) else {
            return Ok(None);
        };
        let Some(channel) = frequency
            .and_then(|f| u16::try_from(f).ok())
            .and_then(frequency_to_channel)
        else {
            return Ok(None);
        };
        let mut info = NetworkInfo::new(self.network.protocol);
        info.address = source;
        info.channel = channel.into();
        info.band = channel_band(channel);
        info.update_from_advertisement(&frame);
        if !self.network.is_same_network(&info) {
            return Err(Error::Connection(
                "received incompatible advertisement frame from host".into(),
            ));
        }
        Ok(Some(info))
    }

    /// 认证之后解析 control port 帧：主机发的断开帧返回原因码，其余返回 `None`。
    ///
    /// 与 Python 版的差异：Python 把认证后的所有 control port 帧都当断开帧解析，格式不对会抛异常终止。
    pub fn parse_disconnect(&self, from: MacAddress, data: &[u8]) -> Option<u8> {
        if from != self.network.address {
            return None;
        }
        DisconnectFrame::decode(data).ok().map(|f| f.reason)
    }

    /// 等待主机把本机写进广播帧：`network` 里含本机地址时完成加入并返回配置计划，否则返回 `None`。
    pub fn try_initialize(&mut self, network: NetworkInfo) -> Option<JoinPlan> {
        let index = network
            .participants
            .iter()
            .position(|p| p.mac_address == self.own_mac)?;
        self.network_id = network.participants[0].ip_address.octets()[2];
        let plan = JoinPlan {
            local_ip: network.participants[index].ip_address,
            broadcast_ip: broadcast_ip(self.network_id),
            neighbors: network
                .participants
                .iter()
                .filter(|p| p.connected)
                .map(|p| (p.ip_address, p.mac_address))
                .collect(),
        };
        self.participant_index = Some(index);
        self.network = network;
        Some(plan)
    }

    /// 用新的广播帧更新网络，返回事件与邻居变更。
    ///
    /// 与 Python 版的差异：Python 只比较槽位的 MAC 地址。协议 1 的 V1 广播帧写满 8 个槽位，
    /// 成员离开后槽位保留原 MAC、只清 `connected`，Python 因此永远报不出 `Leave`；
    /// 这里同时比较 `connected`。
    pub fn update(&mut self, network: NetworkInfo) -> NetworkUpdate {
        // 槽位里“是同一个已连接的人”才算没变。
        let same = |o: &ldn_proto::ParticipantInfo, n: &ldn_proto::ParticipantInfo| {
            o.connected == n.connected && o.mac_address == n.mac_address
        };
        let mut out = NetworkUpdate::default();
        let old = &self.network;
        if network.accept_policy != old.accept_policy {
            out.events.push(Event::AcceptPolicyChanged {
                old: old.accept_policy,
                new: network.accept_policy,
            });
        }
        if network.application_data != old.application_data {
            out.events.push(Event::ApplicationDataChanged {
                old: old.application_data.clone(),
                new: network.application_data.clone(),
            });
        }
        for i in 0..MAX_PARTICIPANTS {
            let (o, n) = (&old.participants[i], &network.participants[i]);
            if o.connected && !same(o, n) {
                out.remove_neighbors.push((o.ip_address, o.mac_address));
                out.events.push(Event::Leave {
                    index: i,
                    participant: o.clone(),
                });
            }
        }
        for i in 0..MAX_PARTICIPANTS {
            let (o, n) = (&old.participants[i], &network.participants[i]);
            if n.connected && !same(o, n) {
                out.add_neighbors.push((n.ip_address, n.mac_address));
                out.events.push(Event::Join {
                    index: i,
                    participant: n.clone(),
                });
            }
        }
        self.network = network;
        out
    }
}
