//! 加入 LDN 网络，对应 Python 版 `STANetwork` 与 `ldn.connect`。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ldn_crypto::{KeyDerivation, Keys};
use ldn_proto::auth::disconnect;
use ldn_proto::{NetworkInfo, ParticipantInfo};
use ldn_wlan::{Factory, Station, StationEvent};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};

use crate::error::{Error, Result};
use crate::event::{Event, random_u64};
use crate::station_core::{JoinConfig, NetworkUpdate, StationCore};

/// 认证请求最多发几次。
const AUTH_ATTEMPTS: usize = 3;
/// 每次认证请求等待应答的时间。
const AUTH_TIMEOUT: Duration = Duration::from_millis(700);
/// 认证成功后等待主机把本机写进广播帧的时间。
const JOIN_TIMEOUT: Duration = Duration::from_secs(1);

/// 加入网络的参数。
#[derive(Debug, Clone)]
pub struct ConnectParam {
    /// 系统密钥。
    pub keys: Keys,
    /// 在哪块网卡上建 STA 接口。
    pub phy: String,
    /// STA 接口名。
    pub ifname: String,
    /// 协议参数（目标网络、用户名、密码等）。
    pub join: JoinConfig,
}

impl ConnectParam {
    /// 以默认接口（`phy0` 上的 `ldn`）加入 `network`。
    pub fn new(keys: Keys, network: NetworkInfo) -> Self {
        Self {
            keys,
            phy: "phy0".into(),
            ifname: "ldn".into(),
            join: JoinConfig::new(network),
        }
    }
}

/// 已加入的网络。
///
/// 后台任务持续处理主机的广播帧（更新成员表和邻居表）和断开通知，结果通过
/// [`next_event`](Self::next_event) 取得。用完调用 [`close`](Self::close) 断开并删除接口。
pub struct StaNetwork {
    station: Arc<Station>,
    core: Arc<Mutex<StationCore>>,
    events: mpsc::UnboundedReceiver<Result<Event>>,
    task: JoinHandle<()>,
}

/// 加入附近的 LDN 网络：连接、LDN 认证、等待分配 IP 并配置接口。需要 root。
pub async fn connect(param: ConnectParam) -> Result<StaNetwork> {
    let network = &param.join.network;
    let kd = KeyDerivation::new(param.keys.clone(), network.protocol);
    let channel =
        u8::try_from(network.channel).map_err(|_| Error::InvalidParam("network channel"))?;

    let factory = Factory::new().await?;
    // 先用临时状态机算密钥（与本机地址无关），接口建好后再用真实地址创建状态机。
    let key =
        StationCore::new(param.join.clone(), kd.clone(), ldn_wire::MacAddress::ZERO)?.data_key()?;
    let ssid = network.network_id().ssid_text();
    let station = factory
        .connect_network(
            &param.phy,
            &param.ifname,
            ssid.as_bytes(),
            channel,
            key.as_ref().map(|k| &k[..]),
        )
        .await?;

    let core = StationCore::new(param.join, kd, station.address())?;
    match join(&station, core).await {
        Ok(core) => Ok(StaNetwork::start(station, core)),
        Err(e) => {
            if let Err(close) = station.close().await {
                log::warn!("failed to close station after join error: {close}");
            }
            Err(e)
        }
    }
}

/// 认证并等待加入完成，成功后返回已初始化的状态机。
async fn join(station: &Station, mut core: StationCore) -> Result<StationCore> {
    authenticate(station, &core).await?;
    station.set_authorized().await?;

    let deadline = Instant::now() + JOIN_TIMEOUT;
    let plan = loop {
        let event = timeout_at(deadline, station.next_event())
            .await
            .map_err(|_| {
                Error::Connection(
                    "failed to obtain IP address after joining network (timeout)".into(),
                )
            })??;
        match event {
            StationEvent::ActionFrame { frame, frequency } => {
                if let Some(network) =
                    core.parse_advertisement(frame.source, &frame.action, frequency)?
                    && let Some(plan) = core.try_initialize(network)
                {
                    break plan;
                }
            }
            StationEvent::Disassociated(_) => {
                return Err(Error::Connection("station was disassociated".into()));
            }
            StationEvent::CustomFrame { .. } => {}
        }
    };
    station
        .add_address(plan.local_ip, plan.broadcast_ip)
        .await?;
    for (ip, mac) in plan.neighbors {
        station.add_neighbor(ip, mac).await?;
    }
    Ok(core)
}

async fn authenticate(station: &Station, core: &StationCore) -> Result<()> {
    let request = core.authentication_request(random_u64())?;
    let host = core.network().address;
    for _ in 0..AUTH_ATTEMPTS {
        station.send_custom_frame(host, &request).await?;
        let deadline = Instant::now() + AUTH_TIMEOUT;
        while let Ok(event) = timeout_at(deadline, station.next_event()).await {
            match event? {
                StationEvent::CustomFrame { mac, data } => {
                    if core.check_authentication_response(mac, &data)? {
                        return Ok(());
                    }
                }
                StationEvent::Disassociated(_) => {
                    return Err(Error::Connection("station was disassociated".into()));
                }
                StationEvent::ActionFrame { .. } => {}
            }
        }
    }
    Err(Error::AuthenticationTimeout)
}

impl StaNetwork {
    fn start(station: Station, core: StationCore) -> Self {
        let station = Arc::new(station);
        let core = Arc::new(Mutex::new(core));
        let (tx, events) = mpsc::unbounded_channel();
        let task = tokio::spawn(run(Arc::clone(&station), Arc::clone(&core), tx));
        Self {
            station,
            core,
            events,
            task,
        }
    }

    /// 最近一次广播帧里的网络状态。
    pub fn info(&self) -> NetworkInfo {
        self.core.lock().unwrap().network().clone()
    }

    /// 本机的参与者信息。
    pub fn participant(&self) -> ParticipantInfo {
        let core = self.core.lock().unwrap();
        let index = core
            .participant_index()
            .expect("initialized before StaNetwork is returned");
        core.network().participants[index].clone()
    }

    /// 网络广播地址。
    pub fn broadcast_ip(&self) -> std::net::Ipv4Addr {
        self.core.lock().unwrap().broadcast_ip()
    }

    /// 等待下一个事件。后台任务出错（例如主机换了网络）时返回该错误，之后不再有事件。
    pub async fn next_event(&mut self) -> Result<Event> {
        self.events
            .recv()
            .await
            .unwrap_or_else(|| Err(Error::Connection("network is closed".into())))
    }

    /// 停止后台任务，断开并删除接口。
    pub async fn close(self) -> Result<()> {
        self.task.abort();
        let _ = self.task.await;
        match Arc::try_unwrap(self.station) {
            Ok(station) => Ok(station.close().await?),
            Err(_) => unreachable!("background task has been joined"),
        }
    }
}

async fn apply(station: &Station, update: NetworkUpdate) -> Result<()> {
    for (ip, mac) in update.remove_neighbors {
        station.remove_neighbor(ip, mac).await?;
    }
    for (ip, mac) in update.add_neighbors {
        station.add_neighbor(ip, mac).await?;
    }
    Ok(())
}

/// 后台循环：处理主机广播与断开通知。出错时把错误作为最后一个事件发出后退出。
async fn run(
    station: Arc<Station>,
    core: Arc<Mutex<StationCore>>,
    tx: mpsc::UnboundedSender<Result<Event>>,
) {
    let result = async {
        loop {
            match station.next_event().await? {
                StationEvent::ActionFrame { frame, frequency } => {
                    let parsed = core.lock().unwrap().parse_advertisement(
                        frame.source,
                        &frame.action,
                        frequency,
                    )?;
                    let Some(network) = parsed else { continue };
                    let update = core.lock().unwrap().update(network);
                    let events = update.events.clone();
                    apply(&station, update).await?;
                    for e in events {
                        let _ = tx.send(Ok(e));
                    }
                }
                StationEvent::CustomFrame { mac, data } => {
                    if let Some(reason) = core.lock().unwrap().parse_disconnect(mac, &data) {
                        let _ = tx.send(Ok(Event::Disconnected { reason }));
                    }
                }
                StationEvent::Disassociated(_) => {
                    let _ = tx.send(Ok(Event::Disconnected {
                        reason: disconnect::CONNECTION_LOST,
                    }));
                }
            }
        }
    }
    .await;
    let result: Result<()> = result;
    if let Err(e) = result {
        let _ = tx.send(Err(e));
    }
}
