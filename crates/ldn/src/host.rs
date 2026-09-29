//! 建立并主持 LDN 网络，对应 Python 版 `APNetwork` 与 `ldn.create_network`。
//!
//! 接口组合沿用 Python 版的设计：AP 接口处理 802.11 管理帧和 LDN 认证，monitor 接口
//! 收发广播帧和数据帧（AP 模式收不到发往广播地址的数据帧），TAP 接口把解密后的数据交给
//! Linux 协议栈。四个后台任务并发运行，任一出错时其余全部取消（等价于 trio nursery）。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ldn_crypto::{KeyDerivation, Keys};
use ldn_proto::NetworkInfo;
use ldn_proto::common::security;
use ldn_wire::MacAddress;
use ldn_wire::frame::Frame;
use ldn_wire::radiotap::RadiotapFrame;
use ldn_wlan::{AccessPoint, AccessPointEvent, Factory, Monitor, Tap};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

use crate::error::{Error, Result};
use crate::event::Event;
use crate::host_core::{HostConfig, HostCore, HostRandom};

/// 广播间隔。
const ADVERTISE_INTERVAL: Duration = Duration::from_millis(100);

/// 建房参数。
#[derive(Debug, Clone)]
pub struct CreateNetworkParam {
    /// 系统密钥。
    pub keys: Keys,
    /// AP 接口所在网卡。
    pub phy: String,
    /// monitor 接口所在网卡，默认与 AP 相同；网卡不支持 AP+monitor 共存时可指向第二块网卡。
    pub phy_monitor: String,
    /// AP 接口名。
    pub ifname: String,
    /// monitor 接口名。
    pub ifname_monitor: String,
    /// TAP 接口名。
    pub ifname_tap: String,
    /// 协议参数。
    pub config: HostConfig,
}

impl CreateNetworkParam {
    /// 默认接口：`phy0` 上的 `ldn` / `ldn-mon`，TAP 口 `ldn-tap`。
    pub fn new(keys: Keys, config: HostConfig) -> Self {
        Self {
            keys,
            phy: "phy0".into(),
            phy_monitor: "phy0".into(),
            ifname: "ldn".into(),
            ifname_monitor: "ldn-mon".into(),
            ifname_tap: "ldn-tap".into(),
            config,
        }
    }
}

type Events = mpsc::UnboundedSender<Result<Event>>;

/// 主机与后台任务共享的状态。锁只在同步计算时持有，任何 await 之前释放。
struct Shared {
    ap: AccessPoint,
    monitor: Monitor,
    tap: Tap,
    core: Mutex<HostCore>,
    events: Events,
}

/// 正在主持的网络。用完调用 [`close`](Self::close)：通知成员网络解散并删除接口。
pub struct HostNetwork {
    shared: Arc<Shared>,
    events: mpsc::UnboundedReceiver<Result<Event>>,
    supervisor: JoinHandle<()>,
}

/// 建立网络并开始广播。需要 root，网卡须支持 AP 与 monitor 接口（见 README）。
pub async fn create_network(param: CreateNetworkParam) -> Result<HostNetwork> {
    let config = param.config;
    config.check()?;
    let kd = KeyDerivation::new(param.keys, config.protocol);
    let key = if config.security_mode == security::PROD {
        Some(kd.derive_data_key(&config.server_random, &config.password)?)
    } else {
        None
    };

    let factory = Factory::new().await?;
    let ssid = ldn_proto::NetworkId {
        ssid: config.ssid,
        ..Default::default()
    }
    .ssid_text();
    let ap = factory
        .create_ap(
            &param.phy,
            &param.ifname,
            ssid.as_bytes(),
            config.channel,
            key.as_ref().map(|k| &k[..]),
            usize::from(config.max_participants),
        )
        .await?;
    let monitor = match factory
        .create_monitor(&param.phy_monitor, &param.ifname_monitor)
        .await
    {
        Ok(m) => m,
        Err(e) => {
            let _ = ap.close().await;
            return Err(e.into());
        }
    };
    let tap = match factory
        .create_tap(&param.ifname_tap, monitor.address())
        .await
    {
        Ok(t) => t,
        Err(e) => {
            let _ = monitor.close().await;
            let _ = ap.close().await;
            return Err(e.into());
        }
    };

    let core = HostCore::new(
        config,
        kd,
        ap.address(),
        monitor.address(),
        HostRandom::generate(),
    )?;
    let (host_ip, broadcast) = (core.host_ip(), core.broadcast_ip());
    let (tx, events) = mpsc::unbounded_channel();
    let shared = Arc::new(Shared {
        ap,
        monitor,
        tap,
        core: Mutex::new(core),
        events: tx,
    });
    if let Err(e) = shared.tap.add_address(host_ip, broadcast).await {
        HostNetwork::teardown(shared).await;
        return Err(e.into());
    }

    let supervisor = tokio::spawn(supervise(Arc::clone(&shared)));
    Ok(HostNetwork {
        shared,
        events,
        supervisor,
    })
}

/// 启动四个后台循环；任一返回错误时把错误发给应用并取消其余循环。
async fn supervise(shared: Arc<Shared>) {
    let mut set: JoinSet<Result<()>> = JoinSet::new();
    set.spawn(process_events(Arc::clone(&shared)));
    set.spawn(send_advertisements(Arc::clone(&shared)));
    set.spawn(receive_data_frames(Arc::clone(&shared)));
    set.spawn(transmit_data_frames(Arc::clone(&shared)));
    while let Some(joined) = set.join_next().await {
        let error = match joined {
            Ok(Ok(())) => continue,
            Ok(Err(e)) => e,
            Err(e) if e.is_cancelled() => continue,
            Err(e) => Error::Connection(format!("background task panicked: {e}")),
        };
        let _ = shared.events.send(Err(error));
        set.abort_all();
    }
}

/// 管理帧与 LDN 认证。`AccessPoint::next_event` 内部完成 802.11 探测/认证/关联。
async fn process_events(shared: Arc<Shared>) -> Result<()> {
    loop {
        match shared.ap.next_event().await? {
            AccessPointEvent::CustomFrame { mac, data } => {
                let outcome = shared
                    .core
                    .lock()
                    .unwrap()
                    .handle_auth_request(mac, &data)?;
                shared.ap.send_custom_frame(mac, &outcome.response).await?;
                if let Some((ip, mac, event)) = outcome.joined {
                    shared.tap.add_neighbor(ip, mac).await?;
                    let _ = shared.events.send(Ok(event));
                }
            }
            AccessPointEvent::Disassociated(mac) => leave(&shared, mac).await?,
            AccessPointEvent::Associated(_) => {}
        }
    }
}

/// 成员离开：更新成员表、删邻居、上报事件。
///
/// 与 Python 版的差异：Python 把邻居加删在 AP 接口上，而成员的 IP 流量走的是 TAP 接口，
/// 所以这里加删在 TAP 接口上。
async fn leave(shared: &Shared, mac: MacAddress) -> Result<()> {
    let left = shared.core.lock().unwrap().handle_disassociation(mac);
    if let Some((ip, mac, event)) = left {
        shared.tap.remove_neighbor(ip, mac).await?;
        let _ = shared.events.send(Ok(event));
    }
    Ok(())
}

async fn send_advertisements(shared: Arc<Shared>) -> Result<()> {
    let mut interval = tokio::time::interval(ADVERTISE_INTERVAL);
    loop {
        interval.tick().await;
        let frame = shared.core.lock().unwrap().advertisement_frame()?;
        shared.monitor.send(&RadiotapFrame::new(frame)).await?;
    }
}

async fn receive_data_frames(shared: Arc<Shared>) -> Result<()> {
    loop {
        if let Frame::Data(frame) = shared.monitor.recv_frame().await? {
            let ethernet = shared.core.lock().unwrap().handle_data_frame(frame);
            if let Some(ethernet) = ethernet {
                shared.tap.write(&ethernet).await?;
            }
        }
    }
}

async fn transmit_data_frames(shared: Arc<Shared>) -> Result<()> {
    loop {
        let ethernet = shared.tap.read().await?;
        let frame = match shared.core.lock().unwrap().build_data_frame(&ethernet) {
            Ok(f) => f,
            Err(e) => {
                log::debug!("dropping malformed frame from tap: {e}");
                continue;
            }
        };
        shared.monitor.send(&RadiotapFrame::new(frame)).await?;
    }
}

impl HostNetwork {
    /// 当前网络状态。
    pub fn info(&self) -> NetworkInfo {
        self.shared.core.lock().unwrap().network().clone()
    }

    /// 网络广播地址。
    pub fn broadcast_ip(&self) -> std::net::Ipv4Addr {
        self.shared.core.lock().unwrap().broadcast_ip()
    }

    /// 修改应用数据（下一次广播生效）。
    pub fn set_application_data(&self, data: Vec<u8>) -> Result<()> {
        self.shared.core.lock().unwrap().set_application_data(data)
    }

    /// 修改接纳策略。
    pub fn set_accept_policy(&self, policy: u8) {
        self.shared.core.lock().unwrap().set_accept_policy(policy);
    }

    /// 修改黑/白名单。
    pub fn set_accept_filter(&self, filter: Vec<MacAddress>) {
        self.shared.core.lock().unwrap().set_accept_filter(filter);
    }

    /// 踢出 `index` 号成员：发断开帧、删除 station、上报 `Leave`。空槽位或主机自己不做任何事。
    pub async fn kick(&self, index: usize) -> Result<()> {
        let target = self.shared.core.lock().unwrap().kick(index);
        let Some((mac, frame)) = target else {
            return Ok(());
        };
        self.shared.ap.send_custom_frame(mac, &frame).await?;
        self.shared.ap.remove_station(mac).await?;
        leave(&self.shared, mac).await
    }

    /// 等待下一个 `Join` / `Leave` 事件。后台任务出错时返回该错误，之后不再有事件。
    pub async fn next_event(&mut self) -> Result<Event> {
        self.events
            .recv()
            .await
            .unwrap_or_else(|| Err(Error::Connection("network is closed".into())))
    }

    /// 通知所有成员网络解散，停止后台任务并删除接口。
    pub async fn close(self) -> Result<()> {
        let frames = self.shared.core.lock().unwrap().destroy_frames();
        let mut result = Ok(());
        for (mac, frame) in frames {
            if let Err(e) = self.shared.ap.send_custom_frame(mac, &frame).await {
                result = result.and(Err(e.into()));
            }
        }
        self.supervisor.abort();
        let _ = self.supervisor.await;
        Self::teardown(self.shared).await;
        result
    }

    /// 删除接口。后台任务已结束时 `shared` 是唯一引用；否则只能交给各接口的 `Drop` 兜底。
    async fn teardown(shared: Arc<Shared>) {
        match Arc::try_unwrap(shared) {
            Ok(Shared {
                ap, monitor, tap, ..
            }) => {
                drop(tap);
                if let Err(e) = monitor.close().await {
                    log::warn!("failed to delete monitor interface: {e}");
                }
                if let Err(e) = ap.close().await {
                    log::warn!("failed to stop access point: {e}");
                }
            }
            Err(_) => {
                log::warn!("background tasks still hold the interfaces; relying on Drop cleanup")
            }
        }
    }
}
