//! WLAN 接口：monitor、TAP、STA、AP，以及创建它们的 [`Factory`]。
//!
//! 对应 Python 版 wlan.py 的 `Monitor`/`Tap`/`Station`/`AccessPoint`/`Factory`。
//! Python 用 `asynccontextmanager` 在退出时清理；这里每个接口提供显式的
//! `async fn close(self)` 做有序清理（断开/停 AP、再删接口），忘了调用时
//! `Drop` 会尽力发一条删除接口的请求，不留残留接口。另外所有 STA/AP 请求都带
//! `SOCKET_OWNER`，nl80211 socket 关闭时内核也会自动断开连接、停止 AP。

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ldn_netlink::nl80211::{
    self as nl, ConnectParams, Event, InterfaceType, NewInterface, StartApParams, Wiphy,
};
use ldn_netlink::{genl::GenlMessage, rtnl};
use ldn_wire::element::{
    Elements, RsnElement, WLAN_AKM_SUITE_PSK, WLAN_CIPHER_SUITE_CCMP, eid, encode_elements,
};
use ldn_wire::frame::{ActionFrame, Frame, MacHeader, stype};
use ldn_wire::radiotap::RadiotapFrame;
use ldn_wire::{MacAddress, channel};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::ap::{ApAction, ApConfig, ApCore, ApEvent};
use crate::client::{Nl80211, Route};
use crate::error::{Error, Result};
use crate::sys;

/// 等待内核确认 `CONNECT` / `START_AP` 的最长时间。
///
/// 与 Python 版的差异：Python 版无限等待；这里超时后报错，避免网卡无响应时永远挂起。
const MLME_TIMEOUT: Duration = Duration::from_secs(10);
/// monitor 口单帧接收缓冲；802.11 帧加 Radiotap 头远小于此。
const MONITOR_MTU: usize = 8192;
/// TAP 口单帧接收缓冲。
const TAP_MTU: usize = 4096;

fn frequency(ch: u8) -> Result<u32> {
    channel::channel_to_frequency(ch)
        .map(u32::from)
        .ok_or_else(|| Error::Protocol(format!("unsupported channel {ch}")))
}

/// 关闭接口的 IPv6，免得内核往 LDN 网络里发 IPv6 邻居发现/路由请求。
fn disable_ipv6(name: &str) -> Result<()> {
    std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"), "1")?;
    Ok(())
}

/// 同时持有 nl80211 与 rtnetlink 客户端，负责创建各种接口。
#[derive(Clone)]
pub struct Factory {
    wlan: Arc<Nl80211>,
    route: Arc<Route>,
}

impl Factory {
    /// 连接 nl80211 与 rtnetlink。
    pub async fn new() -> Result<Self> {
        Ok(Self {
            wlan: Arc::new(Nl80211::connect().await?),
            route: Arc::new(Route::connect()?),
        })
    }

    /// 列出所有 wiphy；普通用户即可调用。
    pub async fn wiphys(&self) -> Result<Vec<Wiphy>> {
        let mut out = Vec::new();
        for payload in self.wlan.request(&nl::get_wiphy_dump()).await? {
            if let Some(w) = Wiphy::parse(&GenlMessage::parse(&payload)?)? {
                out.push(w);
            }
        }
        Ok(out)
    }

    async fn create_interface(
        &self,
        phy: &str,
        ifname: &str,
        iftype: InterfaceType,
    ) -> Result<InterfaceGuard> {
        let wiphy = self
            .wiphys()
            .await?
            .into_iter()
            .find(|w| w.name == phy)
            .ok_or_else(|| Error::Protocol(format!("no wiphy found with name '{phy}'")))?;
        let replies = self
            .wlan
            .request(&nl::new_interface(wiphy.index, ifname, iftype))
            .await?;
        let reply = replies
            .first()
            .ok_or_else(|| Error::Protocol("empty NEW_INTERFACE reply".into()))?;
        let info = NewInterface::parse(&GenlMessage::parse(reply)?)?;
        Ok(InterfaceGuard {
            wlan: Arc::clone(&self.wlan),
            route: Arc::clone(&self.route),
            name: ifname.to_owned(),
            ifindex: info.ifindex,
            mac: info.mac,
            deleted: false,
        })
    }

    /// 在 `phy` 上创建 monitor 接口并拉起，接收所有 BSS 的帧。需要 root。
    pub async fn create_monitor(&self, phy: &str, ifname: &str) -> Result<Monitor> {
        let iface = self
            .create_interface(phy, ifname, InterfaceType::Monitor)
            .await?;
        iface.up().await?;
        let fd = AsyncFd::new(sys::packet_socket(iface.ifindex)?)?;
        Ok(Monitor {
            iface,
            fd,
            filter: None,
        })
    }

    /// 在 `phy` 上创建 STA 接口并连接到 `ssid`；成功返回时已装好密钥、订阅了 Action 帧。
    pub async fn connect_network(
        &self,
        phy: &str,
        ifname: &str,
        ssid: &[u8],
        channel: u8,
        key: Option<&[u8]>,
    ) -> Result<Station> {
        let iface = self
            .create_interface(phy, ifname, InterfaceType::Station)
            .await?;
        Station::connect(iface, ssid, frequency(channel)?, key).await
    }

    /// 在 `phy` 上创建 AP 接口并启动；成功返回时已装好组播密钥、订阅了所需管理帧。
    pub async fn create_ap(
        &self,
        phy: &str,
        ifname: &str,
        ssid: &[u8],
        channel: u8,
        key: Option<&[u8]>,
        max_stations: usize,
    ) -> Result<AccessPoint> {
        let iface = self
            .create_interface(phy, ifname, InterfaceType::Ap)
            .await?;
        let config = ApConfig {
            ifindex: iface.ifindex,
            mac: iface.mac,
            ssid: ssid.to_vec(),
            channel,
            key: key.map(<[u8]>::to_vec),
            max_stations,
        };
        AccessPoint::start(iface, config).await
    }

    /// 创建 TAP 接口，设 MAC 地址后拉起。fd 关闭时内核自动删除该接口。需要 root。
    pub async fn create_tap(&self, ifname: &str, mac: MacAddress) -> Result<Tap> {
        let fd = AsyncFd::new(sys::open_tap(ifname)?)?;
        let ifindex = sys::if_nametoindex(ifname)?;
        let tap = Tap {
            fd,
            ifindex,
            route: Arc::clone(&self.route),
        };
        self.route
            .request(&rtnl::set_link_address(ifindex, mac))
            .await?;
        self.route.request(&rtnl::set_link_up(ifindex)).await?;
        Ok(tap)
    }
}

/// 一个由本进程创建的无线接口，负责在结束时删除它。
struct InterfaceGuard {
    wlan: Arc<Nl80211>,
    route: Arc<Route>,
    name: String,
    ifindex: u32,
    mac: MacAddress,
    deleted: bool,
}

impl InterfaceGuard {
    async fn up(&self) -> Result<()> {
        self.route.request(&rtnl::set_link_up(self.ifindex)).await
    }

    async fn register_frame(&self, subtype: u8) -> Result<()> {
        self.wlan
            .request(&nl::register_frame(self.ifindex, subtype))
            .await
            .map(drop)
    }

    async fn delete(mut self) -> Result<()> {
        self.deleted = true;
        self.wlan
            .request(&nl::del_interface(self.ifindex))
            .await
            .map(drop)
    }
}

impl Drop for InterfaceGuard {
    fn drop(&mut self) {
        if !self.deleted {
            log::debug!(
                "interface {} dropped without close(); deleting it",
                self.name
            );
            self.wlan.send_nowait(&nl::del_interface(self.ifindex));
        }
    }
}

/// monitor 接口：收发带 Radiotap 头的裸 802.11 帧。
pub struct Monitor {
    iface: InterfaceGuard,
    fd: AsyncFd<OwnedFd>,
    filter: Option<MacAddress>,
}

impl Monitor {
    /// 接口 MAC 地址。
    pub fn address(&self) -> MacAddress {
        self.iface.mac
    }

    /// 只接收 BSSID（addr3）为 `bssid` 或广播的帧；`None` 取消过滤。只影响 [`recv_frame`](Self::recv_frame)。
    pub fn set_filter(&mut self, bssid: Option<MacAddress>) {
        self.filter = bssid;
    }

    /// 切到指定信道。
    pub async fn set_channel(&self, ch: u8) -> Result<()> {
        self.iface
            .wlan
            .request(&nl::set_channel(self.iface.ifindex, frequency(ch)?))
            .await
            .map(drop)
    }

    /// 接收下一个 Radiotap 帧（不做 BSSID 过滤），格式错误的帧跳过。
    pub async fn recv(&self) -> Result<RadiotapFrame> {
        let mut buf = vec![0u8; MONITOR_MTU];
        loop {
            let n = self
                .fd
                .async_io(Interest::READABLE, |fd| sys::read(fd.as_raw_fd(), &mut buf))
                .await?;
            match RadiotapFrame::decode(&buf[..n]) {
                Ok(frame) => return Ok(frame),
                Err(e) => log::debug!("ignoring invalid radiotap frame: {e}"),
            }
        }
    }

    /// 发送一个 Radiotap 帧。
    pub async fn send(&self, frame: &RadiotapFrame) -> Result<()> {
        let data = frame.encode();
        self.fd
            .async_io(Interest::WRITABLE, |fd| sys::write(fd.as_raw_fd(), &data))
            .await?;
        Ok(())
    }

    /// 接收下一个可识别且通过 BSSID 过滤的 802.11 帧。
    pub async fn recv_frame(&self) -> Result<Frame> {
        loop {
            let radiotap = self.recv().await?;
            match self.parse_frame(&radiotap.data) {
                Ok(Some(frame)) => return Ok(frame),
                Ok(None) => {}
                Err(e) => log::debug!("ignoring invalid frame: {e}"),
            }
        }
    }

    fn parse_frame(&self, data: &[u8]) -> Result<Option<Frame>> {
        let bssid = MacHeader::decode(data)?.address3;
        if let Some(filter) = self.filter
            && !bssid.is_broadcast()
            && bssid != filter
        {
            return Ok(None);
        }
        Ok(Frame::parse(data)?)
    }

    /// 发送一个 802.11 帧（不带可选 Radiotap 字段，由驱动选速率）。
    pub async fn send_frame(&self, frame: &Frame) -> Result<()> {
        self.send(&RadiotapFrame::new(frame.encode()?)).await
    }

    /// 删除接口。
    pub async fn close(self) -> Result<()> {
        self.iface.delete().await
    }
}

/// TAP 接口：把解密后的数据帧以以太网帧形式交给 Linux 协议栈。
pub struct Tap {
    fd: AsyncFd<OwnedFd>,
    ifindex: u32,
    route: Arc<Route>,
}

impl Tap {
    /// 读出协议栈要发出的下一个以太网帧。
    pub async fn read(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; TAP_MTU];
        let n = self
            .fd
            .async_io(Interest::READABLE, |fd| sys::read(fd.as_raw_fd(), &mut buf))
            .await?;
        buf.truncate(n);
        Ok(buf)
    }

    /// 把收到的以太网帧写入协议栈。
    pub async fn write(&self, frame: &[u8]) -> Result<()> {
        self.fd
            .async_io(Interest::WRITABLE, |fd| sys::write(fd.as_raw_fd(), frame))
            .await?;
        Ok(())
    }

    /// 添加 IPv4 地址（/24）。
    pub async fn add_address(&self, local: Ipv4Addr, broadcast: Ipv4Addr) -> Result<()> {
        self.route
            .request(&rtnl::add_ipv4_address(self.ifindex, local, broadcast, 24))
            .await
    }

    /// 添加永久邻居。
    pub async fn add_neighbor(&self, ip: Ipv4Addr, mac: MacAddress) -> Result<()> {
        self.route
            .request(&rtnl::add_neighbor(self.ifindex, ip, mac))
            .await
    }

    /// 删除邻居。
    pub async fn remove_neighbor(&self, ip: Ipv4Addr, mac: MacAddress) -> Result<()> {
        self.route
            .request(&rtnl::remove_neighbor(self.ifindex, ip, mac))
            .await
    }
}

/// STA 接口上 LDN 关心的事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StationEvent {
    /// 收到 Action 帧（房间广播）。
    ActionFrame {
        /// 帧。
        frame: ActionFrame,
        /// 所在频率（MHz）。
        frequency: Option<u32>,
    },
    /// 收到 LDN 自定义的 control port 帧。
    CustomFrame {
        /// 发送方。
        mac: MacAddress,
        /// 内容。
        data: Vec<u8>,
    },
    /// 被 AP 删除（踢出或网络解散）。
    Disassociated(MacAddress),
}

/// 已连接到网络的 STA 接口。
pub struct Station {
    iface: InterfaceGuard,
    bssid: MacAddress,
}

impl Station {
    async fn connect(
        iface: InterfaceGuard,
        ssid: &[u8],
        frequency: u32,
        key: Option<&[u8]>,
    ) -> Result<Self> {
        iface.up().await?;
        disable_ipv6(&iface.name)?;

        let rsn = RsnElement {
            group_cipher_suite: WLAN_CIPHER_SUITE_CCMP,
            pairwise_cipher_suites: vec![WLAN_CIPHER_SUITE_CCMP],
            akm_suites: vec![WLAN_AKM_SUITE_PSK],
            capabilities: 12,
        };
        let ie = encode_elements(&Elements::from([(eid::RSN, rsn.encode()?)]))?;
        let params = ConnectParams {
            ifindex: iface.ifindex,
            ssid,
            frequency,
            privacy: key.is_some(),
            ie: &ie,
        };
        iface.wlan.request(&nl::connect(&params)).await?;

        let (status, bssid) = tokio::time::timeout(MLME_TIMEOUT, async {
            loop {
                if let Event::Connect { status, bssid } = iface.wlan.next_event().await? {
                    return Ok::<_, Error>((status, bssid));
                }
            }
        })
        .await
        .map_err(|_| Error::Protocol("timed out waiting for connect result".into()))??;
        if status != 0 {
            return Err(Error::Protocol(format!(
                "connect failed with status code {status}"
            )));
        }
        let bssid = bssid.ok_or_else(|| Error::Protocol("connect event without BSSID".into()))?;

        let sta = Self { iface, bssid };
        if let Some(key) = key {
            // 0 号：发给主机的单播帧；1 号：广播帧。与 Python 版一致用同一把密钥。
            sta.iface
                .wlan
                .request(&nl::new_key(sta.iface.ifindex, Some(bssid), 0, key))
                .await?;
            sta.iface
                .wlan
                .request(&nl::new_key(sta.iface.ifindex, None, 1, key))
                .await?;
        }
        sta.iface.register_frame(stype::ACTION).await?;
        Ok(sta)
    }

    /// 接口 MAC 地址。
    pub fn address(&self) -> MacAddress {
        self.iface.mac
    }

    /// 所连 AP（主机）的地址。
    pub fn bssid(&self) -> MacAddress {
        self.bssid
    }

    /// 等待下一个事件，其他 nl80211 事件和畸形帧会被跳过。
    pub async fn next_event(&self) -> Result<StationEvent> {
        loop {
            match self.iface.wlan.next_event().await? {
                Event::Frame { frame, frequency } => match ActionFrame::decode(&frame) {
                    Ok(frame) => return Ok(StationEvent::ActionFrame { frame, frequency }),
                    Err(e) => log::debug!("ignoring invalid action frame: {e}"),
                },
                Event::ControlPortFrame { mac, frame } => {
                    return Ok(StationEvent::CustomFrame { mac, data: frame });
                }
                Event::DelStation { mac } => return Ok(StationEvent::Disassociated(mac)),
                _ => {}
            }
        }
    }

    /// 向 `mac` 发送 LDN 自定义帧。
    pub async fn send_custom_frame(&self, mac: MacAddress, data: &[u8]) -> Result<()> {
        self.iface
            .wlan
            .request(&nl::control_port_frame(self.iface.ifindex, mac, data))
            .await
            .map(drop)
    }

    /// LDN 认证完成后把主机标记为已授权，开始收发数据帧。
    pub async fn set_authorized(&self) -> Result<()> {
        self.iface
            .wlan
            .request(&nl::set_station_authorized(self.iface.ifindex, self.bssid))
            .await
            .map(drop)
    }

    /// 给 STA 接口添加 IPv4 地址（/24）。STA 模式下数据帧由内核直接收发，不需要 TAP。
    pub async fn add_address(&self, local: Ipv4Addr, broadcast: Ipv4Addr) -> Result<()> {
        self.iface
            .route
            .request(&rtnl::add_ipv4_address(
                self.iface.ifindex,
                local,
                broadcast,
                24,
            ))
            .await
    }

    /// 添加永久邻居。
    pub async fn add_neighbor(&self, ip: Ipv4Addr, mac: MacAddress) -> Result<()> {
        self.iface
            .route
            .request(&rtnl::add_neighbor(self.iface.ifindex, ip, mac))
            .await
    }

    /// 删除邻居。
    pub async fn remove_neighbor(&self, ip: Ipv4Addr, mac: MacAddress) -> Result<()> {
        self.iface
            .route
            .request(&rtnl::remove_neighbor(self.iface.ifindex, ip, mac))
            .await
    }

    /// 断开并删除接口。断开失败时仍然删除接口，并返回第一个错误。
    pub async fn close(self) -> Result<()> {
        let disconnect = self
            .iface
            .wlan
            .request(&nl::disconnect(self.iface.ifindex))
            .await
            .map(drop);
        let delete = self.iface.delete().await;
        disconnect.and(delete)
    }
}

/// AP 接口上 LDN 关心的事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessPointEvent {
    /// station 完成 802.11 关联。
    Associated(MacAddress),
    /// station 主动离开。
    Disassociated(MacAddress),
    /// 收到 LDN 自定义的 control port 帧。
    CustomFrame {
        /// 发送方。
        mac: MacAddress,
        /// 内容。
        data: Vec<u8>,
    },
}

/// 已启动的 AP 接口。
///
/// 管理帧（探测、认证、关联）在 [`next_event`](Self::next_event) 里处理，
/// 所以 AP 运行期间必须有一个任务持续调用它；其余方法都接受 `&self`，
/// 可以在另一个任务里并发调用（例如踢人）。
pub struct AccessPoint {
    iface: InterfaceGuard,
    core: Mutex<ApCore>,
    queued: Mutex<VecDeque<AccessPointEvent>>,
}

impl AccessPoint {
    async fn start(iface: InterfaceGuard, config: ApConfig) -> Result<Self> {
        iface.up().await?;
        disable_ipv6(&iface.name)?;
        let core = ApCore::new(config);
        let config = core.config();
        let head = core.beacon_head()?;
        let params = StartApParams {
            ifindex: iface.ifindex,
            ssid: &config.ssid,
            mac: iface.mac,
            frequency: frequency(config.channel)?,
            beacon_head: &head,
            beacon_tail: &[],
            beacon_interval: 100,
            dtim_period: 3,
        };
        iface.wlan.request(&nl::start_ap(&params)).await?;
        tokio::time::timeout(MLME_TIMEOUT, async {
            while iface.wlan.next_event().await? != Event::StartAp {}
            Ok::<_, Error>(())
        })
        .await
        .map_err(|_| Error::Protocol("timed out waiting for AP to start".into()))??;

        let ap = Self {
            core: Mutex::new(core),
            queued: Mutex::new(VecDeque::new()),
            iface,
        };
        let key = ap.core.lock().unwrap().config().key.clone();
        if let Some(key) = key {
            ap.iface
                .wlan
                .request(&nl::new_key(ap.iface.ifindex, None, 1, &key))
                .await?;
            ap.iface
                .wlan
                .request(&nl::set_default_multicast_key(ap.iface.ifindex, 1))
                .await?;
        }
        for subtype in [
            stype::ASSOC_REQ,
            stype::PROBE_REQ,
            stype::DISASSOC,
            stype::AUTH,
            stype::DEAUTH,
        ] {
            ap.iface.register_frame(subtype).await?;
        }
        Ok(ap)
    }

    /// AP 的 MAC 地址（BSSID）。
    pub fn address(&self) -> MacAddress {
        self.iface.mac
    }

    /// 处理管理帧直到有事件可报告。驱动请求失败会作为错误返回。
    pub async fn next_event(&self) -> Result<AccessPointEvent> {
        loop {
            if let Some(event) = self.queued.lock().unwrap().pop_front() {
                return Ok(event);
            }
            match self.iface.wlan.next_event().await? {
                Event::Frame { frame, .. } => {
                    let parsed = match Frame::parse(&frame) {
                        Ok(Some(f)) => f,
                        Ok(None) => continue,
                        Err(e) => {
                            log::debug!("ignoring invalid management frame: {e}");
                            continue;
                        }
                    };
                    // 锁只在计算动作时持有，执行（await）前释放。
                    let actions = self.core.lock().unwrap().handle_frame(&parsed)?;
                    self.execute(actions).await?;
                }
                Event::ControlPortFrame { mac, frame } => {
                    return Ok(AccessPointEvent::CustomFrame { mac, data: frame });
                }
                _ => {}
            }
        }
    }

    async fn execute(&self, actions: Vec<ApAction>) -> Result<()> {
        for action in actions {
            match action {
                ApAction::SendFrame(data) => {
                    self.iface
                        .wlan
                        .request(&nl::frame(self.iface.ifindex, &data))
                        .await?;
                }
                ApAction::Request(req) => {
                    self.iface.wlan.request(&req).await?;
                }
                ApAction::Event(e) => self.queued.lock().unwrap().push_back(match e {
                    ApEvent::Associated(mac) => AccessPointEvent::Associated(mac),
                    ApEvent::Disassociated(mac) => AccessPointEvent::Disassociated(mac),
                }),
            }
        }
        Ok(())
    }

    /// 踢出 station（发 Deauthentication 并让驱动删除它）；不存在时什么都不做。
    pub async fn remove_station(&self, mac: MacAddress) -> Result<()> {
        let actions = self.core.lock().unwrap().remove_station(mac)?;
        self.execute(actions).await
    }

    /// 向 `mac` 发送 LDN 自定义帧。
    pub async fn send_custom_frame(&self, mac: MacAddress, data: &[u8]) -> Result<()> {
        self.iface
            .wlan
            .request(&nl::control_port_frame(self.iface.ifindex, mac, data))
            .await
            .map(drop)
    }

    /// 停止 AP 并删除接口。停止失败时仍然删除接口，并返回第一个错误。
    pub async fn close(self) -> Result<()> {
        let stop = self
            .iface
            .wlan
            .request(&nl::stop_ap(self.iface.ifindex))
            .await
            .map(drop);
        let delete = self.iface.delete().await;
        stop.and(delete)
    }
}
