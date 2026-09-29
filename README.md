# LDN-rs

Python 包 [kinnay/LDN](https://github.com/kinnay/LDN) 的 Rust 重写：在 Linux 上以
nl80211 + monitor + TAP 的方式实现任天堂 Switch 的本地无线通信（LDN），
支持扫描房间、加入房间、建房。

## 仓库结构

```
LDN-rs/
├── Cargo.toml                 workspace；第三方依赖统一钉死版本
├── crates/
│   ├── ldn-wire/              阶段 1：802.11 帧编解码，无 I/O，无第三方依赖
│   ├── ldn-netlink/           阶段 4a：netlink / genl / nl80211 / rtnetlink 编解码，无 I/O
│   │   └── src/{message,nla,genl,nl80211,rtnl}.rs
│   └── ldn-wlan/              阶段 4b：tokio I/O 层
│       └── src/
│           ├── sys.rs         全部系统调用（workspace 里唯一的 unsafe）
│           ├── netlink.rs     异步 netlink socket：按序号分发回复、通知入事件队列
│           ├── client.rs      Nl80211（family 解析、mlme 组播）、Route
│           ├── ap.rs          AP 管理帧状态机（sans-IO）
│           └── interface.rs   Factory、Monitor、Tap、Station、AccessPoint
└── tools/
    ├── gen_python_vectors.py  帧编解码对拍向量
    ├── gen_netlink_vectors.py 驱动 wlan.py 真实代码路径，截获它发出的 netlink 消息
    └── requirements.txt
```

## 开发

```bash
cargo test                      # 单元测试 + 对拍测试（普通用户即可，netlink 部分会连真实内核的 NETLINK_ROUTE）
cargo clippy --all-targets
cargo fmt

# 需要网卡的集成测试，默认 #[ignore]，用法见 crates/ldn-wlan/tests/hardware.rs
cargo test -p ldn-wlan --test hardware -- --ignored list_wiphys

# 重新生成对拍向量（需要旁边有 Python 版仓库）
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements.txt
.venv/bin/python tools/gen_python_vectors.py ../LDN
.venv/bin/python tools/gen_netlink_vectors.py ../LDN
```

对拍向量的生成脚本和各 `tests/*parity*.rs` 里的输入必须逐字段一致，改一边就要改另一边。
测试所需的密钥一律用脚本里写死的假密钥，不要把真实的 `prod.keys` 放进仓库。

## 移植路线

| 阶段 | crate | 内容（对应 Python） | 验证方式 |
|---|---|---|---|
| 1 ✅ | `ldn-wire` | `wlan.py` 的帧与 IE 编解码、`streams.py` | 单元测试 + 19 组对拍 |
| 2 | `ldn-crypto` | `KeyDerivation`、CCMP 加解密、广播帧 AES-CTR/GCM、挑战 HMAC | 假密钥对拍；`DATA_CCMP_ENCRYPTED` 已备好 |
| 3 | `ldn-proto` | `NetworkInfo`、`AdvertisementFrame`、`Challenge*`、LDN `AuthenticationFrame`、`DisconnectFrame` | 对拍向量 |
| 4 ✅ | `ldn-netlink` + `ldn-wlan` | `wlan.py` 的 `Factory`/`Monitor`/`Tap`/`Station`/`AccessPoint` 与 python-netlink | 33 条 netlink 消息逐字节对拍；AP 状态机单测 + 对拍；真实内核 netlink 测试；硬件测试 `#[ignore]` |
| 5 | `ldn` | `Scanner`、`STANetwork`、`APNetwork` 与 `scan`/`connect`/`create_network` | sans-IO 状态机单测；真机联调 Switch |

## 已定的设计

- **异步运行时：tokio。** 后台循环用 `tokio::spawn`/`JoinSet`，超时用 `tokio::time::timeout`。
- **nl80211：自己实现，不用 `wl-nl80211`，也不用 rust-netlink 的其他 crate。** 编解码（`ldn-netlink`）是纯函数，
  可以和 python-netlink 逐字节对拍；socket 层直接用 `libc`（最稳定的依赖）加 tokio `AsyncFd`，AF_PACKET 和 TUN
  本来也只能这样做。依赖只有 `tokio`、`libc`、`log` 三个。
- **异步清理：** 每个接口提供 `async fn close(self)`；忘记调用时 `Drop` 尽力发一条删除接口请求。STA/AP 请求都带
  `SOCKET_OWNER`，进程退出时内核也会自动断开连接、停止 AP。
- **加密库（阶段 2 待定）：** 推荐 RustCrypto 系；`ring` 不提供 AES-CCM 和 AES-ECB。

## 与 Python 版的有意差异

- `DisassociationFrame` 编码时的子类型改为标准的 10（Python 版误写成 11，且 Python 版只解码不编码该帧）。
- `RadiotapFrame` 把频率和信道标志合为 `Option<RadiotapChannel>`，排除 Python 版“只设频率”产生的畸形头。
- `MacAddress` 是 `Copy` 值类型，没有 Python 版 dataclass 共享默认对象的问题。
- 不加密时 `CONNECT` 不发 `NL80211_ATTR_PRIVACY`（python-netlink 的 flag 类型无论真假都编码成“存在”）。
- 等待 `CONNECT` / `START_AP` 确认超过 10 秒报错，Python 版无限等待。
- AP 的管理帧在 `AccessPoint::next_event` 里处理（Python 是独立后台任务），AP 运行期间必须持续调用它。
- 同 ID 的 IE 出现多次时仍只保留最后一个，与 Python 版一致；这不符合 802.11（221 可以出现多次），等到需要解析 Vendor IE 时再改成 `Vec`。

## ldn-wire 主要接口

| 类型 / 函数 | 主要方法 | 说明 |
|---|---|---|
| `stream::Reader<'a>` | `new(data, Endian)`、`u8/u16/u24/u32/u64/u32_be`、`read(n)`、`read_array::<N>()`、`peek`、`rest`、`seek/skip/align`、`pad(n)` | 借用输入缓冲区的只读流，越界返回 `Error::UnexpectedEof` |
| `stream::Writer` | `new(Endian)`、同名写方法、`seek`（可回填）、`into_vec` | 可回填长度字段的输出流；`u24(v, field)` 做位宽检查 |
| `MacAddress` | `new([u8;6])`、`from_u64`、`parse()`、`octets`、`ZERO`/`BROADCAST` | 显示为大写冒号格式 |
| `element::{encode_elements, decode_elements}` | `(&Elements) -> Result<Vec<u8>>` / `(&[u8]) -> Result<Elements>` | `Elements = BTreeMap<u8, Vec<u8>>` |
| `element::RsnElement` | `encode() -> Result<Vec<u8>>` | AP 声明 CCMP + PSK |
| `radiotap::RadiotapFrame` | `new(data)`、`encode() -> Vec<u8>`、`decode(&[u8])` | 只解析 TSFT/Flags/Rate/Channel，其余按头长度跳过 |
| `frame::MacHeader` | `encode() -> [u8; 24]`、`decode(&[u8])` | 3 地址格式 |
| `frame::{AssociationRequest, AssociationResponse, ProbeRequest, ProbeResponse, BeaconFrame, AuthenticationFrame, DeauthenticationFrame, DisassociationFrame, ActionFrame}` | `encode()`、`decode(&[u8])` | 解码时校验类型/子类型 |
| `frame::Frame` | `parse(&[u8]) -> Result<Option<Frame>>`、`encode()` | monitor 口的帧分发；不认识的类型返回 `None` |
| `data::DataFrame` | `encode()`、`decode()`、`ccmp_nonce() -> [u8;13]`、`ccmp_aad() -> [u8;22]` | 受保护帧只处理 CCMP 头，加解密由阶段 2 完成 |
| `data::{SnapHeader, EthernetFrame}` | `encode()`、`decode()` | 数据面与 TAP 口的格式转换 |

## ldn-netlink 主要接口

| 类型 / 函数 | 说明 |
|---|---|
| `message::{encode, parse_messages, RawMessage}` | `nlmsghdr` 编码；一个数据报拆成多条消息，长度越界返回 `Error::Truncated` |
| `message::ErrorMessage::parse(flags, payload)` | ACK / 错误码 + 扩展 ACK 文字说明 |
| `nla::Attrs` | 属性构造器：`u8/u16/u32/string/flag/bytes/nested`，链式调用，`finish()` 统一报告超长错误 |
| `nla::AttrMap` | 属性解析：`get/require/u8/u16/u32/opt_u32/string/nested/nested_array` |
| `genl::{get_family_request, Family::parse, GenlMessage::parse}` | nlctrl 查询 family id、版本与组播组 |
| `nl80211::Request::encode(&Family, seq, pid)` | 下面所有构造函数的产物 |
| `nl80211::{get_wiphy_dump, new_interface, del_interface, set_channel, register_frame, frame, control_port_frame, new_key, set_default_multicast_key, connect, disconnect, set_station_authorized, start_ap, stop_ap, new_station, del_station}` | 与 wlan.py 每个 `request(...)` 一一对应，属性顺序一致 |
| `nl80211::{Event, Wiphy, NewInterface}` | 事件（Connect/StartAp/Frame/ControlPortFrame/DelStation）与回复解析 |
| `rtnl::{set_link_up, set_link_address, add_ipv4_address, add_neighbor, remove_neighbor}` | 返回 `RouteRequest`，`encode(seq, pid)` |

## ldn-wlan 主要接口

| 类型 | 主要方法 | 说明 |
|---|---|---|
| `Factory` | `new()`、`wiphys()`、`create_monitor(phy, ifname)`、`connect_network(phy, ifname, ssid, channel, key)`、`create_ap(phy, ifname, ssid, channel, key, max)`、`create_tap(ifname, mac)` | 除 `wiphys` 外都需要 root |
| `Monitor` | `set_channel`、`set_filter(Option<Mac>)`、`recv/send`（Radiotap）、`recv_frame/send_frame`（`Frame`）、`close` | AF_PACKET 原始 socket |
| `Tap` | `read/write`（以太网帧）、`add_address`、`add_neighbor`、`remove_neighbor` | fd 关闭即删除接口 |
| `Station` | `bssid`、`next_event -> StationEvent`、`send_custom_frame`、`set_authorized`、`close` | 构造成功即已连接、已装密钥 |
| `AccessPoint` | `next_event -> AccessPointEvent`、`remove_station`、`send_custom_frame`、`close` | 方法都是 `&self`，可在另一任务里并发踢人 |
| `ap::ApCore` | `handle_frame(&Frame) -> Vec<ApAction>`、`remove_station`、`beacon_head` | 纯逻辑：探测/认证/关联/人满/重复关联/解除关联 |
| `netlink::NetlinkSocket` | `open(protocol)`、`request(encode)`、`send_nowait`、`add_membership`、`next_event` | 读任务按序号分发回复 |
