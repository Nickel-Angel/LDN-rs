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
│   ├── ldn-crypto/            阶段 2：密钥表与派生、CCMP、AES-CTR/GCM、SHA-256、HMAC（RustCrypto）
│   ├── ldn-proto/             阶段 3：广播帧、挑战、LDN 认证帧、断开帧、NetworkInfo，无 I/O
│   ├── ldn-netlink/           阶段 4a：netlink / genl / nl80211 / rtnetlink 编解码，无 I/O
│   │   └── src/{message,nla,genl,nl80211,rtnl}.rs
│   ├── ldn-wlan/              阶段 4b：tokio I/O 层
│       └── src/
│           ├── sys.rs         全部系统调用（workspace 里唯一的 unsafe）
│           ├── netlink.rs     异步 netlink socket：按序号分发回复、通知入事件队列
│           ├── client.rs      Nl80211（family 解析、mlme 组播）、Route
│           ├── ap.rs          AP 管理帧状态机（sans-IO）
│           └── interface.rs   Factory、Monitor、Tap、Station、AccessPoint
│   └── ldn/                   阶段 5：对外 API（scan / connect / create_network）
│       ├── src/{host_core,station_core}.rs  建房 / 加入的协议状态机（sans-IO）
│       ├── src/{host,station,scan}.rs       把状态机接到 ldn-wlan 接口上的 tokio 驱动
│       └── examples/{scan,join,host}.rs     对应 Python 版 examples/
└── tools/
    ├── gen_python_vectors.py  帧编解码对拍向量
    ├── gen_netlink_vectors.py 驱动 wlan.py 真实代码路径，截获它发出的 netlink 消息
    ├── gen_crypto_vectors.py  用假系统密钥调用 Python 的派生与加密方法
    ├── gen_proto_vectors.py   用假系统密钥调用 Python 的协议类编码各类 LDN 帧
    ├── gen_ldn_vectors.py     用假接口驱动 APNetwork / STANetwork，截获握手、广播和数据面字节
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
.venv/bin/python tools/gen_crypto_vectors.py ../LDN
.venv/bin/python tools/gen_proto_vectors.py ../LDN
.venv/bin/python tools/gen_ldn_vectors.py ../LDN
```

对拍向量的生成脚本和各 `tests/*parity*.rs` 里的输入必须逐字段一致，改一边就要改另一边。
测试所需的密钥一律用脚本里写死的假密钥，不要把真实的 `prod.keys` 放进仓库。

## 移植路线

| 阶段 | crate | 内容（对应 Python） | 验证方式 |
|---|---|---|---|
| 1 ✅ | `ldn-wire` | `wlan.py` 的帧与 IE 编解码、`streams.py` | 单元测试 + 19 组对拍 |
| 2 ✅ | `ldn-crypto` | `load_keys`、`KeyDerivation`、CCMP 加解密、广播帧 AES-CTR/GCM、认证帧 AES-GCM、挑战 HMAC | 协议 1/3 两套假密钥对拍 + CCMP 双向对拍 + 篡改/边界单测 |
| 3 ✅ | `ldn-proto` | `NetworkId`、`NetworkInfo`、`AdvertisementFrame`（V1/V2 载荷，明文/CTR/GCM）、`Challenge*`、LDN `AuthenticationFrame`、`DisconnectFrame` | 18 组对拍（广播帧 4 种、认证帧 8 种）双向 + 篡改/边界单测 |
| 4 ✅ | `ldn-netlink` + `ldn-wlan` | `wlan.py` 的 `Factory`/`Monitor`/`Tap`/`Station`/`AccessPoint` 与 python-netlink | 33 条 netlink 消息逐字节对拍；AP 状态机单测 + 对拍；真实内核 netlink 测试；硬件测试 `#[ignore]` |
| 5 ✅ | `ldn` | `Scanner`、`STANetwork`、`APNetwork` 与 `scan`/`connect`/`create_network`、示例 | 协议 1/3 完整场景（建房→认证加入→拒绝→收发数据→踢人）逐字节对拍；真机联调 Switch **未做** |

## 已定的设计

- **异步运行时：tokio。** 后台循环用 `tokio::spawn`/`JoinSet`，超时用 `tokio::time::timeout`。
- **nl80211：自己实现，不用 `wl-nl80211`，也不用 rust-netlink 的其他 crate。** 编解码（`ldn-netlink`）是纯函数，
  可以和 python-netlink 逐字节对拍；socket 层直接用 `libc`（最稳定的依赖）加 tokio `AsyncFd`，AF_PACKET 和 TUN
  本来也只能这样做。依赖只有 `tokio`、`libc`、`log` 三个。
- **异步清理：** 每个接口提供 `async fn close(self)`；忘记调用时 `Drop` 尽力发一条删除接口请求。STA/AP 请求都带
  `SOCKET_OWNER`，进程退出时内核也会自动断开连接、停止 AP。
- **加密库：RustCrypto**（`aes`、`ccm`、`ctr`、`aes-gcm`、`sha2`、`hmac`，均钉死版本）。纯 Rust、无 C 依赖；`ring` 不提供 AES-CCM 和 AES-ECB。
- **加密原语与帧格式分离：** `ldn-crypto` 只做“给定字节加解密”，广播帧/认证帧/挑战帧的格式留给 `ldn-proto`。

## 与 Python 版的有意差异

- `DisassociationFrame` 编码时的子类型改为标准的 10（Python 版误写成 11，且 Python 版只解码不编码该帧）。
- `RadiotapFrame` 把频率和信道标志合为 `Option<RadiotapChannel>`，排除 Python 版“只设频率”产生的畸形头。
- `MacAddress` 是 `Copy` 值类型，没有 Python 版 dataclass 共享默认对象的问题。
- 不加密时 `CONNECT` 不发 `NL80211_ATTR_PRIVACY`（python-netlink 的 flag 类型无论真假都编码成“存在”）。
- 等待 `CONNECT` / `START_AP` 确认超过 10 秒报错，Python 版无限等待。
- HMAC 校验用常数时间比较（Python 用 `!=`）；密钥文件格式错误时报告行号；`Keys`/`KeyDerivation` 的 `Debug` 不打印密钥值。
- AP 的管理帧在 `AccessPoint::next_event` 里处理（Python 是独立后台任务），AP 运行期间必须持续调用它。
- 广播帧 V2 编码要求已连接槽位数等于 `num_participants`，否则报错（Python 照写出对方无法解析的帧）；V1 解码时应用数据长度字段超过 384 报错（Python 静默截断）。
- `ChallengeRequest` 解码按 64 项读取 params2（Python 只读 8 项，但编码写满 64 项）；参数个数超限报错。
- LDN 认证帧是否加密统一由格式字段决定（Python 格式看“协议 == 1”、加密看“协议 == 3”，协议 1/3 以外会不一致）。
- 名字、用户名超过 32 字节时报错（Python 会写出超长字段破坏帧格式）。
- 主机：已登记的成员重发认证请求时沿用原槽位、不重复 `Join`（Python 会重复登记）；8 个槽位全满回 `DENIED_BY_POLICY`（Python 覆盖 7 号槽位）；不允许踢 0 号主机自己。
- 主机：成员的静态邻居加删在 TAP 接口上（Python 加在 AP 接口上，但成员的 IP 流量走 TAP）。
- 成员：比较参与者槽位时同时看 `connected` 和 MAC。协议 1 的 V1 广播帧成员离开后保留原 MAC，Python 只比 MAC，永远报不出 `Leave`。
- 成员：认证后收到格式不对的 control port 帧时忽略（Python 按断开帧解析，失败即终止）。
- 建房四个后台循环任一出错时取消其余循环，错误从 `next_event()` 返回（对应 trio nursery 语义）。
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

## ldn 主要接口

| 类型 / 函数 | 说明 |
|---|---|
| `scan(&ScanParam) -> Vec<NetworkInfo>` | `ScanParam::new(keys)`：`phy0`、信道 1/6/11、每信道 110ms、协议 1+3 |
| `connect(ConnectParam) -> StaNetwork` | `ConnectParam::new(keys, network)`，`param.join` 里填密码、用户名等；返回时已认证、已分配 IP、已加邻居 |
| `StaNetwork` | `info()`、`participant()`、`broadcast_ip()`、`next_event() -> Event`、`close()` |
| `create_network(CreateNetworkParam) -> HostNetwork` | `CreateNetworkParam::new(keys, HostConfig::new(protocol))`；SSID/信道/主机随机数默认随机 |
| `HostNetwork` | `info()`、`broadcast_ip()`、`set_application_data`、`set_accept_policy`、`set_accept_filter`、`kick(index)`、`next_event()`、`close()` |
| `Event` | `Disconnected`、`Join`、`Leave`、`ApplicationDataChanged`、`AcceptPolicyChanged` |
| `host_core::HostCore` | `handle_auth_request`、`handle_disassociation`、`kick`、`destroy_frames`、`advertisement_frame`、`handle_data_frame`、`build_data_frame` |
| `station_core::StationCore` | `authentication_request`、`check_authentication_response`、`parse_advertisement`、`try_initialize`、`update`、`parse_disconnect`、`data_key` |
| `Error` | `Wlan`/`Proto`/`Crypto`/`Wire`/`InvalidParam`/`AuthenticationRejected(status)`/`AuthenticationTimeout`/`Connection` |

## ldn-crypto 主要接口

| 类型 / 函数 | 说明 |
|---|---|
| `Keys::{parse, load, get, insert}` | `prod.keys` 文本（`名字 = 十六进制`），`Debug` 只显示密钥名 |
| `Protocol::{V1, V3}` | 协议 1 用 `master_key_00`，协议 3 用 `master_key_12` |
| `KeyDerivation::new(keys, protocol)` + `override_{advertise,data,challenge}_key` | 缺失的系统密钥在首次派生时报 `MissingKey` |
| `derive_authentication_key(client_random)`、`derive_data_key(server_random, password)`、`derive_advertise_key(network_id_be)` | 返回 `[u8; 16]` |
| `challenge_key(dev) -> &[u8]` | 固定 HMAC 密钥 `CHALLENGE_KEY` / `CHALLENGE_KEY_DEV` |
| `cipher::{ccmp_encrypt, ccmp_decrypt}(&mut DataFrame, key, ...)` | 直接改 `ldn_wire::data::DataFrame`；失败时帧不变 |
| `cipher::aes_ctr(key, nonce4, data)` | 加解密相同 |
| `cipher::{gcm_seal, gcm_open}(key, nonce12, aad, ...)` | tag 单独返回/传入，调用方按帧格式摆放 |
| `cipher::{sha256, hmac_sha256, hmac_sha256_verify}` | verify 为常数时间 |

## ldn-proto 主要接口

| 类型 | 主要方法 | 说明 |
|---|---|---|
| `NetworkId` | `encode(Endian)`、`decode(&[u8], Endian)`、`ssid_text()` | 广播帧里大端、认证帧里小端 |
| `ParticipantInfo` | 字段：`ip_address`、`mac_address`、`connected`、`name`、`app_version`、`platform` | 名字最多 32 字节 |
| `AdvertisementInfo` | 字段见文档；`participants: [ParticipantInfo; 8]` | 载荷；V1/V2 编码由 `format` 决定 |
| `AdvertisementFrame` | `encode(&KeyDerivation)`、`decode(&[u8], &KeyDerivation)` | Action 帧帧体（Category 起）；格式必须是明文或协议对应的加密方式 |
| `AdvertiseFormat` | `Plain`/`AesCtr`/`AesGcm`、`encrypted_for(Protocol)` | 协议 1 用 CTR，其余用 GCM |
| `ChallengeRequest` / `ChallengeResponse` | `encode(key)`、`decode(&[u8], key)` | 0x300 / 0x100 字节，HMAC-SHA256 签名；key 取 `KeyDerivation::challenge_key(dev)` |
| `AuthenticationFrame` + `AuthPayload::{Request, Response}` | `encode(&KeyDerivation)`、`decode(&[u8], &KeyDerivation)` | 协议 3 用 `client_random` 派生密钥做 AES-GCM；载荷里的 `challenge` 是已签名的挑战字节 |
| `DisconnectFrame` | `encode()`、`decode()` | 原因码见 `auth::disconnect` |
| `NetworkInfo` | `new(Protocol)`、`network_id()`、`is_same_network`、`update_from_advertisement`、`to_advertisement` | 扫描结果 / 主机状态 |
| `Error` | `Wire`/`Crypto`/`NotLdnFrame`/`Invalid`/`TooLong`/`IntegrityCheckFailed` | GCM tag、SHA-256、HMAC 失败统一为 `IntegrityCheckFailed` |

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
