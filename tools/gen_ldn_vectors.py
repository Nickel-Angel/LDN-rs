"""
驱动 Python 版 LDN 的 APNetwork / STANetwork 真实代码，截获高层逻辑产生的字节，
写成 Rust 常量文件，供 ldn crate 的对拍测试使用。

做法：用只记录调用的假接口代替 wlan.AccessPoint / Monitor / Tap / Station，把随机数
（random.randint、secrets.token_bytes）换成固定值，然后让成员与主机在内存里完成一次
认证握手，并各收发一个数据帧。系统密钥复用 gen_crypto_vectors.py 的假值。

用法:
    .venv/bin/python tools/gen_ldn_vectors.py <Python 版 LDN 仓库路径>

取值必须与 crates/ldn/tests/python_parity.rs 一致。
"""

import copy
import pathlib
import sys

import trio

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from gen_crypto_vectors import FAKE_KEYS  # noqa: E402

HOST_MAC = "02:00:00:00:00:01"
GUEST_MAC = "02:00:00:00:00:02"
OTHER_MAC = "02:00:00:00:00:09"
SSID = bytes(range(0xA0, 0xB0))
SERVER_RANDOM = bytes(range(0x50, 0x60))
CLIENT_RANDOM = bytes(range(0x40, 0x50))
PASSWORD = b"LunchPack2DefaultPhrase"
APP_DATA = b"room data"

# Python 版里所有 random.randint 调用按取值区间换成固定值。
FIXED_RANDINT = {
    (0, 0xFFFFFFFF): 0x11223344,              # 广播帧 nonce 初值
    (1, 127): 42,                              # network id（IP 第三段）
    (0, 0xFFFFFFFFFFFFFFFF): 0x0102030405060708,  # 挑战 token / 挑战 nonce
}
HOST_DEVICE_ID = 0x1111222233334444
GUEST_DEVICE_ID = 0x5555666677778888


def fixed_randint(a, b):
    return FIXED_RANDINT[(a, b)]


class Recorder:
    """假接口：记录 send_custom_frame / send_frame / write / 路由操作。"""

    def __init__(self, wlan, mac):
        self.mac = wlan.MACAddress(mac)
        self.custom = []
        self.frames = []
        self.writes = []
        self.route = []
        self.inbox = []

    def address(self):
        return self.mac

    async def send_custom_frame(self, addr, frame):
        self.custom.append((addr, frame))

    async def send_frame(self, frame):
        self.frames.append(frame.encode())

    async def write(self, data):
        self.writes.append(data)

    async def add_neighbor(self, ip, mac):
        self.route.append(("add", ip, str(mac)))

    async def remove_neighbor(self, ip, mac):
        self.route.append(("remove", ip, str(mac)))

    async def add_address(self, ip, broadcast):
        self.route.append(("address", ip, broadcast))

    async def remove_station(self, mac):
        self.route.append(("remove_station", str(mac)))

    async def set_authorized(self):
        pass

    async def next_event(self):
        return self.inbox.pop(0)


def create_param(ldn, protocol):
    p = ldn.CreateNetworkParam()
    p.keys = FAKE_KEYS
    p.local_communication_id = 0x01009B90006DC000
    p.scene_id = 7
    p.max_participants = 4
    p.application_data = APP_DATA
    p.name = b"host"
    p.app_version = 3
    p.platform = ldn.PLATFORM_NX
    p.channel = 6
    p.ssid = SSID
    p.server_random = SERVER_RANDOM
    p.password = PASSWORD
    p.version = 4
    p.device_id = HOST_DEVICE_ID
    p.protocol = protocol
    return p


async def scenario(ldn, wlan, protocol):
    v = {}
    param = create_param(ldn, protocol)
    kd = ldn.KeyDerivation(FAKE_KEYS, protocol)
    key = kd.derive_data_key(SERVER_RANDOM, PASSWORD)
    ap_if, monitor, tap = (Recorder(wlan, HOST_MAC) for _ in range(3))
    host = ldn.APNetwork(ap_if, monitor, tap, param, kd, key)
    await host._initialize_network()
    await host._send_advertisement()
    v["ADV_INITIAL"] = monitor.frames[-1]

    # 成员侧：扫描得到的 NetworkInfo 就是主机当前状态。
    cparam = ldn.ConnectNetworkParam()
    cparam.network = copy.deepcopy(host._network)
    cparam.keys = FAKE_KEYS
    cparam.name = b"guest"
    cparam.app_version = 3
    cparam.platform = ldn.PLATFORM_OUNCE
    cparam.device_id = GUEST_DEVICE_ID
    cparam.client_random = CLIENT_RANDOM
    cparam.password = PASSWORD
    sta_if = Recorder(wlan, GUEST_MAC)
    guest = ldn.STANetwork(sta_if, cparam, kd)

    # 成员发请求 -> 主机处理 -> 应答放进成员的收件箱，再让成员跑完 _authenticate。
    async def deliver(addr, data):
        sta_if.custom.append((addr, data))
        event = wlan.CustomFrameEvent(sta_if.mac, data)
        response = await host._process_authentication_event(event)
        sta_if.inbox.append(wlan.CustomFrameEvent(ap_if.mac, response.encode()))
    sta_if.send_custom_frame = deliver
    await guest._authenticate()
    v["AUTH_REQUEST"] = sta_if.custom[0][1]
    await host._send_advertisement()
    v["ADV_AFTER_JOIN"] = monitor.frames[-1]

    # 同一请求在“黑名单拒绝”时的应答。
    host.set_accept_policy(ldn.ACCEPT_BLACKLIST)
    host.set_accept_filter([wlan.MACAddress(OTHER_MAC)])
    denied = await host._process_authentication_event(
        wlan.CustomFrameEvent(wlan.MACAddress(OTHER_MAC), v["AUTH_REQUEST"]))
    v["AUTH_DENIED"] = denied.encode()

    # 数据面：主机发一个以太网帧；成员发来一个加密帧。
    ethernet = wlan.EthernetFrame(wlan.MACAddress("ff:ff:ff:ff:ff:ff"), ap_if.mac, 0x0800, b"ping")
    v["TAP_OUT"] = ethernet.encode()
    snap = wlan.SNAPHeader(0, ethernet.protocol, ethernet.payload)
    await host._send_data_frame(snap.encode())
    v["DATA_TX"] = monitor.frames[-1]

    incoming = wlan.DataFrame(target=wlan.MACAddress("ff:ff:ff:ff:ff:ff"),
                              source=sta_if.mac, bssid=ap_if.mac,
                              payload=wlan.SNAPHeader(0, 0x0806, b"arp!").encode())
    incoming.encrypt(key, packetno=5, keyid=1)
    v["DATA_RX"] = incoming.encode()
    await host._process_data_frame(incoming)
    v["TAP_IN"] = tap.writes[-1]

    await host.kick(1)
    v["KICK_DISCONNECT"] = ap_if.custom[-1][1]
    await host._send_advertisement()
    v["ADV_AFTER_KICK"] = monitor.frames[-1]
    # 路由操作按“动作 参数...”记成一行一条；AP 接口与 TAP 接口上的操作分开记录。
    v["AP_IFACE_OPS"] = [" ".join(op) for op in ap_if.route]
    v["TAP_OPS"] = [" ".join(op) for op in tap.route]
    return v


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    repo = pathlib.Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(repo))
    import ldn
    from ldn import wlan
    ldn.random.randint = fixed_randint

    vectors = {}
    for protocol in (1, 3):
        result = trio.run(scenario, ldn, wlan, protocol)
        for name, data in result.items():
            vectors[f"P{protocol}_{name}"] = data

    # 单独重放一次拿到主机的认证应答字节（上面的收件箱已被成员消费）。
    async def auth_response(protocol):
        param = create_param(ldn, protocol)
        kd = ldn.KeyDerivation(FAKE_KEYS, protocol)
        key = kd.derive_data_key(SERVER_RANDOM, PASSWORD)
        ap_if, monitor, tap = (Recorder(wlan, HOST_MAC) for _ in range(3))
        host = ldn.APNetwork(ap_if, monitor, tap, param, kd, key)
        request = bytes.fromhex(vectors[f"P{protocol}_AUTH_REQUEST"].hex())
        response = await host._process_authentication_event(
            wlan.CustomFrameEvent(wlan.MACAddress(GUEST_MAC), request))
        return response.encode()
    for protocol in (1, 3):
        vectors[f"P{protocol}_AUTH_RESPONSE"] = trio.run(auth_response, protocol)

    out = pathlib.Path(__file__).resolve().parent.parent / "crates/ldn/tests/vectors/python_ldn_vectors.rs"
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["// @generated by tools/gen_ldn_vectors.py -- 不要手改。",
             f"// 来源: Python LDN {repo.name}；所有系统密钥与随机数均为固定假值。", ""]
    for name, data in vectors.items():
        if isinstance(data, list):
            items = ", ".join(f'"{s}"' for s in data)
            lines.append(f"pub const {name}: &[&str] = &[{items}];")
        else:
            lines.append(f'pub const {name}: &str = "{data.hex()}";')
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
