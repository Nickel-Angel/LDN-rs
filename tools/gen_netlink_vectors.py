"""
驱动 Python 版 LDN 的 wlan.py 真实代码路径，截获它发给内核的每一条 netlink 消息，
写成 Rust 常量文件，供 ldn-netlink 的对拍测试使用。

做法：把 trio socket 换成只记录 send() 的假 socket，并在 send() 里立即回一个
成功 ACK（需要应答的命令附带预置的回复消息）；这样 wlan.py、python-netlink 的
消息组装代码都原样执行，得到的字节就是原项目在真机上会发出的字节。

准备环境见 gen_python_vectors.py。用法:
    .venv/bin/python tools/gen_netlink_vectors.py <Python 版 LDN 仓库路径>

场景里的取值（ifindex、MAC、SSID、密钥……）必须与
crates/ldn-netlink/tests/python_parity.rs 里的常量一致。
"""

import pathlib
import struct
import sys

import trio

# 与 Rust 对拍测试共享的固定值。
PID = 4242
NL80211_FAMILY_ID = 0x22
NL80211_VERSION = 1
IFINDEX = 7
WIPHY_INDEX = 3
AP_MAC = "02:00:00:00:00:01"
STA_MAC = "02:00:00:00:00:02"
STA2_MAC = "02:00:00:00:00:03"
SSID = "00112233445566778899aabbccddeeff"
CHANNEL = 6
KEY = bytes(range(0x20, 0x30))


def setup(repo: pathlib.Path):
    sys.path.insert(0, str(repo))
    import netlink
    from netlink import attributes, generic, nl80211, route
    from ldn import wlan
    return netlink, attributes, generic, nl80211, route, wlan


class Capture:
    """一个假 netlink 端点：记录发出的消息，并按预置脚本回复。"""

    def __init__(self, netlink):
        self.netlink = netlink
        self.sent: list[bytes] = []
        self.replies: dict[int, list] = {}  # netlink 类型之外按“第几条请求”预置回复
        self.sock = None

    # --- trio socket 接口 ---
    def getsockname(self):
        return (PID, 0)

    def setsockopt(self, *args):
        pass

    async def send(self, data: bytes) -> None:
        nl = self.netlink
        self.sent.append(bytes(data))
        _, _, _, seq, _ = struct.unpack_from("IHHII", data)
        for message in self.replies.pop(len(self.sent), []):
            self.sock._packets[seq].append(message)
        ack = struct.pack("i", 0) + data[:16]
        self.sock._replies[seq] = nl.NetlinkMessage(nl.NLMSG_ERROR, 0, ack)
        self.sock._pending.pop(seq).set()

    def make_socket(self):
        self.sock = self.netlink.NetlinkSocket(self)
        return self.sock


def genl_payload(nl80211, cmd: int, attrs: dict) -> bytes:
    """按 python-netlink 的规则编码一条 nl80211 genl 消息体（事件/回复用）。"""
    from netlink import attributes
    header = struct.pack("BBH", cmd, NL80211_VERSION, 0)
    return header + attributes.encode(attrs, nl80211.NL80211.ATTRIBUTES)


def make_nl80211(mods, capture):
    netlink, attributes, generic, nl80211, route, wlan = mods
    sock = capture.make_socket()
    family = generic.Family({
        generic.CTRL_ATTR_FAMILY_ID: NL80211_FAMILY_ID,
        generic.CTRL_ATTR_FAMILY_NAME: "nl80211",
        generic.CTRL_ATTR_VERSION: NL80211_VERSION,
        generic.CTRL_ATTR_HDRSIZE: 0,
        generic.CTRL_ATTR_MAXATTR: 400,
        generic.CTRL_ATTR_MCAST_GROUPS: [
            {generic.CTRL_ATTR_MCAST_GRP_NAME: "config", generic.CTRL_ATTR_MCAST_GRP_ID: 5},
            {generic.CTRL_ATTR_MCAST_GRP_NAME: "mlme", generic.CTRL_ATTR_MCAST_GRP_ID: 7},
        ],
    })
    receiver = generic.GenericNetlinkReceiver(sock)
    return nl80211.NL80211(receiver, family), sock


def push_event(mods, sock, cmd: int, attrs: dict) -> None:
    netlink, _, _, nl80211, _, _ = mods
    payload = genl_payload(nl80211, cmd, attrs)
    sock._send_channel.send_nowait(netlink.NetlinkMessage(NL80211_FAMILY_ID, 0, payload))


def genl_reply(mods, cmd: int, attrs: dict):
    netlink, _, _, nl80211, _, _ = mods
    return netlink.NetlinkMessage(NL80211_FAMILY_ID, 0, genl_payload(nl80211, cmd, attrs))


class FakeRawSocket:
    """替代 Monitor/Interface 里建的 AF_PACKET / AF_INET socket（普通用户建不了）。"""

    def __init__(self, *args, **kwargs):
        pass

    async def bind(self, address):
        pass


async def scenario_monitor(mods):
    """Factory.create_monitor：查 wiphy、建 monitor 接口、拉起、退出时删接口。"""
    netlink, _, _, nl80211, route, wlan = mods
    nl_cap, rt_cap = Capture(netlink), Capture(netlink)
    wlan_sock, _ = make_nl80211(mods, nl_cap)
    router = route.RouteController(rt_cap.make_socket())

    nl_cap.replies[1] = [
        genl_reply(mods, nl80211.NL80211_CMD_NEW_WIPHY, {
            nl80211.NL80211_ATTR_WIPHY: 0, nl80211.NL80211_ATTR_WIPHY_NAME: "phy1"}),
        genl_reply(mods, nl80211.NL80211_CMD_NEW_WIPHY, {
            nl80211.NL80211_ATTR_WIPHY: WIPHY_INDEX, nl80211.NL80211_ATTR_WIPHY_NAME: "phy0"}),
    ]
    nl_cap.replies[2] = [genl_reply(mods, nl80211.NL80211_CMD_NEW_INTERFACE, {
        nl80211.NL80211_ATTR_IFINDEX: IFINDEX,
        nl80211.NL80211_ATTR_MAC: bytes(wlan.MACAddress(AP_MAC)),
    })]

    factory = wlan.Factory(wlan_sock, router)
    async with factory.create_monitor("phy0", "ldn-mon") as monitor:
        assert monitor.index() == IFINDEX
        await monitor.set_channel(CHANNEL)
    return {"MONITOR_NL80211": nl_cap.sent, "MONITOR_ROUTE": rt_cap.sent,
            "WIPHY_DUMP_REPLY": [nl_cap_reply_payloads(nl_cap, mods)]}


def nl_cap_reply_payloads(_cap, mods):
    # 单独再编码一次 wiphy dump 回复的第二条消息，供 Rust 端解析测试。
    _, _, _, nl80211, _, _ = mods
    return genl_payload(nl80211, nl80211.NL80211_CMD_NEW_WIPHY, {
        nl80211.NL80211_ATTR_WIPHY: WIPHY_INDEX, nl80211.NL80211_ATTR_WIPHY_NAME: "phy0"})


async def scenario_station(mods):
    """Station.connect 全流程（带密钥），中间发一条 control port 帧并置 authorized。"""
    netlink, _, _, nl80211, route, wlan = mods
    nl_cap, rt_cap = Capture(netlink), Capture(netlink)
    wlan_sock, sock = make_nl80211(mods, nl_cap)
    router = route.RouteController(rt_cap.make_socket())

    sta = wlan.Station(wlan_sock, router, "ldn", IFINDEX, wlan.MACAddress(STA_MAC),
                       SSID, CHANNEL, KEY)
    connect_event = {
        nl80211.NL80211_ATTR_IFINDEX: IFINDEX,
        nl80211.NL80211_ATTR_MAC: bytes(wlan.MACAddress(AP_MAC)),
        nl80211.NL80211_ATTR_STATUS_CODE: 0,
    }
    push_event(mods, sock, nl80211.NL80211_CMD_CONNECT, connect_event)
    async with sta.connect():
        await sta.send_custom_frame(wlan.MACAddress(AP_MAC), b"\x7f\x00\x22\xaa")
        await sta.set_authorized()
    return {
        "STATION_NL80211": nl_cap.sent,
        "STATION_ROUTE": rt_cap.sent,
        "CONNECT_EVENT": [genl_payload(nl80211, nl80211.NL80211_CMD_CONNECT, connect_event)],
    }


async def scenario_access_point(mods):
    """AccessPoint.create 全流程（带密钥），中间处理探测/认证/关联/解除关联/踢人。"""
    netlink, _, _, nl80211, route, wlan = mods
    nl_cap, rt_cap = Capture(netlink), Capture(netlink)
    wlan_sock, sock = make_nl80211(mods, nl_cap)
    router = route.RouteController(rt_cap.make_socket())

    ap_mac, sta_mac, sta2_mac = (wlan.MACAddress(m) for m in (AP_MAC, STA_MAC, STA2_MAC))
    ap = wlan.AccessPoint(wlan_sock, router, "ldn", IFINDEX, ap_mac, SSID, CHANNEL, KEY, 2)
    push_event(mods, sock, nl80211.NL80211_CMD_START_AP, {nl80211.NL80211_ATTR_IFINDEX: IFINDEX})

    rates = b"\x82\x84\x8b\x96"
    async with ap.create():
        await ap._process_frame(wlan.ProbeRequest(sta_mac, {wlan.WLAN_EID_SSID: SSID.encode()}))
        await ap._process_frame(wlan.AuthenticationFrame(ap_mac, sta_mac, ap_mac, 0, 1, 0))
        await ap._process_frame(wlan.AssociationRequest(ap_mac, sta_mac, 0x0421, 10, {
            wlan.WLAN_EID_SSID: SSID.encode(),
            wlan.WLAN_EID_SUPP_RATES: rates,
            wlan.WLAN_EID_HT_CAPABILITY: b"\x2c\x01",
            wlan.WLAN_EID_EXT_CAPABILITY: b"\x04",
        }))
        await ap._process_frame(wlan.AssociationRequest(ap_mac, sta2_mac, 0x0421, 10, {
            wlan.WLAN_EID_SSID: SSID.encode(), wlan.WLAN_EID_SUPP_RATES: rates}))
        await ap._process_frame(wlan.DisassociationFrame(ap_mac, sta_mac, ap_mac, 8))
        await ap.remove_station(sta2_mac)
        await ap.send_custom_frame(sta_mac, b"\x7f\x00\x22\xaa")
    return {"AP_NL80211": nl_cap.sent, "AP_ROUTE": rt_cap.sent}


async def scenario_tap(mods):
    """Tap 接口与网络层用到的 rtnetlink 操作。"""
    netlink, _, _, _, route, wlan = mods
    nl_cap, rt_cap = Capture(netlink), Capture(netlink)
    wlan_sock, _ = make_nl80211(mods, nl_cap)
    router = route.RouteController(rt_cap.make_socket())
    tap = wlan.Interface(wlan_sock, router, "ldn-tap", 9, wlan.MACAddress(AP_MAC))
    await tap.update_link(wlan.MACAddress(AP_MAC))
    await tap.up()
    await tap.add_address("169.254.1.1", "169.254.1.255")
    await tap.add_neighbor("169.254.1.2", wlan.MACAddress(STA_MAC))
    await tap.remove_neighbor("169.254.1.2", wlan.MACAddress(STA_MAC))
    return {"TAP_ROUTE": rt_cap.sent}


def ctrl_family_reply(mods) -> bytes:
    """nlctrl 对 GETFAMILY(nl80211) 的回复消息体，供 Rust 端解析测试。"""
    _, attributes, generic, _, _, _ = mods
    attrs = {
        generic.CTRL_ATTR_FAMILY_NAME: "nl80211",
        generic.CTRL_ATTR_FAMILY_ID: NL80211_FAMILY_ID,
        generic.CTRL_ATTR_VERSION: NL80211_VERSION,
        generic.CTRL_ATTR_HDRSIZE: 0,
        generic.CTRL_ATTR_MAXATTR: 400,
        generic.CTRL_ATTR_OPS: [
            {generic.CTRL_ATTR_OP_ID: 1, generic.CTRL_ATTR_OP_FLAGS: 0x0e},
        ],
        generic.CTRL_ATTR_MCAST_GROUPS: [
            {generic.CTRL_ATTR_MCAST_GRP_NAME: "config", generic.CTRL_ATTR_MCAST_GRP_ID: 5},
            {generic.CTRL_ATTR_MCAST_GRP_NAME: "mlme", generic.CTRL_ATTR_MCAST_GRP_ID: 7},
        ],
    }
    header = struct.pack("BBH", generic.CTRL_CMD_NEWFAMILY, 2, 0)
    return header + attributes.encode(attrs, generic.GenericNetlinkController.ATTRIBUTES)


def ctrl_family_request() -> list[bytes]:
    """nlctrl GETFAMILY(nl80211) 请求，由 python-netlink 自己组装。"""
    import netlink
    from netlink import generic
    cap = Capture(netlink)
    sock = cap.make_socket()
    bootstrap = generic.Family({
        generic.CTRL_ATTR_FAMILY_ID: generic.GENL_ID_CTRL,
        generic.CTRL_ATTR_FAMILY_NAME: "nlctrl",
        generic.CTRL_ATTR_VERSION: 2,
        generic.CTRL_ATTR_HDRSIZE: 0,
        generic.CTRL_ATTR_MAXATTR: 10,
    })
    ctrl = generic.GenericNetlinkController(generic.GenericNetlinkReceiver(sock), bootstrap)
    cap.replies[1] = [netlink.NetlinkMessage(generic.GENL_ID_CTRL, 0, ctrl_family_reply(MODS))]

    async def run():
        family = await ctrl.get_family_by_name("nl80211")
        assert family.mcast_groups["mlme"] == 7
    trio.run(run)
    return cap.sent


def render_rust(vectors: dict[str, list[bytes]], source: str) -> str:
    lines = ["// @generated by tools/gen_netlink_vectors.py -- 不要手改。",
             f"// 来源: Python LDN {source} + python-netlink", ""]
    for name, messages in vectors.items():
        lines.append(f"pub const {name}: &[&str] = &[")
        lines.extend(f'    "{m.hex()}",' for m in messages)
        lines.append("];")
    return "\n".join(lines) + "\n"


MODS = None


def main() -> None:
    global MODS
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    repo = pathlib.Path(sys.argv[1]).resolve()
    MODS = setup(repo)
    wlan = MODS[5]
    # 普通用户建不了 AF_PACKET socket，也不该改本机 /proc；只替换这两处系统调用。
    wlan.trio.socket.socket = FakeRawSocket
    wlan.Interface.disable_ipv6 = lambda self: None

    vectors: dict[str, list[bytes]] = {"CTRL_GETFAMILY": ctrl_family_request(),
                                       "CTRL_FAMILY_REPLY": [ctrl_family_reply(MODS)]}
    for scenario in (scenario_monitor, scenario_station, scenario_access_point, scenario_tap):
        async def run(s=scenario):
            with trio.fail_after(5):
                return await s(MODS)
        vectors.update(trio.run(run))

    out = pathlib.Path(__file__).resolve().parent.parent / \
        "crates/ldn-netlink/tests/vectors/python_netlink_vectors.rs"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_rust(vectors, repo.name))
    print(f"wrote {out}: " + ", ".join(f"{k}={len(v)}" for k, v in vectors.items()))


if __name__ == "__main__":
    main()
