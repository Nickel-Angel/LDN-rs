"""
用 Python 版 LDN 的协议类生成 ldn-proto 的对拍向量：NetworkId、广播帧（明文 /
AES-CTR / AES-GCM，V1/V2 两种载荷编码）、挑战请求/应答、LDN 认证帧（协议 1 明文、
协议 3 AES-GCM，版本 2/3）、断开帧、NetworkInfo.build_advertisement。

系统密钥复用 gen_crypto_vectors.py 的假值。用法:
    .venv/bin/python tools/gen_proto_vectors.py <Python 版 LDN 仓库路径>

取值必须与 crates/ldn-proto/tests/python_parity.rs 一致。
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from gen_crypto_vectors import FAKE_KEYS  # noqa: E402

CLIENT_RANDOM = bytes(range(0x40, 0x50))
SERVER_RANDOM = bytes(range(0x50, 0x60))
SSID = bytes(range(0xA0, 0xB0))
NONCE = bytes.fromhex("01020304")
APP_DATA = b"application data \x00\x01\x02"
CHALLENGE_REQ_UNK = bytes(range(0xC0, 0xD0))


def participants(ldn, wlan):
    """8 个槽位：0 号主机、2 号成员已连接，其余为空，覆盖 V2 只编码已连接槽位的逻辑。"""
    out = [ldn.ParticipantInfo() for _ in range(8)]
    out[0] = ldn.ParticipantInfo("169.254.9.1", wlan.MACAddress("02:00:00:00:00:01"),
                                 True, b"host", 7, 0)
    out[2] = ldn.ParticipantInfo("169.254.9.3", wlan.MACAddress("02:00:00:00:00:03"),
                                 True, b"player-two", 7, 1)
    return out


def network_id(ldn):
    nid = ldn.NetworkId()
    nid.local_communication_id = 0x01009B90006DC000
    nid.scene_id = 0x1234
    nid.ssid = SSID
    return nid


def adv_info(ldn, wlan, app_version):
    info = ldn.AdvertisementInfo()
    info.server_random = SERVER_RANDOM
    info.security_mode = ldn.SECURITY_MODE_PROD
    info.station_accept_policy = ldn.ACCEPT_BLACKLIST
    info.app_version = app_version
    info.band = 2
    info.channel = 6
    info.max_participants = 4
    info.num_participants = 2
    info.participants = participants(ldn, wlan)
    info.application_data = APP_DATA
    info.challenge = 0x1122334455667788
    return info


def build_vectors(ldn, wlan) -> dict[str, bytes]:
    v = {}
    nid = network_id(ldn)
    v["NETWORK_ID_BE"] = nid.encode(">")
    v["NETWORK_ID_LE"] = nid.encode("<")

    kd1 = ldn.KeyDerivation(FAKE_KEYS, 1)
    kd3 = ldn.KeyDerivation(FAKE_KEYS, 3)

    # 广播帧：(名字, 派生器, 协议, 格式)。V1 载荷的 app_version 来自 0 号参与者，所以两边都填 7。
    for name, kd, protocol, fmt in [
        ("ADV_P1_CTR", kd1, 1, ldn.ADVERTISE_FORMAT_AES_CTR),
        ("ADV_P1_PLAIN", kd1, 1, ldn.ADVERTISE_FORMAT_PLAIN),
        ("ADV_P3_GCM", kd3, 3, ldn.ADVERTISE_FORMAT_AES_GCM),
        ("ADV_P3_PLAIN", kd3, 3, ldn.ADVERTISE_FORMAT_PLAIN),
    ]:
        frame = ldn.AdvertisementFrame(kd, protocol)
        frame.network_id = nid
        frame.version = 3
        frame.format = fmt
        frame.nonce = NONCE
        frame.payload = adv_info(ldn, wlan, 7)
        v[name] = frame.encode()

    req = ldn.ChallengeRequest(flags=1, token=0xAABBCCDD, nonce=0x0102030405060708,
                               device_id=0x1111222233334444, unk=CHALLENGE_REQ_UNK,
                               params1=[1, 2], params2=[3, 4, 5])
    v["CHALLENGE_REQUEST"] = req.encode(ldn.CHALLENGE_KEY)
    resp = ldn.ChallengeResponse(flags=2, nonce=0x0102030405060708,
                                 device_id=0x1111222233334444,
                                 device_id_host=0x5555666677778888,
                                 unk=bytes(range(16)), unk_host=bytes(range(16, 32)))
    v["CHALLENGE_RESPONSE"] = resp.encode(ldn.CHALLENGE_KEY)

    for protocol, kd in ((1, kd1), (3, kd3)):
        for version in (2, 3):
            for is_response in (False, True):
                frame = ldn.AuthenticationFrame(kd, protocol)
                frame.version = version
                frame.status_code = 0 if not is_response else ldn.AUTH_DENIED_BY_POLICY
                frame.network_id = nid
                frame.server_random = SERVER_RANDOM
                frame.client_random = CLIENT_RANDOM
                if is_response:
                    frame.payload = ldn.AuthenticationResponse(
                        platform=1, challenge=v["CHALLENGE_RESPONSE"] if version >= 3 else b"")
                else:
                    frame.payload = ldn.AuthenticationRequest(
                        username=b"player-two", app_version=7, platform=1,
                        challenge=v["CHALLENGE_REQUEST"] if version >= 3 else b"")
                kind = "RESP" if is_response else "REQ"
                v[f"AUTH_P{protocol}_V{version}_{kind}"] = frame.encode()

    v["DISCONNECT"] = ldn.DisconnectFrame(ldn.DISCONNECT_STATION_REJECTED_BY_HOST).encode()

    net = ldn.NetworkInfo(3)
    net.band, net.channel = 2, 11
    net.local_communication_id = nid.local_communication_id
    net.scene_id = nid.scene_id
    net.ssid = SSID
    net.version = 4
    net.server_random = SERVER_RANDOM
    net.app_version = 7
    net.accept_policy = ldn.ACCEPT_ALL
    net.max_participants = 8
    net.num_participants = 2
    net.participants = participants(ldn, wlan)
    net.application_data = APP_DATA
    net.challenge = 42
    net.nonce = NONCE
    v["BUILD_ADVERTISEMENT_P3"] = net.build_advertisement(kd3).encode()
    return v


def render_rust(vectors: dict[str, bytes], source: str) -> str:
    lines = ["// @generated by tools/gen_proto_vectors.py -- 不要手改。",
             f"// 来源: Python LDN {source}；所有系统密钥均为假值。", ""]
    for name, data in vectors.items():
        lines.append(f'pub const {name}: &str = "{data.hex()}";')
    return "\n".join(lines) + "\n"


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    repo = pathlib.Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(repo))
    import ldn
    from ldn import wlan

    out = pathlib.Path(__file__).resolve().parent.parent / \
        "crates/ldn-proto/tests/vectors/python_proto_vectors.rs"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_rust(build_vectors(ldn, wlan), repo.name))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
