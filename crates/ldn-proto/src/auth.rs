//! 经 control port（EtherType 0x88B7）收发的 LDN 自定义帧：认证帧、断开帧，
//! 以及嵌在版本 3 认证帧里的挑战请求/应答。
//!
//! 加入流程：成员完成 802.11 关联后发 [`AuthenticationFrame`]（载荷为
//! [`AuthenticationRequest`]），主机回同样的帧（载荷为 [`AuthenticationResponse`]）。
//! 版本 3 起请求/应答里各带一个用固定 HMAC 密钥签名的挑战。

use ldn_crypto::cipher::{gcm_open, gcm_seal, hmac_sha256, hmac_sha256_verify};
use ldn_crypto::{KeyDerivation, Protocol};
use ldn_wire::stream::{Endian, Reader, Writer};

use crate::common::{
    NetworkId, platform, read_custom_header, read_name, write_custom_header, write_name,
};
use crate::error::{Error, Result};

/// 认证状态码（`AuthenticationFrame::status_code`）。
pub mod status {
    #![allow(missing_docs)]
    pub const SUCCESS: u8 = 0;
    pub const DENIED_BY_POLICY: u8 = 1;
    pub const MALFORMED_REQUEST: u8 = 2;
    pub const TIMEOUT: u8 = 3;
    pub const INVALID_VERSION: u8 = 4;
    pub const UNEXPECTED: u8 = 5;
    pub const CHALLENGE_FAILURE: u8 = 6;
}

/// 断开原因（`DisconnectFrame::reason`）。
pub mod disconnect {
    #![allow(missing_docs)]
    pub const NETWORK_DESTROYED: u8 = 3;
    pub const NETWORK_DESTROYED_FORCEFULLY: u8 = 4;
    pub const STATION_REJECTED_BY_HOST: u8 = 5;
    pub const CONNECTION_LOST: u8 = 6;
}

const KIND_AUTHENTICATION: u16 = 0x102;
const KIND_DISCONNECT: u16 = 0x103;
const FORMAT_PLAIN: u8 = 0;
const FORMAT_AES_GCM: u8 = 1;
/// 认证帧头（version 到 client_random）的长度，也是 GCM 的 AAD。
const AUTH_HEADER_LEN: usize = 0x48;
const TAG_LEN: usize = 16;
const MAC_LEN: usize = 32;

/// 挑战请求/应答共同的外层：`u32 0 | HMAC(32) | 0×12 | body`。
fn seal_challenge(key: &[u8], body: &[u8]) -> Vec<u8> {
    let mut w = Writer::new(Endian::Little);
    w.u32(0);
    w.write(&hmac_sha256(key, body));
    w.pad(12);
    w.write(body);
    w.into_vec()
}

/// 校验外层并返回 body；长度不对返回 [`Error::Invalid`]，HMAC 不对返回 [`Error::IntegrityCheckFailed`]。
fn open_challenge<'a>(
    data: &'a [u8],
    key: &[u8],
    total: usize,
    name: &'static str,
) -> Result<&'a [u8]> {
    if data.len() != total {
        return Err(Error::Invalid(name));
    }
    let mut r = Reader::new(data, Endian::Little);
    r.pad(4)?;
    let mac = r.read(MAC_LEN)?;
    r.pad(12)?;
    let body = r.rest();
    hmac_sha256_verify(key, body, mac)?;
    Ok(body)
}

/// 挑战请求（成员 -> 主机），编码后固定 0x300 字节。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChallengeRequest {
    /// 标志。
    pub flags: u8,
    /// 令牌。
    pub token: u64,
    /// 随机数，主机在应答里回显。
    pub nonce: u64,
    /// 成员的设备 ID。
    pub device_id: u64,
    /// 仅 Switch 2 使用的 16 字节字段。
    pub unk: [u8; 16],
    /// 最多 8 个参数。
    pub params1: Vec<u64>,
    /// 最多 64 个参数。
    pub params2: Vec<u64>,
}

impl ChallengeRequest {
    /// 编码后的长度。
    pub const LEN: usize = 0x300;
    const MAX_PARAMS1: usize = 8;
    const MAX_PARAMS2: usize = 64;

    /// 编码并用 `key`（[`KeyDerivation::challenge_key`]）签名。
    pub fn encode(&self, key: &[u8]) -> Result<Vec<u8>> {
        for (field, len, max) in [
            ("params1", self.params1.len(), Self::MAX_PARAMS1),
            ("params2", self.params2.len(), Self::MAX_PARAMS2),
        ] {
            if len > max {
                return Err(Error::TooLong { field, len, max });
            }
        }
        let mut w = Writer::new(Endian::Little);
        w.u8(0);
        w.u8(0);
        w.u8(self.params1.len() as u8);
        w.u8(self.params2.len() as u8);
        w.u8(self.flags);
        w.pad(3);
        w.u64(self.token);
        w.u64(self.nonce);
        w.u64(self.device_id);
        w.write(&self.unk);
        w.pad(0x60);
        for (list, max) in [
            (&self.params1, Self::MAX_PARAMS1),
            (&self.params2, Self::MAX_PARAMS2),
        ] {
            for &p in list {
                w.u64(p);
            }
            w.pad(8 * (max - list.len()));
        }
        Ok(seal_challenge(key, &w.into_vec()))
    }

    /// 校验签名并解码。
    ///
    /// 与 Python 版的差异：Python 只读 params2 的前 8 项（其编码却写满 64 项），
    /// 这里按 64 项读取，数量字段超过上限时报错。
    pub fn decode(data: &[u8], key: &[u8]) -> Result<Self> {
        let body = open_challenge(data, key, Self::LEN, "challenge request has wrong size")?;
        let mut r = Reader::new(body, Endian::Little);
        r.pad(2)?;
        let n1 = usize::from(r.u8()?);
        let n2 = usize::from(r.u8()?);
        if n1 > Self::MAX_PARAMS1 || n2 > Self::MAX_PARAMS2 {
            return Err(Error::Invalid("challenge parameter count"));
        }
        let flags = r.u8()?;
        r.pad(3)?;
        let mut req = Self {
            flags,
            token: r.u64()?,
            nonce: r.u64()?,
            device_id: r.u64()?,
            unk: r.read_array()?,
            ..Self::default()
        };
        r.pad(0x60)?;
        let mut read = |count, max| -> Result<Vec<u64>> {
            let all = (0..max)
                .map(|_| r.u64())
                .collect::<ldn_wire::Result<Vec<_>>>()?;
            Ok(all[..count].to_vec())
        };
        req.params1 = read(n1, Self::MAX_PARAMS1)?;
        req.params2 = read(n2, Self::MAX_PARAMS2)?;
        Ok(req)
    }
}

/// 挑战应答（主机 -> 成员），编码后固定 0x100 字节。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChallengeResponse {
    /// 标志。
    pub flags: u32,
    /// 回显的请求随机数。
    pub nonce: u64,
    /// 成员的设备 ID。
    pub device_id: u64,
    /// 主机的设备 ID。
    pub device_id_host: u64,
    /// 成员侧 16 字节字段。
    pub unk: [u8; 16],
    /// 主机侧 16 字节字段。
    pub unk_host: [u8; 16],
}

impl ChallengeResponse {
    /// 编码后的长度。
    pub const LEN: usize = 0x100;

    /// 编码并签名。
    pub fn encode(&self, key: &[u8]) -> Vec<u8> {
        let mut w = Writer::new(Endian::Little);
        w.pad(4);
        w.u32(self.flags);
        w.u64(self.nonce);
        w.u64(self.device_id);
        w.u64(self.device_id_host);
        w.write(&self.unk);
        w.write(&self.unk_host);
        w.pad(0x90);
        seal_challenge(key, &w.into_vec())
    }

    /// 校验签名并解码。
    pub fn decode(data: &[u8], key: &[u8]) -> Result<Self> {
        let body = open_challenge(data, key, Self::LEN, "challenge response has wrong size")?;
        let mut r = Reader::new(body, Endian::Little);
        r.pad(4)?;
        let resp = Self {
            flags: r.u32()?,
            nonce: r.u64()?,
            device_id: r.u64()?,
            device_id_host: r.u64()?,
            unk: r.read_array()?,
            unk_host: r.read_array()?,
        };
        r.pad(0x90)?;
        Ok(resp)
    }
}

/// 认证请求载荷（成员 -> 主机）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationRequest {
    /// 用户名，最多 32 字节。
    pub username: Vec<u8>,
    /// 应用版本。
    pub app_version: u16,
    /// 平台。
    pub platform: u8,
    /// 版本 3 起：已签名的 [`ChallengeRequest`] 字节（0x300），空表示没有挑战。
    pub challenge: Vec<u8>,
}

impl Default for AuthenticationRequest {
    fn default() -> Self {
        Self {
            username: Vec::new(),
            app_version: 0,
            platform: platform::NX,
            challenge: Vec::new(),
        }
    }
}

impl AuthenticationRequest {
    fn encode(&self, version: u8) -> Result<Vec<u8>> {
        let mut w = Writer::new(Endian::Big);
        write_name(&mut w, "username", &self.username)?;
        w.u16(self.app_version);
        w.u8(self.platform);
        w.pad(29);
        if version >= 3 {
            w.pad(0x24);
            w.write(&self.challenge);
        }
        Ok(w.into_vec())
    }

    fn decode(data: &[u8], version: u8) -> Result<Self> {
        let mut r = Reader::new(data, Endian::Big);
        let mut req = Self {
            username: read_name(&mut r)?,
            app_version: r.u16()?,
            platform: r.u8()?,
            challenge: Vec::new(),
        };
        r.pad(29)?;
        if version >= 3 {
            r.pad(0x24)?;
            if !r.is_eof() {
                req.challenge = r.read(ChallengeRequest::LEN)?.to_vec();
            }
        }
        Ok(req)
    }
}

/// 认证应答载荷（主机 -> 成员）。版本 3 之前为空。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationResponse {
    /// 主机平台（版本 3 起）。
    pub platform: u8,
    /// 版本 3 起：已签名的 [`ChallengeResponse`] 字节（0x100），空表示没有挑战。
    pub challenge: Vec<u8>,
}

impl Default for AuthenticationResponse {
    fn default() -> Self {
        Self {
            platform: platform::NX,
            challenge: Vec::new(),
        }
    }
}

impl AuthenticationResponse {
    fn encode(&self, version: u8) -> Vec<u8> {
        let mut w = Writer::new(Endian::Big);
        if version >= 3 {
            w.u8(self.platform);
            w.pad(0x83);
            w.write(&self.challenge);
        }
        w.into_vec()
    }

    fn decode(data: &[u8], version: u8) -> Result<Self> {
        let mut resp = Self::default();
        if version >= 3 {
            let mut r = Reader::new(data, Endian::Big);
            resp.platform = r.u8()?;
            r.pad(0x83)?;
            if !r.is_eof() {
                resp.challenge = r.read(ChallengeResponse::LEN)?.to_vec();
            }
        }
        Ok(resp)
    }
}

/// 认证帧的载荷：请求或应答。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPayload {
    /// 成员发出的请求。
    Request(AuthenticationRequest),
    /// 主机的应答。
    Response(AuthenticationResponse),
}

/// LDN 认证帧。协议 1 明文，协议 3 用由 `client_random` 派生的密钥做 AES-GCM。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationFrame {
    /// 协议版本号，决定载荷里是否带挑战（>= 3）。
    pub version: u8,
    /// 状态码，见 [`status`]。
    pub status_code: u8,
    /// 网络标识（本帧里按小端编码）。
    pub network_id: NetworkId,
    /// 主机随机数。
    pub server_random: [u8; 16],
    /// 成员随机数，派生认证密钥。
    pub client_random: [u8; 16],
    /// 载荷。
    pub payload: AuthPayload,
}

/// 协议 1 明文，其余 AES-GCM。
///
/// 与 Python 版的差异：Python 按“协议 == 1”决定格式字段、按“协议 == 3”决定是否加密，
/// 两者在协议 1/3 以外会不一致；这里统一由格式决定是否加密。
fn format_for(protocol: Protocol) -> u8 {
    if protocol == Protocol::V1 {
        FORMAT_PLAIN
    } else {
        FORMAT_AES_GCM
    }
}

impl AuthenticationFrame {
    /// 编码（协议 3 时加密）。
    pub fn encode(&self, kd: &KeyDerivation) -> Result<Vec<u8>> {
        let (payload, is_response) = match &self.payload {
            AuthPayload::Request(r) => (r.encode(self.version)?, false),
            AuthPayload::Response(r) => (r.encode(self.version), true),
        };
        let size = u16::try_from(payload.len()).map_err(|_| Error::TooLong {
            field: "authentication payload",
            len: payload.len(),
            max: u16::MAX as usize,
        })?;
        let format = format_for(kd.protocol());

        let mut h = Writer::new(Endian::Big);
        h.u8(self.version);
        h.u8(size as u8);
        h.u8(self.status_code);
        h.u8(is_response.into());
        h.u8((size >> 8) as u8);
        h.u8(format);
        h.pad(2);
        h.write(&self.network_id.encode(Endian::Little));
        h.write(&self.server_random);
        h.write(&self.client_random);
        let header = h.into_vec();

        let mut w = Writer::new(Endian::Big);
        write_custom_header(&mut w, KIND_AUTHENTICATION);
        w.write(&header);
        if format == FORMAT_AES_GCM {
            let key = kd.derive_authentication_key(&self.client_random)?;
            let nonce: [u8; 12] = header[..12].try_into().unwrap();
            let (ciphertext, tag) = gcm_seal(&key, &nonce, &header, &payload);
            w.write(&tag);
            w.write(&ciphertext);
        } else {
            w.write(&payload);
        }
        Ok(w.into_vec())
    }

    /// 解码并解密。格式字段必须与 `kd` 的协议一致，载荷长度必须与长度字段完全相等。
    pub fn decode(data: &[u8], kd: &KeyDerivation) -> Result<Self> {
        let mut r = Reader::new(data, Endian::Big);
        read_custom_header(&mut r, KIND_AUTHENTICATION, "authentication frame")?;
        let header = r.peek(AUTH_HEADER_LEN)?.to_vec();

        let version = r.u8()?;
        let size_lo = r.u8()?;
        let status_code = r.u8()?;
        let is_response = r.u8()? != 0;
        let size_hi = r.u8()?;
        let format = r.u8()?;
        r.pad(2)?;
        if format != format_for(kd.protocol()) {
            return Err(Error::Invalid(
                "authentication format does not match protocol",
            ));
        }
        let network_id = NetworkId::decode(r.read(NetworkId::LEN)?, Endian::Little)?;
        let server_random = r.read_array()?;
        let client_random = r.read_array()?;
        let tag: Option<[u8; TAG_LEN]> = if format == FORMAT_AES_GCM {
            Some(r.read_array()?)
        } else {
            None
        };

        let size = usize::from(u16::from_be_bytes([size_hi, size_lo]));
        if r.available() != size {
            return Err(Error::Invalid("authentication frame has wrong size"));
        }
        let body = r.rest();
        let plaintext = match tag {
            Some(tag) => {
                let key = kd.derive_authentication_key(&client_random)?;
                let nonce: [u8; 12] = header[..12].try_into().unwrap();
                gcm_open(&key, &nonce, &header, body, &tag)?
            }
            None => body.to_vec(),
        };
        let payload = if is_response {
            AuthPayload::Response(AuthenticationResponse::decode(&plaintext, version)?)
        } else {
            AuthPayload::Request(AuthenticationRequest::decode(&plaintext, version)?)
        };
        Ok(Self {
            version,
            status_code,
            network_id,
            server_random,
            client_random,
            payload,
        })
    }
}

/// 断开帧：主机解散网络或踢人时发给成员。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisconnectFrame {
    /// 原因，见 [`disconnect`]。
    pub reason: u8,
}

impl DisconnectFrame {
    /// 编码，固定 38 字节。
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new(Endian::Big);
        write_custom_header(&mut w, KIND_DISCONNECT);
        w.u8(self.reason);
        w.pad(31);
        w.into_vec()
    }

    /// 解码。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data, Endian::Big);
        read_custom_header(&mut r, KIND_DISCONNECT, "disconnect frame")?;
        let reason = r.u8()?;
        r.pad(31)?;
        Ok(Self { reason })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldn_crypto::Keys;
    use ldn_crypto::keys::CHALLENGE_KEY;

    #[test]
    fn challenge_hmac_and_limits() {
        let req = ChallengeRequest {
            params2: (0..64).collect(),
            ..Default::default()
        };
        let bytes = req.encode(&CHALLENGE_KEY).unwrap();
        assert_eq!(bytes.len(), ChallengeRequest::LEN);
        assert_eq!(
            ChallengeRequest::decode(&bytes, &CHALLENGE_KEY).unwrap(),
            req
        );
        assert_eq!(
            ChallengeRequest::decode(&bytes, b"other"),
            Err(Error::IntegrityCheckFailed)
        );
        assert!(ChallengeRequest::decode(&bytes[1..], &CHALLENGE_KEY).is_err());

        let too_many = ChallengeRequest {
            params1: vec![0; 9],
            ..Default::default()
        };
        assert!(matches!(
            too_many.encode(&CHALLENGE_KEY),
            Err(Error::TooLong { .. })
        ));

        let resp = ChallengeResponse {
            nonce: 7,
            ..Default::default()
        };
        let bytes = resp.encode(&CHALLENGE_KEY);
        assert_eq!(
            ChallengeResponse::decode(&bytes, &CHALLENGE_KEY).unwrap(),
            resp
        );
    }

    #[test]
    fn authentication_size_and_format_checks() {
        let kd = KeyDerivation::new(Keys::default(), Protocol::V1);
        let frame = AuthenticationFrame {
            version: 2,
            status_code: 0,
            network_id: NetworkId::default(),
            server_random: [1; 16],
            client_random: [2; 16],
            payload: AuthPayload::Request(AuthenticationRequest {
                username: b"a".to_vec(),
                ..Default::default()
            }),
        };
        let mut bytes = frame.encode(&kd).unwrap();
        assert_eq!(AuthenticationFrame::decode(&bytes, &kd).unwrap(), frame);

        // 协议 3 的解码器拒绝明文格式，而且不需要系统密钥就能判断出来。
        let kd3 = KeyDerivation::new(Keys::default(), Protocol::V3);
        assert!(matches!(
            AuthenticationFrame::decode(&bytes, &kd3),
            Err(Error::Invalid(_))
        ));

        bytes.push(0);
        assert!(matches!(
            AuthenticationFrame::decode(&bytes, &kd),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn disconnect_roundtrip() {
        let f = DisconnectFrame {
            reason: disconnect::CONNECTION_LOST,
        };
        assert_eq!(DisconnectFrame::decode(&f.encode()), Ok(f));
        let mut bad = f.encode();
        bad[4] = 0x02; // 改成认证帧类型
        assert!(matches!(
            DisconnectFrame::decode(&bad),
            Err(Error::NotLdnFrame(_))
        ));
    }
}
