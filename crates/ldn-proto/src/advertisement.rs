//! 广播帧：主机每 100ms 以 802.11 Action 帧广播房间信息，扫描方据此列出房间。
//!
//! 线上格式（大端）：
//!
//! ```text
//! 7F | OUI 00 22 AA | 04 | 00 | 01 01 | 00×4          12 字节 Action 帧前缀
//! NetworkId(32) | version | format | size(u16) | nonce(4)   0x28 字节帧头，同时是 AAD/哈希输入
//! 明文 / AES-CTR：SHA-256(32) || 载荷(size = 0x500)，整体按 format 加密
//! AES-GCM：      tag(16) || 密文(size)
//! ```
//!
//! 载荷有两种编码：明文和 AES-CTR 用定长的 V1（0x500 字节，8 个参与者槽位全写），
//! AES-GCM 用变长的 V2（只写已连接的参与者）。

use std::net::Ipv4Addr;

use ldn_crypto::cipher::{aes_ctr, gcm_open, gcm_seal, sha256};
use ldn_crypto::{KeyDerivation, Protocol};
use ldn_wire::MacAddress;
use ldn_wire::stream::{Endian, Reader, Writer};

use crate::common::{
    MAX_PARTICIPANTS, NINTENDO_OUI, NetworkId, ParticipantInfo, read_name, security, write_name,
};
use crate::error::{Error, Result};

/// V1 载荷的固定长度。
const V1_PAYLOAD_LEN: usize = 0x500;
/// V1 载荷里应用数据区的固定长度，也是应用数据的上限。
pub const MAX_APPLICATION_DATA_V1: usize = 384;
/// 帧头（NetworkId 到 nonce）长度。
const HEADER_LEN: usize = 0x28;
const SHA_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// Action 帧 Category：vendor-specific。
const CATEGORY_VENDOR: u8 = 0x7F;
/// OUI 之后的协议号：LDN。
const OUI_TYPE_LDN: u8 = 4;
/// 帧类型：广播帧。
const KIND_ADVERTISEMENT: u16 = 0x101;
/// 帧头里允许的版本号。
const SUPPORTED_VERSIONS: [u8; 3] = [2, 3, 4];

/// 广播帧的加密方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdvertiseFormat {
    /// 不加密，仅 SHA-256 校验（`SECURITY_MODE_SYSTEM_DEBUG`）。
    Plain = 1,
    /// AES-CTR + SHA-256（协议 1）。
    AesCtr = 2,
    /// AES-GCM（协议 3）。
    AesGcm = 3,
}

impl AdvertiseFormat {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Plain),
            2 => Ok(Self::AesCtr),
            3 => Ok(Self::AesGcm),
            _ => Err(Error::Invalid("unknown advertisement format")),
        }
    }

    /// 给定协议下加密时使用的格式：协议 1 用 AES-CTR，其余用 AES-GCM。
    pub fn encrypted_for(protocol: Protocol) -> Self {
        if protocol == Protocol::V1 {
            Self::AesCtr
        } else {
            Self::AesGcm
        }
    }
}

/// 广播帧的载荷：房间状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertisementInfo {
    /// 主机随机数，参与数据帧密钥派生。
    pub server_random: [u8; 16],
    /// 安全模式，见 [`security`]。
    pub security_mode: u16,
    /// 接纳策略，见 [`accept`](crate::common::accept)。
    pub station_accept_policy: u8,
    /// 应用版本。V1 编码里不单独存储，解码时取 0 号参与者的版本。
    pub app_version: u16,
    /// 频段（20.0.0 起），6 位。
    pub band: u8,
    /// 信道（20.0.0 起），10 位。
    pub channel: u16,
    /// 最大人数。
    pub max_participants: u8,
    /// 当前人数。
    pub num_participants: u8,
    /// 8 个参与者槽位，0 号是主机。
    pub participants: [ParticipantInfo; MAX_PARTICIPANTS],
    /// 游戏自定义数据。
    pub application_data: Vec<u8>,
    /// 挑战值（6.0.0 起）。
    pub challenge: u64,
}

impl Default for AdvertisementInfo {
    fn default() -> Self {
        Self {
            server_random: [0; 16],
            security_mode: security::PROD,
            station_accept_policy: 0,
            app_version: 0,
            band: 0,
            channel: 0,
            max_participants: 0,
            num_participants: 0,
            participants: Default::default(),
            application_data: Vec::new(),
            challenge: 0,
        }
    }
}

impl AdvertisementInfo {
    fn band_channel(&self) -> Result<u16> {
        if self.band >= 1 << 6 || self.channel >= 1 << 10 {
            return Err(Error::Invalid("band or channel out of range"));
        }
        Ok((u16::from(self.band) << 10) | self.channel)
    }

    fn set_band_channel(&mut self, value: u16) {
        self.band = (value >> 10) as u8;
        self.channel = value & 0x3FF;
    }

    /// V1（明文 / AES-CTR）编码，固定 0x500 字节。
    fn encode_v1(&self) -> Result<Vec<u8>> {
        if self.application_data.len() > MAX_APPLICATION_DATA_V1 {
            return Err(Error::TooLong {
                field: "application_data",
                len: self.application_data.len(),
                max: MAX_APPLICATION_DATA_V1,
            });
        }
        let mut w = Writer::new(Endian::Big);
        w.write(&self.server_random);
        w.u16(self.security_mode);
        w.u8(self.station_accept_policy);
        w.pad(1);
        w.u16(self.band_channel()?);
        w.u8(self.max_participants);
        w.u8(self.num_participants);
        for p in &self.participants {
            w.write(&p.ip_address.octets());
            w.write(&p.mac_address.octets());
            w.u8(p.connected.into());
            w.u8(p.platform);
            write_name(&mut w, "participant name", &p.name)?;
            w.u16(p.app_version);
            w.pad(10);
        }
        w.pad(2);
        w.u16(self.application_data.len() as u16);
        w.write(&self.application_data);
        w.pad(MAX_APPLICATION_DATA_V1 - self.application_data.len());
        w.pad(412);
        w.u64(self.challenge);
        let out = w.into_vec();
        debug_assert_eq!(out.len(), V1_PAYLOAD_LEN);
        Ok(out)
    }

    fn decode_v1(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data, Endian::Big);
        let mut info = Self {
            server_random: r.read_array()?,
            security_mode: r.u16()?,
            ..Self::default()
        };
        info.station_accept_policy = r.u8()?;
        r.pad(1)?;
        info.set_band_channel(r.u16()?);
        info.max_participants = r.u8()?;
        info.num_participants = r.u8()?;
        for p in &mut info.participants {
            p.ip_address = Ipv4Addr::from(r.read_array::<4>()?);
            p.mac_address = MacAddress::new(r.read_array()?);
            p.connected = r.u8()? != 0;
            p.platform = r.u8()?;
            p.name = read_name(&mut r)?;
            p.app_version = r.u16()?;
            r.pad(10)?;
        }
        info.app_version = info.participants[0].app_version;
        r.pad(2)?;
        let size = usize::from(r.u16()?);
        let area = r.read(MAX_APPLICATION_DATA_V1)?;
        info.application_data = area
            .get(..size)
            .ok_or(Error::Invalid("application data size"))?
            .to_vec();
        r.pad(412)?;
        info.challenge = r.u64()?;
        Ok(info)
    }

    /// V2（AES-GCM）编码：只写已连接的参与者，带槽位号。
    ///
    /// 与 Python 版的差异：已连接的槽位数与 `num_participants` 不一致时报错
    /// （Python 会照写，产生对方无法正确解析的帧）。
    fn encode_v2(&self) -> Result<Vec<u8>> {
        let connected = self.participants.iter().filter(|p| p.connected).count();
        if connected != usize::from(self.num_participants) {
            return Err(Error::Invalid(
                "num_participants does not match connected participants",
            ));
        }
        let security_mode = u8::try_from(self.security_mode)
            .map_err(|_| Error::Invalid("security mode out of range"))?;
        let app_data_len =
            u16::try_from(self.application_data.len()).map_err(|_| Error::TooLong {
                field: "application_data",
                len: self.application_data.len(),
                max: u16::MAX as usize,
            })?;
        let mut w = Writer::new(Endian::Big);
        w.write(&self.server_random);
        w.u64(self.challenge);
        w.u8(security_mode);
        w.u8(self.station_accept_policy);
        w.u16(self.app_version);
        w.pad(8);
        w.u16(self.band_channel()?);
        w.u8(self.max_participants);
        w.u8(self.num_participants);
        for (index, p) in self
            .participants
            .iter()
            .enumerate()
            .filter(|(_, p)| p.connected)
        {
            w.write(&p.ip_address.octets());
            w.write(&p.mac_address.octets());
            w.u8(index as u8);
            w.u8(p.platform);
            write_name(&mut w, "participant name", &p.name)?;
            w.pad(4);
        }
        w.u16(app_data_len);
        w.write(&self.application_data);
        Ok(w.into_vec())
    }

    fn decode_v2(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data, Endian::Big);
        let mut info = Self {
            server_random: r.read_array()?,
            challenge: r.u64()?,
            ..Self::default()
        };
        info.security_mode = r.u8()?.into();
        info.station_accept_policy = r.u8()?;
        info.app_version = r.u16()?;
        r.pad(8)?;
        info.set_band_channel(r.u16()?);
        info.max_participants = r.u8()?;
        info.num_participants = r.u8()?;
        for _ in 0..info.num_participants {
            let ip_address = Ipv4Addr::from(r.read_array::<4>()?);
            let mac_address = MacAddress::new(r.read_array()?);
            let index = usize::from(r.u8()?);
            let platform = r.u8()?;
            let name = read_name(&mut r)?;
            r.pad(4)?;
            // 槽位号越界的条目丢弃，与 Python 一致。
            if let Some(slot) = info.participants.get_mut(index) {
                *slot = ParticipantInfo {
                    ip_address,
                    mac_address,
                    connected: true,
                    name,
                    app_version: info.app_version,
                    platform,
                };
            }
        }
        let size = usize::from(r.u16()?);
        info.application_data = r.read(size)?.to_vec();
        Ok(info)
    }
}

/// 广播帧（Action 帧的帧体，从 Category 字节起）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertisementFrame {
    /// 网络标识。
    pub network_id: NetworkId,
    /// 协议版本号（2~4）。
    pub version: u8,
    /// 加密方式。
    pub format: AdvertiseFormat,
    /// 4 字节随机数，参与 CTR/GCM nonce；每次载荷变化时主机会更新它。
    pub nonce: [u8; 4],
    /// 载荷。
    pub payload: AdvertisementInfo,
}

impl AdvertisementFrame {
    fn header(&self, size: u16) -> Vec<u8> {
        let mut w = Writer::new(Endian::Big);
        self.network_id.write(&mut w);
        w.u8(self.version);
        w.u8(self.format as u8);
        w.u16(size);
        w.write(&self.nonce);
        w.into_vec()
    }

    fn key(&self, kd: &KeyDerivation) -> Result<[u8; 16]> {
        Ok(kd.derive_advertise_key(&self.network_id.encode(Endian::Big))?)
    }

    fn gcm_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.nonce);
        nonce
    }

    /// 编码并按 `format` 加密。明文格式不需要系统密钥。
    pub fn encode(&self, kd: &KeyDerivation) -> Result<Vec<u8>> {
        let plaintext = match self.format {
            AdvertiseFormat::AesGcm => self.payload.encode_v2()?,
            _ => self.payload.encode_v1()?,
        };
        let size = u16::try_from(plaintext.len())
            .map_err(|_| Error::Invalid("advertisement too large"))?;
        let header = self.header(size);

        let body = match self.format {
            AdvertiseFormat::Plain | AdvertiseFormat::AesCtr => {
                // 哈希覆盖帧头 + 32 字节 0（哈希自身的位置）+ 载荷。
                let digest = sha256(&[&header[..], &[0; SHA_LEN], &plaintext].concat());
                let hashed = [&digest[..], &plaintext].concat();
                if self.format == AdvertiseFormat::Plain {
                    hashed
                } else {
                    aes_ctr(&self.key(kd)?, &self.nonce, &hashed)
                }
            }
            AdvertiseFormat::AesGcm => {
                let (ciphertext, tag) =
                    gcm_seal(&self.key(kd)?, &self.gcm_nonce(), &header, &plaintext);
                [&tag[..], &ciphertext].concat()
            }
        };

        let mut w = Writer::new(Endian::Big);
        w.u8(CATEGORY_VENDOR);
        w.u24(NINTENDO_OUI, "oui")?;
        w.u8(OUI_TYPE_LDN);
        w.pad(1);
        w.u16(KIND_ADVERTISEMENT);
        w.pad(4);
        w.write(&header);
        w.write(&body);
        Ok(w.into_vec())
    }

    /// 解码并解密、校验。格式必须是明文或 `kd` 的协议对应的加密方式。
    ///
    /// 不是 LDN 广播帧返回 [`Error::NotLdnFrame`]；哈希或 GCM tag 不对返回
    /// [`Error::IntegrityCheckFailed`]（通常是系统密钥不对）。
    pub fn decode(data: &[u8], kd: &KeyDerivation) -> Result<Self> {
        let mut r = Reader::new(data, Endian::Big);
        if r.u8()? != CATEGORY_VENDOR || r.u24()? != NINTENDO_OUI || r.u8()? != OUI_TYPE_LDN {
            return Err(Error::NotLdnFrame("advertisement frame"));
        }
        r.pad(1)?;
        if r.u16()? != KIND_ADVERTISEMENT {
            return Err(Error::NotLdnFrame("advertisement frame"));
        }
        r.pad(4)?;

        let header = r.peek(HEADER_LEN)?.to_vec();
        let network_id = NetworkId::read(&mut r)?;
        let version = r.u8()?;
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(Error::Invalid("unsupported advertisement version"));
        }
        let format = AdvertiseFormat::from_u8(r.u8()?)?;
        if format != AdvertiseFormat::Plain
            && format != AdvertiseFormat::encrypted_for(kd.protocol())
        {
            return Err(Error::Invalid(
                "advertisement format does not match protocol",
            ));
        }
        let size = usize::from(r.u16()?);
        if format != AdvertiseFormat::AesGcm && size != V1_PAYLOAD_LEN {
            return Err(Error::Invalid("unexpected advertisement size field"));
        }
        let nonce = r.read_array()?;
        let mut frame = Self {
            network_id,
            version,
            format,
            nonce,
            payload: AdvertisementInfo::default(),
        };

        frame.payload = match format {
            AdvertiseFormat::Plain | AdvertiseFormat::AesCtr => {
                let body = r.read(SHA_LEN + size)?;
                let hashed = if format == AdvertiseFormat::AesCtr {
                    aes_ctr(&frame.key(kd)?, &nonce, body)
                } else {
                    body.to_vec()
                };
                let (digest, plaintext) = hashed.split_at(SHA_LEN);
                if sha256(&[&header[..], &[0; SHA_LEN], plaintext].concat()) != digest {
                    return Err(Error::IntegrityCheckFailed);
                }
                AdvertisementInfo::decode_v1(plaintext)?
            }
            AdvertiseFormat::AesGcm => {
                let tag: [u8; TAG_LEN] = r.read_array()?;
                let ciphertext = r.read(size)?;
                let plaintext = gcm_open(
                    &frame.key(kd)?,
                    &frame.gcm_nonce(),
                    &header,
                    ciphertext,
                    &tag,
                )?;
                AdvertisementInfo::decode_v2(&plaintext)?
            }
        };
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldn_crypto::Keys;

    fn kd(protocol: Protocol) -> KeyDerivation {
        let mut kd = KeyDerivation::new(Keys::default(), protocol);
        kd.override_advertise_key = Some([5; 16]);
        kd
    }

    fn frame(format: AdvertiseFormat) -> AdvertisementFrame {
        let mut payload = AdvertisementInfo {
            num_participants: 1,
            application_data: b"app".to_vec(),
            ..Default::default()
        };
        payload.participants[3] = ParticipantInfo {
            connected: true,
            name: b"x".to_vec(),
            ..Default::default()
        };
        AdvertisementFrame {
            network_id: NetworkId::default(),
            version: 3,
            format,
            nonce: [9; 4],
            payload,
        }
    }

    #[test]
    fn roundtrip_all_formats() {
        for (format, protocol) in [
            (AdvertiseFormat::Plain, Protocol::V1),
            (AdvertiseFormat::AesCtr, Protocol::V1),
            (AdvertiseFormat::AesGcm, Protocol::V3),
        ] {
            let f = frame(format);
            let kd = kd(protocol);
            let decoded = AdvertisementFrame::decode(&f.encode(&kd).unwrap(), &kd).unwrap();
            assert_eq!(
                decoded.payload.participants[3], f.payload.participants[3],
                "{format:?}"
            );
            assert_eq!(decoded.payload.application_data, b"app");
        }
    }

    #[test]
    fn format_must_match_protocol() {
        let bytes = frame(AdvertiseFormat::AesCtr)
            .encode(&kd(Protocol::V1))
            .unwrap();
        assert_eq!(
            AdvertisementFrame::decode(&bytes, &kd(Protocol::V3)),
            Err(Error::Invalid(
                "advertisement format does not match protocol"
            ))
        );
    }

    #[test]
    fn wrong_key_and_tampering_are_detected() {
        let bytes = frame(AdvertiseFormat::AesGcm)
            .encode(&kd(Protocol::V3))
            .unwrap();
        let mut other = kd(Protocol::V3);
        other.override_advertise_key = Some([6; 16]);
        assert_eq!(
            AdvertisementFrame::decode(&bytes, &other),
            Err(Error::IntegrityCheckFailed)
        );

        let mut plain = frame(AdvertiseFormat::Plain)
            .encode(&kd(Protocol::V1))
            .unwrap();
        let last = plain.len() - 1;
        plain[last] ^= 1;
        assert_eq!(
            AdvertisementFrame::decode(&plain, &kd(Protocol::V1)),
            Err(Error::IntegrityCheckFailed)
        );
    }

    #[test]
    fn non_ldn_and_bad_header() {
        let kd = kd(Protocol::V1);
        let mut bytes = frame(AdvertiseFormat::Plain).encode(&kd).unwrap();
        bytes[0] = 0x04;
        assert!(matches!(
            AdvertisementFrame::decode(&bytes, &kd),
            Err(Error::NotLdnFrame(_))
        ));

        let mut f = frame(AdvertiseFormat::Plain);
        f.version = 1;
        assert!(matches!(
            AdvertisementFrame::decode(&f.encode(&kd).unwrap(), &kd),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn encode_validation() {
        let kd = kd(Protocol::V3);
        let mut f = frame(AdvertiseFormat::AesGcm);
        f.payload.num_participants = 2;
        assert!(f.encode(&kd).is_err());

        let mut f = frame(AdvertiseFormat::Plain);
        f.payload.application_data = vec![0; 385];
        assert!(matches!(f.encode(&kd), Err(Error::TooLong { .. })));

        let mut f = frame(AdvertiseFormat::Plain);
        f.payload.channel = 1024;
        assert!(f.encode(&kd).is_err());
    }
}
