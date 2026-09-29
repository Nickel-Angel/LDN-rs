//! 系统密钥表（prod.keys）与 LDN 的密钥派生。

use std::collections::BTreeMap;
use std::fmt;

use aes::Aes128;
use aes::cipher::{BlockCipherDecrypt, KeyInit};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// AES-128 密钥。
pub type Key = [u8; 16];

/// 挑战 HMAC 的固定密钥（正式机）。
pub const CHALLENGE_KEY: [u8; 32] =
    hex32("f84b487fb37251c263bf11609036589266af70ca79b44c93c7370c5769c0f602");
/// 挑战 HMAC 的固定密钥（开发机）。
pub const CHALLENGE_KEY_DEV: [u8; 32] =
    hex32("5a0fbfb5b5c5a2733439401b3d46938343f5d2f494224a7c007b61eaacbc1f20");

/// 认证帧和数据帧共用的派生源。
const DATA_KEY_SOURCE: [u8; 16] = hex16("f1e7018419a84f711da714c2cf919c9c");
/// 广播帧的派生源。
const ADVERTISE_KEY_SOURCE: [u8; 16] = hex16("191884743e24c77d87c69e4207d0c438");

const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("invalid hex digit"),
    }
}

/// 编译期把十六进制常量转成字节，避免手抄字节数组出错。
const fn hex_n<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    assert!(b.len() == N * 2);
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = hex_digit(b[2 * i]) << 4 | hex_digit(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex16(s: &str) -> [u8; 16] {
    hex_n(s)
}

const fn hex32(s: &str) -> [u8; 32] {
    hex_n(s)
}

/// 系统密钥表：密钥名 -> 值，来自用户自己从主机导出的 `prod.keys`。
///
/// `Debug` 只打印密钥名，不打印值，避免密钥进日志。
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Keys(BTreeMap<String, Vec<u8>>);

impl Keys {
    /// 解析 `名字 = 十六进制` 格式的文本，空行跳过；名字和值两侧的空白会被去掉。
    ///
    /// 与 Python 版的差异：Python 版任何格式错误都直接抛 `ValueError`，这里报告出错行号。
    pub fn parse(text: &str) -> Result<Self> {
        let mut keys = BTreeMap::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let invalid = || Error::InvalidKeyFile { line: i + 1 };
            let (name, value) = line.split_once('=').ok_or_else(invalid)?;
            keys.insert(
                name.trim().to_owned(),
                decode_hex(value.trim()).ok_or_else(invalid)?,
            );
        }
        Ok(Self(keys))
    }

    /// 读取并解析密钥文件。路径里的 `~` 不会展开，由调用方处理。
    pub fn load(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// 插入或覆盖一把密钥（测试或从别处取得密钥时使用）。
    pub fn insert(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.0.insert(name.into(), value);
    }

    /// 按名字取密钥。
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.0.get(name).map(Vec::as_slice)
    }

    fn require16(&self, name: &'static str) -> Result<Key> {
        let value = self.get(name).ok_or(Error::MissingKey(name))?;
        value.try_into().map_err(|_| Error::InvalidKeyLength {
            name,
            len: value.len(),
        })
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// LDN 协议版本，决定用哪把主密钥和哪种帧加密方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Protocol(pub u8);

impl Protocol {
    /// 协议 1：广播帧 AES-CTR，认证帧明文；主密钥 `master_key_00`。
    pub const V1: Self = Self(1);
    /// 协议 3（Switch 2 引入）：广播帧与认证帧都用 AES-GCM；主密钥 `master_key_12`。
    pub const V3: Self = Self(3);

    fn master_key_name(self) -> Result<&'static str> {
        match self.0 {
            1 => Ok("master_key_00"),
            3 => Ok("master_key_12"),
            other => Err(Error::UnsupportedProtocol(other)),
        }
    }
}

/// 从系统密钥派生 LDN 各类帧的会话密钥，对应 Python 版 `KeyDerivation`。
///
/// 派生链：`master_key` 依次用 AES-ECB 解密 `aes_kek_generation_source`、用途源、
/// `aes_key_generation_source`，得到的密钥再解密 `SHA-256(data)[..16]`。
///
/// 三个 `override_*` 字段用于没有系统密钥、但已知派生结果的场合（例如抓包研究）；
/// 设置后对应的派生直接返回它。认证密钥没有覆盖项，与 Python 版一致。
#[derive(Clone, PartialEq, Eq)]
pub struct KeyDerivation {
    keys: Keys,
    protocol: Protocol,
    /// 覆盖广播帧密钥。
    pub override_advertise_key: Option<Key>,
    /// 覆盖数据帧密钥。
    pub override_data_key: Option<Key>,
    /// 覆盖挑战 HMAC 密钥（任意长度）。
    pub override_challenge_key: Option<Vec<u8>>,
}

impl fmt::Debug for KeyDerivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyDerivation")
            .field("keys", &self.keys)
            .field("protocol", &self.protocol)
            .field(
                "override_advertise_key",
                &self.override_advertise_key.is_some(),
            )
            .field("override_data_key", &self.override_data_key.is_some())
            .field(
                "override_challenge_key",
                &self.override_challenge_key.is_some(),
            )
            .finish()
    }
}

impl KeyDerivation {
    /// 创建派生器。不在这里检查密钥是否齐全：只用覆盖密钥时不需要系统密钥，
    /// 缺失的密钥在第一次真正派生时报 [`Error::MissingKey`]。
    pub fn new(keys: Keys, protocol: Protocol) -> Self {
        Self {
            keys,
            protocol,
            override_advertise_key: None,
            override_data_key: None,
            override_challenge_key: None,
        }
    }

    /// 协议版本。
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn derive(&self, data: &[u8], source: &[u8; 16]) -> Result<Key> {
        let master = self.keys.require16(self.protocol.master_key_name()?)?;
        let kek_source = self.keys.require16("aes_kek_generation_source")?;
        let key_source = self.keys.require16("aes_key_generation_source")?;

        let mut key = ecb_decrypt(&master, kek_source);
        key = ecb_decrypt(&key, *source);
        key = ecb_decrypt(&key, key_source);
        let digest: [u8; 32] = Sha256::digest(data).into();
        Ok(ecb_decrypt(&key, digest[..16].try_into().unwrap()))
    }

    /// 认证帧（协议 3 的 AES-GCM）密钥，由客户端随机数派生。
    pub fn derive_authentication_key(&self, client_random: &[u8]) -> Result<Key> {
        self.derive(client_random, &DATA_KEY_SOURCE)
    }

    /// 数据帧 CCMP 密钥，由主机随机数和房间密码派生。
    pub fn derive_data_key(&self, server_random: &[u8], password: &[u8]) -> Result<Key> {
        if let Some(key) = self.override_data_key {
            return Ok(key);
        }
        let mut data = server_random.to_vec();
        data.extend_from_slice(password);
        self.derive(&data, &DATA_KEY_SOURCE)
    }

    /// 广播帧密钥；`data` 是大端编码的 NetworkId（32 字节）。
    pub fn derive_advertise_key(&self, data: &[u8]) -> Result<Key> {
        if let Some(key) = self.override_advertise_key {
            return Ok(key);
        }
        self.derive(data, &ADVERTISE_KEY_SOURCE)
    }

    /// 挑战请求/应答的 HMAC 密钥：固定值，开发机与正式机不同。
    pub fn challenge_key(&self, dev: bool) -> &[u8] {
        match &self.override_challenge_key {
            Some(key) => key,
            None if dev => &CHALLENGE_KEY_DEV,
            None => &CHALLENGE_KEY,
        }
    }
}

/// 单块 AES-128-ECB 解密。
fn ecb_decrypt(key: &Key, block: [u8; 16]) -> Key {
    let cipher = Aes128::new(key.into());
    let mut block = block.into();
    cipher.decrypt_block(&mut block);
    block.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keys_file() {
        let keys = Keys::parse("\n  a = 00ff \nb=10\n").unwrap();
        assert_eq!(keys.get("a"), Some(&[0x00, 0xFF][..]));
        assert_eq!(keys.get("b"), Some(&[0x10][..]));
        assert_eq!(format!("{keys:?}"), r#"{"a", "b"}"#);
    }

    #[test]
    fn parse_errors_report_line() {
        assert_eq!(
            Keys::parse("a = 00\nno equals\n"),
            Err(Error::InvalidKeyFile { line: 2 })
        );
        assert_eq!(Keys::parse("a = 0"), Err(Error::InvalidKeyFile { line: 1 }));
        assert_eq!(
            Keys::parse("a = zz"),
            Err(Error::InvalidKeyFile { line: 1 })
        );
        assert_eq!(
            Keys::parse("a = é0"),
            Err(Error::InvalidKeyFile { line: 1 })
        );
    }

    #[test]
    fn missing_and_bad_keys() {
        let kd = KeyDerivation::new(Keys::default(), Protocol::V1);
        assert_eq!(
            kd.derive_authentication_key(&[]),
            Err(Error::MissingKey("master_key_00"))
        );

        let mut keys = Keys::default();
        keys.insert("master_key_00", vec![0; 15]);
        let kd = KeyDerivation::new(keys, Protocol::V1);
        assert_eq!(
            kd.derive_data_key(&[], &[]),
            Err(Error::InvalidKeyLength {
                name: "master_key_00",
                len: 15
            })
        );

        let kd = KeyDerivation::new(Keys::default(), Protocol(2));
        assert_eq!(
            kd.derive_advertise_key(&[]),
            Err(Error::UnsupportedProtocol(2))
        );
    }

    #[test]
    fn overrides_skip_system_keys() {
        let mut kd = KeyDerivation::new(Keys::default(), Protocol(2));
        kd.override_data_key = Some([1; 16]);
        kd.override_advertise_key = Some([2; 16]);
        assert_eq!(kd.derive_data_key(b"x", b"y"), Ok([1; 16]));
        assert_eq!(kd.derive_advertise_key(b"x"), Ok([2; 16]));
        assert_eq!(kd.challenge_key(false), &CHALLENGE_KEY);
        assert_eq!(kd.challenge_key(true), &CHALLENGE_KEY_DEV);
        kd.override_challenge_key = Some(vec![9; 3]);
        assert_eq!(kd.challenge_key(true), &[9, 9, 9]);
        // Debug 不泄露覆盖密钥的值。
        assert!(!format!("{kd:?}").contains("[1, 1"));
    }
}
