//! LDN 各类帧用到的加解密原语。
//!
//! | 用途 | 算法 | Python 对应 |
//! |---|---|---|
//! | 数据帧 | AES-128-CCM，8 字节 MIC（CCMP） | `wlan.DataFrame.encrypt/decrypt` |
//! | 广播帧（协议 1） | AES-128-CTR，4 字节 nonce + 96 位计数器 | `AdvertisementFrame._encrypt_aes_ctr` |
//! | 广播帧（协议 3）、认证帧（协议 3） | AES-128-GCM，12 字节 nonce，16 字节 tag | `_encrypt_aes_gcm` |
//! | 广播帧完整性（协议 1） | SHA-256 | `hashlib.sha256` |
//! | 挑战请求/应答 | HMAC-SHA256 | `hmac.digest` |

use aes::Aes128;
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::AeadInOut;
use ccm::Ccm;
use ccm::consts::{U8, U13};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, KeyInit, Mac};
use ldn_wire::data::DataFrame;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::keys::Key;

/// CCMP：AES-128-CCM，8 字节 MIC，13 字节 nonce。
type Ccmp = Ccm<Aes128, U8, U13>;
/// pycryptodome 的 CTR 模式在 nonce 之后接大端计数器，从 0 开始；与 128 位大端计数器等价。
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// CCMP MIC 长度。
pub const CCMP_MIC_LEN: usize = 8;
/// GCM tag 长度。
pub const GCM_TAG_LEN: usize = 16;

/// 用 CCMP 加密数据帧：把 `payload` 换成 `密文 || MIC`，置 Protected 位并记下包序号与密钥号。
///
/// 已加密的帧返回 [`Error::AlreadyProtected`]；`packet_number` 超过 48 位或 `key_id`
/// 超过 3 时返回编码错误且帧保持不变。调用方负责保证同一密钥下包序号不重复。
pub fn ccmp_encrypt(
    frame: &mut DataFrame,
    key: &Key,
    packet_number: u64,
    key_id: u8,
) -> Result<()> {
    if frame.protected {
        return Err(Error::AlreadyProtected);
    }
    let mut encrypted = DataFrame {
        protected: true,
        packet_number,
        key_id,
        ..frame.clone()
    };
    // 先编码一次，让 ldn-wire 统一检查字段范围。
    encrypted.encode()?;
    let tag = Ccmp::new(key.into())
        .encrypt_inout_detached(
            &encrypted.ccmp_nonce().into(),
            &encrypted.ccmp_aad(),
            encrypted.payload.as_mut_slice().into(),
        )
        .map_err(|_| Error::InvalidLength("CCMP payload"))?;
    encrypted.payload.extend_from_slice(&tag);
    *frame = encrypted;
    Ok(())
}

/// 解密受保护的数据帧，成功后 `payload` 为明文、Protected 位清除；未加密的帧原样返回成功。
///
/// MIC 校验失败返回 [`Error::AuthenticationFailed`]，帧体短于 MIC 返回
/// [`Error::InvalidLength`]；出错时帧保持不变。
pub fn ccmp_decrypt(frame: &mut DataFrame, key: &Key) -> Result<()> {
    if !frame.protected {
        return Ok(());
    }
    let split = frame
        .payload
        .len()
        .checked_sub(CCMP_MIC_LEN)
        .ok_or(Error::InvalidLength("CCMP payload"))?;
    let (ciphertext, mic) = frame.payload.split_at(split);
    let mut plaintext = ciphertext.to_vec();
    let mic: [u8; CCMP_MIC_LEN] = mic.try_into().unwrap();
    Ccmp::new(key.into())
        .decrypt_inout_detached(
            &frame.ccmp_nonce().into(),
            &frame.ccmp_aad(),
            plaintext.as_mut_slice().into(),
            &mic.into(),
        )
        .map_err(|_| Error::AuthenticationFailed)?;
    frame.payload = plaintext;
    frame.protected = false;
    Ok(())
}

/// AES-128-CTR，加密与解密相同。`nonce` 是广播帧头里的 4 字节随机数。
pub fn aes_ctr(key: &Key, nonce: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(nonce);
    let mut out = data.to_vec();
    Aes128Ctr::new(key.into(), &iv.into()).apply_keystream(&mut out);
    out
}

/// AES-128-GCM 加密，返回 `(密文, tag)`。
///
/// 广播帧的 nonce 是 4 字节随机数后补 8 个 0，认证帧是帧头前 12 字节；
/// 两者的 tag 在帧里的位置也不同（广播帧在密文前，认证帧单独一段），所以分开返回。
pub fn gcm_seal(
    key: &Key,
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; GCM_TAG_LEN]) {
    let mut out = plaintext.to_vec();
    let tag = Aes128Gcm::new(key.into())
        .encrypt_inout_detached(&(*nonce).into(), aad, out.as_mut_slice().into())
        .expect("AES-GCM plaintext length is far below the 64 GiB limit");
    (out, tag.into())
}

/// AES-128-GCM 解密；tag 校验失败返回 [`Error::AuthenticationFailed`]。
pub fn gcm_open(
    key: &Key,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; GCM_TAG_LEN],
) -> Result<Vec<u8>> {
    let mut out = ciphertext.to_vec();
    Aes128Gcm::new(key.into())
        .decrypt_inout_detached(
            &(*nonce).into(),
            aad,
            out.as_mut_slice().into(),
            &(*tag).into(),
        )
        .map_err(|_| Error::AuthenticationFailed)?;
    Ok(out)
}

/// SHA-256 摘要。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HMAC-SHA256。
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// 常数时间校验 HMAC-SHA256。
///
/// 与 Python 版的差异：Python 用 `!=` 比较 MAC，存在理论上的计时侧信道；这里常数时间比较。
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected: &[u8]) -> Result<()> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.verify_slice(expected)
        .map_err(|_| Error::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldn_wire::MacAddress;

    const KEY: Key = [7; 16];

    fn frame() -> DataFrame {
        DataFrame {
            target: MacAddress::BROADCAST,
            source: MacAddress::new([2, 0, 0, 0, 0, 1]),
            bssid: MacAddress::new([2, 0, 0, 0, 0, 1]),
            from_ds: true,
            payload: b"hello".to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn ccmp_roundtrip_and_tamper() {
        let mut f = frame();
        ccmp_encrypt(&mut f, &KEY, 5, 1).unwrap();
        assert!(f.protected);
        assert_eq!(f.payload.len(), 5 + CCMP_MIC_LEN);
        assert_eq!(
            ccmp_encrypt(&mut f.clone(), &KEY, 6, 1),
            Err(Error::AlreadyProtected)
        );

        let mut tampered = f.clone();
        tampered.payload[0] ^= 1;
        assert_eq!(
            ccmp_decrypt(&mut tampered, &KEY),
            Err(Error::AuthenticationFailed)
        );
        assert!(tampered.protected, "frame must be unchanged on failure");

        // 地址属于 AAD：改地址同样让校验失败。
        let mut readdressed = f.clone();
        readdressed.target = MacAddress::ZERO;
        assert_eq!(
            ccmp_decrypt(&mut readdressed, &KEY),
            Err(Error::AuthenticationFailed)
        );

        ccmp_decrypt(&mut f, &KEY).unwrap();
        assert_eq!(f.payload, b"hello");
        assert!(!f.protected);
    }

    #[test]
    fn ccmp_edge_cases() {
        let mut plain = frame();
        ccmp_decrypt(&mut plain, &KEY).unwrap();
        assert_eq!(plain, frame());

        let mut f = frame();
        assert!(ccmp_encrypt(&mut f, &KEY, 1 << 48, 1).is_err());
        assert_eq!(f, frame());

        let mut short = DataFrame {
            protected: true,
            payload: vec![0; 7],
            ..frame()
        };
        assert_eq!(
            ccmp_decrypt(&mut short, &KEY),
            Err(Error::InvalidLength("CCMP payload"))
        );
    }

    #[test]
    fn ctr_is_symmetric() {
        let data = b"0123456789abcdef0123";
        let ct = aes_ctr(&KEY, &[1, 2, 3, 4], data);
        assert_ne!(ct, data);
        assert_eq!(aes_ctr(&KEY, &[1, 2, 3, 4], &ct), data);
    }

    #[test]
    fn gcm_roundtrip_and_tamper() {
        let nonce = [3; 12];
        let (ct, tag) = gcm_seal(&KEY, &nonce, b"hdr", b"payload");
        assert_eq!(
            gcm_open(&KEY, &nonce, b"hdr", &ct, &tag).unwrap(),
            b"payload"
        );
        assert_eq!(
            gcm_open(&KEY, &nonce, b"HDR", &ct, &tag),
            Err(Error::AuthenticationFailed)
        );
        let mut bad = tag;
        bad[0] ^= 1;
        assert_eq!(
            gcm_open(&KEY, &nonce, b"hdr", &ct, &bad),
            Err(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn hmac_verify() {
        let mac = hmac_sha256(b"k", b"data");
        assert_eq!(hmac_sha256_verify(b"k", b"data", &mac), Ok(()));
        assert_eq!(
            hmac_sha256_verify(b"k", b"data", &mac[..31]),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(
            hmac_sha256_verify(b"x", b"data", &mac),
            Err(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn sha256_known_answer() {
        // FIPS 180-2 “abc”。
        assert_eq!(sha256(b"abc")[..4], [0xba, 0x78, 0x16, 0xbf]);
    }
}
