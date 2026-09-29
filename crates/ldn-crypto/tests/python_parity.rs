//! 与 Python 版加密代码逐字节对拍。期望值由 `tools/gen_crypto_vectors.py` 生成，
//! 所有系统密钥都是脚本里的假值；这里的输入常量必须与脚本一致。

#[allow(dead_code)]
mod vectors {
    include!("vectors/python_crypto_vectors.rs");
}
#[allow(dead_code)]
mod wire_vectors {
    include!("../../ldn-wire/tests/vectors/python_vectors.rs");
}

use ldn_crypto::cipher::{
    aes_ctr, ccmp_decrypt, ccmp_encrypt, gcm_open, gcm_seal, hmac_sha256, hmac_sha256_verify,
};
use ldn_crypto::keys::{CHALLENGE_KEY, CHALLENGE_KEY_DEV};
use ldn_crypto::{KeyDerivation, Keys, Protocol};
use ldn_wire::data::DataFrame;

const CLIENT_RANDOM: [u8; 16] = seq(0x40);
const SERVER_RANDOM: [u8; 16] = seq(0x50);
const CCMP_KEY: [u8; 16] = seq(0x70);
const PASSWORD: &[u8] = b"LunchPack2DefaultPhrase";
const ADV_NONCE: [u8; 4] = [1, 2, 3, 4];
const PLAINTEXT: &[u8] = b"LDN crypto parity plaintext, longer than one AES block.";
const HMAC_DATA: &[u8] = b"challenge body";

const fn seq(start: u8) -> [u8; 16] {
    let mut out = [0; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = start + i as u8;
        i += 1;
    }
    out
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn key16(s: &str) -> [u8; 16] {
    unhex(s).try_into().unwrap()
}

fn auth_header() -> Vec<u8> {
    (0x60..0x60 + 0x48).collect()
}

fn derivation(protocol: Protocol) -> KeyDerivation {
    let text = String::from_utf8(unhex(vectors::KEYS_FILE)).unwrap();
    KeyDerivation::new(Keys::parse(&text).unwrap(), protocol)
}

/// 每个协议版本一组向量：(协议, 认证密钥, 数据密钥, 广播派生数据, 广播密钥, CTR, GCM, 认证密文, 认证 tag)
fn cases() -> [(Protocol, [&'static str; 8]); 2] {
    use vectors::*;
    [
        (
            Protocol::V1,
            [
                P1_AUTH_KEY,
                P1_DATA_KEY,
                P1_ADV_KEY_DATA,
                P1_ADV_KEY,
                P1_ADV_CTR,
                P1_ADV_GCM,
                P1_AUTH_GCM_CT,
                P1_AUTH_GCM_TAG,
            ],
        ),
        (
            Protocol::V3,
            [
                P3_AUTH_KEY,
                P3_DATA_KEY,
                P3_ADV_KEY_DATA,
                P3_ADV_KEY,
                P3_ADV_CTR,
                P3_ADV_GCM,
                P3_AUTH_GCM_CT,
                P3_AUTH_GCM_TAG,
            ],
        ),
    ]
}

#[test]
fn key_derivation() {
    for (protocol, [auth, data, adv_data, adv, ..]) in cases() {
        let kd = derivation(protocol);
        assert_eq!(
            kd.derive_authentication_key(&CLIENT_RANDOM).unwrap(),
            key16(auth),
            "{protocol:?} auth"
        );
        assert_eq!(
            kd.derive_data_key(&SERVER_RANDOM, PASSWORD).unwrap(),
            key16(data),
            "{protocol:?} data"
        );
        assert_eq!(
            kd.derive_advertise_key(&unhex(adv_data)).unwrap(),
            key16(adv),
            "{protocol:?} adv"
        );
    }
}

#[test]
fn advertisement_ctr_and_gcm() {
    let header = auth_header();
    for (protocol, [_, _, _, adv, ctr, gcm, ..]) in cases() {
        let key = key16(adv);
        let ctr = unhex(ctr);
        assert_eq!(
            aes_ctr(&key, &ADV_NONCE, PLAINTEXT),
            ctr,
            "{protocol:?} ctr"
        );
        assert_eq!(aes_ctr(&key, &ADV_NONCE, &ctr), PLAINTEXT);

        // 广播帧 GCM：nonce = 4 字节随机数 + 8 个 0，AAD = 帧头 0x28 字节，帧里 tag 在密文前。
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&ADV_NONCE);
        let (ct, tag) = gcm_seal(&key, &nonce, &header[..0x28], PLAINTEXT);
        let expected = unhex(gcm);
        assert_eq!([&tag[..], &ct[..]].concat(), expected, "{protocol:?} gcm");
        let tag: [u8; 16] = expected[..16].try_into().unwrap();
        assert_eq!(
            gcm_open(&key, &nonce, &header[..0x28], &expected[16..], &tag).unwrap(),
            PLAINTEXT
        );
    }
}

#[test]
fn authentication_gcm() {
    let header = auth_header();
    let nonce: [u8; 12] = header[..12].try_into().unwrap();
    for (protocol, [auth, _, _, _, _, _, ct, tag]) in cases() {
        let key = key16(auth);
        let (got_ct, got_tag) = gcm_seal(&key, &nonce, &header, PLAINTEXT);
        assert_eq!(got_ct, unhex(ct), "{protocol:?} ct");
        assert_eq!(got_tag, key16(tag), "{protocol:?} tag");
        assert_eq!(
            gcm_open(&key, &nonce, &header, &got_ct, &got_tag).unwrap(),
            PLAINTEXT
        );
    }
}

#[test]
fn challenge_hmac() {
    assert_eq!(CHALLENGE_KEY.to_vec(), unhex(vectors::CHALLENGE_KEY));
    assert_eq!(
        CHALLENGE_KEY_DEV.to_vec(),
        unhex(vectors::CHALLENGE_KEY_DEV)
    );
    let kd = derivation(Protocol::V1);
    let mac = hmac_sha256(kd.challenge_key(false), HMAC_DATA);
    assert_eq!(mac.to_vec(), unhex(vectors::HMAC_PROD));
    assert!(hmac_sha256_verify(kd.challenge_key(false), HMAC_DATA, &mac).is_ok());
    assert!(hmac_sha256_verify(kd.challenge_key(true), HMAC_DATA, &mac).is_err());
}

#[test]
fn ccmp_matches_python_both_ways() {
    let expected = unhex(vectors::CCMP_ENCRYPTED_FRAME);
    let mut frame = DataFrame::decode(&expected).unwrap();
    ccmp_decrypt(&mut frame, &CCMP_KEY).unwrap();
    assert_eq!(frame.payload, PLAINTEXT);

    // 再用同样的包序号加密回去，必须得到 Python 的原始字节。
    ccmp_encrypt(&mut frame, &CCMP_KEY, 0xAABB_CCDD, 1).unwrap();
    assert_eq!(frame.encode().unwrap(), expected);
}

#[test]
fn ccmp_decrypts_ldn_wire_vector() {
    // ldn-wire 阶段 1 准备的加密帧：密钥 CCMP_TEST_KEY，明文是 SNAP 向量。
    let key = key16(wire_vectors::CCMP_TEST_KEY);
    let mut frame = DataFrame::decode(&unhex(wire_vectors::DATA_CCMP_ENCRYPTED)).unwrap();
    ccmp_decrypt(&mut frame, &key).unwrap();
    assert_eq!(frame.payload, unhex(wire_vectors::SNAP));
}
