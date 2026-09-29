//! 扫描附近的 LDN 网络，对应 Python 版 `Scanner` 与 `ldn.scan`。

use std::time::Duration;

use ldn_crypto::{KeyDerivation, Keys, Protocol};
use ldn_proto::{AdvertisementFrame, NetworkInfo};
use ldn_wire::MacAddress;
use ldn_wire::channel::frequency_to_channel;
use ldn_wire::frame::ActionFrame;
use ldn_wire::radiotap::RadiotapFrame;
use ldn_wlan::Factory;

use crate::error::{Error, Result};
use crate::event::channel_band;

/// LDN 广播帧的固定前缀：vendor-specific、Nintendo OUI、LDN、广播帧类型。
const ADVERTISEMENT_PREFIX: [u8; 8] = [0x7F, 0x00, 0x22, 0xAA, 0x04, 0x00, 0x01, 0x01];

/// 扫描参数。
#[derive(Debug, Clone)]
pub struct ScanParam {
    /// 系统密钥。
    pub keys: Keys,
    /// 在哪块网卡上建 monitor 接口。
    pub phy: String,
    /// monitor 接口名。
    pub ifname: String,
    /// 依次扫描的信道。
    pub channels: Vec<u8>,
    /// 每个信道停留时间；主机每 100ms 广播一次，默认 110ms 保证至少收到一次。
    pub dwell_time: Duration,
    /// 尝试用哪些协议解析广播帧。
    pub protocols: Vec<Protocol>,
}

impl ScanParam {
    /// 默认参数：`phy0` 上的 `ldn` 接口，信道 1/6/11，协议 1 和 3。
    pub fn new(keys: Keys) -> Self {
        Self {
            keys,
            phy: "phy0".into(),
            ifname: "ldn".into(),
            channels: vec![1, 6, 11],
            dwell_time: Duration::from_millis(110),
            protocols: vec![Protocol::V1, Protocol::V3],
        }
    }
}

/// 尝试把 monitor 口收到的一帧解析为 LDN 网络；不是广播帧或各协议都解析失败时返回 `None`。
///
/// 地址取自 802.11 头，信道和频段取自 Radiotap 的频率字段（没有该字段的帧跳过）。
pub fn parse_scan_frame(
    radiotap: &RadiotapFrame,
    derivations: &[KeyDerivation],
) -> Option<NetworkInfo> {
    let channel = radiotap
        .channel
        .and_then(|c| frequency_to_channel(c.frequency))?;
    let action = ActionFrame::decode(&radiotap.data).ok()?;
    if !action.action.starts_with(&ADVERTISEMENT_PREFIX) {
        return None;
    }
    for kd in derivations {
        if let Ok(frame) = AdvertisementFrame::decode(&action.action, kd) {
            let mut info = NetworkInfo::new(kd.protocol());
            info.address = action.source;
            info.channel = channel.into();
            info.band = channel_band(channel);
            info.update_from_advertisement(&frame);
            return Some(info);
        }
    }
    log::warn!(
        "failed to parse advertisement frame from {}, ignoring it",
        action.source
    );
    None
}

/// 扫描附近的 LDN 网络，每个主机地址只返回第一次收到的结果。需要 root。
pub async fn scan(param: &ScanParam) -> Result<Vec<NetworkInfo>> {
    for &ch in &param.channels {
        if !ldn_wire::channel::is_valid_channel(ch) {
            return Err(Error::InvalidParam("invalid channel"));
        }
    }
    if param
        .protocols
        .iter()
        .any(|p| *p != Protocol::V1 && *p != Protocol::V3)
    {
        return Err(Error::InvalidParam("invalid protocol"));
    }
    let derivations: Vec<KeyDerivation> = param
        .protocols
        .iter()
        .map(|&p| KeyDerivation::new(param.keys.clone(), p))
        .collect();

    let factory = Factory::new().await?;
    let mut monitor = factory.create_monitor(&param.phy, &param.ifname).await?;
    monitor.set_filter(Some(MacAddress::BROADCAST));

    let result = async {
        let mut networks: Vec<NetworkInfo> = Vec::new();
        for &ch in &param.channels {
            monitor.set_channel(ch).await?;
            let deadline = tokio::time::Instant::now() + param.dwell_time;
            while let Ok(frame) = tokio::time::timeout_at(deadline, monitor.recv()).await {
                if let Some(info) = parse_scan_frame(&frame?, &derivations)
                    && !networks.iter().any(|n| n.address == info.address)
                {
                    networks.push(info);
                }
            }
        }
        Ok::<_, Error>(networks)
    }
    .await;
    monitor.close().await?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldn_proto::AdvertiseFormat;
    use ldn_wire::radiotap::RadiotapChannel;

    fn kd() -> KeyDerivation {
        let mut kd = KeyDerivation::new(Keys::default(), Protocol::V3);
        kd.override_advertise_key = Some([1; 16]);
        kd
    }

    fn radiotap(action: Vec<u8>, frequency: Option<u16>) -> RadiotapFrame {
        let data = ActionFrame {
            source: MacAddress::new([2, 0, 0, 0, 0, 1]),
            action,
        }
        .encode();
        RadiotapFrame {
            data,
            channel: frequency.map(|frequency| RadiotapChannel {
                frequency,
                flags: 0,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn parses_advertisement_with_channel_from_radiotap() {
        let mut net = NetworkInfo::new(Protocol::V3);
        net.version = 4;
        let body = net.to_advertisement().encode(&kd()).unwrap();
        assert_eq!(net.to_advertisement().format, AdvertiseFormat::AesGcm);

        let info = parse_scan_frame(&radiotap(body.clone(), Some(2462)), &[kd()]).unwrap();
        assert_eq!((info.channel, info.band, info.version), (11, 2, 4));
        assert_eq!(info.address, MacAddress::new([2, 0, 0, 0, 0, 1]));

        assert!(parse_scan_frame(&radiotap(body.clone(), None), &[kd()]).is_none());
        let mut wrong = kd();
        wrong.override_advertise_key = Some([2; 16]);
        assert!(parse_scan_frame(&radiotap(body, Some(2462)), &[wrong]).is_none());
        assert!(
            parse_scan_frame(&radiotap(vec![0x7F, 0, 0x22, 0xAA], Some(2462)), &[kd()]).is_none()
        );
    }
}
