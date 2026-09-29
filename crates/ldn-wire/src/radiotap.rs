//! Radiotap 头：monitor 接口收发裸 802.11 帧时包在最外层的元数据头。

use crate::error::{Error, Result};
use crate::stream::{Endian, Reader, Writer};

const PRESENT_TSFT: u32 = 1 << 0;
const PRESENT_FLAGS: u32 = 1 << 1;
const PRESENT_RATE: u32 = 1 << 2;
const PRESENT_CHANNEL: u32 = 1 << 3;
/// present 位图的第 31 位表示后面还跟着一个 32 位扩展位图。
const PRESENT_EXT: u32 = 1 << 31;

/// Radiotap Channel 字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RadiotapChannel {
    /// 中心频率（MHz）。
    pub frequency: u16,
    /// 信道标志位（2GHz/5GHz、OFDM/CCK 等）。
    pub flags: u16,
}

/// Radiotap 头及其承载的 802.11 帧。
///
/// 只认识前 4 个标准字段（TSFT、Flags、Rate、Channel），驱动附带的其他字段
/// 会按头长度整体跳过。扫描需要 Channel 字段里的频率来判断广播帧所在信道。
///
/// 与 Python 版的差异：Python 版把频率和信道标志拆成两个可选字段，只设频率
/// 不设标志时会置 present 位却不写字段，产生畸形头；这里合并为一个
/// [`RadiotapChannel`]，从类型上排除这种状态。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RadiotapFrame {
    /// Radiotap 头之后的 802.11 帧（MAC 头起）。
    pub data: Vec<u8>,
    /// TSFT：接收时刻的微秒计时器。
    pub mactime: Option<u64>,
    /// Flags 字段。
    pub flags: Option<u8>,
    /// Rate 字段，单位 500kbps。
    pub rate: Option<u8>,
    /// Channel 字段。
    pub channel: Option<RadiotapChannel>,
}

impl RadiotapFrame {
    /// 只包一个 802.11 帧、不带任何可选字段，用于发送（由驱动自行决定速率）。
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            ..Self::default()
        }
    }

    /// 编码：Radiotap 头按 8 字节对齐后再拼接 [`data`](Self::data)。
    pub fn encode(&self) -> Vec<u8> {
        let mut present = 0;
        if self.mactime.is_some() {
            present |= PRESENT_TSFT;
        }
        if self.flags.is_some() {
            present |= PRESENT_FLAGS;
        }
        if self.rate.is_some() {
            present |= PRESENT_RATE;
        }
        if self.channel.is_some() {
            present |= PRESENT_CHANNEL;
        }

        let mut w = Writer::new(Endian::Little);
        w.u8(0); // version
        w.pad(1);
        w.skip(2); // 头长度，写完字段后回填
        w.u32(present);
        if let Some(t) = self.mactime {
            w.align(8);
            w.u64(t);
        }
        if let Some(f) = self.flags {
            w.u8(f);
        }
        if let Some(r) = self.rate {
            w.u8(r);
        }
        if let Some(c) = self.channel {
            w.align(2);
            w.u16(c.frequency);
            w.u16(c.flags);
        }
        w.align(8);

        let header_len = w.tell();
        w.write(&self.data);
        w.seek(2);
        // 头最多 8+8+1+1+4 再对齐到 24 字节，不可能超过 u16。
        w.u16(header_len as u16);
        w.into_vec()
    }

    /// 解码 Radiotap 头并取出其后的 802.11 帧。
    ///
    /// 版本号不为 0、已知字段越过头长度、头长度越过缓冲区时返回错误。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data, Endian::Little);
        if r.u8()? != 0 {
            return Err(Error::InvalidRadiotap("version must be 0"));
        }
        r.pad(1)?;
        let header_len = usize::from(r.u16()?);

        // 只关心第一个位图；扩展位图只需读过去。
        let present = r.u32()?;
        let mut word = present;
        while word & PRESENT_EXT != 0 {
            word = r.u32()?;
        }

        let mut frame = Self::default();
        if present & PRESENT_TSFT != 0 {
            r.align(8)?;
            frame.mactime = Some(r.u64()?);
        }
        if present & PRESENT_FLAGS != 0 {
            frame.flags = Some(r.u8()?);
        }
        if present & PRESENT_RATE != 0 {
            frame.rate = Some(r.u8()?);
        }
        if present & PRESENT_CHANNEL != 0 {
            r.align(2)?;
            frame.channel = Some(RadiotapChannel {
                frequency: r.u16()?,
                flags: r.u16()?,
            });
        }

        if r.tell() > header_len {
            return Err(Error::InvalidRadiotap("length field is too small"));
        }
        r.seek(header_len)?;
        frame.data = r.rest().to_vec();
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_frame_has_8_byte_header() {
        let encoded = RadiotapFrame::new(vec![0xAB]).encode();
        assert_eq!(encoded, [0, 0, 8, 0, 0, 0, 0, 0, 0xAB]);
        assert_eq!(
            RadiotapFrame::decode(&encoded).unwrap(),
            RadiotapFrame::new(vec![0xAB])
        );
    }

    #[test]
    fn extended_present_bitmap_and_unknown_fields_are_skipped() {
        // present = CHANNEL | EXT，后跟一个扩展位图，再跟频道字段和 4 字节未知字段。
        let data = [
            0, 0, 20, 0, // version, pad, len=20
            0x08, 0, 0, 0x80, // present word 0
            0, 0, 0, 0, // present word 1
            0x85, 0x09, 0xA0, 0x00, // channel: 2437, 0x00a0
            0xEE, 0xEE, 0xEE, 0xEE, // unknown field
            0x42, // payload
        ];
        let frame = RadiotapFrame::decode(&data).unwrap();
        assert_eq!(
            frame.channel,
            Some(RadiotapChannel {
                frequency: 2437,
                flags: 0xA0
            })
        );
        assert_eq!(frame.data, [0x42]);
    }

    #[test]
    fn rejects_bad_version_and_lengths() {
        assert_eq!(
            RadiotapFrame::decode(&[1, 0, 8, 0, 0, 0, 0, 0]),
            Err(Error::InvalidRadiotap("version must be 0"))
        );
        // 声明了 Flags 字段但头长度只有 8。
        assert_eq!(
            RadiotapFrame::decode(&[0, 0, 8, 0, 2, 0, 0, 0, 0]),
            Err(Error::InvalidRadiotap("length field is too small"))
        );
        // 头长度超过缓冲区。
        assert_eq!(
            RadiotapFrame::decode(&[0, 0, 64, 0, 0, 0, 0, 0]),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(RadiotapFrame::decode(&[0, 0]), Err(Error::UnexpectedEof));
    }
}
