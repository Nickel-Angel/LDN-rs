//! 带位置游标的内存读写流，对应 Python 版 `ldn/streams.py`。
//!
//! 只移植了编解码实际用到的方法。后续移植 LDN 层（广播帧、认证帧）需要 `u128`、
//! UTF-16 字符串等类型时再补，不预先铺满。

use crate::error::{Error, Result};

/// 多字节整数的字节序。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    /// 小端，802.11 头和 Radiotap 使用。
    Little,
    /// 大端，SNAP/以太网头和 RSN 套件编号使用。
    Big,
}

/// 只读输入流。任何越界读取或定位都返回 [`Error::UnexpectedEof`]，不会 panic。
///
/// 读出的切片借用自原始缓冲区，不做拷贝。
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    endian: Endian,
}

impl<'a> Reader<'a> {
    /// 以给定字节序从 `data` 开头开始读取。
    pub fn new(data: &'a [u8], endian: Endian) -> Self {
        Self {
            data,
            pos: 0,
            endian,
        }
    }

    /// 当前位置（相对缓冲区起点的字节偏移）。
    pub fn tell(&self) -> usize {
        self.pos
    }

    /// 当前位置到末尾还剩多少字节。
    pub fn available(&self) -> usize {
        self.data.len() - self.pos
    }

    /// 是否已读到末尾。
    pub fn is_eof(&self) -> bool {
        self.pos == self.data.len()
    }

    /// 定位到绝对偏移 `pos`；允许恰好定位到末尾，超过末尾则报错且位置不变。
    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        self.pos = pos;
        Ok(())
    }

    /// 向前跳过 `n` 字节。
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.seek(self.pos.checked_add(n).ok_or(Error::UnexpectedEof)?)
    }

    /// 前进到 `n` 的整数倍位置（Radiotap 字段对齐用）。`n` 必须大于 0。
    pub fn align(&mut self, n: usize) -> Result<()> {
        self.skip((n - self.pos % n) % n)
    }

    /// 查看接下来的 `n` 字节但不移动位置。
    pub fn peek(&self, n: usize) -> Result<&'a [u8]> {
        if self.available() < n {
            return Err(Error::UnexpectedEof);
        }
        Ok(&self.data[self.pos..self.pos + n])
    }

    /// 读取 `n` 字节并前进。
    pub fn read(&mut self, n: usize) -> Result<&'a [u8]> {
        let bytes = self.peek(n)?;
        self.pos += n;
        Ok(bytes)
    }

    /// 读取定长数组，例如 6 字节 MAC 地址。
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0; N];
        out.copy_from_slice(self.read(N)?);
        Ok(out)
    }

    /// 读取剩余全部字节；已到末尾时返回空切片。
    pub fn rest(&mut self) -> &'a [u8] {
        let bytes = &self.data[self.pos..];
        self.pos = self.data.len();
        bytes
    }

    /// 读取 `n` 个填充字节，任何一个不为 0 都返回 [`Error::InvalidPadding`]。
    pub fn pad(&mut self, n: usize) -> Result<()> {
        if self.read(n)?.iter().any(|&b| b != 0) {
            return Err(Error::InvalidPadding);
        }
        Ok(())
    }

    /// 读取 1 字节无符号整数。
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.read(1)?[0])
    }

    /// 按流的字节序读取 16 位无符号整数。
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.read_array()?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        })
    }

    /// 按流的字节序读取 24 位无符号整数（SNAP 的 OUI 字段）。
    pub fn u24(&mut self) -> Result<u32> {
        let [a, b, c] = self.read_array()?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes([a, b, c, 0]),
            Endian::Big => u32::from_be_bytes([0, a, b, c]),
        })
    }

    /// 按流的字节序读取 32 位无符号整数。
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.read_array()?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        })
    }

    /// 不论流的字节序，总是按大端读取 32 位整数（RSN 套件编号）。
    pub fn u32_be(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    /// 按流的字节序读取 64 位无符号整数。
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.read_array()?;
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        })
    }
}

/// 可回填的输出流。
///
/// 与普通 `Vec<u8>` 追加的区别是可以 [`seek`](Self::seek) 回前面覆盖写，
/// 用于“先占位、写完正文后再回填长度字段”（Radiotap 头长度）。定位到末尾之后会补 0。
#[derive(Debug, Clone)]
pub struct Writer {
    data: Vec<u8>,
    pos: usize,
    endian: Endian,
}

impl Writer {
    /// 创建使用给定字节序的空输出流。
    pub fn new(endian: Endian) -> Self {
        Self {
            data: Vec::new(),
            pos: 0,
            endian,
        }
    }

    /// 当前写入位置。
    pub fn tell(&self) -> usize {
        self.pos
    }

    /// 定位到绝对偏移 `pos`，越过末尾时用 0 扩展缓冲区。
    pub fn seek(&mut self, pos: usize) {
        if pos > self.data.len() {
            self.data.resize(pos, 0);
        }
        self.pos = pos;
    }

    /// 向前跳过 `n` 字节（越过末尾部分补 0）。
    pub fn skip(&mut self, n: usize) {
        self.seek(self.pos + n);
    }

    /// 前进到 `n` 的整数倍位置。`n` 必须大于 0。
    pub fn align(&mut self, n: usize) {
        self.skip((n - self.pos % n) % n);
    }

    /// 在当前位置写入 `bytes`，覆盖已有内容，必要时扩展缓冲区。
    pub fn write(&mut self, bytes: &[u8]) {
        let end = self.pos + bytes.len();
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
    }

    /// 写入 `n` 个 0 字节。
    pub fn pad(&mut self, n: usize) {
        self.write(&vec![0; n]);
    }

    /// 写入 1 字节无符号整数。
    pub fn u8(&mut self, v: u8) {
        self.write(&[v]);
    }

    /// 按流的字节序写入 16 位无符号整数。
    pub fn u16(&mut self, v: u16) {
        match self.endian {
            Endian::Little => self.write(&v.to_le_bytes()),
            Endian::Big => self.write(&v.to_be_bytes()),
        }
    }

    /// 按流的字节序写入 24 位无符号整数；`v` 超过 24 位时返回
    /// [`Error::FieldOutOfRange`]，`field` 用于标明是哪个字段。
    pub fn u24(&mut self, v: u32, field: &'static str) -> Result<()> {
        if v > 0x00FF_FFFF {
            return Err(Error::FieldOutOfRange { field });
        }
        match self.endian {
            Endian::Little => self.write(&v.to_le_bytes()[..3]),
            Endian::Big => self.write(&v.to_be_bytes()[1..]),
        }
        Ok(())
    }

    /// 按流的字节序写入 32 位无符号整数。
    pub fn u32(&mut self, v: u32) {
        match self.endian {
            Endian::Little => self.write(&v.to_le_bytes()),
            Endian::Big => self.write(&v.to_be_bytes()),
        }
    }

    /// 不论流的字节序，总是按大端写入 32 位整数。
    pub fn u32_be(&mut self, v: u32) {
        self.write(&v.to_be_bytes());
    }

    /// 按流的字节序写入 64 位无符号整数。
    pub fn u64(&mut self, v: u64) {
        match self.endian {
            Endian::Little => self.write(&v.to_le_bytes()),
            Endian::Big => self.write(&v.to_be_bytes()),
        }
    }

    /// 取出已写入的全部字节（包括 seek 越过末尾时补的 0）。
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_reads_both_endians() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(Reader::new(&data, Endian::Little).u16(), Ok(0x0201));
        assert_eq!(Reader::new(&data, Endian::Big).u16(), Ok(0x0102));
        assert_eq!(Reader::new(&data, Endian::Little).u24(), Ok(0x03_0201));
        assert_eq!(Reader::new(&data, Endian::Big).u24(), Ok(0x01_0203));
        assert_eq!(Reader::new(&data, Endian::Little).u32_be(), Ok(0x0102_0304));
    }

    #[test]
    fn reader_overflow_is_error_and_keeps_position() {
        let mut r = Reader::new(&[1, 2, 3], Endian::Little);
        r.u8().unwrap();
        assert_eq!(r.u32(), Err(Error::UnexpectedEof));
        assert_eq!(r.tell(), 1);
        assert_eq!(r.seek(4), Err(Error::UnexpectedEof));
        assert!(r.seek(3).is_ok());
        assert!(r.is_eof());
        assert_eq!(r.rest(), &[] as &[u8]);
    }

    #[test]
    fn reader_skip_does_not_overflow_usize() {
        let mut r = Reader::new(&[0], Endian::Little);
        r.u8().unwrap();
        assert_eq!(r.skip(usize::MAX), Err(Error::UnexpectedEof));
    }

    #[test]
    fn reader_pad_rejects_nonzero() {
        assert_eq!(Reader::new(&[0, 0], Endian::Little).pad(2), Ok(()));
        assert_eq!(
            Reader::new(&[0, 1], Endian::Little).pad(2),
            Err(Error::InvalidPadding)
        );
    }

    #[test]
    fn reader_align() {
        let mut r = Reader::new(&[0; 16], Endian::Little);
        r.skip(3).unwrap();
        r.align(8).unwrap();
        assert_eq!(r.tell(), 8);
        r.align(8).unwrap();
        assert_eq!(r.tell(), 8);
    }

    #[test]
    fn writer_seek_back_overwrites_and_seek_forward_zero_fills() {
        let mut w = Writer::new(Endian::Little);
        w.skip(2);
        w.u8(0xAA);
        w.seek(0);
        w.u16(0x1234);
        w.seek(5);
        assert_eq!(w.into_vec(), vec![0x34, 0x12, 0xAA, 0, 0]);
    }

    #[test]
    fn writer_u24_range_check() {
        let mut w = Writer::new(Endian::Big);
        assert!(w.u24(0x00AB_CDEF, "oui").is_ok());
        assert_eq!(
            w.u24(0x0100_0000, "oui"),
            Err(Error::FieldOutOfRange { field: "oui" })
        );
        assert_eq!(w.into_vec(), vec![0xAB, 0xCD, 0xEF]);
    }
}
