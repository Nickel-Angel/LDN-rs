//! netlink 属性（NLA）：`u16 长度 | u16 类型 | 值 | 补齐到 4 字节`。

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// 属性类型里的“嵌套”标志位。
pub const NLA_F_NESTED: u16 = 1 << 15;
/// 属性类型里的“网络字节序”标志位。
pub const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
/// 去掉两个标志位后的类型掩码。
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

const HEADER_LEN: usize = 4;
const MAX_VALUE_LEN: usize = u16::MAX as usize - HEADER_LEN;

/// 按 4 字节对齐向上取整。
pub(crate) const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// 属性列表构造器，按调用顺序输出。
///
/// 写入方法返回 `&mut Self` 便于链式调用和条件追加。值过长的错误不在写入时返回，
/// 而是记下来在 [`finish`](Self::finish) 时统一报告，这样请求构造函数本身不必返回 `Result`。
///
/// 嵌套属性不置 [`NLA_F_NESTED`] 位，与 python-netlink 一致；内核对这些老属性不做严格检查。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attrs {
    buf: Vec<u8>,
    error: Option<Error>,
}

impl Attrs {
    /// 空属性列表。
    pub fn new() -> Self {
        Self::default()
    }

    /// 追加一个原始值属性。
    pub fn bytes(&mut self, kind: u16, value: &[u8]) -> &mut Self {
        if value.len() > MAX_VALUE_LEN {
            self.error.get_or_insert(Error::AttributeTooLong {
                kind,
                len: value.len(),
            });
            return self;
        }
        self.buf
            .extend_from_slice(&((value.len() + HEADER_LEN) as u16).to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(value);
        self.buf.resize(align4(self.buf.len()), 0);
        self
    }

    /// 追加 u8 属性。
    pub fn u8(&mut self, kind: u16, value: u8) -> &mut Self {
        self.bytes(kind, &[value])
    }

    /// 追加 u16 属性。
    pub fn u16(&mut self, kind: u16, value: u16) -> &mut Self {
        self.bytes(kind, &value.to_ne_bytes())
    }

    /// 追加 u32 属性。
    pub fn u32(&mut self, kind: u16, value: u32) -> &mut Self {
        self.bytes(kind, &value.to_ne_bytes())
    }

    /// 追加以 NUL 结尾的字符串属性。
    pub fn string(&mut self, kind: u16, value: &str) -> &mut Self {
        let mut data = Vec::with_capacity(value.len() + 1);
        data.extend_from_slice(value.as_bytes());
        data.push(0);
        self.bytes(kind, &data)
    }

    /// 追加空值的标志属性（出现即为真）。
    pub fn flag(&mut self, kind: u16) -> &mut Self {
        self.bytes(kind, &[])
    }

    /// 追加嵌套属性；内层的错误会传递到外层。
    pub fn nested(&mut self, kind: u16, inner: Attrs) -> &mut Self {
        match inner.finish() {
            Ok(data) => self.bytes(kind, &data),
            Err(e) => {
                self.error.get_or_insert(e);
                self
            }
        }
    }

    /// 取出编码结果；若之前有属性值过长，返回第一个错误。
    pub fn finish(self) -> Result<Vec<u8>> {
        match self.error {
            Some(e) => Err(e),
            None => Ok(self.buf),
        }
    }
}

/// 解析出的属性表：类型（已去掉标志位）-> 值。
///
/// 同一类型出现多次时只保留最后一个，与 python-netlink 一致；需要保留全部
/// 顺序的场合（例如数组）用 [`parse_list`]。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttrMap<'a>(BTreeMap<u16, &'a [u8]>);

/// 按出现顺序解析属性列表。长度字段越界时返回 [`Error::Truncated`]。
pub fn parse_list(data: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let header = data.get(pos..pos + HEADER_LEN).ok_or(Error::Truncated)?;
        let len = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        let kind = u16::from_ne_bytes([header[2], header[3]]) & NLA_TYPE_MASK;
        if len < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let value = data
            .get(pos + HEADER_LEN..pos + len)
            .ok_or(Error::Truncated)?;
        out.push((kind, value));
        // 最后一个属性后面的填充可能被省略，所以只要不越界就接受。
        pos += align4(len);
    }
    Ok(out)
}

impl<'a> AttrMap<'a> {
    /// 解析属性列表。
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        Ok(Self(parse_list(data)?.into_iter().collect()))
    }

    /// 原始值；不存在时返回 `None`。
    pub fn get(&self, kind: u16) -> Option<&'a [u8]> {
        self.0.get(&kind).copied()
    }

    /// 属性是否存在（标志属性用它判断真假）。
    pub fn contains(&self, kind: u16) -> bool {
        self.0.contains_key(&kind)
    }

    /// 必需的原始值。
    pub fn require(&self, kind: u16) -> Result<&'a [u8]> {
        self.get(kind).ok_or(Error::MissingAttribute(kind))
    }

    fn fixed<const N: usize>(&self, kind: u16) -> Result<[u8; N]> {
        self.require(kind)?
            .try_into()
            .map_err(|_| Error::InvalidAttribute(kind))
    }

    /// 必需的 u8 属性。
    pub fn u8(&self, kind: u16) -> Result<u8> {
        Ok(self.fixed::<1>(kind)?[0])
    }

    /// 必需的 u16 属性。
    pub fn u16(&self, kind: u16) -> Result<u16> {
        self.fixed(kind).map(u16::from_ne_bytes)
    }

    /// 必需的 u32 属性。
    pub fn u32(&self, kind: u16) -> Result<u32> {
        self.fixed(kind).map(u32::from_ne_bytes)
    }

    /// 可选的 u32 属性：不存在返回 `None`，存在但长度不对仍然报错。
    pub fn opt_u32(&self, kind: u16) -> Result<Option<u32>> {
        if self.contains(kind) {
            self.u32(kind).map(Some)
        } else {
            Ok(None)
        }
    }

    /// 必需的字符串属性，去掉末尾的 NUL；不是合法 UTF-8 时报 [`Error::InvalidAttribute`]。
    pub fn string(&self, kind: u16) -> Result<String> {
        let raw = self.require(kind)?;
        let end = raw.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        String::from_utf8(raw[..end].to_vec()).map_err(|_| Error::InvalidAttribute(kind))
    }

    /// 必需的嵌套属性。
    pub fn nested(&self, kind: u16) -> Result<AttrMap<'a>> {
        AttrMap::parse(self.require(kind)?)
    }

    /// 嵌套数组（外层每个元素的类型是下标，值是一组嵌套属性），按出现顺序返回。
    /// 属性不存在时返回空数组。
    pub fn nested_array(&self, kind: u16) -> Result<Vec<AttrMap<'a>>> {
        let Some(raw) = self.get(kind) else {
            return Ok(Vec::new());
        };
        parse_list(raw)?
            .into_iter()
            .map(|(_, value)| AttrMap::parse(value))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_pads_to_four_bytes() {
        let mut a = Attrs::new();
        a.u8(2, 0).flag(5).string(4, "ab");
        assert_eq!(
            a.finish().unwrap(),
            [
                5, 0, 2, 0, 0, 0, 0, 0, 4, 0, 5, 0, 7, 0, 4, 0, b'a', b'b', 0, 0
            ]
        );
    }

    #[test]
    fn nested_roundtrip_and_typed_getters() {
        let mut inner = Attrs::new();
        inner.u32(1, 0xDEAD_BEEF).string(2, "mlme");
        let mut outer = Attrs::new();
        outer.u16(3, 7).nested(9, inner);
        let data = outer.finish().unwrap();

        let map = AttrMap::parse(&data).unwrap();
        assert_eq!(map.u16(3), Ok(7));
        let nested = map.nested(9).unwrap();
        assert_eq!(nested.u32(1), Ok(0xDEAD_BEEF));
        assert_eq!(nested.string(2).as_deref(), Ok("mlme"));
        assert_eq!(map.u32(3), Err(Error::InvalidAttribute(3)));
        assert_eq!(map.u8(42), Err(Error::MissingAttribute(42)));
        assert_eq!(map.opt_u32(42), Ok(None));
    }

    #[test]
    fn flags_in_type_are_masked() {
        let data = [4, 0, 0x05, 0x80]; // 类型 5 带 NLA_F_NESTED
        assert!(AttrMap::parse(&data).unwrap().contains(5));
    }

    #[test]
    fn too_long_value_is_reported_at_finish() {
        let mut a = Attrs::new();
        a.bytes(51, &vec![0; 70_000]).u32(3, 1);
        assert_eq!(
            a.finish(),
            Err(Error::AttributeTooLong {
                kind: 51,
                len: 70_000
            })
        );

        let mut inner = Attrs::new();
        inner.bytes(1, &vec![0; 70_000]);
        let mut outer = Attrs::new();
        outer.nested(80, inner);
        assert!(outer.finish().is_err());
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert_eq!(parse_list(&[8, 0, 1, 0, 0]), Err(Error::Truncated));
        assert_eq!(parse_list(&[2, 0, 1, 0]), Err(Error::Truncated));
        assert_eq!(parse_list(&[4, 0]), Err(Error::Truncated));
        // 最后一个属性省略尾部填充是合法的。
        assert_eq!(parse_list(&[5, 0, 1, 0, 9]).unwrap(), vec![(1, &[9u8][..])]);
    }

    #[test]
    fn nested_array_keeps_order() {
        let mut g0 = Attrs::new();
        g0.u32(2, 5);
        let mut g1 = Attrs::new();
        g1.u32(2, 7);
        let mut arr = Attrs::new();
        arr.nested(1, g0).nested(2, g1);
        let mut outer = Attrs::new();
        outer.nested(7, arr);
        let data = outer.finish().unwrap();
        let groups = AttrMap::parse(&data).unwrap().nested_array(7).unwrap();
        let ids: Vec<u32> = groups.iter().map(|g| g.u32(2).unwrap()).collect();
        assert_eq!(ids, [5, 7]);
    }
}
