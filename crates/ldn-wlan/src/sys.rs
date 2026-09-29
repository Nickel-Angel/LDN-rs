//! 本项目用到的全部 Linux 系统调用，也是整个 workspace 里唯一允许 `unsafe` 的地方。
//!
//! 每个函数只做一次薄封装：把参数装进内核结构体、调用 libc、把 `-1` 转成
//! `io::Error`。所有 fd 都以 `O_NONBLOCK | O_CLOEXEC` 创建，交给 tokio 的 `AsyncFd` 驱动。

#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const SOL_NETLINK: libc::c_int = 270;
const NETLINK_ADD_MEMBERSHIP: libc::c_int = 1;
const NETLINK_CAP_ACK: libc::c_int = 10;
const NETLINK_EXT_ACK: libc::c_int = 11;
const ETH_P_ALL: u16 = 3;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x4004_54CA;

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn check_size(ret: libc::ssize_t) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

fn new_socket(domain: libc::c_int, protocol: libc::c_int) -> io::Result<OwnedFd> {
    let kind = libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
    // SAFETY: socket() 不读写用户内存；成功时返回的 fd 由 OwnedFd 独占。
    let fd = check(unsafe { libc::socket(domain, kind, protocol) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn set_int_option(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: 传入指向栈上 c_int 的指针和它的长度，内核只读取这 4 字节。
    check(unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as u32,
        )
    })?;
    Ok(())
}

/// 创建并绑定一个 netlink socket，返回 fd 和内核分配的端口号（`nl_pid`）。
///
/// 同时打开 `NETLINK_CAP_ACK`（错误消息只回显请求头）和 `NETLINK_EXT_ACK`
/// （错误消息附带文字说明），与 python-netlink 一致。
pub fn netlink_socket(protocol: libc::c_int) -> io::Result<(OwnedFd, u32)> {
    let fd = new_socket(libc::AF_NETLINK, protocol)?;
    set_int_option(fd.as_raw_fd(), SOL_NETLINK, NETLINK_CAP_ACK, 1)?;
    set_int_option(fd.as_raw_fd(), SOL_NETLINK, NETLINK_EXT_ACK, 1)?;

    // SAFETY: sockaddr_nl 是纯数据结构，全零是合法值（pid 0 = 让内核分配）。
    let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    // SAFETY: addr 在调用期间有效，len 与其类型一致。
    check(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_nl).cast(),
            len,
        )
    })?;

    let mut out_len = len;
    // SAFETY: 内核最多写入 out_len 字节到 addr。
    check(unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut addr as *mut libc::sockaddr_nl).cast(),
            &mut out_len,
        )
    })?;
    Ok((fd, addr.nl_pid))
}

/// 加入 netlink 组播组（例如 nl80211 的 `mlme`）。
pub fn add_membership(fd: RawFd, group: u32) -> io::Result<()> {
    let group =
        libc::c_int::try_from(group).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    set_int_option(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group)
}

/// 创建绑定到 `ifindex` 的 AF_PACKET 原始 socket，收发该接口上的全部帧
/// （monitor 口上即带 Radiotap 头的 802.11 帧）。需要 `CAP_NET_RAW`。
pub fn packet_socket(ifindex: u32) -> io::Result<OwnedFd> {
    let protocol = ETH_P_ALL.to_be();
    let fd = new_socket(libc::AF_PACKET, libc::c_int::from(protocol))?;
    // SAFETY: sockaddr_ll 是纯数据结构，全零后填写必要字段。
    let mut addr: libc::sockaddr_ll = unsafe { zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = protocol;
    addr.sll_ifindex =
        libc::c_int::try_from(ifindex).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let len = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    // SAFETY: addr 在调用期间有效，len 与其类型一致。
    check(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_ll).cast(),
            len,
        )
    })?;
    Ok(fd)
}

/// 打开 `/dev/net/tun` 并创建名为 `name` 的 TAP 接口（无包信息头）。需要 `CAP_NET_ADMIN`。
pub fn open_tap(name: &str) -> io::Result<OwnedFd> {
    // SAFETY: ifreq 是纯数据结构（含 union），全零合法。
    let mut req: libc::ifreq = unsafe { zeroed() };
    if name.len() >= req.ifr_name.len() || name.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    for (dst, &src) in req.ifr_name.iter_mut().zip(name.as_bytes()) {
        *dst = src as libc::c_char;
    }
    req.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;

    let path = c"/dev/net/tun";
    // SAFETY: path 是以 NUL 结尾的静态字符串。
    let fd = check(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    })?;
    // SAFETY: 成功返回的 fd 由 OwnedFd 独占。
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: TUNSETIFF 读写一个 ifreq，req 在调用期间有效。
    check(unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut req as *mut libc::ifreq) })?;
    Ok(fd)
}

/// 接口名 -> ifindex。
pub fn if_nametoindex(name: &str) -> io::Result<u32> {
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: name 是以 NUL 结尾的有效字符串。
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        index => Ok(index),
    }
}

/// 在非阻塞 fd 上读一次；没有数据时返回 `WouldBlock`。
pub fn read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: 内核最多写入 buf.len() 字节到 buf。
    check_size(unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) })
}

/// 在非阻塞 fd 上写一次；缓冲区满时返回 `WouldBlock`。
pub fn write(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: 内核只读取 buf 的 buf.len() 字节。
    check_size(unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netlink_socket_gets_port_id() {
        // 创建 NETLINK_ROUTE socket 不需要特权。
        let (_fd, pid) = netlink_socket(libc::NETLINK_ROUTE).unwrap();
        assert_ne!(pid, 0);
    }

    #[test]
    fn loopback_index_and_bad_names() {
        assert_eq!(if_nametoindex("lo").unwrap(), 1);
        assert!(if_nametoindex("no-such-iface0").is_err());
        assert!(if_nametoindex("a\0b").is_err());
        assert_eq!(
            open_tap("this-name-is-too-long").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
