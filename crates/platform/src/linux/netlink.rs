//! A small client for the kernel's routing interface, rtnetlink: one request
//! at a time, each on a socket of its own, and the replies to it.
//!
//! Security rule: a reply is believed only when it comes from the kernel
//! itself (sender port 0) and answers this request (its sequence number).
//! Ordinary programs cannot send to another program's socket of this kind,
//! but the check costs nothing and does not depend on that.

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::sockopt::{self, Timeout};
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, recvfrom, sendto, socket_with,
};

/// The numbers of the kernel's interface used here, spelled out so that
/// their types fit the messages. A test checks them against the C library.
pub(super) mod consts {
    pub(crate) const NLMSG_ERROR: u16 = 2;
    pub(crate) const NLMSG_DONE: u16 = 3;
    pub(crate) const NLM_F_REQUEST: u16 = 0x1;
    pub(crate) const NLM_F_ACK: u16 = 0x4;
    pub(crate) const NLM_F_DUMP: u16 = 0x300;
    pub(crate) const NLM_F_EXCL: u16 = 0x200;
    pub(crate) const NLM_F_CREATE: u16 = 0x400;

    pub(crate) const RTM_NEWLINK: u16 = 16;
    pub(crate) const RTM_GETLINK: u16 = 18;
    pub(crate) const RTM_SETLINK: u16 = 19;
    pub(crate) const RTM_NEWADDR: u16 = 20;
    pub(crate) const RTM_DELADDR: u16 = 21;
    pub(crate) const RTM_GETADDR: u16 = 22;
    pub(crate) const RTM_NEWROUTE: u16 = 24;
    pub(crate) const RTM_DELROUTE: u16 = 25;
    pub(crate) const RTM_GETROUTE: u16 = 26;

    pub(crate) const RTA_DST: u16 = 1;
    pub(crate) const RTA_OIF: u16 = 4;
    pub(crate) const RTA_GATEWAY: u16 = 5;
    pub(crate) const RTA_PRIORITY: u16 = 6;
    pub(crate) const RTA_MULTIPATH: u16 = 9;
    pub(crate) const RTA_TABLE: u16 = 15;

    pub(crate) const IFLA_IFNAME: u16 = 3;
    pub(crate) const IFLA_MTU: u16 = 4;
    pub(crate) const IFLA_LINKINFO: u16 = 18;
    pub(crate) const IFLA_INFO_KIND: u16 = 1;

    pub(crate) const IFA_ADDRESS: u16 = 1;
    pub(crate) const IFA_LOCAL: u16 = 2;

    pub(crate) const AF_UNSPEC: u8 = 0;
    pub(crate) const AF_INET: u8 = 2;
    pub(crate) const RT_TABLE_MAIN: u8 = 254;
    pub(crate) const RTN_UNICAST: u8 = 1;
    pub(crate) const RT_SCOPE_UNIVERSE: u8 = 0;
    pub(crate) const RT_SCOPE_LINK: u8 = 253;
    /// In a removal: a route of any scope.
    pub(crate) const RT_SCOPE_NOWHERE: u8 = 255;
    pub(crate) const IFF_UP: u32 = 0x1;
}

use consts::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR};

/// How long to wait for the kernel, which answers at once: only something
/// broken takes this long, and it is reported rather than waited on.
const WAIT: Duration = Duration::from_secs(5);
/// Each request has a socket of its own, so one number is enough.
const SEQ: u32 = 1;
const HEADER: usize = 16;
/// Room for the largest message the kernel sends in one piece.
const BUFFER: usize = 64 * 1024;

fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// A request's body: a fixed header, then attributes.
pub(super) struct Body(Vec<u8>);

impl Body {
    pub(super) fn new(header: &[u8]) -> Self {
        let mut bytes = header.to_vec();
        bytes.resize(align(bytes.len()), 0);
        Self(bytes)
    }

    pub(super) fn attr(mut self, kind: u16, value: &[u8]) -> Self {
        let len = u16::try_from(4 + value.len()).expect("a short attribute");
        self.0.extend_from_slice(&len.to_ne_bytes());
        self.0.extend_from_slice(&kind.to_ne_bytes());
        self.0.extend_from_slice(value);
        self.0.resize(align(self.0.len()), 0);
        self
    }

    pub(super) fn u32(self, kind: u16, value: u32) -> Self {
        self.attr(kind, &value.to_ne_bytes())
    }

    /// An address, in network order as the kernel keeps it.
    pub(super) fn ipv4(self, kind: u16, value: Ipv4Addr) -> Self {
        self.attr(kind, &value.octets())
    }
}

/// One message from the kernel: its type and what follows its header.
pub(super) struct Message {
    pub(super) kind: u16,
    pub(super) body: Vec<u8>,
}

/// Sends one request and gathers the replies. `flags` adds to "request":
/// [`NLM_F_DUMP`] for a listing, which ends when the kernel says it is done;
/// anything else asks for the kernel's acknowledgement, which ends it and
/// carries the error, if there was one.
pub(super) fn request(kind: u16, flags: u16, body: &Body) -> io::Result<Vec<Message>> {
    let socket = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None,
    )?;
    sockopt::set_socket_timeout(&socket, Timeout::Recv, Some(WAIT))?;
    let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
    let flags = NLM_F_REQUEST | flags | if dump { 0 } else { NLM_F_ACK };
    let len = u32::try_from(HEADER + body.0.len()).expect("a short request");
    let mut message = Vec::with_capacity(HEADER + body.0.len());
    message.extend_from_slice(&len.to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&SEQ.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(&body.0);
    let kernel = SocketAddrNetlink::new(0, 0);
    sendto(&socket, &message, SendFlags::empty(), &kernel)?;

    let mut replies = Vec::new();
    let mut buffer = vec![0u8; BUFFER];
    loop {
        let (got, whole, from) = match recvfrom(&socket, &mut buffer[..], RecvFlags::TRUNC) {
            Err(rustix::io::Errno::INTR) => continue,
            received => received?,
        };
        if whole > got {
            return Err(broken("a reply did not fit"));
        }
        let from = from.and_then(|from| SocketAddrNetlink::try_from(from).ok());
        if from.map(|from| from.pid()) != Some(0) {
            continue;
        }
        let mut rest = &buffer[..got];
        while rest.len() >= HEADER {
            let field = |at: usize| [rest[at], rest[at + 1], rest[at + 2], rest[at + 3]];
            let len = u32::from_ne_bytes(field(0)) as usize;
            if len < HEADER || len > rest.len() {
                return Err(broken("a reply's length is wrong"));
            }
            let kind = u16::from_ne_bytes([rest[4], rest[5]]);
            let seq = u32::from_ne_bytes(field(8));
            let body = &rest[HEADER..len];
            rest = &rest[align(len).min(rest.len())..];
            if seq != SEQ {
                continue;
            }
            match kind {
                NLMSG_ERROR | NLMSG_DONE => {
                    let code = body
                        .get(..4)
                        .map(|code| i32::from_ne_bytes(code.try_into().expect("four bytes")));
                    match code {
                        Some(code) if code < 0 => {
                            return Err(io::Error::from_raw_os_error(-code));
                        }
                        None if kind == NLMSG_ERROR => {
                            return Err(broken("an error without its code"));
                        }
                        // An acknowledgement, or the end of a listing.
                        _ if kind == NLMSG_DONE || !dump => return Ok(replies),
                        _ => {}
                    }
                }
                _ => replies.push(Message {
                    kind,
                    body: body.to_vec(),
                }),
            }
        }
    }
}

fn broken(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("netlink: {what}"))
}

/// The attributes after a message's fixed header, as type and value. Flag
/// bits in the type are dropped. A malformed one ends the list.
pub(super) fn attrs(data: &[u8]) -> Vec<(u16, &[u8])> {
    let mut found = Vec::new();
    let mut rest = data;
    while rest.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        let kind = u16::from_ne_bytes([rest[2], rest[3]]) & 0x3fff;
        if len < 4 || len > rest.len() {
            break;
        }
        found.push((kind, &rest[4..len]));
        rest = &rest[align(len).min(rest.len())..];
    }
    found
}

/// An attribute's value as an address, when it is one.
pub(super) fn as_ipv4(value: &[u8]) -> Option<Ipv4Addr> {
    let octets: [u8; 4] = value.try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

/// An attribute's value as a number, when it is one.
pub(super) fn as_u32(value: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(value.try_into().ok()?))
}

/// An attribute's value as text, without the ending NUL.
pub(super) fn as_text(value: &[u8]) -> Option<&str> {
    let value = value.strip_suffix(&[0]).unwrap_or(value);
    std::str::from_utf8(value).ok()
}

#[cfg(test)]
mod tests {
    use super::consts::*;
    use super::*;

    // The numbers spelled out here are the C library's.
    #[test]
    fn the_numbers_are_the_kernels() {
        assert_eq!(NLMSG_ERROR, libc::NLMSG_ERROR as u16);
        assert_eq!(NLMSG_DONE, libc::NLMSG_DONE as u16);
        assert_eq!(NLM_F_REQUEST, libc::NLM_F_REQUEST as u16);
        assert_eq!(NLM_F_ACK, libc::NLM_F_ACK as u16);
        assert_eq!(NLM_F_DUMP, libc::NLM_F_DUMP as u16);
        assert_eq!(NLM_F_EXCL, libc::NLM_F_EXCL as u16);
        assert_eq!(NLM_F_CREATE, libc::NLM_F_CREATE as u16);
        let messages = [
            (RTM_NEWLINK, libc::RTM_NEWLINK),
            (RTM_GETLINK, libc::RTM_GETLINK),
            (RTM_SETLINK, libc::RTM_SETLINK),
            (RTM_NEWADDR, libc::RTM_NEWADDR),
            (RTM_DELADDR, libc::RTM_DELADDR),
            (RTM_GETADDR, libc::RTM_GETADDR),
            (RTM_NEWROUTE, libc::RTM_NEWROUTE),
            (RTM_DELROUTE, libc::RTM_DELROUTE),
            (RTM_GETROUTE, libc::RTM_GETROUTE),
        ];
        for (ours, theirs) in messages {
            assert_eq!(ours, theirs);
        }
        let attributes = [
            (RTA_DST, libc::RTA_DST),
            (RTA_OIF, libc::RTA_OIF),
            (RTA_GATEWAY, libc::RTA_GATEWAY),
            (RTA_PRIORITY, libc::RTA_PRIORITY),
            (RTA_MULTIPATH, libc::RTA_MULTIPATH),
            (RTA_TABLE, libc::RTA_TABLE),
            (IFLA_IFNAME, libc::IFLA_IFNAME),
            (IFLA_MTU, libc::IFLA_MTU),
            (IFLA_LINKINFO, libc::IFLA_LINKINFO),
            (IFLA_INFO_KIND, libc::IFLA_INFO_KIND),
            (IFA_ADDRESS, libc::IFA_ADDRESS),
            (IFA_LOCAL, libc::IFA_LOCAL),
        ];
        for (ours, theirs) in attributes {
            assert_eq!(ours, theirs);
        }
        assert_eq!(AF_UNSPEC, libc::AF_UNSPEC as u8);
        assert_eq!(AF_INET, libc::AF_INET as u8);
        assert_eq!(RT_TABLE_MAIN, libc::RT_TABLE_MAIN);
        assert_eq!(RTN_UNICAST, libc::RTN_UNICAST);
        assert_eq!(RT_SCOPE_UNIVERSE, libc::RT_SCOPE_UNIVERSE);
        assert_eq!(RT_SCOPE_LINK, libc::RT_SCOPE_LINK);
        assert_eq!(RT_SCOPE_NOWHERE, libc::RT_SCOPE_NOWHERE);
        assert_eq!(IFF_UP, libc::IFF_UP as u32);
    }

    // Attributes are padded to four bytes and read back as written; a
    // truncated one ends the list instead of being read past.
    #[test]
    fn attributes_round_trip_and_stop_at_a_bad_length() {
        let body = Body::new(&[1, 2, 3])
            .ipv4(RTA_DST, Ipv4Addr::new(192, 0, 2, 0))
            .attr(IFLA_IFNAME, b"tun0\0")
            .u32(RTA_OIF, 7);
        assert_eq!(body.0.len(), 4 + 8 + 12 + 8);
        let found = attrs(&body.0[4..]);
        assert_eq!(found.len(), 3);
        assert_eq!(as_ipv4(found[0].1), Some(Ipv4Addr::new(192, 0, 2, 0)));
        assert_eq!(as_text(found[1].1), Some("tun0"));
        assert_eq!(as_u32(found[2].1), Some(7));
        let mut cut = body.0[4..].to_vec();
        // The second attribute's length, made longer than what is left.
        cut[8..10].copy_from_slice(&200u16.to_ne_bytes());
        assert_eq!(attrs(&cut).len(), 1, "read past the end");
    }

    // The kernel answers, and says when something is not there.
    #[test]
    fn the_kernel_answers_and_reports_errors() {
        let lo = Body::new(&[0; 16]).attr(IFLA_IFNAME, b"lo\0");
        let replies = request(RTM_GETLINK, 0, &lo).expect("ask about lo");
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].kind, RTM_NEWLINK);
        let none = Body::new(&[0; 16]).attr(IFLA_IFNAME, b"uvt-nothing\0");
        let missing = request(RTM_GETLINK, 0, &none)
            .err()
            .and_then(|e| e.raw_os_error());
        assert_eq!(missing, Some(libc::ENODEV));
        let all = request(RTM_GETLINK, NLM_F_DUMP, &Body::new(&[0; 16])).expect("list");
        assert!(!all.is_empty(), "no links at all");
    }
}
