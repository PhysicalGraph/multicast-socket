use std::collections::HashMap;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};

#[cfg(feature = "tokio")]
use std::convert::TryFrom;
#[cfg(feature = "tokio")]
use tokio::io::Interest;

use nix::sys::socket as sock;
use nix::sys::uio::IoVec;

fn create_on_interfaces(
    options: crate::MulticastOptions,
    interfaces: Vec<Ipv4Addr>,
    multicast_address: SocketAddrV4,
) -> io::Result<MulticastSocket> {
    let socket = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))?;
    socket.set_read_timeout(options.read_timeout)?;
    socket.set_multicast_loop_v4(options.loopback)?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;

    // Ipv4PacketInfo translates to `IP_PKTINFO`. Checkout the [ip
    // manpage](https://man7.org/linux/man-pages/man7/ip.7.html) for more details. In summary
    // setting this option allows for determining on which interface a packet was received.
    sock::setsockopt(socket.as_raw_fd(), sock::sockopt::Ipv4PacketInfo, &true)
        .map_err(nix_to_io_error)?;

    for interface in &interfaces {
        println!("Joining multicast addr {multicast_address:#?} for iface {interface:#?}");
        socket.join_multicast_v4(multicast_address.ip(), &interface)?;
    }

    Ok(MulticastSocket {
        socket,
        inner: MulticastSocketInner {
            interfaces,
            multicast_address,
            buffer_size: options.buffer_size,
            options: Some(options),
        },
    })
}

struct MulticastSocketInner {
    interfaces: Vec<Ipv4Addr>,
    multicast_address: SocketAddrV4,
    buffer_size: usize,
    options: Option<crate::MulticastOptions>,
}

pub struct MulticastSocket {
    socket: socket2::Socket,
    inner: MulticastSocketInner,
}

#[derive(Debug, Clone)]
pub enum Interface {
    Default,
    Ip(Ipv4Addr),
    Index(i32),
}

#[derive(Debug, Clone)]
pub struct Message {
    pub data: Vec<u8>,
    pub origin_address: SocketAddrV4,
    pub interface: Interface,
}

/// The crate `get_if_addrs` is reading the bytes of sockets on the wrong endianess on MIPS
/// So the adresses are reversed...
/// The crate `get_if_addrs` is archived and I don't have bandwidth to fork it
/// So this is a hotfix
#[cfg(target_arch = "mips")]
fn reverse_interface(interface: get_if_addrs::Interface) -> get_if_addrs::Interface {
    get_if_addrs::Interface {
        name: interface.name,
        addr: match interface.addr {
            get_if_addrs::IfAddr::V4(v4) => {
                let reversed = get_if_addrs::Ifv4Addr {
                    ip: reverse_address(v4.ip),
                    netmask: reverse_address(v4.netmask),
                    broadcast: v4.broadcast.map(reverse_address),
                };
                get_if_addrs::IfAddr::V4(reversed)
            }
            addr => addr,
        },
    }
}

#[cfg(target_arch = "mips")]
fn reverse_address(v4: Ipv4Addr) -> Ipv4Addr {
    let mut octets = v4.octets();
    octets.reverse();
    octets.into()
}

pub fn all_ipv4_interfaces() -> io::Result<Vec<Ipv4Addr>> {
    #[cfg(not(target_arch = "mips"))]
    let interfaces = get_if_addrs::get_if_addrs()?.into_iter();
    #[cfg(target_arch = "mips")]
    let interfaces = get_if_addrs::get_if_addrs()?
        .into_iter()
        .map(reverse_interface);

    // We have to filter the same interface if it has multiple ips
    // https://stackoverflow.com/questions/49819010/ip-add-membership-fails-when-set-both-on-interface-and-its-subinterface-is-that
    let mut collected_interfaces = HashMap::with_capacity(interfaces.len());
    for interface in interfaces {
        if !collected_interfaces.contains_key(&interface.name) {
            match interface.ip() {
                std::net::IpAddr::V4(v4) if !interface.is_loopback() => {
                    collected_interfaces.insert(interface.name, v4);
                }
                _ => {}
            }
        }
    }
    Ok(collected_interfaces.into_iter().map(|(_, ip)| ip).collect())
}

impl MulticastSocket {
    pub fn all_interfaces(multicast_address: SocketAddrV4) -> io::Result<Self> {
        let interfaces = all_ipv4_interfaces()?;
        create_on_interfaces(Default::default(), interfaces, multicast_address)
    }

    pub fn with_options(
        multicast_address: SocketAddrV4,
        interfaces: Vec<Ipv4Addr>,
        options: crate::MulticastOptions,
    ) -> io::Result<Self> {
        create_on_interfaces(options, interfaces, multicast_address)
    }
}

fn nix_to_io_error(e: nix::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

impl MulticastSocket {
    pub fn bind(&mut self) -> io::Result<()> {
        let options =
            self.inner.options.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::AlreadyExists, "Socket already bound")
            })?;
        self.socket.bind(
            &SocketAddr::new(
                options.bind_address.into(),
                self.inner.multicast_address.port(),
            )
            .into(),
        )
    }

    pub fn receive(&self) -> io::Result<Message> {
        let mut data_buffer = vec![0; self.inner.buffer_size];
        let mut control_buffer = nix::cmsg_space!(libc::in_pktinfo);

        let message = sock::recvmsg(
            self.socket.as_raw_fd(),
            &[IoVec::from_mut_slice(&mut data_buffer)],
            Some(&mut control_buffer),
            sock::MsgFlags::empty(),
        )
        .map_err(nix_to_io_error)?;

        let origin_address = match message.address {
            Some(sock::SockAddr::Inet(v4)) => Some(v4.to_std()),
            _ => None,
        };
        let origin_address = match origin_address {
            Some(SocketAddr::V4(v4)) => v4,
            _ => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        };

        let mut interface = Interface::Default;

        for cmsg in message.cmsgs() {
            if let sock::ControlMessageOwned::Ipv4PacketInfo(pktinfo) = cmsg {
                interface = Interface::Index(pktinfo.ipi_ifindex as _);
            }
        }

        Ok(Message {
            data: data_buffer[0..message.bytes].to_vec(),
            origin_address,
            interface,
        })
    }

    pub fn send_to(
        &self,
        buf: &[u8],
        interface: &Interface,
        addr: SocketAddrV4,
    ) -> io::Result<usize> {
        let mut pkt_info: libc::in_pktinfo = unsafe { mem::zeroed() };

        match interface {
            Interface::Default => {}
            Interface::Ip(address) => pkt_info.ipi_spec_dst = sock::Ipv4Addr::from_std(address).0,
            Interface::Index(index) => pkt_info.ipi_ifindex = *index as _,
        };

        let destination = sock::InetAddr::from_std(&addr.into());

        sock::sendmsg(
            self.socket.as_raw_fd(),
            &[IoVec::from_slice(&buf)],
            &[sock::ControlMessage::Ipv4PacketInfo(&pkt_info)],
            sock::MsgFlags::empty(),
            Some(&sock::SockAddr::new_inet(destination)),
        )
        .map_err(nix_to_io_error)
    }

    pub fn send(&self, buf: &[u8], interface: &Interface) -> io::Result<usize> {
        self.send_to(buf, interface, self.inner.multicast_address)
    }

    pub fn broadcast_to(&self, buf: &[u8], addr: SocketAddrV4) -> io::Result<()> {
        for interface in &self.inner.interfaces {
            println!("Sending to interface {interface:#?}");
            self.send_to(buf, &Interface::Ip(*interface), addr)?;
        }
        Ok(())
    }

    pub fn broadcast(&self, buf: &[u8]) -> io::Result<()> {
        self.broadcast_to(buf, self.inner.multicast_address)
    }
}

#[cfg(feature = "tokio")]
pub struct AsyncMulticastSocket {
    socket: tokio::net::UdpSocket,
    inner: MulticastSocketInner,
}

/// Converts this socket in to one with an `async` API.
/// This will call `bind` on the socket if it has not already
/// been bound.
#[cfg(feature = "tokio")]
impl TryFrom<MulticastSocket> for AsyncMulticastSocket {
    type Error = io::Error;

    fn try_from(value: MulticastSocket) -> Result<Self, Self::Error> {
        let mut other = value;
        other.inner.options = other.inner.options.map(|mut opts| {
            opts.read_timeout = None;
            opts
        });
        other.socket.set_nonblocking(true)?;
        other.bind()?;

        let sock = tokio::net::UdpSocket::from_std(other.socket.into())?;

        Ok(Self {
            socket: sock,
            inner: other.inner,
        })
    }
}

#[cfg(feature = "tokio")]
impl AsyncMulticastSocket {
    pub async fn receive(&self) -> io::Result<Message> {
        let mut data_buffer = vec![0; self.inner.buffer_size];
        let mut control_buffer = nix::cmsg_space!(libc::in_pktinfo);

        // There is no Async API for the UNIX sendmsg/recvmsg vectored scatter-gather
        // calls, and the multihome functionality relies on receiving that ancillary data,
        // so we have to make this operation async "manually".
        self.socket.readable().await?;
        let message = self.socket.try_io(Interest::READABLE, || {
            sock::recvmsg(
                self.socket.as_raw_fd(),
                &[IoVec::from_mut_slice(&mut data_buffer)],
                Some(&mut control_buffer),
                sock::MsgFlags::empty(),
            )
            .map_err(nix_to_io_error)
        })?;

        let origin_address = match message.address {
            Some(sock::SockAddr::Inet(v4)) => Some(v4.to_std()),
            _ => None,
        };
        let origin_address = match origin_address {
            Some(SocketAddr::V4(v4)) => v4,
            _ => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        };

        let mut interface = Interface::Default;

        for cmsg in message.cmsgs() {
            if let sock::ControlMessageOwned::Ipv4PacketInfo(pktinfo) = cmsg {
                interface = Interface::Index(pktinfo.ipi_ifindex as _);
            }
        }

        Ok(Message {
            data: data_buffer[0..message.bytes].to_vec(),
            origin_address,
            interface,
        })
    }

    pub async fn send_to(
        &self,
        buf: &[u8],
        interface: &Interface,
        addr: SocketAddrV4,
    ) -> io::Result<usize> {
        let mut pkt_info: libc::in_pktinfo = unsafe { mem::zeroed() };

        match interface {
            Interface::Default => {}
            Interface::Ip(address) => pkt_info.ipi_spec_dst = sock::Ipv4Addr::from_std(address).0,
            Interface::Index(index) => pkt_info.ipi_ifindex = *index as _,
        };

        let destination = sock::InetAddr::from_std(&addr.into());

        // There is no Async API for the UNIX sendmsg/recvmsg vectored scatter-gather
        // calls, and the multihome functionality relies on receiving that ancillary data,
        // so we have to make this operation async "manually".
        self.socket.writable().await?;
        self.socket.try_io(Interest::WRITABLE, || {
            sock::sendmsg(
                self.socket.as_raw_fd(),
                &[IoVec::from_slice(&buf)],
                &[sock::ControlMessage::Ipv4PacketInfo(&pkt_info)],
                sock::MsgFlags::empty(),
                Some(&sock::SockAddr::new_inet(destination)),
            )
            .map_err(nix_to_io_error)
        })
    }
    pub async fn send(&self, buf: &[u8], interface: &Interface) -> io::Result<usize> {
        self.send_to(buf, interface, self.inner.multicast_address)
            .await
    }

    pub async fn broadcast_to(&self, buf: &[u8], addr: SocketAddrV4) -> io::Result<()> {
        for interface in &self.inner.interfaces {
            println!("Sending to interface {interface:#?}");
            self.send_to(buf, &Interface::Ip(*interface), addr).await?;
        }
        Ok(())
    }

    pub async fn broadcast(&self, buf: &[u8]) -> io::Result<()> {
        self.broadcast_to(buf, self.inner.multicast_address).await
    }
}
