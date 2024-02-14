use std::collections::HashMap;
use std::io::IoSliceMut;
use std::io::{self, IoSlice};
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;

use network_interface::{NetworkInterface, NetworkInterfaceConfig, V4IfAddr};
use socket2::{Domain, Protocol, Socket, Type};

#[cfg(feature = "tokio")]
use tokio::io::Interest;

use nix::sys::socket::{self as sock, RecvMsg};

fn create_on_interfaces(
    options: crate::MulticastOptions,
    interfaces: Vec<Ipv4Addr>,
    multicast_address: SocketAddrV4,
) -> io::Result<MulticastSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(options.nonblocking)?;
    if !options.nonblocking {
        socket.set_read_timeout(options.read_timeout)?;
    }
    socket.set_multicast_loop_v4(options.loopback)?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;

    // Ipv4PacketInfo translates to `IP_PKTINFO`. Checkout the [ip
    // manpage](https://man7.org/linux/man-pages/man7/ip.7.html) for more details. In summary
    // setting this option allows for determining on which interface a packet was received.
    sock::setsockopt(socket.as_raw_fd(), sock::sockopt::Ipv4PacketInfo, &true)
        .map_err(nix_to_io_error)?;

    for interface in &interfaces {
        socket.join_multicast_v4(multicast_address.ip(), &interface)?;
    }

    socket.bind(&SocketAddr::new(options.bind_address.into(), multicast_address.port()).into())?;

    Ok(MulticastSocket {
        socket,
        inner: MulticastSocketInner {
            interfaces,
            multicast_address,
            buffer_size: options.buffer_size,
        },
    })
}

struct MulticastSocketInner {
    interfaces: Vec<Ipv4Addr>,
    multicast_address: SocketAddrV4,
    buffer_size: usize,
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

pub fn all_ipv4_interfaces() -> io::Result<Vec<Ipv4Addr>> {
    let interfaces =
        NetworkInterface::show().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    // We have to filter the same interface if it has multiple ips
    // https://stackoverflow.com/questions/49819010/ip-add-membership-fails-when-set-both-on-interface-and-its-subinterface-is-that
    let mut collected_interfaces = HashMap::with_capacity(interfaces.len());
    for iface in interfaces.iter() {
        for (name, ipv4addr) in iface.addr.iter().filter_map(|addr| {
            if let network_interface::Addr::V4(V4IfAddr { ip, .. }) = addr {
                if !ip.is_loopback() {
                    Some((iface.name.clone(), ip.clone()))
                } else {
                    None
                }
            } else {
                None
            }
        }) {
            if !collected_interfaces.contains_key(&name) {
                collected_interfaces.insert(name, ipv4addr);
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
    match e {
        nix::errno::Errno::EAGAIN => io::ErrorKind::WouldBlock.into(),
        _ => io::Error::new(io::ErrorKind::Other, e),
    }
}

impl MulticastSocket {
    pub fn receive(&self) -> io::Result<Message> {
        let mut data_buffer = vec![0; self.inner.buffer_size];
        let mut control_buffer = nix::cmsg_space!(libc::in_pktinfo);
        let io_slice = &mut [IoSliceMut::new(&mut data_buffer)];

        let message: RecvMsg<sock::SockaddrIn> = sock::recvmsg(
            self.socket.as_raw_fd(),
            io_slice,
            Some(&mut control_buffer),
            sock::MsgFlags::empty(),
        )
        .map_err(nix_to_io_error)?;

        let origin_address = match message.address {
            Some(sockaddr) => SocketAddrV4::new(
                Ipv4Addr::from(sockaddr.ip().to_le()),
                sockaddr.port().to_le(),
            ),
            _ => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        };

        let mut interface = Interface::Default;

        for cmsg in message.cmsgs() {
            if let sock::ControlMessageOwned::Ipv4PacketInfo(pktinfo) = cmsg {
                interface = Interface::Index(pktinfo.ipi_ifindex as _);
            }
        }

        // Weird borrow interaction here because of the mutable borrow that
        // goes in to the IoSlice, so it's time to bust out the good old fashioned
        // for loop.
        let mut data = Vec::with_capacity(message.bytes);
        for i in 0..message.bytes {
            data.push(data_buffer[i]);
        }
        Ok(Message {
            data,
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
            Interface::Ip(address) => {
                pkt_info.ipi_spec_dst = libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.octets()),
                }
            }
            Interface::Index(index) => pkt_info.ipi_ifindex = *index as _,
        };

        sock::sendmsg(
            self.socket.as_raw_fd(),
            &[IoSlice::new(&buf)],
            &[sock::ControlMessage::Ipv4PacketInfo(&pkt_info)],
            sock::MsgFlags::empty(),
            Some(&sock::SockaddrIn::from(SocketAddrV4::from(addr))),
        )
        .map_err(nix_to_io_error)
    }

    pub fn send(&self, buf: &[u8], interface: &Interface) -> io::Result<usize> {
        self.send_to(buf, interface, self.inner.multicast_address)
    }

    pub fn broadcast_to(&self, buf: &[u8], addr: SocketAddrV4) -> io::Result<()> {
        for interface in &self.inner.interfaces {
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

    fn try_from(other: MulticastSocket) -> Result<Self, Self::Error> {
        other.socket.set_nonblocking(true)?;
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

        // There is no Async API for the UNIX sendmsg/recvmsg vectored scatter-gather
        // calls, and the multihome functionality relies on receiving that ancillary data,
        // so we have to make this operation async "manually".
        self.socket
            .async_io(Interest::READABLE, || {
                let io_slice = &mut [IoSliceMut::new(&mut data_buffer)];
                let mut control_buffer = nix::cmsg_space!(libc::in_pktinfo);
                let message: RecvMsg<sock::SockaddrIn> = sock::recvmsg(
                    self.socket.as_raw_fd(),
                    io_slice,
                    Some(&mut control_buffer),
                    sock::MsgFlags::empty(),
                )
                .map_err(nix_to_io_error)?;

                let origin_address = match message.address {
                    Some(sockaddr) => SocketAddrV4::new(
                        Ipv4Addr::from(sockaddr.ip().to_le()),
                        sockaddr.port().to_le(),
                    ),
                    _ => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                };

                let mut interface = Interface::Default;

                for cmsg in message.cmsgs() {
                    if let sock::ControlMessageOwned::Ipv4PacketInfo(pktinfo) = cmsg {
                        interface = Interface::Index(pktinfo.ipi_ifindex as _);
                    }
                }

                // Weird borrow interaction here because of the mutable borrow that
                // goes in to the IoSlice, so it's time to bust out the good old fashioned
                // for loop.
                let mut data = Vec::with_capacity(message.bytes);
                for i in 0..message.bytes {
                    data.push(data_buffer[i]);
                }

                Ok(Message {
                    data,
                    origin_address,
                    interface,
                })
            })
            .await
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
            Interface::Ip(address) => {
                pkt_info.ipi_spec_dst = libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.octets()),
                }
            }
            Interface::Index(index) => pkt_info.ipi_ifindex = *index as _,
        };

        // There is no Async API for the UNIX sendmsg/recvmsg vectored scatter-gather
        // calls, and the multihome functionality relies on receiving that ancillary data,
        // so we have to make this operation async "manually".
        self.socket
            .async_io(Interest::WRITABLE, || {
                sock::sendmsg(
                    self.socket.as_raw_fd(),
                    &[IoSlice::new(&buf)],
                    &[sock::ControlMessage::Ipv4PacketInfo(&pkt_info)],
                    sock::MsgFlags::empty(),
                    Some(&sock::SockaddrIn::from(SocketAddrV4::from(addr))),
                )
                .map_err(nix_to_io_error)
            })
            .await
    }
    pub async fn send(&self, buf: &[u8], interface: &Interface) -> io::Result<usize> {
        self.send_to(buf, interface, self.inner.multicast_address)
            .await
    }

    pub async fn broadcast_to(&self, buf: &[u8], addr: SocketAddrV4) -> io::Result<()> {
        for interface in &self.inner.interfaces {
            self.send_to(buf, &Interface::Ip(*interface), addr).await?;
        }
        Ok(())
    }

    pub async fn broadcast(&self, buf: &[u8]) -> io::Result<()> {
        self.broadcast_to(buf, self.inner.multicast_address).await
    }
}
