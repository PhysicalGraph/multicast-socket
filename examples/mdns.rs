use multicast_socket::MulticastSocket;
use std::{net::SocketAddrV4, thread::sleep, time::Duration};

fn main() {
    let mdns_multicast_address = SocketAddrV4::new([224, 0, 0, 251].into(), 5353);

    // Validate that building with options works with the public API
    let with_options = MulticastSocket::with_options(
        mdns_multicast_address,
        multicast_socket::all_ipv4_interfaces()
            .expect("could not fetch all interfaces for options"),
        multicast_socket::MulticastOptions {
            ..Default::default()
        },
    )
    .expect("validate that we are starting with options");
    drop(with_options);

    let mut socket = MulticastSocket::all_interfaces(mdns_multicast_address)
        .expect("could not create and bind socket");

    socket.bind().expect("Could not bind");

    let data = vec![1, 2];
    socket
        .broadcast(&data)
        .expect("could not broadcast message to ips being listened");

    loop {
        if let Ok(message) = socket.receive() {
            dbg!(&message.interface);
            dbg!(&message.origin_address);

            let data = vec![9, 8, 7];
            socket
                .send(&data, &message.interface)
                .expect("could not send data");
        };
        sleep(Duration::from_millis(500))
    }
}
