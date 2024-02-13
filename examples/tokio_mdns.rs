use multicast_socket::{AsyncMulticastSocket, MulticastSocket};
use std::{convert::TryInto, net::SocketAddrV4};
use tokio::time::{sleep, Duration};

#[tokio::main(flavor = "current_thread")]
async fn main() {
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

    let socket =
        MulticastSocket::all_interfaces(mdns_multicast_address).expect("could not create socket");

    let async_socket: AsyncMulticastSocket =
        socket.try_into().expect("Couldn't convert to async socket");

    let data = vec![1, 2];
    async_socket
        .broadcast(&data)
        .await
        .expect("could not broadcast message to ips being listened");

    loop {
        if let Ok(message) = async_socket.receive().await {
            dbg!(&message.interface);
            dbg!(&message.origin_address);

            let data = vec![9, 8, 7];
            async_socket
                .send(&data, &message.interface)
                .await
                .expect("could not send data");
        };
        sleep(Duration::from_millis(500)).await;
    }
}
