use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use mio::{Events, Poll, Token};
use veloce::time::Instant;
use veloce_gnss::Gpsd;

// Some token to allow us to identify the Gpsd client.
const CLIENT: Token = Token(0);

pub fn main() {
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(128);

    // Setup the GPSD client socket.
    let mut gpsd = Gpsd::new(
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 2947).into(),
        poll.registry().try_clone().unwrap(),
        CLIENT,
        Instant::now(),
    )
    .unwrap();

    // Start an event loop.
    loop {
        let now = Instant::now();

        // Poll Gpsd to make it processing some work.
        gpsd.poll(now).unwrap();

        // Process each event.
        for event in events.iter() {
            match event.token() {
                CLIENT => {
                    gpsd.ready(event, now);
                }
                // We don't expect any events with tokens other than those we provided.
                _ => unreachable!(),
            }
        }

        // Poll Mio for events, blocking until we get an event or a timeout.
        poll.poll(&mut events, Some(Duration::from_secs(1)))
            .unwrap();
    }
}
