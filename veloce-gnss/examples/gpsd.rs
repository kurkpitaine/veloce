use std::time::Duration;

use mio::{Events, Poll, Token};
use veloce::utils;
use veloce_gnss::Gpsd;

// Some token to allow us to identify the Gpsd client.
const CLIENT: Token = Token(0);

pub fn main() {
    utils::setup_logging("trace");

    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(128);

    // Setup the GPSD client socket.
    let mut gpsd = Gpsd::new(
        "127.0.0.1:2947".to_string(),
        poll.registry().try_clone().unwrap(),
        CLIENT,
    )
    .unwrap();

    // Start an event loop.
    loop {
        // Poll Gpsd to make it processing some work.
        gpsd.poll().unwrap();

        // Process each event.
        for event in events.iter() {
            match event.token() {
                CLIENT => {
                    gpsd.ready(event);
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
