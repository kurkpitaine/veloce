use std::{io, time::Duration};

use zmq::{Context, Error, PollEvents, Socket};

/// ZeroMQ based publisher.
pub struct Publisher {
    /// ZeroMQ socket.
    socket: Socket,
}

impl Publisher {
    /// Constructs a new [Publisher]. `addr` should contain the ip address of the
    /// interface the publisher binds to, and also the port, ie: `127.0.0.1:5556`.
    pub fn new(addr: String) -> io::Result<Publisher> {
        let ctx = Context::new();
        let socket = ctx.socket(zmq::SocketType::PUB)?;
        let endpoint = "tcp://".to_string() + &addr;

        socket.bind(&endpoint)?;

        Ok(Publisher { socket })
    }

    /// Sends `data` to the subscribers.
    /// This function is non-blocking and returns immediately whether data has
    /// been sent or not.
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        Ok(self.socket.send(data, zmq::DONTWAIT)?)
    }

    /// Returns the underlying socket file descriptor.
    pub fn raw_fd(&self) -> io::Result<i32> {
        Ok(self.socket.get_fd()?)
    }
}

/// ZeroMQ based subscriber.
pub struct Subscriber {
    /// ZeroMQ socket.
    socket: Socket,
}

impl Subscriber {
    /// Constructs a new [Publisher]. `addr` should contain the ip address
    /// the subscriber connects to, and also the port, ie: `127.0.0.1:5556`.
    /// FQDNs in place of ip address are supported by ZeroMQ but it will make
    /// this function a blocking call for the time the DNS resolution is made.
    pub fn new(addr: String) -> io::Result<Subscriber> {
        let ctx = Context::new();
        let socket = ctx.socket(zmq::SocketType::SUB)?;
        let endpoint = "tcp://".to_string() + &addr;

        socket.connect(&endpoint)?;
        socket.set_subscribe(&[])?;
        socket.set_reconnect_ivl_max(500)?;

        Ok(Subscriber { socket })
    }

    /// Sets the connect `timeout` for this subscriber socket.
    pub fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        Ok(self
            .socket
            .set_connect_timeout(timeout.as_millis() as i32)?)
    }

    /// Receive data from a publisher.
    /// This function is non blocking and returns immediately whether data has
    /// been received or not.
    pub fn recv(&self) -> io::Result<Vec<u8>> {
        Ok(self.socket.recv_bytes(zmq::DONTWAIT)?)
    }

    /// Query whether the socket can receive more frames.
    pub fn recv_more(&self) -> io::Result<bool> {
        Ok(self.socket.get_rcvmore()?)
    }

    /// Query ZMQ events.
    pub fn events(&self) -> io::Result<PollEvents> {
        Ok(self.socket.get_events()?)
    }

    /// Wait until the subscriber socket becomes readable.
    /// Setting `timeout` to None will make this call blocking forever until data is available.
    /// `timeout` has millisecond granularity, and could be set to 0 to make this call non-blocking.
    pub fn poll(&self, timeout: Option<Duration>) -> io::Result<()> {
        let timeout = timeout.map_or(-1, |t| t.as_millis() as i64);

        loop {
            match self.socket.poll(zmq::POLLIN, timeout) {
                Ok(_) => return Ok(()),
                Err(Error::EINTR) => {}
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    /// Returns the underlying socket file descriptor.
    pub fn raw_fd(&self) -> io::Result<i32> {
        Ok(self.socket.get_fd()?)
    }
}

/// ZeroMQ based replier.
pub struct Replier {
    /// ZeroMQ socket.
    socket: Socket,
}

impl Replier {
    /// Constructs a new [Replier]. `addr` should contain the ip address of the
    /// interface the replier binds to, and also the port, ie: `127.0.0.1:5556`.
    pub fn new(addr: String) -> io::Result<Replier> {
        let ctx = Context::new();
        let socket = ctx.socket(zmq::SocketType::REP)?;
        let endpoint = "tcp://".to_string() + &addr;

        socket.bind(&endpoint)?;

        Ok(Replier { socket })
    }

    /// Constructs a new [Replier] backed by a Unix Domain Socket.
    /// `name` should contain the path to the Unix Domain Socket the replier binds to.
    pub fn new_uds(name: String) -> io::Result<Replier> {
        let ctx = Context::new();
        let socket = ctx.socket(zmq::SocketType::REP)?;
        let endpoint = "ipc://".to_string() + &name;

        socket.bind(&endpoint)?;

        Ok(Replier { socket })
    }

    /// Sets the connect `timeout` for this replier socket.
    pub fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        Ok(self
            .socket
            .set_connect_timeout(timeout.as_millis() as i32)?)
    }

    /// Sends `data` to the requesters.
    /// This function is non-blocking and returns immediately whether data has
    /// been sent or not.
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        Ok(self.socket.send(data, zmq::DONTWAIT)?)
    }

    /// Receive data from a requester.
    /// This function is non blocking and returns immediately whether data has
    /// been received or not.
    pub fn recv(&self) -> io::Result<Vec<u8>> {
        Ok(self.socket.recv_bytes(zmq::DONTWAIT)?)
    }

    /// Query whether the socket can receive more frames.
    pub fn recv_more(&self) -> io::Result<bool> {
        Ok(self.socket.get_rcvmore()?)
    }

    /// Query ZMQ events.
    pub fn events(&self) -> io::Result<PollEvents> {
        Ok(self.socket.get_events()?)
    }

    /// Wait until the replier socket becomes readable.
    /// Setting `timeout` to None will make this call blocking forever until data is available.
    /// `timeout` has millisecond granularity, and could be set to 0 to make this call non-blocking.
    pub fn poll(&self, timeout: Option<Duration>) -> io::Result<()> {
        let timeout = timeout.map_or(-1, |t| t.as_millis() as i64);

        loop {
            match self.socket.poll(zmq::POLLIN, timeout) {
                Ok(_) => return Ok(()),
                Err(Error::EINTR) => {}
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    /// Returns the underlying socket file descriptor.
    pub fn raw_fd(&self) -> io::Result<i32> {
        Ok(self.socket.get_fd()?)
    }
}

/// ZeroMQ based requester.
pub struct Requester {
    /// ZeroMQ socket.
    socket: Socket,
}

impl Requester {
    /// Constructs a new [Requester]. `addr` should contain the ip address
    /// the requester connects to, and also the port, ie: `127.0.0.1:5556`.
    /// FQDNs in place of ip address are supported by ZeroMQ but it will make
    /// this function a blocking call for the time the DNS resolution is made.
    pub fn new(addr: String) -> io::Result<Requester> {
        let ctx = Context::new();
        let socket = ctx.socket(zmq::SocketType::REQ)?;
        let endpoint = "tcp://".to_string() + &addr;

        socket.connect(&endpoint)?;
        socket.set_subscribe(&[])?;
        socket.set_reconnect_ivl_max(500)?;

        Ok(Requester { socket })
    }

    /// Constructs a new [Requester] backed by a Unix Domain Socket.
    /// `name` should contain the path to the Unix Domain Socket that
    /// the requester connects to.
    pub fn new_uds(name: String) -> io::Result<Requester> {
        let ctx = Context::new();
        let socket = ctx.socket(zmq::SocketType::REQ)?;
        let endpoint = "ipc://".to_string() + &name;

        socket.connect(&endpoint)?;
        socket.set_subscribe(&[])?;
        socket.set_reconnect_ivl_max(500)?;

        Ok(Requester { socket })
    }

    /// Sets the connect `timeout` for this requester socket.
    pub fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        Ok(self
            .socket
            .set_connect_timeout(timeout.as_millis() as i32)?)
    }

    /// Sends `data` to the requester.
    /// This function is non-blocking and returns immediately whether data has
    /// been sent or not.
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        Ok(self.socket.send(data, zmq::DONTWAIT)?)
    }

    /// Receive data from a replier.
    /// This function is non blocking and returns immediately whether data has
    /// been received or not.
    pub fn recv(&self) -> io::Result<Vec<u8>> {
        Ok(self.socket.recv_bytes(zmq::DONTWAIT)?)
    }

    /// Query whether the socket can receive more frames.
    pub fn recv_more(&self) -> io::Result<bool> {
        Ok(self.socket.get_rcvmore()?)
    }

    /// Query ZMQ events.
    pub fn events(&self) -> io::Result<PollEvents> {
        Ok(self.socket.get_events()?)
    }

    /// Wait until the replier socket becomes readable.
    /// Setting `timeout` to None will make this call blocking forever until data is available.
    /// `timeout` has millisecond granularity, and could be set to 0 to make this call non-blocking.
    pub fn poll(&self, timeout: Option<Duration>) -> io::Result<()> {
        let timeout = timeout.map_or(-1, |t| t.as_millis() as i64);

        loop {
            match self.socket.poll(zmq::POLLIN, timeout) {
                Ok(_) => return Ok(()),
                Err(Error::EINTR) => {}
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    /// Returns the underlying socket file descriptor.
    pub fn raw_fd(&self) -> io::Result<i32> {
        Ok(self.socket.get_fd()?)
    }
}
