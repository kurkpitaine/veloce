use std::{fmt::Debug, io, os::fd::RawFd, rc::Rc};

use mio::unix::SourceFd;
use veloce_ipc::{ZmqPublisher, ZmqReplier};

use crate::config::Config;

/// IPC publisher and replier.
pub struct Ipc {
    /// IPC publisher.
    publisher: (Rc<ZmqPublisher>, RawFd),
    /// IPC replier.
    replier: (Rc<ZmqReplier>, RawFd),
}

impl Debug for Ipc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipc")
            .field("publisher", &"ZmqPublisher")
            .field("replier", &"ZmqReplier")
            .finish()
    }
}

impl Ipc {
    /// Builds a new IPC instance containing a publisher and a replier.
    pub fn new(config: &Config) -> Result<Self, io::Error> {
        let pub_addr = format!("0.0.0.0:{}", config.ipc_publisher_port);
        let rep_addr = format!("0.0.0.0:{}", config.ipc_replier_port);

        let publisher = Rc::new(ZmqPublisher::new(pub_addr)?);
        let replier = Rc::new(ZmqReplier::new(rep_addr)?);

        let pub_fd = publisher.raw_fd()?;
        let rep_fd = replier.raw_fd()?;

        Ok(Self {
            publisher: (publisher, pub_fd),
            replier: (replier, rep_fd),
        })
    }

    /// Returns the underlying publisher.
    pub fn publisher(&self) -> Rc<ZmqPublisher> {
        self.publisher.0.clone()
    }

    /// Returns the underlying publisher.
    pub fn replier(&self) -> Rc<ZmqReplier> {
        self.replier.0.clone()
    }

    /// Returns the underlying publisher as a mio [SourceFd].
    #[allow(unused)]
    pub fn pub_as_source_fd(&self) -> Result<SourceFd, io::Error> {
        Ok(SourceFd(&self.publisher.1))
    }

    /// Returns the underlying replier as a mio [SourceFd].
    #[allow(unused)]
    pub fn rep_as_source_fd(&self) -> Result<SourceFd, io::Error> {
        Ok(SourceFd(&self.replier.1))
    }
}
