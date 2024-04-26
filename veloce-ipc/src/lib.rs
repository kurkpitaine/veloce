mod proto;
mod zmq;

pub mod prelude {
    pub use prost;
}

pub use zmq::{Publisher as ZmqPublisher, Subscriber as ZmqSubscriber};

pub use proto::event::{event::EventType as IpcEventType, Event as IpcEvent};
