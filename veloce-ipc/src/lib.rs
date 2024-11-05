mod proto;
mod zmq;

pub mod prelude {
    pub use prost;
    pub use zmq;
}

pub use zmq::{
    Publisher as ZmqPublisher, Replier as ZmqReplier, Requester as ZmqRequester,
    Subscriber as ZmqSubscriber,
};

pub use proto::denm;
pub use proto::message::{event::EventType as IpcEventType, Event as IpcEvent};
