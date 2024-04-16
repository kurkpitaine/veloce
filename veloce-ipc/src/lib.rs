mod event;
mod zmq;

pub use event::{Event as IpcEvent, EventType as IpcEventType};
use rkyv::{
    ser::{ScratchSpace, Serializer},
    with::UnixTimestampError,
    Fallible,
};

pub use zmq::{Publisher as ZmqPublisher, Subscriber as ZmqSubscriber};

pub mod prelude {
    pub use rkyv;
}

#[derive(Debug)]
pub struct IpcSerializationError;

#[derive(Debug)]
pub struct IpcDeserializationError;

/// Custom serializer for our [IpcEvent].
pub struct IpcSerializer<S> {
    inner: S,
}

impl<S> IpcSerializer<S> {
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Fallible> Fallible for IpcSerializer<S> {
    type Error = IpcSerializerError<S::Error>;
}

impl<S: Serializer> Serializer for IpcSerializer<S> {
    #[inline]
    fn pos(&self) -> usize {
        self.inner.pos()
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.inner.write(bytes).map_err(IpcSerializerError::Inner)
    }
}

impl<S: Default> Default for IpcSerializer<S> {
    fn default() -> Self {
        Self {
            inner: S::default(),
        }
    }
}

#[derive(Debug)]
pub enum IpcSerializerError<E> {
    Inner(E),
    UnixTimestampError,
}

impl<E> From<UnixTimestampError> for IpcSerializerError<E> {
    fn from(_: UnixTimestampError) -> Self {
        Self::UnixTimestampError
    }
}

impl<S: ScratchSpace> ScratchSpace for IpcSerializer<S> {
    unsafe fn push_scratch(
        &mut self,
        layout: std::alloc::Layout,
    ) -> Result<std::ptr::NonNull<[u8]>, Self::Error> {
        self.inner
            .push_scratch(layout)
            .map_err(IpcSerializerError::Inner)
    }

    unsafe fn pop_scratch(
        &mut self,
        ptr: std::ptr::NonNull<u8>,
        layout: std::alloc::Layout,
    ) -> Result<(), Self::Error> {
        self.inner
            .pop_scratch(ptr, layout)
            .map_err(IpcSerializerError::Inner)
    }
}
