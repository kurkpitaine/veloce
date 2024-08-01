use core::fmt;
use managed::ManagedSlice;

use crate::iface::Interface;

/// Opaque struct with space for storing one interface.
///
/// This is public so you can use it to allocate space for storing
/// interfaces when creating an InterfaceSet.
#[derive(Debug, Default)]
pub struct InterfaceStorage {
    inner: Option<Item>,
}

impl InterfaceStorage {
    pub const EMPTY: Self = Self { inner: None };
}

/// An item of an interface set.
#[derive(Debug)]
pub(crate) struct Item {
    /// Handle of this interface within its enclosing `InterfaceSet`.
    pub(crate) handle: InterfaceHandle,
    /// Mainly useful for debug output.
    pub(crate) interface: Interface,
}

/// A handle, identifying an interface in an InterfaceSet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterfaceHandle(usize);

impl fmt::Display for InterfaceHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// An extensible set of interfaces.
#[derive(Debug)]
pub struct InterfaceSet<'a> {
    interfaces: ManagedSlice<'a, InterfaceStorage>,
}

impl<'a> InterfaceSet<'a> {
    /// Create an interface set using the provided storage.
    pub fn new<InterfacesT>(interfaces: InterfacesT) -> InterfaceSet<'a>
    where
        InterfacesT: Into<ManagedSlice<'a, InterfaceStorage>>,
    {
        let interfaces = interfaces.into();
        InterfaceSet { interfaces }
    }

    /// Add an interface to the set, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add(&mut self, interface: Interface) -> InterfaceHandle {
        fn put<'a>(
            index: usize,
            slot: &mut InterfaceStorage,
            interface: Interface,
        ) -> InterfaceHandle {
            net_trace!("[{}]: adding", index);
            let handle = InterfaceHandle(index);
            *slot = InterfaceStorage {
                inner: Some(Item { handle, interface }),
            };
            handle
        }

        for (index, slot) in self.interfaces.iter_mut().enumerate() {
            if slot.inner.is_none() {
                return put(index, slot, interface);
            }
        }

        match &mut self.interfaces {
            ManagedSlice::Borrowed(_) => panic!("adding an interface to a full InterfaceSet"),
            ManagedSlice::Owned(interfaces) => {
                interfaces.push(InterfaceStorage { inner: None });
                let index = interfaces.len() - 1;
                put(index, &mut interfaces[index], interface)
            }
        }
    }

    /// Get an interface from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this interface set
    /// or the interface has the wrong type.
    pub fn get(&self, handle: InterfaceHandle) -> &Interface {
        match self.interfaces[handle.0].inner.as_ref() {
            Some(item) => &item.interface,
            None => panic!("handle does not refer to a valid interface"),
        }
    }

    /// Get a mutable interface from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this interface set
    /// or the interface has the wrong type.
    pub fn get_mut(&mut self, handle: InterfaceHandle) -> &mut Interface {
        match self.interfaces[handle.0].inner.as_mut() {
            Some(item) => &mut item.interface,
            None => panic!("handle does not refer to a valid interface"),
        }
    }

    /// Remove an interface from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this interface set.
    pub fn remove(&mut self, handle: InterfaceHandle) -> Interface {
        net_trace!("[{}]: removing", handle.0);
        match self.interfaces[handle.0].inner.take() {
            Some(item) => item.interface,
            None => panic!("handle does not refer to a valid interface"),
        }
    }

    /// Get an iterator to the inner Interfaces.
    pub fn iter(&self) -> impl Iterator<Item = (InterfaceHandle, &Interface)> {
        self.items().map(|i| (i.handle, &i.interface))
    }

    /// Get a mutable iterator to the inner Interfaces.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (InterfaceHandle, &mut Interface)> {
        self.items_mut().map(|i| (i.handle, &mut i.interface))
    }

    /// Iterate every interface in this set.
    pub(crate) fn items(&self) -> impl Iterator<Item = &Item> + '_ {
        self.interfaces.iter().filter_map(|x| x.inner.as_ref())
    }

    /// Iterate every interface in this set.
    pub(crate) fn items_mut(&mut self) -> impl Iterator<Item = &mut Item> + '_ {
        self.interfaces.iter_mut().filter_map(|x| x.inner.as_mut())
    }
}
