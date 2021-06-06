mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}

pub mod pretty_print;

mod ethernet;
mod geonet;

pub use self::pretty_print::PrettyPrinter;

pub use self::ethernet::{
    Address as EthernetAddress, EtherType as EthernetProtocol, Frame as EthernetFrame,
    Repr as EthernetRepr, HEADER_LEN as ETHERNET_HEADER_LEN,
};

pub use self::geonet::{Address as GnAddress, TrafficClass as GnTrafficClass};
