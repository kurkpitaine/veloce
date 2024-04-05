use super::check;
use super::EthernetPacket;
use super::InterfaceInner;
use super::InterfaceServices;
use super::SocketSet;
use crate::phy::PacketMeta;
use crate::wire::*;

impl InterfaceInner {
    #[cfg(feature = "medium-ethernet")]
    pub(super) fn process_ethernet<'frame, 'services>(
        &mut self,
        srv: InterfaceServices<'services>,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        frame: &'frame [u8],
    ) -> Option<(
        InterfaceServices<'services>,
        EthernetAddress,
        EthernetPacket<'frame>,
    )> {
        let eth_frame = check!(EthernetFrame::new_checked(frame));
        let eth_repr = check!(EthernetRepr::parse(&eth_frame));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && HardwareAddress::Ethernet(eth_frame.dst_addr()) != self.hardware_addr
        {
            return None;
        }

        match eth_frame.ethertype() {
            #[cfg(feature = "proto-geonet")]
            EthernetProtocol::Geonet => self
                .process_geonet_packet(srv, sockets, meta, &eth_frame.payload(), eth_repr)
                .map(|e| (e.0, e.1, EthernetPacket::Geonet(e.2))),
            // Drop all other traffic.
            _ => None,
        }
    }
}
