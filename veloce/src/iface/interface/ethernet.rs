use super::check;
use super::EthernetPacket;
use super::InterfaceContext;
use super::InterfaceInner;
use super::SecuredDataBuffer;
use super::SocketSet;
use crate::phy::PacketMeta;
use crate::wire::*;

impl InterfaceInner {
    #[cfg(feature = "medium-ethernet")]
    pub(super) fn process_ethernet<'frame, 'ctx>(
        &mut self,
        ctx: InterfaceContext<'ctx>,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        frame: &'frame [u8],
        sec_buf: &'frame mut SecuredDataBuffer,
    ) -> Option<(
        InterfaceContext<'ctx>,
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
                .process_geonet_packet(ctx, sockets, meta, eth_frame.payload(), eth_repr, sec_buf)
                .map(|(ctx, addr, pkt)| (ctx, addr, pkt.into())),
            // Drop all other traffic.
            _ => None,
        }
    }
}
