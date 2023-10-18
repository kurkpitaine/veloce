use super::check;
use super::DispatchError;
use super::EthernetPacket;
use super::InterfaceInner;
use super::InterfaceServices;
use super::SocketSet;
use crate::geonet::phy::{PacketMeta, TxToken};
use crate::geonet::wire::*;

impl InterfaceInner {
    #[cfg(feature = "medium-ethernet")]
    pub(super) fn process_ethernet<'frame>(
        &mut self,
        srv: InterfaceServices,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        frame: &'frame [u8],
    ) -> Option<(EthernetAddress, EthernetPacket<'frame>)> {
        let eth_frame = check!(EthernetFrame::new_checked(frame));

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
                .process_geonet_packet(srv, &eth_frame.payload(), eth_frame.src_addr())
                .map(|e| (e.0, EthernetPacket::Geonet(e.1))),
            // Drop all other traffic.
            _ => None,
        }
    }

    #[cfg(feature = "medium-ethernet")]
    pub(super) fn dispatch_ethernet<Tx, F>(
        &mut self,
        tx_token: Tx,
        buffer_len: usize,
        f: F,
    ) -> Result<(), DispatchError>
    where
        Tx: TxToken,
        F: FnOnce(EthernetFrame<&mut [u8]>),
    {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        tx_token.consume(tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);

            f(frame);

            Ok(())
        })
    }
}
