use super::check;
use super::EthernetPacket;
use super::InterfaceInner;
use super::InterfaceServices;
use super::SocketSet;
use crate::phy::PacketMeta;
use crate::wire::*;

impl InterfaceInner {
    #[cfg(feature = "medium-ieee80211p")]
    pub(super) fn process_ieee80211p<'frame, 'services>(
        &mut self,
        srv: InterfaceServices<'services>,
        sockets: &mut SocketSet,
        _meta: PacketMeta,
        frame: &'frame [u8],
    ) -> Option<(
        InterfaceServices<'services>,
        EthernetAddress,
        EthernetPacket<'frame>,
    )> {
        let ieee80211_frame = check!(Ieee80211Frame::new_checked(frame));
        let ieee80211_repr = check!(Ieee80211Repr::parse(&ieee80211_frame));

        let llc_frame = check!(LlcFrame::new_checked(ieee80211_frame.payload()));
        let llc_repr = check!(LlcRepr::parse(&llc_frame));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !ieee80211_repr.dst_addr.is_broadcast()
            && !ieee80211_repr.dst_addr.is_multicast()
            && HardwareAddress::Ethernet(ieee80211_repr.dst_addr) != self.hardware_addr
        {
            return None;
        }

        match llc_repr.snap_protocol {
            #[cfg(feature = "proto-geonet")]
            EthernetProtocol::Geonet => {
                let eth_repr = EthernetRepr {
                    src_addr: ieee80211_repr.src_addr,
                    dst_addr: ieee80211_repr.dst_addr,
                    ethertype: llc_repr.snap_protocol,
                };
                self.process_geonet_packet(srv, sockets, &llc_frame.payload(), eth_repr)
                    .map(|e| (e.0, e.1, EthernetPacket::Geonet(e.2)))
            }
            // Drop all other traffic.
            _ => None,
        }
    }
}
