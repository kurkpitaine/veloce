use super::check;
use super::EthernetPacket;
use super::InterfaceContext;
use super::InterfaceInner;
use super::SecuredDataBuffer;
use super::SocketSet;
use crate::phy::PacketMeta;
use crate::wire::*;

impl InterfaceInner {
    #[cfg(feature = "medium-ieee80211p")]
    pub(super) fn process_ieee80211p<'frame, 'ctx>(
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
    )>
    where
        'frame: 'ctx,
    {
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
                self.process_geonet_packet(
                    ctx,
                    sockets,
                    meta,
                    llc_frame.payload(),
                    eth_repr,
                    sec_buf,
                )
                .map(|(ctx, addr, pkt)| (ctx, addr, pkt.into()))
            }
            // Drop all other traffic.
            _ => None,
        }
    }
}
