use crate::{
    iface::SocketSet,
    network::Indication,
    socket::{btp::Indication as BtpIndication, *},
    wire::{BtpAHeader, BtpARepr, BtpBHeader, BtpBRepr, GeonetVariant},
};

use super::{check, InterfaceContext, InterfaceInner};

impl InterfaceInner {
    /// Processes a BTP-A packet.
    pub(super) fn process_btp_a(
        &mut self,
        srv: &InterfaceContext,
        sockets: &mut SocketSet,
        ind: Indication,
        _handled_by_geonet_socket: bool,
        packet: &GeonetVariant,
        payload: &[u8],
    ) {
        // We only accept unicast packets.
        let GeonetVariant::Unicast(uc_repr) = packet else {
            return;
        };

        let btp_a = check!(BtpAHeader::new_checked(payload));
        let btp_a_repr = check!(BtpARepr::parse(&btp_a));

        let payload = btp_a.payload();

        let btp_ind = BtpIndication {
            transport: ind.transport,
            ali_id: ind.ali_id,
            #[cfg(feature = "proto-security")]
            its_aid: ind.its_aid,
            #[cfg(feature = "proto-security")]
            cert_id: ind.cert_id,
            rem_lifetime: ind.rem_lifetime,
            rem_hop_limit: ind.rem_hop_limit,
            traffic_class: ind.traffic_class,
        };

        for btp_socket in sockets
            .items_mut()
            .filter_map(|i| btp::SocketA::downcast_mut(&mut i.socket))
        {
            if btp_socket.accepts(self, &srv, &uc_repr, &btp_a_repr) {
                btp_socket.process(self, &srv, btp_ind, &uc_repr, &btp_a_repr, payload);
                return;
            }
        }
    }

    /// Processes a BTP-B packet.
    pub(super) fn process_btp_b(
        &mut self,
        srv: &InterfaceContext,
        sockets: &mut SocketSet,
        ind: Indication,
        _handled_by_geonet_socket: bool,
        payload: &[u8],
    ) {
        let btp_b = check!(BtpBHeader::new_checked(payload));
        let btp_b_repr = check!(BtpBRepr::parse(&btp_b));

        let payload = btp_b.payload();

        let btp_ind = BtpIndication {
            transport: ind.transport,
            ali_id: ind.ali_id,
            #[cfg(feature = "proto-security")]
            its_aid: ind.its_aid,
            #[cfg(feature = "proto-security")]
            cert_id: ind.cert_id,
            rem_lifetime: ind.rem_lifetime,
            rem_hop_limit: ind.rem_hop_limit,
            traffic_class: ind.traffic_class,
        };

        for btp_socket in sockets
            .items_mut()
            .filter_map(|i| btp::SocketB::downcast_mut(&mut i.socket))
        {
            if btp_socket.accepts(self, srv, &btp_b_repr) {
                btp_socket.process(self, srv, btp_ind, payload);
                return;
            }
        }

        #[cfg(feature = "socket-cam")]
        for cam_socket in sockets
            .items_mut()
            .filter_map(|i| cam::Socket::downcast_mut(&mut i.socket))
        {
            if cam_socket.accepts(self, srv, &btp_b_repr) {
                cam_socket.process(self, srv, btp_ind, payload);
                return;
            }
        }

        #[cfg(feature = "socket-denm")]
        for denm_socket in sockets
            .items_mut()
            .filter_map(|i| denm::Socket::downcast_mut(&mut i.socket))
        {
            if denm_socket.accepts(self, srv, &btp_b_repr) {
                denm_socket.process(self, srv, btp_ind, payload);
                return;
            }
        }
    }
}
