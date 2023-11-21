use crate::geonet::{
    iface::SocketSet,
    network::Indication,
    socket::{btp::Indication as BtpIndication, *},
    wire::{BtpAHeader, BtpARepr, BtpBHeader, BtpBRepr},
};

use super::{check, InterfaceInner};

impl InterfaceInner {
    /// Processes a BTP-A packet.
    pub(super) fn process_btp_a(
        &mut self,
        _sockets: &mut SocketSet,
        _ind: Indication,
        _handled_by_geonet_socket: bool,
        payload: &[u8],
    ) {
        let btp_a = check!(BtpAHeader::new_checked(payload));
        let _btp_a_repr = check!(BtpARepr::parse(&btp_a));
    }

    /// Processes a BTP-B packet.
    pub(super) fn process_btp_b(
        &mut self,
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
            its_aid: ind.its_aid,
            cert_id: ind.cert_id,
            rem_lifetime: ind.rem_lifetime,
            rem_hop_limit: ind.rem_hop_limit,
            traffic_class: ind.traffic_class,
        };

        for btp_socket in sockets
            .items_mut()
            .filter_map(|i| btp::SocketB::downcast_mut(&mut i.socket))
        {
            if btp_socket.accepts(self, &btp_b_repr) {
                btp_socket.process(self, btp_ind, payload);
                return;
            }
        }
    }
}
