use crate::{
    config::{self, GnAreaForwardingAlgorithm, GnNonAreaForwardingAlgorithm},
    iface::{congestion::CongestionError, location_table::LocationTable},
    network::GnCore,
    phy::{ChannelBusyRatio, Device, Medium, TxToken},
    time::{Duration, Instant},
    wire::{EthernetAddress, EthernetFrame, EthernetProtocol, GeonetRepr, GeonetVariant},
};

#[cfg(feature = "medium-ieee80211p")]
use crate::wire::{
    ieee80211::{FrameControl, QoSControl},
    Ieee80211Frame, Ieee80211Repr, LlcFrame, LlcRepr,
};

use super::{GeonetPacket, Interface, InterfaceInner};

/// A congestion control algorithm.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CongestionControl {
    /// No congestion control.
    None,
    /// Congestion control backed by Limeric algorithm.
    Limeric,
    /// Congestion control backed by Limeric with Dual Alpha algorithm.
    LimericDualAlpha,
}

impl Interface {
    /// Set an algorithm for congestion control.
    ///
    /// `CongestionControl::None` indicates that no congestion control is applied.
    /// Options `CongestionControl::Limeric` and `CongestionControl::LimericDualAlpha` are also available.
    pub fn set_congestion_control(&mut self, congestion_control: CongestionControl) {
        use crate::iface::congestion::*;

        let controller = match congestion_control {
            CongestionControl::None => AnyController::None(no_control::NoControl),
            CongestionControl::Limeric => {
                let lim = limeric::Limeric::new(Default::default());
                AnyController::Limeric(lim)
            }
            CongestionControl::LimericDualAlpha => {
                let mut lim = limeric::Limeric::new(Default::default());
                lim.enable_dual_alpha(Default::default());
                AnyController::Limeric(lim)
            }
        };

        self.congestion_control = Congestion::new(controller);
    }

    /// Return the current congestion control algorithm.
    pub fn congestion_control(&self) -> CongestionControl {
        use crate::iface::congestion::*;

        match &self.congestion_control.controller {
            AnyController::None(_) => CongestionControl::None,
            AnyController::Limeric(lim) => {
                if lim.dual_alpha_enabled() {
                    CongestionControl::LimericDualAlpha
                } else {
                    CongestionControl::Limeric
                }
            }
        }
    }

    /// Runs the congestion control algorithm.
    pub(crate) fn run_congestion_control(&mut self, timestamp: Instant, cbr: ChannelBusyRatio) {
        let rc = self.congestion_control.controller.inner_mut();
        rc.update_cbr(timestamp, cbr);
        rc.run(timestamp);

        self.congestion_control
            .compute_global_cbr(&self.inner.location_table, timestamp);
    }

    /// Egress frames buffered in the congestion control queues.
    pub(crate) fn congestion_control_egress<D>(&mut self, core: &mut GnCore, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        let trc = &mut self.congestion_control;

        let egress_at = match trc.egress_at {
            Some(e) if e <= core.now => e,
            _ => return false,
        };
        /* // Do not transmit if gate is closed.
        if !trc.controller.inner().can_tx(core.now) {
            return false;
        } */

        let rc = loop {
            // Find the queue with the smallest delay.
            let queue_opt = trc
                .queues
                .iter_mut()
                .filter(|e| !e.1.is_empty())
                .map(|e| (e.1, trc.controller.inner().tx_allowed_at(Some(*e.0))))
                .min_by_key(|k| k.1);

            let Some((q, _)) = queue_opt else {
                // Nothing to transmit. If we get here, this means trc.egress_at has some value.
                // Set it to None to avoid rescheduling for egress with empty queues.
                trc.egress_at = None;
                return false;
            };

            let res = q.dequeue_one(|node| {
                let tx_token = device
                    .transmit(core.now)
                    .ok_or(CongestionError::Exhausted)?;

                let dst_hw_addr = node.metadata().dst_hw_addr;
                let gn_repr = node.metadata().packet.to_owned();
                let payload = node.payload();

                let gn_pkt = GeonetPacket::new(gn_repr, Some(payload));

                // ETSI TS 103 836-4-2 V2.1.1 annex C.2: If CBF algorithm is used,
                // check if packet is a duplicate and drop it if so.
                if (config::GN_AREA_FORWARDING_ALGORITHM == GnAreaForwardingAlgorithm::Cbf
                    || config::GN_NON_AREA_FORWARDING_ALGORITHM
                        == GnNonAreaForwardingAlgorithm::Cbf)
                    && Self::cbf_duplication_check(
                        gn_pkt.repr().inner(),
                        &self.inner.location_table,
                    )
                {
                    // Drop packet.
                    return Err(CongestionError::CbfDuplicate);
                }

                self.inner
                    .dispatch_congestion_control(tx_token, core, dst_hw_addr, gn_pkt)
            });

            match res {
                Some(Ok(l)) => break Some(l),
                Some(Err(CongestionError::CbfDuplicate)) => {
                    net_debug!("skipping DCC buffered packet: duplicate packet");
                    continue;
                }
                Some(Err(CongestionError::Exhausted)) => {
                    net_debug!("failed to transmit DCC buffered packet: device exhausted");
                    break None;
                }
                _ => break None,
            }
        }
        .is_some_and(|total_len| {
            // G5 bandwidth is 6 Mbps.
            let bytes_per_usec: f64 = 6.144 / 8.0;
            let tx_duration_usec = bytes_per_usec * total_len as f64;
            trc.controller
                .inner_mut()
                .notify_tx(core.now, Duration::from_micros(tx_duration_usec as u64));
            true
        });

        // Reschedule for egress if there is at least one queue with packets.
        let has_pkt = trc.queues.iter().filter(|q| !q.1.is_empty()).count() > 0;
        if has_pkt {
            trc.egress_at = Some(egress_at + trc.controller.inner().tx_interval());
        } else {
            trc.egress_at = None;
        }

        rc
    }

    /// Check if the packet is a duplicate.
    fn cbf_duplication_check(pkt_variant: &GeonetVariant, location_table: &LocationTable) -> bool {
        let address = pkt_variant.source_address();

        let seq_number = match pkt_variant {
            GeonetVariant::Unicast(p) => p.extended_header.sequence_number,
            GeonetVariant::Anycast(p) => p.extended_header.sequence_number,
            GeonetVariant::Broadcast(p) => p.extended_header.sequence_number,
            GeonetVariant::TopoBroadcast(p) => p.extended_header.sequence_number,
            GeonetVariant::LocationServiceRequest(p) => p.extended_header.sequence_number,
            GeonetVariant::LocationServiceReply(p) => p.extended_header.sequence_number,
            _ => return false,
        };

        let Some(dpc) = location_table.duplicate_counter(address, seq_number) else {
            return false;
        };

        if dpc > 1 {
            net_debug!(
                "DCC: duplicate packet: src={} seq={} dpc={}",
                address,
                seq_number,
                dpc
            );
            true
        } else {
            false
        }
    }
}

impl InterfaceInner {
    pub(super) fn dispatch_congestion_control<Tx: TxToken>(
        &mut self,
        mut tx_token: Tx,
        _: &mut GnCore,
        dst_hw_addr: EthernetAddress,
        packet: GeonetPacket,
    ) -> Result<usize, CongestionError> {
        // First we calculate the total length that we will have to emit.
        let mut total_len = match packet.repr() {
            #[cfg(feature = "proto-security")]
            GeonetRepr::Secured { repr, encapsulated } => {
                repr.basic_header_len() + encapsulated.len()
            }
            GeonetRepr::Unsecured(u) => u.buffer_len(),
            #[cfg(feature = "proto-security")]
            _ => unreachable!(),
        };

        let gn_repr = packet.repr();
        let caps = self.caps.clone();

        // Add the size of the Ethernet header if the medium is Ethernet.
        #[cfg(feature = "medium-ethernet")]
        if matches!(caps.medium, Medium::Ethernet) {
            total_len = EthernetFrame::<&[u8]>::buffer_len(total_len);
        }

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);
            frame.set_dst_addr(dst_hw_addr);
            frame.set_ethertype(EthernetProtocol::Geonet);
        };

        // Add the size of the Ieee 802.11 Qos with LLC header if the medium is Ieee 802.11p.
        #[cfg(feature = "medium-ieee80211p")]
        if matches!(caps.medium, Medium::Ieee80211p) {
            total_len =
                total_len + Ieee80211Frame::<&[u8]>::header_len() + LlcFrame::<&[u8]>::header_len();
        }

        // Emit function for the Ieee 802.11 Qos with LLC header.
        #[cfg(feature = "medium-ieee80211p")]
        let emit_ieee80211 = |tx_buffer: &mut [u8]| {
            let src_addr = self.hardware_addr.ethernet_or_panic();

            let mut frame_ctrl = FrameControl::from_bytes(&[0, 0]);
            frame_ctrl.set_type(2); // Data frame
            frame_ctrl.set_sub_type(8); // QoS subtype

            let mut qos_ctrl = QoSControl::from_bytes(&[0, 0]);
            let cat = gn_repr.inner().traffic_class().access_category();
            qos_ctrl.set_access_category(cat);
            qos_ctrl.set_ack_policy(1); // No Ack

            let ieee80211_repr = Ieee80211Repr {
                frame_control: frame_ctrl,
                duration_or_id: Default::default(),
                dst_addr: dst_hw_addr,
                src_addr,
                bss_id: EthernetAddress::BROADCAST,
                sequence_control: Default::default(),
                qos_control: qos_ctrl,
            };

            let llc_repr = LlcRepr {
                dsap: 0xaa,
                ssap: 0xaa,
                control: 0x03,
                snap_vendor: [0; 3],
                snap_protocol: EthernetProtocol::Geonet,
            };

            let mut ieee80211_frame = Ieee80211Frame::new_unchecked(tx_buffer);
            ieee80211_repr.emit(&mut ieee80211_frame);

            let mut llc_frame = LlcFrame::new_unchecked(ieee80211_frame.payload_mut());
            llc_repr.emit(&mut llc_frame);
        };

        // Emit function for the Geonetworking header and payload.
        #[allow(unused_mut)]
        let emit_gn = |gn_repr: &GeonetRepr<GeonetVariant>, mut tx_buffer: &mut [u8]| {
            #[cfg(feature = "proto-security")]
            if let GeonetRepr::Secured { encapsulated, .. } = gn_repr {
                // Emit the basic header.
                gn_repr.inner().emit_basic_header(&mut tx_buffer);
                // Put the encapsulated content in the tx buffer.
                tx_buffer[gn_repr.inner().basic_header_len()..].copy_from_slice(encapsulated);
            } else {
                gn_repr.inner().emit(&mut tx_buffer);
                packet.emit_payload(&mut tx_buffer[gn_repr.inner().header_len()..]);
            };

            #[cfg(not(feature = "proto-security"))]
            let payload_buf = &mut tx_buffer[gn_repr.inner().header_len()..];
            #[cfg(not(feature = "proto-security"))]
            packet.emit_payload(payload_buf)
        };

        tx_token.set_meta(Default::default());
        tx_token.consume(total_len, |mut tx_buffer| {
            #[cfg(feature = "medium-ethernet")]
            if matches!(caps.medium, Medium::Ethernet) {
                emit_ethernet(tx_buffer);
                tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
            }

            #[cfg(feature = "medium-ieee80211p")]
            if matches!(caps.medium, Medium::Ieee80211p) {
                emit_ieee80211(tx_buffer);
                let pl_start =
                    Ieee80211Frame::<&[u8]>::header_len() + LlcFrame::<&[u8]>::header_len();
                tx_buffer = &mut tx_buffer[pl_start..];
            }

            emit_gn(gn_repr, tx_buffer);
            Ok(total_len)
        })
    }
}
