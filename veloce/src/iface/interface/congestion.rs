use crate::{
    iface::congestion::CongestionError,
    network::GnCore,
    phy::{ChannelBusyRatio, Device, Medium, TxToken},
    time::{Duration, Instant},
    wire::{
        ieee80211::{FrameControl, QoSControl},
        EthernetAddress, EthernetFrame, EthernetProtocol, GeonetVariant, Ieee80211Frame,
        Ieee80211Repr, LlcFrame, LlcRepr,
    },
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

        // Find the queue with the smallest delay.
        let queue_opt = trc
            .queues
            .iter_mut()
            .filter(|e| !e.1.is_empty())
            .map(|e| (e.1, trc.controller.inner().tx_allowed_at(Some(*e.0))))
            .min_by_key(|k| k.1);

        let Some((q, _)) = queue_opt else {
            return false;
        };

        let rc = q
            .dequeue_one(|node| {
                let tx_token = device.transmit(core.now).ok_or_else(|| {
                    net_debug!("failed to transmit DCC buffered packet: device exhausted");
                    CongestionError::Exhausted
                })?;

                let dst_hw_addr = node.metadata().dst_hw_addr;
                let gn_repr = node.metadata().packet.to_owned();
                let payload = node.payload();

                let gn_pkt = GeonetPacket::new(gn_repr, Some(payload));

                self.inner
                    .dispatch_congestion_control(tx_token, core, dst_hw_addr, gn_pkt)
            })
            .is_some_and(|r| {
                match r {
                    Ok(total_len) => {
                        // G5 bandwidth is 6 Mbps.
                        let bytes_per_usec: f32 = 6.144 / 8.0;
                        let tx_duration_usec = bytes_per_usec * total_len as f32;
                        trc.controller
                            .inner_mut()
                            .notify_tx(core.now, Duration::from_micros(tx_duration_usec as u64));
                        true
                    }
                    Err(_) => false,
                }
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
}

impl InterfaceInner {
    pub(super) fn dispatch_congestion_control<Tx: TxToken>(
        &mut self,
        mut tx_token: Tx,
        core: &mut GnCore,
        dst_hw_addr: EthernetAddress,
        packet: GeonetPacket,
    ) -> Result<usize, CongestionError> {
        let gn_repr = packet.repr().inner();
        let caps = self.caps.clone();

        // First we calculate the total length that we will have to emit.
        let mut total_len = gn_repr.buffer_len();

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
            let cat = gn_repr.traffic_class().access_category();
            qos_ctrl.set_access_category(cat);
            qos_ctrl.set_ack_policy(1); // No Ack

            let ieee80211_repr = Ieee80211Repr {
                frame_control: frame_ctrl,
                duration_or_id: Default::default(),
                dst_addr: dst_hw_addr,
                src_addr: src_addr,
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
        let emit_gn = |repr: &GeonetVariant, mut tx_buffer: &mut [u8]| {
            gn_repr.emit(&mut tx_buffer);

            let payload_buf = &mut tx_buffer[repr.header_len()..];
            packet.emit_payload(payload_buf)
        };

        tx_token.set_meta(Default::default());
        tx_token
            .consume(total_len, |mut tx_buffer| {
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

                emit_gn(&gn_repr, tx_buffer);
                Ok(total_len)
            })
            .and_then(|r| {
                // Not sure about that...
                self.defer_beacon(core, &gn_repr);
                Ok(r)
            })
    }
}
