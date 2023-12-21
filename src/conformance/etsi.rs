use crate::{
    iface::Interface,
    network::GnCore,
    wire::{GnAddress, UtInitialize, UtMessageType, UtPacket},
};

pub type Result = core::result::Result<UtMessageType, ()>;

pub struct State {
    /// Initially configured Geonetworking address
    initial_address: GnAddress,
}

impl State {
    /// Constructs a new State.
    pub fn new(addr: GnAddress) -> Self {
        State {
            initial_address: addr,
        }
    }

    /// Dispatch an Uppertester request.
    pub fn ut_dispatcher(
        &self,
        iface: &mut Interface,
        router: &mut GnCore,
        buffer: &[u8],
    ) -> Result {
        let ut_packet = UtPacket::new(buffer);

        match ut_packet.message_type() {
            UtMessageType::UtInitialize => self.ut_initialize(iface, router, ut_packet.payload()),
            UtMessageType::UtChangePosition => Err(()),
            UtMessageType::UtChangePseudonym => Err(()),
            UtMessageType::UtGnTriggerResult => Err(()),
            UtMessageType::UtGnTriggerGeoUnicast => Err(()),
            UtMessageType::UtGnTriggerGeoBroadcast => Err(()),
            UtMessageType::UtGnTriggerGeoAnycast => Err(()),
            UtMessageType::UtGnTriggerShb => Err(()),
            UtMessageType::UtGnTriggerTsb => Err(()),
            UtMessageType::UtBtpTriggerA => Err(()),
            UtMessageType::UtBtpTriggerB => Err(()),
            _ => Err(()),
        }
    }

    fn ut_initialize(&self, iface: &mut Interface, router: &mut GnCore, buffer: &[u8]) -> Result {
        let ut_init = UtInitialize::new(buffer);

        // TODO: set correct certificate if testing with security.
        // return an error since we don't support security yet.
        if ut_init.hashed_id8() != UtInitialize::<&[u8]>::ZERO_HASHEDID8 {
            return Err(());
        }

        // Reset buffers
        iface.ls_buffer.clear();
        iface.uc_forwarding_buffer.clear();
        iface.bc_forwarding_buffer.clear();
        iface.cb_forwarding_buffer.clear();

        // Reset location table
        iface.inner.clear_location_table();

        // Reset sequence number
        iface.inner.reset_sequence_number();

        // Reset geonetworking address
        router.set_address(self.initial_address);

        Ok(UtMessageType::UtInitializeResult)
    }
}
