/// ITS Application Object Identifier Registration numbers, as ETSI TS 102 965 V2.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AID {
    /// Cooperative Awareness Basic service, ie: CAM message.
    CA = 36,
    /// Decentralized Event Notification Basic service, ie: DENM message.
    DEN = 37,
    /// Traffic Light Manoeuver service, ie: SPAT message.
    TLM = 137,
    /// Road Lane Topology service, ie: MAP message.
    RLT = 138,
    /// In Vehicle Information service, ie: IVI message.
    IVI = 139,
    /// Traffic Light Control Request service, ie: SREM message.
    TLCR = 140,
    /// GeoNetworking Management Communications.
    GnMgmt = 141,
    /// Certificate Revocation List service.
    CRL = 622,
    /// Secured Certificate Request service.
    SCR = 623,
    /// Certificate Trust List service.
    CTL = 624,
    /// Traffic Light Control Status service, ie: SSEM message.
    TLCS = 637,
    /// Vulnerable Road User service, ie: VAM message.
    VRU = 638,
    /// CP service.
    CP = 639,
    /// Interference Management Zone service, ie: IMZM message.
    IMZ = 640,
    /// Service Announcement service, ie: SAM message.
    SA = 540_801,
    /// GNSS Positioning Correction service.
    GPC = 540_802,
}
