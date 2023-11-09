pub mod type_a;
pub mod type_b;

pub mod ports {
    /// Cooperative Advertisement service BTP port number.
    pub const CAM: u16 = 2001;
    /// Decentralized Event Notification service BTP port number.
    pub const DENM: u16 = 2002;
    /// Road Lane Topology MAP service BTP port number.
    pub const MAPEM: u16 = 2003;
    /// Traffic Light Maneuver Signal Phase And Timing service BTP port number.
    pub const SPATEM: u16 = 2004;
    /// Service Announcement service BTP port number.
    pub const SAEM: u16 = 2005;
    /// In Vehicle Information service BTP port number.
    pub const IVIM: u16 = 2006;
    /// Traffic Light Controller Signal Request service BTP port number.
    pub const SREM: u16 = 2007;
    /// Traffic Light Controller Signal Status service BTP port number.
    pub const SSEM: u16 = 2008;
    /// Cooperative Perception service BTP port number.
    pub const CPM: u16 = 2009;
    /// Electric Vehicle Charging Spot Notification Point Of Interest service BTP port number.
    pub const EVCSN_POI: u16 = 2010;
    /// Tyre Pressure Gauge Reservation service BTP port number.
    pub const TRM: u16 = 2011;
    /// Tyre Pressure Gauge Reservation Confirmation service BTP port number.
    pub const TCM: u16 = 2011;
    /// Tyre Pressure Gauge Vehicle Data Request service BTP port number.
    pub const VDRM: u16 = 2011;
    /// Tyre Pressure Gauge Vehicle Data Provisioning service BTP port number.
    pub const VDPM: u16 = 2011;
    /// Tyre Pressure Gauge Vehicle End Of Filling service BTP port number.
    pub const EOFM: u16 = 2011;
    /// Electric Vehicle Recharging Spot Reservation service BTP port number.
    pub const EV_RSR: u16 = 2012;
    /// GNSS Positioning Correction RTC service BTP port number.
    pub const RTCMEM: u16 = 2013;
    /// Certificate Trust List service BTP port number.
    pub const CTLM: u16 = 2014;
    /// Certificate Revocation List service BTP port number.
    pub const CRLM: u16 = 2015;
    /// Certificate Request service BTP port number.
    pub const EC_AT_REQUEST: u16 = 2016;
    /// Multimedia Content Dissemination service BTP port number.
    pub const MCDM: u16 = 2017;
    /// Vulnerable Road User Awareness service BTP port number.
    pub const VAM: u16 = 2018;
    /// Interference Management Zone service BTP port number.
    pub const IMZM: u16 = 2019;
    /// Diagnostic Status service BTP port number.
    pub const DSM: u16 = 2020;
}
