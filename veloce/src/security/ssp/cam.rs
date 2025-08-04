//! Cooperative Awareness messages SSP definition.
//! See ETSI TS 103 900 V2.1.1 chapter 6.2.2.2.

use crate::security::ssp::SSP_VERSION_2;

use super::{SspContainer, SspError, SspResult, SspTrait, SSP_VERSION_1};

mod field {
    /// SafetyCar / SafetyCarContainer signing permission octet index and bit position.
    pub const SAFETY_CAR: (usize, u8) = (1, 0);
    /// Emergency / EmergencyContainer signing permission octet index and bit position.
    pub const EMERGENCY: (usize, u8) = (1, 1);
    /// Rescue / RescueContainer signing permission octet index and bit position.
    pub const RESCUE: (usize, u8) = (1, 2);
    /// Roadwork / RoadworkContainerBasic signing permission octet index and bit position.
    pub const ROADWORK: (usize, u8) = (1, 3);
    /// DangerousGoods / DangerousGoodsContainer signing permission octet index and bit position.
    pub const DANGEROUS_GOODS: (usize, u8) = (1, 4);
    /// SpecialTransport / SpecialTransport Container signing permission octet index and bit position.
    pub const SPECIAL_TRANSPORT: (usize, u8) = (1, 5);
    /// PublicTransport / PublicTransport Container signing permission octet index and bit position.
    pub const PUBLIC_TRANSPORT: (usize, u8) = (1, 6);
    /// CenDsrcTollingZone / ProtectedCommunicationZonesRSU signing permission octet index and bit position.
    pub const TOLLING_ZONE: (usize, u8) = (1, 7);
    /// TwoWheelerContainer: cyclist signing permission octet index and bit position.
    pub const TWO_WHEELER_CYCLIST: (usize, u8) = (2, 0);
    /// TwoWheelerContainer signing permission octet index and bit position.
    pub const TWO_WHEELER: (usize, u8) = (2, 1);
    /// SpeedLimit / SafetyCarContainer signing permission octet index and bit position.
    pub const SPEED_LIMIT: (usize, u8) = (2, 2);
    /// NoPassingForTrucks / SafetyCarContainer: TrafficRule signing permission octet index and bit position.
    pub const NO_TRUCKS: (usize, u8) = (2, 3);
    /// NoPassing / SafetyCarContainer: TrafficRule signing permission octet index and bit position.
    pub const NO_PASSING: (usize, u8) = (2, 4);
    /// RequestForFreeCrossingAtATrafficLight / EmergencyContainer: EmergencyPriority Container signing permission octet index and bit position.
    pub const FREE_CROSSING_REQ: (usize, u8) = (2, 5);
    /// RequestForRightOfWay / EmergencyContainer: EmergencyPriority signing permission octet index and bit position.
    pub const RIGHT_OF_WAY_REQ: (usize, u8) = (2, 6);
    /// ClosedLanes / RoadworksContainerBasic signing permission octet index and bit position.
    pub const CLOSED_LANES: (usize, u8) = (2, 7);
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Cooperative Awareness Message permissions parameters.
pub enum CamPermission {
    /// SafetyCar / SafetyCarContainer signing permission.
    SafetyCar,
    /// Emergency / EmergencyContainer signing permission.
    Emergency,
    /// Rescue / RescueContainer signing permission.
    Rescue,
    /// Roadwork / RoadworkContainerBasic signing permission.
    Roadwork,
    /// DangerousGoods / DangerousGoodsContainer signing permission.
    DangerousGoods,
    /// SpecialTransport / SpecialTransport Container signing permission.
    SpecialTransport,
    /// PublicTransport / PublicTransport Container signing permission.
    PublicTransport,
    /// CenDsrcTollingZone / ProtectedCommunicationZonesRSU signing permission.
    CenDsrcTollingZoneOrProtectedCommunicationZonesRSU,
    /// SpeedLimit / SafetyCarContainer signing permission.
    SpeedLimit,
    /// NoPassingForTrucks / SafetyCarContainer: TrafficRule signing permission.
    NoPassingForTrucks,
    /// NoPassing / SafetyCarContainer: TrafficRule signing permission.
    NoPassing,
    /// RequestForFreeCrossingAtATrafficLight / EmergencyContainer: EmergencyPriority Container signing permission.
    RequestForFreeCrossingAtATrafficLight,
    /// RequestForRightOfWay / EmergencyContainer: EmergencyPriority signing permission.
    RequestForRightOfWay,
    /// ClosedLanes / RoadworksContainerBasic signing permission.
    ClosedLanes,
    /// TwoWheeler signing permission.
    TwoWheeler,
    /// TwoWheeler: Cyclist signing permission.
    TwoWheelerCyclist,
}

/// Length for CAM SSP. Same for V1 and V2.
const CAM_SSP_LEN_V1_V2: usize = 3;

/// A CamSsp representation.
///
/// This enum abstracts the various versions of SSPs. It either contains a V1
/// or V2 concrete high-level representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CamSsp {
    /// Version 1 of the CAM SSP.
    V1(CamSspV1),
    /// Version 2 of the cam SSP.
    V2(CamSspV2),
    /// Future version of the CAM SSP. SSP specification guarantees that
    /// a future SSP version will be at least as long as the current one.
    Future(CamSspV2),
}

impl CamSsp {
    /// Create a new version 1 [CamSsp].
    pub fn new_v1() -> CamSsp {
        CamSsp::V1(CamSspV1::new())
    }

    /// Create a new version 2 [CamSsp].
    pub fn new_v2() -> CamSsp {
        CamSsp::V2(CamSspV2::new())
    }

    /// Create a new [CamSsp] from a slice, choosing the correct version.
    pub fn parse(buf: &[u8]) -> SspResult<CamSsp> {
        if buf.len() < CAM_SSP_LEN_V1_V2 {
            return Err(SspError::Length);
        }

        let version = buf[0];

        match version {
            SSP_VERSION_1 => Ok(CamSsp::V1(CamSspV1::parse(buf)?)),
            SSP_VERSION_2 => Ok(CamSsp::V2(CamSspV2::parse(buf)?)),
            _ if buf.len() >= CAM_SSP_LEN_V1_V2 => {
                let mut raw = [0u8; CAM_SSP_LEN_V1_V2 - 1];
                raw.copy_from_slice(&buf[1..CAM_SSP_LEN_V1_V2 - 1]);
                Ok(CamSsp::Future(CamSspV2::from_raw_permissions(raw)))
            }
            _ => Err(SspError::Malformed),
        }
    }

    /// Emit the SSP as a vector of bytes, consuming itself.
    pub fn emit(self) -> Vec<u8> {
        match self {
            CamSsp::V1(v1_ssp) => v1_ssp.emit().to_vec(),
            CamSsp::V2(v2_ssp) => v2_ssp.emit().to_vec(),
            CamSsp::Future(u_ssp) => u_ssp.emit().to_vec(),
        }
    }

    /// Get the SSP version.
    pub const fn version(&self) -> u8 {
        match self {
            CamSsp::V1(_) => SSP_VERSION_1,
            CamSsp::V2(_) => SSP_VERSION_2,
            CamSsp::Future(_) => SSP_VERSION_2,
        }
    }

    /// Query whether the DENM SSP is version 1.
    pub const fn is_v1(&self) -> bool {
        matches!(self, CamSsp::V1(_))
    }

    /// Query whether the DENM SSP is version 2.
    pub const fn is_v2(&self) -> bool {
        matches!(self, CamSsp::V2(_))
    }

    /// Query whether the CAM SSP has the given permission.
    pub fn has_permission(&self, permission: CamPermission) -> bool {
        match self {
            CamSsp::V1(v1_ssp) => v1_ssp.has_permission(permission),
            CamSsp::V2(v2_ssp) => v2_ssp.has_permission(permission),
            CamSsp::Future(u_ssp) => u_ssp.has_permission(permission),
        }
    }
}

impl PartialOrd for CamSsp {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CamSsp {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.version().cmp(&other.version())
    }
}

impl From<CamSspV1> for CamSsp {
    fn from(value: CamSspV1) -> Self {
        Self::V1(value)
    }
}

impl From<CamSspV2> for CamSsp {
    fn from(value: CamSspV2) -> Self {
        Self::V2(value)
    }
}

impl SspTrait for CamSsp {
    type SspType = CamSsp;
    type PermissionType = CamPermission;

    fn contains_permissions_of(&self, other: &Self::SspType) -> bool {
        match (self, other) {
            (CamSsp::V1(s), CamSsp::V1(o)) => s.contains_permissions_of(o),
            (CamSsp::V2(s), CamSsp::V2(o)) => s.contains_permissions_of(o),
            _ => false,
        }
    }

    fn has_permission(&self, permission: Self::PermissionType) -> bool {
        match self {
            CamSsp::V1(s) => s.has_permission(permission),
            CamSsp::V2(s) => s.has_permission(permission),
            CamSsp::Future(s) => s.has_permission(permission),
        }
    }

    fn set_permission(&mut self, permission: Self::PermissionType) {
        match self {
            CamSsp::V1(s) => s.set_permission(permission),
            CamSsp::V2(s) => s.set_permission(permission),
            CamSsp::Future(s) => s.set_permission(permission),
        }
    }

    fn clear_permission(&mut self, permission: Self::PermissionType) {
        match self {
            CamSsp::V1(s) => s.clear_permission(permission),
            CamSsp::V2(s) => s.clear_permission(permission),
            CamSsp::Future(s) => s.clear_permission(permission),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Cooperative Awareness Message Service Specific Permissions version 1.
pub struct CamSspV1(SspContainer<CAM_SSP_LEN_V1_V2>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Cooperative Awareness Message Service Specific Permissions version 2.
pub struct CamSspV2(SspContainer<CAM_SSP_LEN_V1_V2>);

impl Default for CamSspV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl CamSspV1 {
    /// Constructs a [CamSspV1].
    pub const fn new() -> CamSspV1 {
        CamSspV1(SspContainer::new(SSP_VERSION_1))
    }

    /// Get the size of [CamSspV1] in buffer.
    pub const fn buf_size() -> usize {
        CAM_SSP_LEN_V1_V2
    }

    /// Constructs a [CamSspV1] from the provided `permissions` value.
    pub const fn from_raw_permissions(permissions: [u8; 2]) -> CamSspV1 {
        CamSspV1(SspContainer::from_slice([
            SSP_VERSION_1,
            permissions[0],
            permissions[1],
        ]))
    }

    /// Constructs a [CamSspV1] from bytes, ensuring length and
    /// version are supported.
    pub fn parse(buf: &[u8]) -> SspResult<CamSspV1> {
        // Ensure no panics.
        if buf.len() < CAM_SSP_LEN_V1_V2 {
            return Err(SspError::Length);
        }

        // Ensure version is supported.
        if buf[0] != SSP_VERSION_1 {
            return Err(SspError::Version);
        }

        Ok(CamSspV1(SspContainer::from_bytes(buf)))
    }

    /// Emit the SSP as a byte array, consuming itself.
    pub const fn emit(self) -> [u8; CAM_SSP_LEN_V1_V2] {
        self.0.into_inner()
    }
}

impl SspTrait for CamSspV1 {
    type SspType = CamSspV1;
    type PermissionType = CamPermission;

    fn contains_permissions_of(&self, other: &Self::SspType) -> bool {
        self.0.inner[1] | other.0.inner[1] == self.0.inner[1]
            && self.0.inner[2] | other.0.inner[2] == self.0.inner[2]
    }

    fn has_permission(&self, permission: Self::PermissionType) -> bool {
        match permission {
            CamPermission::SafetyCar => self
                .0
                .read_bit::<{ field::SAFETY_CAR.0 }, { field::SAFETY_CAR.1 }>(),
            CamPermission::Emergency => self
                .0
                .read_bit::<{ field::EMERGENCY.0 }, { field::EMERGENCY.1 }>(),
            CamPermission::Rescue => self
                .0
                .read_bit::<{ field::RESCUE.0 }, { field::RESCUE.1 }>(),
            CamPermission::Roadwork => self
                .0
                .read_bit::<{ field::ROADWORK.0 }, { field::ROADWORK.1 }>(),
            CamPermission::DangerousGoods => self
                .0
                .read_bit::<{ field::DANGEROUS_GOODS.0 }, { field::DANGEROUS_GOODS.1 }>(),
            CamPermission::SpecialTransport => self
                .0
                .read_bit::<{ field::SPECIAL_TRANSPORT.0 }, { field::SPECIAL_TRANSPORT.1 }>(),
            CamPermission::PublicTransport => self
                .0
                .read_bit::<{ field::PUBLIC_TRANSPORT.0 }, { field::PUBLIC_TRANSPORT.1 }>(),
            CamPermission::CenDsrcTollingZoneOrProtectedCommunicationZonesRSU => self
                .0
                .read_bit::<{ field::TOLLING_ZONE.0 }, { field::TOLLING_ZONE.1 }>(),
            CamPermission::SpeedLimit => self
                .0
                .read_bit::<{ field::SPEED_LIMIT.0 }, { field::SPEED_LIMIT.1 }>(),
            CamPermission::NoPassingForTrucks => self
                .0
                .read_bit::<{ field::NO_TRUCKS.0 }, { field::NO_TRUCKS.1 }>(),
            CamPermission::NoPassing => self
                .0
                .read_bit::<{ field::NO_PASSING.0 }, { field::NO_PASSING.1 }>(),
            CamPermission::RequestForFreeCrossingAtATrafficLight => {
                self.0
                    .read_bit::<{ field::FREE_CROSSING_REQ.0 }, { field::FREE_CROSSING_REQ.1 }>()
            }
            CamPermission::RequestForRightOfWay => self
                .0
                .read_bit::<{ field::RIGHT_OF_WAY_REQ.0 }, { field::RIGHT_OF_WAY_REQ.1 }>(),
            CamPermission::ClosedLanes => self
                .0
                .read_bit::<{ field::CLOSED_LANES.0 }, { field::CLOSED_LANES.1 }>(),
            _ => false,
        }
    }

    /// Set the corresponding `permission` bit in the SSP.
    fn set_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            CamPermission::SafetyCar => self
                .0
                .write_bit::<{ field::SAFETY_CAR.0 }, { field::SAFETY_CAR.1 }>(true),
            CamPermission::Emergency => self
                .0
                .write_bit::<{ field::EMERGENCY.0 }, { field::EMERGENCY.1 }>(true),
            CamPermission::Rescue => self
                .0
                .write_bit::<{ field::RESCUE.0 }, { field::RESCUE.1 }>(true),
            CamPermission::Roadwork => self
                .0
                .write_bit::<{ field::ROADWORK.0 }, { field::ROADWORK.1 }>(true),
            CamPermission::DangerousGoods => self
                .0
                .write_bit::<{ field::DANGEROUS_GOODS.0 }, { field::DANGEROUS_GOODS.1 }>(true),
            CamPermission::SpecialTransport => self
                .0
                .write_bit::<{ field::SPECIAL_TRANSPORT.0 }, { field::SPECIAL_TRANSPORT.1 }>(true),
            CamPermission::PublicTransport => self
                .0
                .write_bit::<{ field::PUBLIC_TRANSPORT.0 }, { field::PUBLIC_TRANSPORT.1 }>(true),
            CamPermission::CenDsrcTollingZoneOrProtectedCommunicationZonesRSU => self
                .0
                .write_bit::<{ field::TOLLING_ZONE.0 }, { field::TOLLING_ZONE.1 }>(true),
            CamPermission::SpeedLimit => self
                .0
                .write_bit::<{ field::SPEED_LIMIT.0 }, { field::SPEED_LIMIT.1 }>(true),
            CamPermission::NoPassingForTrucks => self
                .0
                .write_bit::<{ field::NO_TRUCKS.0 }, { field::NO_TRUCKS.1 }>(true),
            CamPermission::NoPassing => self
                .0
                .write_bit::<{ field::NO_PASSING.0 }, { field::NO_PASSING.1 }>(true),
            CamPermission::RequestForFreeCrossingAtATrafficLight => {
                self.0
                    .write_bit::<{ field::FREE_CROSSING_REQ.0 }, { field::FREE_CROSSING_REQ.1 }>(
                        true,
                    )
            }
            CamPermission::RequestForRightOfWay => self
                .0
                .write_bit::<{ field::RIGHT_OF_WAY_REQ.0 }, { field::RIGHT_OF_WAY_REQ.1 }>(true),
            CamPermission::ClosedLanes => self
                .0
                .write_bit::<{ field::CLOSED_LANES.0 }, { field::CLOSED_LANES.1 }>(true),
            _ => {}
        }
    }

    /// Clear the corresponding `permission` bit in the SSP.
    fn clear_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            CamPermission::SafetyCar => self
                .0
                .write_bit::<{ field::SAFETY_CAR.0 }, { field::SAFETY_CAR.1 }>(false),
            CamPermission::Emergency => self
                .0
                .write_bit::<{ field::EMERGENCY.0 }, { field::EMERGENCY.1 }>(false),
            CamPermission::Rescue => self
                .0
                .write_bit::<{ field::RESCUE.0 }, { field::RESCUE.1 }>(false),
            CamPermission::Roadwork => self
                .0
                .write_bit::<{ field::ROADWORK.0 }, { field::ROADWORK.1 }>(false),
            CamPermission::DangerousGoods => self
                .0
                .write_bit::<{ field::DANGEROUS_GOODS.0 }, { field::DANGEROUS_GOODS.1 }>(false),
            CamPermission::SpecialTransport => self
                .0
                .write_bit::<{ field::SPECIAL_TRANSPORT.0 }, { field::SPECIAL_TRANSPORT.1 }>(false),
            CamPermission::PublicTransport => self
                .0
                .write_bit::<{ field::PUBLIC_TRANSPORT.0 }, { field::PUBLIC_TRANSPORT.1 }>(false),
            CamPermission::CenDsrcTollingZoneOrProtectedCommunicationZonesRSU => self
                .0
                .write_bit::<{ field::TOLLING_ZONE.0 }, { field::TOLLING_ZONE.1 }>(false),
            CamPermission::SpeedLimit => self
                .0
                .write_bit::<{ field::SPEED_LIMIT.0 }, { field::SPEED_LIMIT.1 }>(false),
            CamPermission::NoPassingForTrucks => self
                .0
                .write_bit::<{ field::NO_TRUCKS.0 }, { field::NO_TRUCKS.1 }>(false),
            CamPermission::NoPassing => self
                .0
                .write_bit::<{ field::NO_PASSING.0 }, { field::NO_PASSING.1 }>(false),
            CamPermission::RequestForFreeCrossingAtATrafficLight => {
                self.0
                    .write_bit::<{ field::FREE_CROSSING_REQ.0 }, { field::FREE_CROSSING_REQ.1 }>(
                        true,
                    )
            }
            CamPermission::RequestForRightOfWay => self
                .0
                .write_bit::<{ field::RIGHT_OF_WAY_REQ.0 }, { field::RIGHT_OF_WAY_REQ.1 }>(false),
            CamPermission::ClosedLanes => self
                .0
                .write_bit::<{ field::CLOSED_LANES.0 }, { field::CLOSED_LANES.1 }>(false),
            _ => {}
        }
    }
}

impl Default for CamSspV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl CamSspV2 {
    /// Constructs a [CamSspV2].
    pub const fn new() -> CamSspV2 {
        CamSspV2(SspContainer::new(SSP_VERSION_2))
    }

    /// Get the size of [CamSspV2] in buffer.
    pub const fn buf_size() -> usize {
        CAM_SSP_LEN_V1_V2
    }

    /// Constructs a [CamSspV2] from the provided `permissions` value.
    pub const fn from_raw_permissions(permissions: [u8; 2]) -> CamSspV2 {
        CamSspV2(SspContainer::from_slice([
            SSP_VERSION_1,
            permissions[0],
            permissions[1],
        ]))
    }

    /// Constructs a [CamSspV2] from bytes, ensuring length and
    /// version are supported.
    pub fn parse(buf: &[u8]) -> SspResult<CamSspV2> {
        // Ensure no panics.
        if buf.len() < CAM_SSP_LEN_V1_V2 {
            return Err(SspError::Length);
        }

        // Ensure version is supported.
        if buf[0] != SSP_VERSION_2 {
            return Err(SspError::Version);
        }

        Ok(CamSspV2(SspContainer::from_bytes(buf)))
    }

    /// Emit the SSP as a byte array, consuming itself.
    pub const fn emit(self) -> [u8; CAM_SSP_LEN_V1_V2] {
        self.0.into_inner()
    }
}

impl SspTrait for CamSspV2 {
    type SspType = CamSspV2;
    type PermissionType = CamPermission;

    fn contains_permissions_of(&self, other: &Self::SspType) -> bool {
        self.0.inner[1] | other.0.inner[1] == self.0.inner[1]
            && self.0.inner[2] | other.0.inner[2] == self.0.inner[2]
    }

    fn has_permission(&self, permission: Self::PermissionType) -> bool {
        match permission {
            CamPermission::SafetyCar => self
                .0
                .read_bit::<{ field::SAFETY_CAR.0 }, { field::SAFETY_CAR.1 }>(),
            CamPermission::Emergency => self
                .0
                .read_bit::<{ field::EMERGENCY.0 }, { field::EMERGENCY.1 }>(),
            CamPermission::Rescue => self
                .0
                .read_bit::<{ field::RESCUE.0 }, { field::RESCUE.1 }>(),
            CamPermission::Roadwork => self
                .0
                .read_bit::<{ field::ROADWORK.0 }, { field::ROADWORK.1 }>(),
            CamPermission::DangerousGoods => self
                .0
                .read_bit::<{ field::DANGEROUS_GOODS.0 }, { field::DANGEROUS_GOODS.1 }>(),
            CamPermission::SpecialTransport => self
                .0
                .read_bit::<{ field::SPECIAL_TRANSPORT.0 }, { field::SPECIAL_TRANSPORT.1 }>(),
            CamPermission::PublicTransport => self
                .0
                .read_bit::<{ field::PUBLIC_TRANSPORT.0 }, { field::PUBLIC_TRANSPORT.1 }>(),
            CamPermission::CenDsrcTollingZoneOrProtectedCommunicationZonesRSU => self
                .0
                .read_bit::<{ field::TOLLING_ZONE.0 }, { field::TOLLING_ZONE.1 }>(),
            CamPermission::SpeedLimit => self
                .0
                .read_bit::<{ field::SPEED_LIMIT.0 }, { field::SPEED_LIMIT.1 }>(),
            CamPermission::NoPassingForTrucks => self
                .0
                .read_bit::<{ field::NO_TRUCKS.0 }, { field::NO_TRUCKS.1 }>(),
            CamPermission::NoPassing => self
                .0
                .read_bit::<{ field::NO_PASSING.0 }, { field::NO_PASSING.1 }>(),
            CamPermission::RequestForFreeCrossingAtATrafficLight => {
                self.0
                    .read_bit::<{ field::FREE_CROSSING_REQ.0 }, { field::FREE_CROSSING_REQ.1 }>()
            }
            CamPermission::RequestForRightOfWay => self
                .0
                .read_bit::<{ field::RIGHT_OF_WAY_REQ.0 }, { field::RIGHT_OF_WAY_REQ.1 }>(),
            CamPermission::ClosedLanes => self
                .0
                .read_bit::<{ field::CLOSED_LANES.0 }, { field::CLOSED_LANES.1 }>(),
            CamPermission::TwoWheeler => self
                .0
                .read_bit::<{ field::TWO_WHEELER.0 }, { field::TWO_WHEELER.1 }>(),
            CamPermission::TwoWheelerCyclist => self
                .0
                .read_bit::<{ field::TWO_WHEELER_CYCLIST.0 }, { field::TWO_WHEELER_CYCLIST.1 }>(),
        }
    }

    /// Set the corresponding `permission` bit in the SSP.
    fn set_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            CamPermission::SafetyCar => self
                .0
                .write_bit::<{ field::SAFETY_CAR.0 }, { field::SAFETY_CAR.1 }>(true),
            CamPermission::Emergency => self
                .0
                .write_bit::<{ field::EMERGENCY.0 }, { field::EMERGENCY.1 }>(true),
            CamPermission::Rescue => self
                .0
                .write_bit::<{ field::RESCUE.0 }, { field::RESCUE.1 }>(true),
            CamPermission::Roadwork => self
                .0
                .write_bit::<{ field::ROADWORK.0 }, { field::ROADWORK.1 }>(true),
            CamPermission::DangerousGoods => self
                .0
                .write_bit::<{ field::DANGEROUS_GOODS.0 }, { field::DANGEROUS_GOODS.1 }>(true),
            CamPermission::SpecialTransport => self
                .0
                .write_bit::<{ field::SPECIAL_TRANSPORT.0 }, { field::SPECIAL_TRANSPORT.1 }>(true),
            CamPermission::PublicTransport => self
                .0
                .write_bit::<{ field::PUBLIC_TRANSPORT.0 }, { field::PUBLIC_TRANSPORT.1 }>(true),
            CamPermission::CenDsrcTollingZoneOrProtectedCommunicationZonesRSU => self
                .0
                .write_bit::<{ field::TOLLING_ZONE.0 }, { field::TOLLING_ZONE.1 }>(true),
            CamPermission::SpeedLimit => self
                .0
                .write_bit::<{ field::SPEED_LIMIT.0 }, { field::SPEED_LIMIT.1 }>(true),
            CamPermission::NoPassingForTrucks => self
                .0
                .write_bit::<{ field::NO_TRUCKS.0 }, { field::NO_TRUCKS.1 }>(true),
            CamPermission::NoPassing => self
                .0
                .write_bit::<{ field::NO_PASSING.0 }, { field::NO_PASSING.1 }>(true),
            CamPermission::RequestForFreeCrossingAtATrafficLight => {
                self.0
                    .write_bit::<{ field::FREE_CROSSING_REQ.0 }, { field::FREE_CROSSING_REQ.1 }>(
                        true,
                    )
            }
            CamPermission::RequestForRightOfWay => self
                .0
                .write_bit::<{ field::RIGHT_OF_WAY_REQ.0 }, { field::RIGHT_OF_WAY_REQ.1 }>(true),
            CamPermission::ClosedLanes => self
                .0
                .write_bit::<{ field::CLOSED_LANES.0 }, { field::CLOSED_LANES.1 }>(true),
            CamPermission::TwoWheeler => self
                .0
                .write_bit::<{ field::TWO_WHEELER.0 }, { field::TWO_WHEELER.1 }>(true),
            CamPermission::TwoWheelerCyclist => self
                .0
                .write_bit::<{ field::TWO_WHEELER_CYCLIST.0 }, { field::TWO_WHEELER_CYCLIST.1 }>(
                    true,
                ),
        }
    }

    /// Clear the corresponding `permission` bit in the SSP.
    fn clear_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            CamPermission::SafetyCar => self
                .0
                .write_bit::<{ field::SAFETY_CAR.0 }, { field::SAFETY_CAR.1 }>(false),
            CamPermission::Emergency => self
                .0
                .write_bit::<{ field::EMERGENCY.0 }, { field::EMERGENCY.1 }>(false),
            CamPermission::Rescue => self
                .0
                .write_bit::<{ field::RESCUE.0 }, { field::RESCUE.1 }>(false),
            CamPermission::Roadwork => self
                .0
                .write_bit::<{ field::ROADWORK.0 }, { field::ROADWORK.1 }>(false),
            CamPermission::DangerousGoods => self
                .0
                .write_bit::<{ field::DANGEROUS_GOODS.0 }, { field::DANGEROUS_GOODS.1 }>(false),
            CamPermission::SpecialTransport => self
                .0
                .write_bit::<{ field::SPECIAL_TRANSPORT.0 }, { field::SPECIAL_TRANSPORT.1 }>(false),
            CamPermission::PublicTransport => self
                .0
                .write_bit::<{ field::PUBLIC_TRANSPORT.0 }, { field::PUBLIC_TRANSPORT.1 }>(false),
            CamPermission::CenDsrcTollingZoneOrProtectedCommunicationZonesRSU => self
                .0
                .write_bit::<{ field::TOLLING_ZONE.0 }, { field::TOLLING_ZONE.1 }>(false),
            CamPermission::SpeedLimit => self
                .0
                .write_bit::<{ field::SPEED_LIMIT.0 }, { field::SPEED_LIMIT.1 }>(false),
            CamPermission::NoPassingForTrucks => self
                .0
                .write_bit::<{ field::NO_TRUCKS.0 }, { field::NO_TRUCKS.1 }>(false),
            CamPermission::NoPassing => self
                .0
                .write_bit::<{ field::NO_PASSING.0 }, { field::NO_PASSING.1 }>(false),
            CamPermission::RequestForFreeCrossingAtATrafficLight => {
                self.0
                    .write_bit::<{ field::FREE_CROSSING_REQ.0 }, { field::FREE_CROSSING_REQ.1 }>(
                        true,
                    )
            }
            CamPermission::RequestForRightOfWay => self
                .0
                .write_bit::<{ field::RIGHT_OF_WAY_REQ.0 }, { field::RIGHT_OF_WAY_REQ.1 }>(false),
            CamPermission::ClosedLanes => self
                .0
                .write_bit::<{ field::CLOSED_LANES.0 }, { field::CLOSED_LANES.1 }>(false),
            CamPermission::TwoWheeler => self
                .0
                .write_bit::<{ field::TWO_WHEELER.0 }, { field::TWO_WHEELER.1 }>(false),
            CamPermission::TwoWheelerCyclist => self
                .0
                .write_bit::<{ field::TWO_WHEELER_CYCLIST.0 }, { field::TWO_WHEELER_CYCLIST.1 }>(
                    false,
                ),
        }
    }
}
