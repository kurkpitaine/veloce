//! Cooperative Awareness messages SSP definition.
//! See ETSI TS 103 900 V2.1.1 chapter 6.2.2.2.

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
}

/// Length for CAM SSP.
const CAM_SSP_LEN: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Secured Certificate Request Service Specific Permissions.
pub struct CamSsp(SspContainer<CAM_SSP_LEN>);

impl Default for CamSsp {
    fn default() -> Self {
        Self::new()
    }
}

impl CamSsp {
    /// Constructs a [CamSsp].
    pub const fn new() -> CamSsp {
        CamSsp(SspContainer::new(SSP_VERSION_1))
    }

    /// Get the size of [CamSsp] in buffer.
    pub const fn buf_size() -> usize {
        CAM_SSP_LEN
    }

    /// Constructs a [CamSsp] from the provided `permissions` value.
    pub const fn from_raw_permissions(permissions: [u8; 2]) -> CamSsp {
        CamSsp(SspContainer::from_slice([
            SSP_VERSION_1,
            permissions[0],
            permissions[1],
        ]))
    }

    /// Constructs a [CamSsp] from bytes, ensuring length and
    /// version are supported.
    pub fn parse(buf: &[u8]) -> SspResult<CamSsp> {
        // Ensure no panics.
        if buf.len() < CAM_SSP_LEN {
            return Err(SspError::Length);
        }

        // Ensure version is supported.
        if buf[0] != SSP_VERSION_1 {
            return Err(SspError::Version);
        }

        Ok(CamSsp(SspContainer::from_bytes(buf)))
    }
}

impl SspTrait for CamSsp {
    type SspType = CamSsp;
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
        }
    }
}
