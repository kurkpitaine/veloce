//! Decentralized Event Notification messages SSP definition.
//! See ETSI TS 103 831 V2.2.1 chapter 6.2.2.2.

use veloce_asn1::defs::etsi__its__cdd as cdd;

use super::{SspContainer, SspError, SspResult, SspTrait, SSP_VERSION_1, SSP_VERSION_2};

mod field {
    /// humanPresenceOnTheRoad signing permission octet index and bit position.
    pub const HUMAN_ON_ROAD: (usize, u8) = (1, 0);
    /// hazardousLocation-AnimalOnTheRoad signing permission octet index and bit position.
    pub const ANIMAL_ON_ROAD: (usize, u8) = (1, 1);
    /// hazardousLocation-ObstacleOnTheRoad signing permission octet index and bit position.
    pub const OBSTACLE_ON_ROAD: (usize, u8) = (1, 2);
    /// hazardousLocation-SurfaceCondition signing permission octet index and bit position.
    pub const SURFACE_COND: (usize, u8) = (1, 3);
    /// adverseWeatherCondition-Adhesion signing permission octet index and bit position.
    pub const ADHESION: (usize, u8) = (1, 4);
    /// roadworks signing permission octet index and bit position.
    pub const ROADWORKS: (usize, u8) = (1, 5);
    /// accident signing permission octet index and bit position.
    pub const ACCIDENT: (usize, u8) = (1, 6);
    /// trafficCondition signing permission octet index and bit position.
    pub const TRAFFIC_COND: (usize, u8) = (1, 7);
    /// vehicleBreakdown signing permission octet index and bit position.
    pub const VEHICLE_BREAKDOWN: (usize, u8) = (2, 0);
    /// dangerousEndOfQueue signing permission octet index and bit position.
    pub const END_OF_QUEUE: (usize, u8) = (2, 1);
    /// slowVehicle signing permission octet index and bit position.
    pub const SLOW_VEHICLE: (usize, u8) = (2, 2);
    /// adverseWeatherCondition-Precipitation signing permission octet index and bit position.
    pub const PRECIPITATION: (usize, u8) = (2, 3);
    /// adverseWeatherCondition-Visibility signing permission octet index and bit position.
    pub const VISIBILITY: (usize, u8) = (2, 4);
    /// adverseWeatherCondition-ExtremeWeatherCondition signing permission octet index and bit position.
    pub const EXTREME_WEATHER_COND: (usize, u8) = (2, 5);
    /// rescueAndRecoveryWorkInProgress signing permission octet index and bit position.
    pub const RESCUE_AND_RECOVERY: (usize, u8) = (2, 6);
    /// wrongWayDriving signing permission octet index and bit position.
    pub const WRONG_WAY_DRIVING: (usize, u8) = (2, 7);
    /// dangerousSituation signing permission octet index and bit position.
    pub const DANGEROUS_SITUATION: (usize, u8) = (3, 0);
    /// signalViolation signing permission octet index and bit position.
    pub const SIGNAL_VIOLATION: (usize, u8) = (3, 1);
    /// collisionRisk signing permission octet index and bit position.
    pub const COLLISION_RISK: (usize, u8) = (3, 2);
    /// hazardousLocation-DangerousCurve signing permission octet index and bit position.
    pub const DANGEROUS_CURVE: (usize, u8) = (3, 3);
    /// emergencyVehicleApproaching signing permission octet index and bit position.
    pub const EMERGENCY_VEHICLE_APPROACHING: (usize, u8) = (3, 4);
    /// stationaryVehicle signing permission octet index and bit position.
    pub const STATIONARY_VEHICLE: (usize, u8) = (3, 5);
    /// humanProblem signing permission octet index and bit position.
    pub const HUMAN_PROBLEM: (usize, u8) = (3, 6);
    /// postCrash signing permission octet index and bit position.
    pub const POST_CRASH: (usize, u8) = (3, 7);
    /// railwayLevelCrossing signing permission octet index and bit position.
    pub const RAILWAY_LEVEL_CROSSING: (usize, u8) = (4, 4);
    /// publicTransportVehicleApproaching signing permission octet index and bit position.
    pub const PUBLIC_TRANSPORT_VEHICLE_APPROACHING: (usize, u8) = (4, 5);
    /// aquaplaning signing permission octet index and bit position.
    pub const AQUAPLANING: (usize, u8) = (4, 6);
    /// impassability signing permission octet index and bit position.
    pub const IMPASSABILITY: (usize, u8) = (4, 7);
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Cooperative Awareness Message permissions parameters.
pub enum DenmPermission {
    /// humanPresenceOnTheRoad signing permission.
    HumanPresenceOnTheRoad,
    /// hazardousLocation-AnimalOnTheRoad signing permission.
    HazardousLocationAnimalOnTheRoad,
    /// hazardousLocation-ObstacleOnTheRoad signing permission.
    HazardousLocationObstacleOnTheRoad,
    /// hazardousLocation-SurfaceCondition signing permission.
    HazardousLocationSurfaceCondition,
    /// adverseWeatherCondition-Adhesion signing permission.
    AdverseWeatherConditionAdhesion,
    /// roadworks signing permission.
    Roadworks,
    /// accident signing permission.
    Accident,
    /// trafficCondition signing permission.
    TrafficCondition,
    /// vehicleBreakdown signing permission.
    VehicleBreakdown,
    /// dangerousEndOfQueue signing permission.
    DangerousEndOfQueue,
    /// slowVehicle signing permission.
    SlowVehicle,
    /// adverseWeatherCondition-Precipitation signing permission.
    AdverseWeatherConditionPrecipitation,
    /// adverseWeatherCondition-Visibility signing permission.
    AdverseWeatherConditionVisibility,
    /// adverseWeatherCondition-ExtremeWeatherCondition signing permission.
    AdverseWeatherConditionExtremeWeatherCondition,
    /// rescueAndRecoveryWorkInProgress signing permission.
    RescueAndRecoveryWorkInProgress,
    /// wrongWayDriving signing permission.
    WrongWayDriving,
    /// dangerousSituation signing permission.
    DangerousSituation,
    /// signalViolation signing permission.
    SignalViolation,
    /// collisionRisk signing permission.
    CollisionRisk,
    /// hazardousLocation-DangerousCurve signing permission.
    HazardousLocationDangerousCurve,
    /// emergencyVehicleApproaching signing permission.
    EmergencyVehicleApproaching,
    /// stationaryVehicle signing permission.
    StationaryVehicle,
    /// humanProblem signing permission.
    HumanProblem,
    /// postCrash signing permission.
    PostCrash,
    /// railwayLevelCrossing signing permission.
    RailwayLevelCrossing,
    /// publicTransportVehicleApproaching signing permission.
    PublicTransportVehicleApproaching,
    /// aquaplaning signing permission.
    Aquaplaning,
    /// impassability signing permission.
    Impassability,
}

/// Error returned by [`DenmPermission::try_from`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NoMatchingPermission;

impl TryFrom<&cdd::CauseCodeChoice> for DenmPermission {
    type Error = NoMatchingPermission;

    fn try_from(value: &cdd::CauseCodeChoice) -> Result<Self, Self::Error> {
        let res = match value {
            cdd::CauseCodeChoice::trafficCondition1(_) => DenmPermission::TrafficCondition,
            cdd::CauseCodeChoice::accident2(_) => DenmPermission::Accident,
            cdd::CauseCodeChoice::roadworks3(_) => DenmPermission::Roadworks,
            cdd::CauseCodeChoice::impassability5(_) => DenmPermission::Impassability,
            cdd::CauseCodeChoice::adverseWeatherCondition_Adhesion6(_) => {
                DenmPermission::AdverseWeatherConditionAdhesion
            }
            cdd::CauseCodeChoice::aquaplaning7(_) => DenmPermission::Aquaplaning,
            cdd::CauseCodeChoice::hazardousLocation_SurfaceCondition9(_) => {
                DenmPermission::HazardousLocationSurfaceCondition
            }
            cdd::CauseCodeChoice::hazardousLocation_ObstacleOnTheRoad10(_) => {
                DenmPermission::HazardousLocationObstacleOnTheRoad
            }
            cdd::CauseCodeChoice::hazardousLocation_AnimalOnTheRoad11(_) => {
                DenmPermission::HazardousLocationAnimalOnTheRoad
            }
            cdd::CauseCodeChoice::humanPresenceOnTheRoad12(_) => {
                DenmPermission::HumanPresenceOnTheRoad
            }
            cdd::CauseCodeChoice::wrongWayDriving14(_) => DenmPermission::WrongWayDriving,
            cdd::CauseCodeChoice::rescueAndRecoveryWorkInProgress15(_) => {
                DenmPermission::RescueAndRecoveryWorkInProgress
            }
            cdd::CauseCodeChoice::adverseWeatherCondition_ExtremeWeatherCondition17(_) => {
                DenmPermission::AdverseWeatherConditionExtremeWeatherCondition
            }
            cdd::CauseCodeChoice::adverseWeatherCondition_Visibility18(_) => {
                DenmPermission::AdverseWeatherConditionVisibility
            }
            cdd::CauseCodeChoice::adverseWeatherCondition_Precipitation19(_) => {
                DenmPermission::AdverseWeatherConditionPrecipitation
            }
            cdd::CauseCodeChoice::slowVehicle26(_) => DenmPermission::SlowVehicle,
            cdd::CauseCodeChoice::dangerousEndOfQueue27(_) => DenmPermission::DangerousEndOfQueue,
            cdd::CauseCodeChoice::publicTransportVehicleApproaching28(_) => {
                DenmPermission::PublicTransportVehicleApproaching
            }
            cdd::CauseCodeChoice::vehicleBreakdown91(_) => DenmPermission::VehicleBreakdown,
            cdd::CauseCodeChoice::postCrash92(_) => DenmPermission::PostCrash,
            cdd::CauseCodeChoice::humanProblem93(_) => DenmPermission::HumanProblem,
            cdd::CauseCodeChoice::stationaryVehicle94(_) => DenmPermission::StationaryVehicle,
            cdd::CauseCodeChoice::emergencyVehicleApproaching95(_) => {
                DenmPermission::EmergencyVehicleApproaching
            }
            cdd::CauseCodeChoice::hazardousLocation_DangerousCurve96(_) => {
                DenmPermission::HazardousLocationDangerousCurve
            }
            cdd::CauseCodeChoice::collisionRisk97(_) => DenmPermission::CollisionRisk,
            cdd::CauseCodeChoice::signalViolation98(_) => DenmPermission::SignalViolation,
            cdd::CauseCodeChoice::dangerousSituation99(_) => DenmPermission::DangerousSituation,
            cdd::CauseCodeChoice::railwayLevelCrossing100(_) => {
                DenmPermission::RailwayLevelCrossing
            }
            _ => return Err(NoMatchingPermission),
        };

        Ok(res)
    }
}

/// Length for DENM SSP version 1.
const DENM_SSP_V1_LEN: usize = 4;
/// Length for DENM SSP version 2.
const DENM_SSP_V2_LEN: usize = 5;

/// A DenmSsp representation.
///
/// This enum abstracts the various versions of SSPs. It either contains a V1
/// or V2 concrete high-level representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DenmSsp {
    /// Version 1 of the DENM SSP.
    V1(DenmSspV1),
    /// Version 2 of the DENM SSP.
    V2(DenmSspV2),
    /// Unknown version of the DENM SSP. SSP specification guarantees that
    /// a future SSP version will be at least as long as the current one.
    Unknown(DenmSspV2),
}

impl DenmSsp {
    /// Create a new version 1 [DenmSsp].
    pub fn new_v1() -> DenmSsp {
        DenmSsp::V1(DenmSspV1::new())
    }

    /// Create a new version 2 [DenmSsp].
    pub fn new_v2() -> DenmSsp {
        DenmSsp::V2(DenmSspV2::new())
    }

    /// Create a new [DenmSsp] from a slice, choosing the correct version.
    pub fn parse(buf: &[u8]) -> SspResult<DenmSsp> {
        if buf.len() < DENM_SSP_V1_LEN {
            return Err(SspError::Length);
        }

        let version = buf[0];

        match version {
            SSP_VERSION_1 => Ok(DenmSsp::V1(DenmSspV1::parse(buf)?)),
            SSP_VERSION_2 => Ok(DenmSsp::V2(DenmSspV2::parse(buf)?)),
            _ if buf.len() >= DENM_SSP_V2_LEN => {
                let mut raw = [0u8; DENM_SSP_V2_LEN - 1];
                raw.copy_from_slice(&buf[1..DENM_SSP_V2_LEN - 1]);
                Ok(DenmSsp::Unknown(DenmSspV2::from_raw_permissions(raw)))
            }
            _ => Err(SspError::Malformed),
        }
    }

    /// Query whether the DENM SSP is version 1.
    pub const fn is_v1(&self) -> bool {
        match self {
            DenmSsp::V1(_) => true,
            _ => false,
        }
    }

    /// Query whether the DENM SSP is version 2.
    pub const fn is_v2(&self) -> bool {
        match self {
            DenmSsp::V2(_) => true,
            _ => false,
        }
    }

    /// Query whether the DENM SSP has the given permission.
    pub fn has_permission(&self, permission: DenmPermission) -> bool {
        match self {
            DenmSsp::V1(v1_ssp) => v1_ssp.has_permission(permission),
            DenmSsp::V2(v2_ssp) => v2_ssp.has_permission(permission),
            DenmSsp::Unknown(u_ssp) => u_ssp.has_permission(permission),
        }
    }
}

impl From<DenmSspV1> for DenmSsp {
    fn from(value: DenmSspV1) -> Self {
        Self::V1(value)
    }
}

impl From<DenmSspV2> for DenmSsp {
    fn from(value: DenmSspV2) -> Self {
        Self::V2(value)
    }
}

impl SspTrait for DenmSsp {
    type SspType = DenmSsp;
    type PermissionType = DenmPermission;

    fn contains_permissions_of(&self, other: &Self::SspType) -> bool {
        match (self, other) {
            (DenmSsp::V1(s), DenmSsp::V1(o)) => s.contains_permissions_of(o),
            (DenmSsp::V2(s), DenmSsp::V2(o)) => s.contains_permissions_of(o),
            _ => false,
        }
    }

    fn has_permission(&self, permission: Self::PermissionType) -> bool {
        match self {
            DenmSsp::V1(s) => s.has_permission(permission),
            DenmSsp::V2(s) => s.has_permission(permission),
            DenmSsp::Unknown(s) => s.has_permission(permission),
        }
    }

    fn set_permission(&mut self, permission: Self::PermissionType) {
        match self {
            DenmSsp::V1(s) => s.set_permission(permission),
            DenmSsp::V2(s) => s.set_permission(permission),
            DenmSsp::Unknown(s) => s.set_permission(permission),
        }
    }

    fn clear_permission(&mut self, permission: Self::PermissionType) {
        match self {
            DenmSsp::V1(s) => s.clear_permission(permission),
            DenmSsp::V2(s) => s.clear_permission(permission),
            DenmSsp::Unknown(s) => s.clear_permission(permission),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Decentralized Event Notification Message Service Specific Permissions version 1.
pub struct DenmSspV1(SspContainer<DENM_SSP_V1_LEN>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Decentralized Event Notification Message Service Specific Permissions version 2.
pub struct DenmSspV2(SspContainer<DENM_SSP_V2_LEN>);

impl DenmSspV1 {
    /// Constructs a [DenmSspV1].
    pub const fn new() -> DenmSspV1 {
        DenmSspV1(SspContainer::new(SSP_VERSION_1))
    }

    /// Get the size of [DenmSspV1] in buffer.
    pub const fn buf_size() -> usize {
        DENM_SSP_V1_LEN
    }

    /// Constructs a [DenmSspV1] from the provided `permissions` value.
    pub const fn from_raw_permissions(permissions: [u8; 3]) -> DenmSspV1 {
        DenmSspV1(SspContainer::from_slice([
            SSP_VERSION_1,
            permissions[0],
            permissions[1],
            permissions[2],
        ]))
    }

    /// Constructs a [DenmSspV1] from bytes, ensuring length and
    /// version are supported.
    pub fn parse(buf: &[u8]) -> SspResult<DenmSspV1> {
        // Ensure no panics.
        if buf.len() < DENM_SSP_V1_LEN {
            return Err(SspError::Length);
        }

        // Ensure version is supported.
        if buf[0] != SSP_VERSION_1 {
            return Err(SspError::Version);
        }

        Ok(DenmSspV1(SspContainer::from_bytes(buf)))
    }
}

impl SspTrait for DenmSspV1 {
    type SspType = DenmSspV1;
    type PermissionType = DenmPermission;

    fn contains_permissions_of(&self, other: &Self::SspType) -> bool {
        self.0.inner[1] | other.0.inner[1] == self.0.inner[1]
            && self.0.inner[2] | other.0.inner[2] == self.0.inner[2]
    }

    fn has_permission(&self, permission: Self::PermissionType) -> bool {
        match permission {
            DenmPermission::HumanPresenceOnTheRoad => self
                .0
                .read_bit::<{ field::HUMAN_ON_ROAD.0 }, { field::HUMAN_ON_ROAD.1 }>(),
            DenmPermission::HazardousLocationAnimalOnTheRoad => self
                .0
                .read_bit::<{ field::ANIMAL_ON_ROAD.0 }, { field::ANIMAL_ON_ROAD.1 }>(),
            DenmPermission::HazardousLocationObstacleOnTheRoad => {
                self.0
                    .read_bit::<{ field::OBSTACLE_ON_ROAD.0 }, { field::OBSTACLE_ON_ROAD.1 }>()
            }
            DenmPermission::HazardousLocationSurfaceCondition => self
                .0
                .read_bit::<{ field::SURFACE_COND.0 }, { field::SURFACE_COND.1 }>(),
            DenmPermission::AdverseWeatherConditionAdhesion => self
                .0
                .read_bit::<{ field::ADHESION.0 }, { field::ADHESION.1 }>(),
            DenmPermission::Roadworks => self
                .0
                .read_bit::<{ field::ROADWORKS.0 }, { field::ROADWORKS.1 }>(),
            DenmPermission::Accident => self
                .0
                .read_bit::<{ field::ACCIDENT.0 }, { field::ACCIDENT.1 }>(),
            DenmPermission::TrafficCondition => self
                .0
                .read_bit::<{ field::TRAFFIC_COND.0 }, { field::TRAFFIC_COND.1 }>(),
            DenmPermission::VehicleBreakdown => self
                .0
                .read_bit::<{ field::VEHICLE_BREAKDOWN.0 }, { field::VEHICLE_BREAKDOWN.1 }>(),
            DenmPermission::DangerousEndOfQueue => self
                .0
                .read_bit::<{ field::END_OF_QUEUE.0 }, { field::END_OF_QUEUE.1 }>(),
            DenmPermission::SlowVehicle => self
                .0
                .read_bit::<{ field::SLOW_VEHICLE.0 }, { field::SLOW_VEHICLE.1 }>(),
            DenmPermission::AdverseWeatherConditionPrecipitation => {
                self.0
                    .read_bit::<{ field::PRECIPITATION.0 }, { field::PRECIPITATION.1 }>()
            }
            DenmPermission::AdverseWeatherConditionVisibility => self
                .0
                .read_bit::<{ field::VISIBILITY.0 }, { field::VISIBILITY.1 }>(),
            DenmPermission::AdverseWeatherConditionExtremeWeatherCondition => self.0.read_bit::<{
                field::EXTREME_WEATHER_COND.0
            }, {
                field::EXTREME_WEATHER_COND.1
            }>(
            ),
            DenmPermission::RescueAndRecoveryWorkInProgress => {
                self.0
                    .read_bit::<{ field::RESCUE_AND_RECOVERY.0 }, { field::RESCUE_AND_RECOVERY.1 }>(
                    )
            }
            DenmPermission::WrongWayDriving => self
                .0
                .read_bit::<{ field::WRONG_WAY_DRIVING.0 }, { field::WRONG_WAY_DRIVING.1 }>(),
            DenmPermission::DangerousSituation => self
                .0
                .read_bit::<{ field::DANGEROUS_SITUATION.0 }, { field::DANGEROUS_SITUATION.1 }>(),
            DenmPermission::SignalViolation => self
                .0
                .read_bit::<{ field::SIGNAL_VIOLATION.0 }, { field::SIGNAL_VIOLATION.1 }>(),
            DenmPermission::CollisionRisk => self
                .0
                .read_bit::<{ field::COLLISION_RISK.0 }, { field::COLLISION_RISK.1 }>(),
            DenmPermission::HazardousLocationDangerousCurve => self
                .0
                .read_bit::<{ field::DANGEROUS_CURVE.0 }, { field::DANGEROUS_CURVE.1 }>(),
            DenmPermission::EmergencyVehicleApproaching => self.0.read_bit::<{
                field::EMERGENCY_VEHICLE_APPROACHING.0
            }, {
                field::EMERGENCY_VEHICLE_APPROACHING.1
            }>(),
            DenmPermission::StationaryVehicle => self
                .0
                .read_bit::<{ field::STATIONARY_VEHICLE.0 }, { field::STATIONARY_VEHICLE.1 }>(),
            DenmPermission::HumanProblem => self
                .0
                .read_bit::<{ field::HUMAN_PROBLEM.0 }, { field::HUMAN_PROBLEM.1 }>(),
            DenmPermission::PostCrash => self
                .0
                .read_bit::<{ field::POST_CRASH.0 }, { field::POST_CRASH.1 }>(),
            _ => false,
        }
    }

    fn set_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            DenmPermission::HumanPresenceOnTheRoad => self
                .0
                .write_bit::<{ field::HUMAN_ON_ROAD.0 }, { field::HUMAN_ON_ROAD.1 }>(true),
            DenmPermission::HazardousLocationAnimalOnTheRoad => self
                .0
                .write_bit::<{ field::ANIMAL_ON_ROAD.0 }, { field::ANIMAL_ON_ROAD.1 }>(true),
            DenmPermission::HazardousLocationObstacleOnTheRoad => {
                self.0
                    .write_bit::<{ field::OBSTACLE_ON_ROAD.0 }, { field::OBSTACLE_ON_ROAD.1 }>(true)
            }
            DenmPermission::HazardousLocationSurfaceCondition => self
                .0
                .write_bit::<{ field::SURFACE_COND.0 }, { field::SURFACE_COND.1 }>(true),
            DenmPermission::AdverseWeatherConditionAdhesion => self
                .0
                .write_bit::<{ field::ADHESION.0 }, { field::ADHESION.1 }>(true),
            DenmPermission::Roadworks => self
                .0
                .write_bit::<{ field::ROADWORKS.0 }, { field::ROADWORKS.1 }>(true),
            DenmPermission::Accident => self
                .0
                .write_bit::<{ field::ACCIDENT.0 }, { field::ACCIDENT.1 }>(true),
            DenmPermission::TrafficCondition => self
                .0
                .write_bit::<{ field::TRAFFIC_COND.0 }, { field::TRAFFIC_COND.1 }>(true),
            DenmPermission::VehicleBreakdown => self
                .0
                .write_bit::<{ field::VEHICLE_BREAKDOWN.0 }, { field::VEHICLE_BREAKDOWN.1 }>(true),
            DenmPermission::DangerousEndOfQueue => self
                .0
                .write_bit::<{ field::END_OF_QUEUE.0 }, { field::END_OF_QUEUE.1 }>(true),
            DenmPermission::SlowVehicle => self
                .0
                .write_bit::<{ field::SLOW_VEHICLE.0 }, { field::SLOW_VEHICLE.1 }>(true),
            DenmPermission::AdverseWeatherConditionPrecipitation => {
                self.0
                    .write_bit::<{ field::PRECIPITATION.0 }, { field::PRECIPITATION.1 }>(true)
            }
            DenmPermission::AdverseWeatherConditionVisibility => self
                .0
                .write_bit::<{ field::VISIBILITY.0 }, { field::VISIBILITY.1 }>(true),
            DenmPermission::AdverseWeatherConditionExtremeWeatherCondition => self.0.write_bit::<{
                field::EXTREME_WEATHER_COND.0
            }, {
                field::EXTREME_WEATHER_COND.1
            }>(
                true
            ),
            DenmPermission::RescueAndRecoveryWorkInProgress => self.0.write_bit::<{
                field::RESCUE_AND_RECOVERY.0
            }, {
                field::RESCUE_AND_RECOVERY.1
            }>(true),
            DenmPermission::WrongWayDriving => self
                .0
                .write_bit::<{ field::WRONG_WAY_DRIVING.0 }, { field::WRONG_WAY_DRIVING.1 }>(true),
            DenmPermission::DangerousSituation => self
                .0
                .write_bit::<{ field::DANGEROUS_SITUATION.0 }, { field::DANGEROUS_SITUATION.1 }>(
                    true,
                ),
            DenmPermission::SignalViolation => self
                .0
                .write_bit::<{ field::SIGNAL_VIOLATION.0 }, { field::SIGNAL_VIOLATION.1 }>(true),
            DenmPermission::CollisionRisk => self
                .0
                .write_bit::<{ field::COLLISION_RISK.0 }, { field::COLLISION_RISK.1 }>(true),
            DenmPermission::HazardousLocationDangerousCurve => self
                .0
                .write_bit::<{ field::DANGEROUS_CURVE.0 }, { field::DANGEROUS_CURVE.1 }>(true),
            DenmPermission::EmergencyVehicleApproaching => self.0.write_bit::<{
                field::EMERGENCY_VEHICLE_APPROACHING.0
            }, {
                field::EMERGENCY_VEHICLE_APPROACHING.1
            }>(true),
            DenmPermission::StationaryVehicle => self
                .0
                .write_bit::<{ field::STATIONARY_VEHICLE.0 }, { field::STATIONARY_VEHICLE.1 }>(
                    true,
                ),
            DenmPermission::HumanProblem => self
                .0
                .write_bit::<{ field::HUMAN_PROBLEM.0 }, { field::HUMAN_PROBLEM.1 }>(true),
            DenmPermission::PostCrash => self
                .0
                .write_bit::<{ field::POST_CRASH.0 }, { field::POST_CRASH.1 }>(true),
            _ => {}
        }
    }

    fn clear_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            DenmPermission::HumanPresenceOnTheRoad => self
                .0
                .write_bit::<{ field::HUMAN_ON_ROAD.0 }, { field::HUMAN_ON_ROAD.1 }>(false),
            DenmPermission::HazardousLocationAnimalOnTheRoad => self
                .0
                .write_bit::<{ field::ANIMAL_ON_ROAD.0 }, { field::ANIMAL_ON_ROAD.1 }>(false),
            DenmPermission::HazardousLocationObstacleOnTheRoad => {
                self.0
                    .write_bit::<{ field::OBSTACLE_ON_ROAD.0 }, { field::OBSTACLE_ON_ROAD.1 }>(
                        false,
                    )
            }
            DenmPermission::HazardousLocationSurfaceCondition => self
                .0
                .write_bit::<{ field::SURFACE_COND.0 }, { field::SURFACE_COND.1 }>(false),
            DenmPermission::AdverseWeatherConditionAdhesion => self
                .0
                .write_bit::<{ field::ADHESION.0 }, { field::ADHESION.1 }>(false),
            DenmPermission::Roadworks => self
                .0
                .write_bit::<{ field::ROADWORKS.0 }, { field::ROADWORKS.1 }>(false),
            DenmPermission::Accident => self
                .0
                .write_bit::<{ field::ACCIDENT.0 }, { field::ACCIDENT.1 }>(false),
            DenmPermission::TrafficCondition => self
                .0
                .write_bit::<{ field::TRAFFIC_COND.0 }, { field::TRAFFIC_COND.1 }>(false),
            DenmPermission::VehicleBreakdown => self
                .0
                .write_bit::<{ field::VEHICLE_BREAKDOWN.0 }, { field::VEHICLE_BREAKDOWN.1 }>(false),
            DenmPermission::DangerousEndOfQueue => self
                .0
                .write_bit::<{ field::END_OF_QUEUE.0 }, { field::END_OF_QUEUE.1 }>(false),
            DenmPermission::SlowVehicle => self
                .0
                .write_bit::<{ field::SLOW_VEHICLE.0 }, { field::SLOW_VEHICLE.1 }>(false),
            DenmPermission::AdverseWeatherConditionPrecipitation => {
                self.0
                    .write_bit::<{ field::PRECIPITATION.0 }, { field::PRECIPITATION.1 }>(false)
            }
            DenmPermission::AdverseWeatherConditionVisibility => self
                .0
                .write_bit::<{ field::VISIBILITY.0 }, { field::VISIBILITY.1 }>(false),
            DenmPermission::AdverseWeatherConditionExtremeWeatherCondition => self.0.write_bit::<{
                field::EXTREME_WEATHER_COND.0
            }, {
                field::EXTREME_WEATHER_COND.1
            }>(
                true
            ),
            DenmPermission::RescueAndRecoveryWorkInProgress => self.0.write_bit::<{
                field::RESCUE_AND_RECOVERY.0
            }, {
                field::RESCUE_AND_RECOVERY.1
            }>(false),
            DenmPermission::WrongWayDriving => self
                .0
                .write_bit::<{ field::WRONG_WAY_DRIVING.0 }, { field::WRONG_WAY_DRIVING.1 }>(false),
            DenmPermission::DangerousSituation => self
                .0
                .write_bit::<{ field::DANGEROUS_SITUATION.0 }, { field::DANGEROUS_SITUATION.1 }>(
                    true,
                ),
            DenmPermission::SignalViolation => self
                .0
                .write_bit::<{ field::SIGNAL_VIOLATION.0 }, { field::SIGNAL_VIOLATION.1 }>(false),
            DenmPermission::CollisionRisk => self
                .0
                .write_bit::<{ field::COLLISION_RISK.0 }, { field::COLLISION_RISK.1 }>(false),
            DenmPermission::HazardousLocationDangerousCurve => self
                .0
                .write_bit::<{ field::DANGEROUS_CURVE.0 }, { field::DANGEROUS_CURVE.1 }>(false),
            DenmPermission::EmergencyVehicleApproaching => self.0.write_bit::<{
                field::EMERGENCY_VEHICLE_APPROACHING.0
            }, {
                field::EMERGENCY_VEHICLE_APPROACHING.1
            }>(false),
            DenmPermission::StationaryVehicle => self
                .0
                .write_bit::<{ field::STATIONARY_VEHICLE.0 }, { field::STATIONARY_VEHICLE.1 }>(
                    true,
                ),
            DenmPermission::HumanProblem => self
                .0
                .write_bit::<{ field::HUMAN_PROBLEM.0 }, { field::HUMAN_PROBLEM.1 }>(false),
            DenmPermission::PostCrash => self
                .0
                .write_bit::<{ field::POST_CRASH.0 }, { field::POST_CRASH.1 }>(false),
            _ => {}
        }
    }
}

impl DenmSspV2 {
    /// Constructs a [DenmSspV2].
    pub const fn new() -> DenmSspV2 {
        DenmSspV2(SspContainer::new(SSP_VERSION_2))
    }

    /// Get the size of [DenmSspV2] in buffer.
    pub const fn buf_size() -> usize {
        DENM_SSP_V2_LEN
    }

    /// Constructs a [DenmSspV2] from the provided `permissions` value.
    pub const fn from_raw_permissions(permissions: [u8; 4]) -> DenmSspV2 {
        DenmSspV2(SspContainer::from_slice([
            SSP_VERSION_2,
            permissions[0],
            permissions[1],
            permissions[2],
            permissions[3],
        ]))
    }

    /// Constructs a [DenmSspV2] from bytes, ensuring length and
    /// version are supported.
    pub fn parse(buf: &[u8]) -> SspResult<DenmSspV2> {
        // Ensure no panics.
        if buf.len() < DENM_SSP_V2_LEN {
            return Err(SspError::Length);
        }

        // Ensure version is supported.
        if buf[0] != SSP_VERSION_2 {
            return Err(SspError::Version);
        }

        Ok(DenmSspV2(SspContainer::from_bytes(buf)))
    }
}

impl SspTrait for DenmSspV2 {
    type SspType = DenmSspV2;
    type PermissionType = DenmPermission;

    fn contains_permissions_of(&self, other: &Self::SspType) -> bool {
        self.0.inner[1] | other.0.inner[1] == self.0.inner[1]
            && self.0.inner[2] | other.0.inner[2] == self.0.inner[2]
    }

    fn has_permission(&self, permission: Self::PermissionType) -> bool {
        match permission {
            DenmPermission::HumanPresenceOnTheRoad => self
                .0
                .read_bit::<{ field::HUMAN_ON_ROAD.0 }, { field::HUMAN_ON_ROAD.1 }>(),
            DenmPermission::HazardousLocationAnimalOnTheRoad => self
                .0
                .read_bit::<{ field::ANIMAL_ON_ROAD.0 }, { field::ANIMAL_ON_ROAD.1 }>(),
            DenmPermission::HazardousLocationObstacleOnTheRoad => {
                self.0
                    .read_bit::<{ field::OBSTACLE_ON_ROAD.0 }, { field::OBSTACLE_ON_ROAD.1 }>()
            }
            DenmPermission::HazardousLocationSurfaceCondition => self
                .0
                .read_bit::<{ field::SURFACE_COND.0 }, { field::SURFACE_COND.1 }>(),
            DenmPermission::AdverseWeatherConditionAdhesion => self
                .0
                .read_bit::<{ field::ADHESION.0 }, { field::ADHESION.1 }>(),
            DenmPermission::Roadworks => self
                .0
                .read_bit::<{ field::ROADWORKS.0 }, { field::ROADWORKS.1 }>(),
            DenmPermission::Accident => self
                .0
                .read_bit::<{ field::ACCIDENT.0 }, { field::ACCIDENT.1 }>(),
            DenmPermission::TrafficCondition => self
                .0
                .read_bit::<{ field::TRAFFIC_COND.0 }, { field::TRAFFIC_COND.1 }>(),
            DenmPermission::VehicleBreakdown => self
                .0
                .read_bit::<{ field::VEHICLE_BREAKDOWN.0 }, { field::VEHICLE_BREAKDOWN.1 }>(),
            DenmPermission::DangerousEndOfQueue => self
                .0
                .read_bit::<{ field::END_OF_QUEUE.0 }, { field::END_OF_QUEUE.1 }>(),
            DenmPermission::SlowVehicle => self
                .0
                .read_bit::<{ field::SLOW_VEHICLE.0 }, { field::SLOW_VEHICLE.1 }>(),
            DenmPermission::AdverseWeatherConditionPrecipitation => {
                self.0
                    .read_bit::<{ field::PRECIPITATION.0 }, { field::PRECIPITATION.1 }>()
            }
            DenmPermission::AdverseWeatherConditionVisibility => self
                .0
                .read_bit::<{ field::VISIBILITY.0 }, { field::VISIBILITY.1 }>(),
            DenmPermission::AdverseWeatherConditionExtremeWeatherCondition => self.0.read_bit::<{
                field::EXTREME_WEATHER_COND.0
            }, {
                field::EXTREME_WEATHER_COND.1
            }>(
            ),
            DenmPermission::RescueAndRecoveryWorkInProgress => {
                self.0
                    .read_bit::<{ field::RESCUE_AND_RECOVERY.0 }, { field::RESCUE_AND_RECOVERY.1 }>(
                    )
            }
            DenmPermission::WrongWayDriving => self
                .0
                .read_bit::<{ field::WRONG_WAY_DRIVING.0 }, { field::WRONG_WAY_DRIVING.1 }>(),
            DenmPermission::DangerousSituation => self
                .0
                .read_bit::<{ field::DANGEROUS_SITUATION.0 }, { field::DANGEROUS_SITUATION.1 }>(),
            DenmPermission::SignalViolation => self
                .0
                .read_bit::<{ field::SIGNAL_VIOLATION.0 }, { field::SIGNAL_VIOLATION.1 }>(),
            DenmPermission::CollisionRisk => self
                .0
                .read_bit::<{ field::COLLISION_RISK.0 }, { field::COLLISION_RISK.1 }>(),
            DenmPermission::HazardousLocationDangerousCurve => self
                .0
                .read_bit::<{ field::DANGEROUS_CURVE.0 }, { field::DANGEROUS_CURVE.1 }>(),
            DenmPermission::EmergencyVehicleApproaching => self.0.read_bit::<{
                field::EMERGENCY_VEHICLE_APPROACHING.0
            }, {
                field::EMERGENCY_VEHICLE_APPROACHING.1
            }>(),
            DenmPermission::StationaryVehicle => self
                .0
                .read_bit::<{ field::STATIONARY_VEHICLE.0 }, { field::STATIONARY_VEHICLE.1 }>(),
            DenmPermission::HumanProblem => self
                .0
                .read_bit::<{ field::HUMAN_PROBLEM.0 }, { field::HUMAN_PROBLEM.1 }>(),
            DenmPermission::PostCrash => self
                .0
                .read_bit::<{ field::POST_CRASH.0 }, { field::POST_CRASH.1 }>(),
            DenmPermission::RailwayLevelCrossing => self.0.read_bit::<{
                field::RAILWAY_LEVEL_CROSSING.0
            }, {
                field::RAILWAY_LEVEL_CROSSING.1
            }>(),
            DenmPermission::PublicTransportVehicleApproaching => self.0.read_bit::<{
                field::PUBLIC_TRANSPORT_VEHICLE_APPROACHING.0
            }, {
                field::PUBLIC_TRANSPORT_VEHICLE_APPROACHING.1
            }>(),
            DenmPermission::Aquaplaning => self.0.read_bit::<{ field::AQUAPLANING.0 }, {
                field::AQUAPLANING.1
            }>(),
            DenmPermission::Impassability => self.0.read_bit::<{ field::IMPASSABILITY.0 }, {
                field::IMPASSABILITY.1
            }>(),
        }
    }

    fn set_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            DenmPermission::HumanPresenceOnTheRoad => self
                .0
                .write_bit::<{ field::HUMAN_ON_ROAD.0 }, { field::HUMAN_ON_ROAD.1 }>(true),
            DenmPermission::HazardousLocationAnimalOnTheRoad => self
                .0
                .write_bit::<{ field::ANIMAL_ON_ROAD.0 }, { field::ANIMAL_ON_ROAD.1 }>(true),
            DenmPermission::HazardousLocationObstacleOnTheRoad => {
                self.0
                    .write_bit::<{ field::OBSTACLE_ON_ROAD.0 }, { field::OBSTACLE_ON_ROAD.1 }>(true)
            }
            DenmPermission::HazardousLocationSurfaceCondition => self
                .0
                .write_bit::<{ field::SURFACE_COND.0 }, { field::SURFACE_COND.1 }>(true),
            DenmPermission::AdverseWeatherConditionAdhesion => self
                .0
                .write_bit::<{ field::ADHESION.0 }, { field::ADHESION.1 }>(true),
            DenmPermission::Roadworks => self
                .0
                .write_bit::<{ field::ROADWORKS.0 }, { field::ROADWORKS.1 }>(true),
            DenmPermission::Accident => self
                .0
                .write_bit::<{ field::ACCIDENT.0 }, { field::ACCIDENT.1 }>(true),
            DenmPermission::TrafficCondition => self
                .0
                .write_bit::<{ field::TRAFFIC_COND.0 }, { field::TRAFFIC_COND.1 }>(true),
            DenmPermission::VehicleBreakdown => self
                .0
                .write_bit::<{ field::VEHICLE_BREAKDOWN.0 }, { field::VEHICLE_BREAKDOWN.1 }>(true),
            DenmPermission::DangerousEndOfQueue => self
                .0
                .write_bit::<{ field::END_OF_QUEUE.0 }, { field::END_OF_QUEUE.1 }>(true),
            DenmPermission::SlowVehicle => self
                .0
                .write_bit::<{ field::SLOW_VEHICLE.0 }, { field::SLOW_VEHICLE.1 }>(true),
            DenmPermission::AdverseWeatherConditionPrecipitation => {
                self.0
                    .write_bit::<{ field::PRECIPITATION.0 }, { field::PRECIPITATION.1 }>(true)
            }
            DenmPermission::AdverseWeatherConditionVisibility => self
                .0
                .write_bit::<{ field::VISIBILITY.0 }, { field::VISIBILITY.1 }>(true),
            DenmPermission::AdverseWeatherConditionExtremeWeatherCondition => self.0.write_bit::<{
                field::EXTREME_WEATHER_COND.0
            }, {
                field::EXTREME_WEATHER_COND.1
            }>(
                true
            ),
            DenmPermission::RescueAndRecoveryWorkInProgress => self.0.write_bit::<{
                field::RESCUE_AND_RECOVERY.0
            }, {
                field::RESCUE_AND_RECOVERY.1
            }>(true),
            DenmPermission::WrongWayDriving => self
                .0
                .write_bit::<{ field::WRONG_WAY_DRIVING.0 }, { field::WRONG_WAY_DRIVING.1 }>(true),
            DenmPermission::DangerousSituation => self
                .0
                .write_bit::<{ field::DANGEROUS_SITUATION.0 }, { field::DANGEROUS_SITUATION.1 }>(
                    true,
                ),
            DenmPermission::SignalViolation => self
                .0
                .write_bit::<{ field::SIGNAL_VIOLATION.0 }, { field::SIGNAL_VIOLATION.1 }>(true),
            DenmPermission::CollisionRisk => self
                .0
                .write_bit::<{ field::COLLISION_RISK.0 }, { field::COLLISION_RISK.1 }>(true),
            DenmPermission::HazardousLocationDangerousCurve => self
                .0
                .write_bit::<{ field::DANGEROUS_CURVE.0 }, { field::DANGEROUS_CURVE.1 }>(true),
            DenmPermission::EmergencyVehicleApproaching => self.0.write_bit::<{
                field::EMERGENCY_VEHICLE_APPROACHING.0
            }, {
                field::EMERGENCY_VEHICLE_APPROACHING.1
            }>(true),
            DenmPermission::StationaryVehicle => self
                .0
                .write_bit::<{ field::STATIONARY_VEHICLE.0 }, { field::STATIONARY_VEHICLE.1 }>(
                    true,
                ),
            DenmPermission::HumanProblem => self
                .0
                .write_bit::<{ field::HUMAN_PROBLEM.0 }, { field::HUMAN_PROBLEM.1 }>(true),
            DenmPermission::PostCrash => self
                .0
                .write_bit::<{ field::POST_CRASH.0 }, { field::POST_CRASH.1 }>(true),
            DenmPermission::RailwayLevelCrossing => self.0.write_bit::<{
                field::RAILWAY_LEVEL_CROSSING.0
            }, {
                field::RAILWAY_LEVEL_CROSSING.1
            }>(true),
            DenmPermission::PublicTransportVehicleApproaching => self.0.write_bit::<{
                field::PUBLIC_TRANSPORT_VEHICLE_APPROACHING.0
            }, {
                field::PUBLIC_TRANSPORT_VEHICLE_APPROACHING.1
            }>(true),
            DenmPermission::Aquaplaning => self.0.write_bit::<{ field::AQUAPLANING.0 }, {
                field::AQUAPLANING.1
            }>(true),
            DenmPermission::Impassability => self.0.write_bit::<{ field::IMPASSABILITY.0 }, {
                field::IMPASSABILITY.1
            }>(true),
        }
    }

    fn clear_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            DenmPermission::HumanPresenceOnTheRoad => self
                .0
                .write_bit::<{ field::HUMAN_ON_ROAD.0 }, { field::HUMAN_ON_ROAD.1 }>(false),
            DenmPermission::HazardousLocationAnimalOnTheRoad => self
                .0
                .write_bit::<{ field::ANIMAL_ON_ROAD.0 }, { field::ANIMAL_ON_ROAD.1 }>(false),
            DenmPermission::HazardousLocationObstacleOnTheRoad => {
                self.0
                    .write_bit::<{ field::OBSTACLE_ON_ROAD.0 }, { field::OBSTACLE_ON_ROAD.1 }>(
                        false,
                    )
            }
            DenmPermission::HazardousLocationSurfaceCondition => self
                .0
                .write_bit::<{ field::SURFACE_COND.0 }, { field::SURFACE_COND.1 }>(false),
            DenmPermission::AdverseWeatherConditionAdhesion => self
                .0
                .write_bit::<{ field::ADHESION.0 }, { field::ADHESION.1 }>(false),
            DenmPermission::Roadworks => self
                .0
                .write_bit::<{ field::ROADWORKS.0 }, { field::ROADWORKS.1 }>(false),
            DenmPermission::Accident => self
                .0
                .write_bit::<{ field::ACCIDENT.0 }, { field::ACCIDENT.1 }>(false),
            DenmPermission::TrafficCondition => self
                .0
                .write_bit::<{ field::TRAFFIC_COND.0 }, { field::TRAFFIC_COND.1 }>(false),
            DenmPermission::VehicleBreakdown => self
                .0
                .write_bit::<{ field::VEHICLE_BREAKDOWN.0 }, { field::VEHICLE_BREAKDOWN.1 }>(false),
            DenmPermission::DangerousEndOfQueue => self
                .0
                .write_bit::<{ field::END_OF_QUEUE.0 }, { field::END_OF_QUEUE.1 }>(false),
            DenmPermission::SlowVehicle => self
                .0
                .write_bit::<{ field::SLOW_VEHICLE.0 }, { field::SLOW_VEHICLE.1 }>(false),
            DenmPermission::AdverseWeatherConditionPrecipitation => {
                self.0
                    .write_bit::<{ field::PRECIPITATION.0 }, { field::PRECIPITATION.1 }>(false)
            }
            DenmPermission::AdverseWeatherConditionVisibility => self
                .0
                .write_bit::<{ field::VISIBILITY.0 }, { field::VISIBILITY.1 }>(false),
            DenmPermission::AdverseWeatherConditionExtremeWeatherCondition => self.0.write_bit::<{
                field::EXTREME_WEATHER_COND.0
            }, {
                field::EXTREME_WEATHER_COND.1
            }>(
                true
            ),
            DenmPermission::RescueAndRecoveryWorkInProgress => self.0.write_bit::<{
                field::RESCUE_AND_RECOVERY.0
            }, {
                field::RESCUE_AND_RECOVERY.1
            }>(false),
            DenmPermission::WrongWayDriving => self
                .0
                .write_bit::<{ field::WRONG_WAY_DRIVING.0 }, { field::WRONG_WAY_DRIVING.1 }>(false),
            DenmPermission::DangerousSituation => self
                .0
                .write_bit::<{ field::DANGEROUS_SITUATION.0 }, { field::DANGEROUS_SITUATION.1 }>(
                    true,
                ),
            DenmPermission::SignalViolation => self
                .0
                .write_bit::<{ field::SIGNAL_VIOLATION.0 }, { field::SIGNAL_VIOLATION.1 }>(false),
            DenmPermission::CollisionRisk => self
                .0
                .write_bit::<{ field::COLLISION_RISK.0 }, { field::COLLISION_RISK.1 }>(false),
            DenmPermission::HazardousLocationDangerousCurve => self
                .0
                .write_bit::<{ field::DANGEROUS_CURVE.0 }, { field::DANGEROUS_CURVE.1 }>(false),
            DenmPermission::EmergencyVehicleApproaching => self.0.write_bit::<{
                field::EMERGENCY_VEHICLE_APPROACHING.0
            }, {
                field::EMERGENCY_VEHICLE_APPROACHING.1
            }>(false),
            DenmPermission::StationaryVehicle => self
                .0
                .write_bit::<{ field::STATIONARY_VEHICLE.0 }, { field::STATIONARY_VEHICLE.1 }>(
                    true,
                ),
            DenmPermission::HumanProblem => self
                .0
                .write_bit::<{ field::HUMAN_PROBLEM.0 }, { field::HUMAN_PROBLEM.1 }>(false),
            DenmPermission::PostCrash => self
                .0
                .write_bit::<{ field::POST_CRASH.0 }, { field::POST_CRASH.1 }>(false),
            DenmPermission::RailwayLevelCrossing => self.0.write_bit::<{
                field::RAILWAY_LEVEL_CROSSING.0
            }, {
                field::RAILWAY_LEVEL_CROSSING.1
            }>(false),
            DenmPermission::PublicTransportVehicleApproaching => self.0.write_bit::<{
                field::PUBLIC_TRANSPORT_VEHICLE_APPROACHING.0
            }, {
                field::PUBLIC_TRANSPORT_VEHICLE_APPROACHING.1
            }>(false),
            DenmPermission::Aquaplaning => self.0.write_bit::<{ field::AQUAPLANING.0 }, {
                field::AQUAPLANING.1
            }>(false),
            DenmPermission::Impassability => self.0.write_bit::<{ field::IMPASSABILITY.0 }, {
                field::IMPASSABILITY.1
            }>(false),
        }
    }
}
