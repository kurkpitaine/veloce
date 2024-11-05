use core::fmt;

use veloce_asn1::{
    defs::etsi_103097_v211::ieee1609_dot2_base_types::{
        BitmapSsp, BitmapSspRange, PsidSsp, PsidSspRange, ServiceSpecificPermissions, SspRange,
    },
    prelude::rasn::types::Integer,
};

use super::ssp::{
    cam::CamSsp, crl::CrlSsp, ctl::CtlSsp, denm::DenmSsp, scr::ScrSsp, SspError, SspTrait,
};

enum_with_unknown! {
    /// ITS Application Object Identifier Registration numbers, as ETSI TS 102 965 V2.1.1.
   pub enum AID(u64) {
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
}

impl fmt::Display for AID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct AIDUnsupportedFormatError;

impl TryFrom<&Integer> for AID {
    type Error = AIDUnsupportedFormatError;

    fn try_from(value: &Integer) -> Result<Self, Self::Error> {
        use veloce_asn1::prelude::num_traits::ToPrimitive;
        value
            .to_u64()
            .ok_or(AIDUnsupportedFormatError)
            .map(AID::from)
    }
}

impl From<AID> for Integer {
    fn from(value: AID) -> Self {
        u64::from(value).into()
    }
}

/// Generic container for SSPs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PermissionSspContainer<S: SspTrait> {
    /// SSP.
    pub ssp: S,
    /// Mask for SSP Range.
    pub mask: Option<Vec<u8>>,
}

impl<S: SspTrait> From<S> for PermissionSspContainer<S> {
    fn from(ssp: S) -> Self {
        Self { ssp, mask: None }
    }
}

/// Permission error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PermissionError {
    /// AID format is not supported, ie: too big for our platform.
    UnsupportedAIDFormat,
    /// Unsupported SSP format. Should be bitmapssp.
    UnsupportedSSPFormat,
    /// No SSP present for [AID], but it should be.
    NoSSP(AID),
    /// SSP value and mask length mismatch.
    LenMismatch,
    /// Generic SSP error.
    SSP(SspError),
}

impl fmt::Display for PermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PermissionError::UnsupportedAIDFormat => write!(f, "Unsupported AID format"),
            PermissionError::UnsupportedSSPFormat => write!(f, "Unsupported SSP format"),
            PermissionError::NoSSP(aid) => write!(f, "No SSP for AID: {}", aid),
            PermissionError::LenMismatch => write!(f, "SSP and mask length mismatch"),
            PermissionError::SSP(e) => write!(f, "SSP error: {}", e),
        }
    }
}

/// Signing permission.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Permission {
    /// Cooperative Awareness message service permission.
    CAM(PermissionSspContainer<CamSsp>),
    /// Decentralized Event Notification message service permission.
    DENM(PermissionSspContainer<DenmSsp>),
    /// Certificate Revocation List service permission.
    CRL(PermissionSspContainer<CrlSsp>),
    /// Certificate Trust List service permission.
    CTL(PermissionSspContainer<CtlSsp>),
    /// GeoNetworking Management Communications service permission.
    GnMgmt,
    /// Secured Certificate Request service permission.
    SCR(PermissionSspContainer<ScrSsp>),
    /// Fallback variant for an unknown permission type.
    Unknown {
        aid: u64,
        ssp: Option<Vec<u8>>,
        mask: Option<Vec<u8>>,
    },
}

impl Default for Permission {
    fn default() -> Self {
        Self::Unknown {
            aid: 0,
            ssp: None,
            mask: None,
        }
    }
}

impl Permission {
    /// Get the AID of the permission.
    pub fn aid(&self) -> AID {
        match self {
            Permission::CAM(_) => AID::CA,
            Permission::DENM(_) => AID::DEN,
            Permission::CRL(_) => AID::CRL,
            Permission::CTL(_) => AID::CTL,
            Permission::GnMgmt => AID::GnMgmt,
            Permission::SCR(_) => AID::SCR,
            Permission::Unknown { aid, .. } => AID::from(*aid),
        }
    }

    /// Check if the permission contains the other permissions.
    pub fn contains_permissions_of(&self, other: &Permission) -> bool {
        match (self, other) {
            (Permission::CAM(l), Permission::CAM(r)) => l.ssp.contains_permissions_of(&r.ssp),
            (Permission::DENM(l), Permission::DENM(r)) => l.ssp.contains_permissions_of(&r.ssp),
            (Permission::CRL(l), Permission::CRL(r)) => l.ssp.contains_permissions_of(&r.ssp),
            (Permission::CTL(l), Permission::CTL(r)) => l.ssp.contains_permissions_of(&r.ssp),
            (Permission::GnMgmt, Permission::GnMgmt) => true,
            (Permission::SCR(l), Permission::SCR(r)) => l.ssp.contains_permissions_of(&r.ssp),
            (
                Permission::Unknown { ssp: Some(l), .. },
                Permission::Unknown { ssp: Some(r), .. },
            ) if l.len() == r.len() => l.iter().zip(r.iter()).all(|(lv, rv)| lv | *rv == *lv),
            _ => false,
        }
    }

    /// Get a reference on the inner [DenmSsp].
    ///
    /// # Panics
    /// This method panics of the inner SSP is not [DenmSsp] type.
    pub fn denm_or_panic(&self) -> &DenmSsp {
        match self {
            Permission::DENM(ssp) => &ssp.ssp,
            _ => panic!("Permission is not DENM type."),
        }
    }
}

impl<'a> TryFrom<&'a PsidSsp> for Permission {
    type Error = PermissionError;

    fn try_from(value: &'a PsidSsp) -> Result<Self, Self::Error> {
        let extract_ssp = |r: &'a PsidSsp| -> Result<Option<&'a BitmapSsp>, PermissionError> {
            let Some(ssp_range) = &r.ssp else {
                return Ok(None);
            };

            let b = match ssp_range {
                ServiceSpecificPermissions::bitmapSsp(b) => b,
                _ => return Err(PermissionError::UnsupportedSSPFormat),
            };

            Ok(Some(b))
        };

        let aid =
            AID::try_from(&value.psid.0).map_err(|_| PermissionError::UnsupportedAIDFormat)?;

        let res = match aid {
            AID::CA => {
                let raw = extract_ssp(value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = CamSsp::parse(&raw.0).map_err(PermissionError::SSP)?;
                Permission::CAM(PermissionSspContainer { ssp, mask: None })
            }
            AID::DEN => {
                let raw = extract_ssp(value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = DenmSsp::parse(&raw.0).map_err(PermissionError::SSP)?;
                Permission::DENM(PermissionSspContainer { ssp, mask: None })
            }
            AID::CRL => {
                let raw = extract_ssp(value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = CrlSsp::parse(&raw.0).map_err(PermissionError::SSP)?;
                Permission::CRL(PermissionSspContainer { ssp, mask: None })
            }
            AID::CTL => {
                let raw = extract_ssp(value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = CtlSsp::parse(&raw.0).map_err(PermissionError::SSP)?;

                Permission::CTL(PermissionSspContainer { ssp, mask: None })
            }
            AID::GnMgmt => Permission::GnMgmt,
            AID::SCR => {
                let raw = extract_ssp(value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = ScrSsp::parse(&raw.0).map_err(PermissionError::SSP)?;

                Permission::SCR(PermissionSspContainer { ssp, mask: None })
            }
            _ => {
                let raw = extract_ssp(value)?;

                Permission::Unknown {
                    aid: aid.into(),
                    ssp: raw.map(|v| v.0.to_vec()),
                    mask: None,
                }
            }
        };

        Ok(res)
    }
}

impl<'a> TryFrom<&'a PsidSspRange> for Permission {
    type Error = PermissionError;

    fn try_from(value: &'a PsidSspRange) -> Result<Self, Self::Error> {
        let extract_ssp_range =
            |r: &'a PsidSspRange| -> Result<Option<&'a BitmapSspRange>, PermissionError> {
                let Some(ssp_range) = &r.ssp_range else {
                    return Ok(None);
                };

                let r = match ssp_range {
                    SspRange::bitmapSspRange(r) => r,
                    _ => return Err(PermissionError::UnsupportedSSPFormat),
                };

                if r.ssp_bitmask.len() != r.ssp_value.len() {
                    return Err(PermissionError::LenMismatch);
                }

                Ok(Some(r))
            };

        let aid =
            AID::try_from(&value.psid.0).map_err(|_| PermissionError::UnsupportedAIDFormat)?;

        let res = match aid {
            AID::CA => {
                let range = extract_ssp_range(value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = CamSsp::parse(&range.ssp_value).map_err(PermissionError::SSP)?;
                let mask = Some(range.ssp_bitmask.to_vec());

                Permission::CAM(PermissionSspContainer { ssp, mask })
            }
            AID::DEN => {
                let range = extract_ssp_range(value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = DenmSsp::parse(&range.ssp_value).map_err(PermissionError::SSP)?;
                let mask = Some(range.ssp_bitmask.to_vec());

                Permission::DENM(PermissionSspContainer { ssp, mask })
            }
            AID::CRL => {
                let range = extract_ssp_range(value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = CrlSsp::parse(&range.ssp_value).map_err(PermissionError::SSP)?;
                let mask = Some(range.ssp_bitmask.to_vec());

                Permission::CRL(PermissionSspContainer { ssp, mask })
            }
            AID::CTL => {
                let range = extract_ssp_range(value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = CtlSsp::parse(&range.ssp_value).map_err(PermissionError::SSP)?;
                let mask = Some(range.ssp_bitmask.to_vec());

                Permission::CTL(PermissionSspContainer { ssp, mask })
            }
            AID::GnMgmt => Permission::GnMgmt,
            AID::SCR => {
                let range = extract_ssp_range(value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = ScrSsp::parse(&range.ssp_value).map_err(PermissionError::SSP)?;
                let mask = Some(range.ssp_bitmask.to_vec());

                Permission::SCR(PermissionSspContainer { ssp, mask })
            }
            _ => {
                let range = extract_ssp_range(value)?;

                Permission::Unknown {
                    aid: aid.into(),
                    ssp: range.map(|r| r.ssp_value.to_vec()),
                    mask: range.map(|r| r.ssp_bitmask.to_vec()),
                }
            }
        };

        Ok(res)
    }
}
