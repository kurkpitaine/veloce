use veloce_asn1::{
    defs::etsi_103097_v211::ieee1609Dot2Base_types::{
        BitmapSsp, BitmapSspRange, PsidSsp, PsidSspRange, ServiceSpecificPermissions, SspRange,
    },
    prelude::rasn::types::Integer,
};

use super::ssp::{crl::CrlSsp, ctl::CtlSsp, scr::ScrSsp, SspError};

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

pub struct AIDUnsupportedFormatError;

impl TryFrom<&Integer> for AID {
    type Error = AIDUnsupportedFormatError;

    fn try_from(value: &Integer) -> Result<Self, Self::Error> {
        if value < &Integer::from(0) {
            return Err(AIDUnsupportedFormatError);
        }

        let (_, val) = value.to_u64_digits();

        if val.len() != 1 {
            return Err(AIDUnsupportedFormatError);
        }

        Ok(AID::from(val[0]))
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

/// Signing permission.
/// the `mask` field of each variant is used to describe an SSP Range type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Permission {
    /// Certificate Revocation List service permission.
    CRL { ssp: CrlSsp, mask: Option<Vec<u8>> },
    /// Certificate Trust List service permission.
    CTL { ssp: CtlSsp, mask: Option<Vec<u8>> },
    /// Secured Certificate Request service permission.
    SCR { ssp: ScrSsp, mask: Option<Vec<u8>> },
    /// Fallback variant for an unknown permission type.
    Unknown {
        aid: u64,
        ssp: Option<Vec<u8>>,
        mask: Option<Vec<u8>>,
    },
}

impl Permission {
    /// Get the AID of the permission.
    pub fn aid(&self) -> AID {
        match self {
            Permission::CRL { .. } => AID::CRL,
            Permission::CTL { .. } => AID::CTL,
            Permission::SCR { .. } => AID::SCR,
            Permission::Unknown { aid, .. } => AID::Unknown(*aid),
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
            AID::CRL => {
                let raw = extract_ssp(&value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = CrlSsp::parse(&raw.0).map_err(PermissionError::SSP)?;

                Permission::CRL { ssp, mask: None }
            }
            AID::SCR => {
                let raw = extract_ssp(&value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = ScrSsp::parse(&raw.0).map_err(PermissionError::SSP)?;

                Permission::SCR { ssp, mask: None }
            }
            AID::CTL => {
                let raw = extract_ssp(&value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = CtlSsp::parse(&raw.0).map_err(PermissionError::SSP)?;

                Permission::CTL { ssp, mask: None }
            }
            _ => {
                let raw = extract_ssp(&value)?;

                Permission::Unknown {
                    aid: aid.into(),
                    ssp: raw.and_then(|v| Some(v.0.to_vec())),
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
            AID::CRL => {
                let range = extract_ssp_range(&value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = CrlSsp::parse(&range.ssp_value).map_err(PermissionError::SSP)?;
                let mask = Some(range.ssp_bitmask.to_vec());

                Permission::CRL { ssp, mask }
            }
            AID::SCR => {
                let range = extract_ssp_range(&value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = ScrSsp::parse(&range.ssp_value).map_err(PermissionError::SSP)?;
                let mask = Some(range.ssp_bitmask.to_vec());

                Permission::SCR { ssp, mask }
            }
            AID::CTL => {
                let range = extract_ssp_range(&value)?.ok_or(PermissionError::NoSSP(aid))?;
                let ssp = CtlSsp::parse(&range.ssp_value).map_err(PermissionError::SSP)?;
                let mask = Some(range.ssp_bitmask.to_vec());

                Permission::CTL { ssp, mask }
            }
            _ => {
                let range = extract_ssp_range(&value)?;

                Permission::Unknown {
                    aid: aid.into(),
                    ssp: range.and_then(|r| Some(r.ssp_value.to_vec())),
                    mask: range.and_then(|r| Some(r.ssp_bitmask.to_vec())),
                }
            }
        };

        Ok(res)
    }
}
