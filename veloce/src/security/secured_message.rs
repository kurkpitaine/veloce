//! Wrapper around a received secured Geonetworking message.
//! This implementation supports ETSI TS 103 097 V2.1.1. V1.3.1 and V1.4.1
//! could be supported also as they use the same Asn.1 message structure.

use veloce_asn1::defs::etsi_103097_v211::{
    etsi_ts103097Module::{EtsiTs103097Data, EtsiTs103097DataSigned},
    ieee1609Dot2::{self, Certificate as EtsiCertificate},
    ieee1609Dot2Base_types::HashedId8,
};
use veloce_asn1::prelude::rasn::{self, error::DecodeError};

use crate::{security::certificate::Certificate, time::TAI2004};

use super::signature::{EcdsaSignature, EcdsaSignatureError};

pub type SecuredMessageResult<T> = core::result::Result<T, SecuredMessageError>;

#[derive(Debug)]
/// Secured message signer identifier method. See [SecuredMessage::signer_identifier].
pub enum SignerIdentifier {
    /// Signer identifier is a certificate digest. Frequently used in CAM messages to
    /// shrink their size over the air.
    Digest(HashedId8),
    /// Signer identifier is a full certificate.
    Certificate(EtsiCertificate),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Secured message errors.
pub enum SecuredMessageError {
    /// Asn.1 decoding error.
    Asn1(DecodeError),
    /// Security protocol version is not supported.
    UnsupportedProtocolVersion,
    /// Secured message content is malformed, ie: a mandatory field
    /// is absent or a present field should be absent.
    Malformed,
    /// Secured message certificate content is malformed.
    MalformedCertificate,
    /// No generation time value in message.
    NoGenerationTime,
    /// Invalid number of certificates. [ieee1609Dot2::SignerIdentifier::certificate] shall contain
    /// exactly one certificate.
    InvalidNumberOfCerts,
    /// Message is not signed.
    NotSigned,
    /// Message is self signed.
    SelfSigned,
    /// Signature error.
    Signature(EcdsaSignatureError),
    /// Signer identifier type is not supported.
    UnsupportedSignerIdentifier,
    /// Message does not contain data. [ieee1609Dot2::SignedDataPayload::data] should be present.
    NoData,
    /// Message data is of wrong type. Should be [ieee1609Dot2::Ieee1609Dot2Content::unsecuredData].
    DataContent,
}

/// Geonetworking secured message wrapper around an [EtsiTs103097DataSigned]
/// structure.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecuredMessage {
    /// Inner message structure.
    inner: EtsiTs103097DataSigned,
}

impl SecuredMessage {
    /// Constructs a [SecuredMessage] from bytes.
    pub fn from_bytes(bytes: &[u8]) -> SecuredMessageResult<Self> {
        Ok(Self {
            inner: Self::decode(bytes)?,
        })
    }

    /// Returns the generation time field of the secured message.
    pub fn generation_time(&self) -> SecuredMessageResult<TAI2004> {
        use ieee1609Dot2::Ieee1609Dot2Content;

        let Ieee1609Dot2Content::signedData(ref sd) = self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        sd.tbs_data
            .header_info
            .generation_time
            .as_ref()
            .ok_or(SecuredMessageError::NoGenerationTime)
            .map(|gen_time| TAI2004::from_millis_const(gen_time.0 .0 as i64))
    }

    /// Returns the message signature.
    pub fn signature(&self) -> SecuredMessageResult<EcdsaSignature> {
        use ieee1609Dot2::Ieee1609Dot2Content;

        let Ieee1609Dot2Content::signedData(ref sd) = self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        let sig =
            EcdsaSignature::try_from(&sd.signature).map_err(SecuredMessageError::Signature)?;

        Ok(sig)
    }

    /// Returns the signer identifier field of the secured message.
    pub fn signer_identifier(&self) -> SecuredMessageResult<SignerIdentifier> {
        use ieee1609Dot2::Ieee1609Dot2Content;

        let Ieee1609Dot2Content::signedData(ref sd) = self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        let signer_id = match &sd.signer {
            ieee1609Dot2::SignerIdentifier::digest(digest) => {
                SignerIdentifier::Digest(digest.clone())
            }
            ieee1609Dot2::SignerIdentifier::certificate(cert_seq) => {
                SignerIdentifier::Certificate(cert_seq.0[0].clone())
            }
            ieee1609Dot2::SignerIdentifier::R_self(_) => {
                return Err(SecuredMessageError::SelfSigned);
            }
            _ => return Err(SecuredMessageError::UnsupportedSignerIdentifier),
        };

        Ok(signer_id)
    }

    fn decode(bytes: &[u8]) -> SecuredMessageResult<EtsiTs103097DataSigned> {
        let data = rasn::coer::decode::<EtsiTs103097DataSigned>(bytes)
            .map_err(SecuredMessageError::Asn1)?;

        Self::verify_etsi_data_signed_constraints(&data)?;

        Ok(data)
    }

    /// Check `data` is valid according to EtsiTs103097Data Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    #[inline]
    fn verify_etsi_data_signed_constraints(
        data: &EtsiTs103097DataSigned,
    ) -> SecuredMessageResult<()> {
        use ieee1609Dot2::Ieee1609Dot2Content;

        SecuredMessage::verify_etsi_data_constraints(&data.0)?;

        let signed_data = match data.0 .0.content {
            Ieee1609Dot2Content::signedData(ref sd) => sd,
            _ => return Err(SecuredMessageError::NotSigned),
        };

        let Some(ref data) = signed_data.tbs_data.payload.data else {
            return Err(SecuredMessageError::NoData);
        };

        match data.content {
            Ieee1609Dot2Content::unsecuredData(_) => {}
            _ => return Err(SecuredMessageError::DataContent),
        };

        Ok(())
    }

    /// Check `data` is valid according to EtsiTs103097Data Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    #[inline]
    fn verify_etsi_data_constraints(data: &EtsiTs103097Data) -> SecuredMessageResult<()> {
        use ieee1609Dot2::{Ieee1609Dot2Content, RecipientInfo, SignerIdentifier};
        if data.0.protocol_version.0 != 3 {
            return Err(SecuredMessageError::UnsupportedProtocolVersion);
        }

        match data.0.content {
            Ieee1609Dot2Content::signedData(ref sd) => {
                let header_info = &sd.tbs_data.header_info;
                if header_info.generation_time.is_none()
                    || header_info.p2pcd_learning_request.is_some()
                    || header_info.missing_crl_identifier.is_some()
                {
                    return Err(SecuredMessageError::Malformed);
                }

                if let SignerIdentifier::certificate(ref seq_of_certs) = sd.signer {
                    if seq_of_certs.0.len() != 1 {
                        return Err(SecuredMessageError::InvalidNumberOfCerts);
                    }

                    Certificate::verify_etsi_constraints(&seq_of_certs.0[0])
                        .map_err(|_| SecuredMessageError::MalformedCertificate)?;
                }
            }
            Ieee1609Dot2Content::encryptedData(ref ed) => {
                for recipient in &ed.recipients.0 {
                    match recipient {
                        RecipientInfo::signedDataRecipInfo(_) | RecipientInfo::certRecipInfo(_) => {
                        }
                        _ => return Err(SecuredMessageError::Malformed),
                    }
                }
            }
            Ieee1609Dot2Content::unsecuredData(_)
            | Ieee1609Dot2Content::signedX509CertificateRequest(_) => {}
            Ieee1609Dot2Content::signedCertificateRequest(_) => {
                return Err(SecuredMessageError::Malformed)
            }
            _ => {}
        }

        Ok(())
    }
}
