//! Wrapper around a received secured Geonetworking message.
//! This implementation supports ETSI TS 103 097 V2.1.1. V1.3.1 and V1.4.1
//! could be supported also as they use the same Asn.1 message structure.

use core::fmt;

use veloce_asn1::defs::etsi_103097_v211::ieee1609Dot2::{
    HeaderInfo, Ieee1609Dot2Content, Ieee1609Dot2Data, SignedData, SignedDataPayload,
    ToBeSignedData,
};
use veloce_asn1::defs::etsi_103097_v211::ieee1609Dot2Base_types::{
    EccP256CurvePoint, EcdsaP256Signature, HashAlgorithm, HashedId3, Opaque, Psid,
    SequenceOfHashedId3, Signature, ThreeDLocation, Time64, Uint64, Uint8,
};
use veloce_asn1::prelude::rasn::types::FixedOctetString;
use veloce_asn1::prelude::rasn::{self, error::DecodeError};
use veloce_asn1::{
    defs::etsi_103097_v211::{
        etsi_ts103097Module::{EtsiTs103097Data, EtsiTs103097DataSigned},
        ieee1609Dot2::{self, Certificate as EtsiCertificate},
        ieee1609Dot2Base_types::HashedId8,
    },
    prelude::rasn::error::EncodeError,
    prelude::rasn::types::OctetString,
};

use crate::{security::certificate::Certificate, time::TAI2004};

use super::permission::AID;
use super::signature::{EcdsaSignature, EcdsaSignatureError};

pub type SecuredMessageResult<T> = core::result::Result<T, SecuredMessageError>;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Secured message signer identifier method. See [SecuredMessage::signer_identifier].
pub enum SignerIdentifier {
    /// Signer identifier is a certificate digest. Frequently used in CAM messages to
    /// shrink their size over the air.
    Digest(HashedId8),
    /// Signer identifier is a full certificate.
    Certificate(EtsiCertificate),
}

impl TryFrom<&ieee1609Dot2::SignerIdentifier> for SignerIdentifier {
    type Error = SecuredMessageError;

    fn try_from(signer_id: &ieee1609Dot2::SignerIdentifier) -> Result<Self, Self::Error> {
        let res = match signer_id {
            ieee1609Dot2::SignerIdentifier::digest(digest) => {
                SignerIdentifier::Digest(digest.clone())
            }
            ieee1609Dot2::SignerIdentifier::certificate(cert_seq) => {
                SignerIdentifier::Certificate(cert_seq.0[0].clone())
            }
            ieee1609Dot2::SignerIdentifier::R_self(_) => {
                return Err(SecuredMessageError::SelfSigned)
            }
            _ => return Err(SecuredMessageError::UnsupportedSignerIdentifier),
        };

        Ok(res)
    }
}

impl Into<ieee1609Dot2::SignerIdentifier> for SignerIdentifier {
    fn into(self) -> ieee1609Dot2::SignerIdentifier {
        match self {
            SignerIdentifier::Digest(digest) => ieee1609Dot2::SignerIdentifier::digest(digest),
            SignerIdentifier::Certificate(cert) => {
                let seq = ieee1609Dot2::SequenceOfCertificate(vec![cert]);
                ieee1609Dot2::SignerIdentifier::certificate(seq)
            }
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Secured message errors.
pub enum SecuredMessageError {
    /// Asn.1 decoding error.
    Asn1Decode(DecodeError),
    /// Asn.1 encoding error.
    Asn1Encode(EncodeError),
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
    /// AID format is not supported.
    UnsupportedAIDFormat,
    /// Message does not contain data. [ieee1609Dot2::SignedDataPayload::data] should be present.
    NoData,
    /// Message data is of wrong type. Should be [ieee1609Dot2::Ieee1609Dot2Content::unsecuredData].
    DataContent,
}

impl fmt::Display for SecuredMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecuredMessageError::Asn1Decode(e) => write!(f, "asn1 decoding error: {}", e),
            SecuredMessageError::Asn1Encode(e) => write!(f, "asn1 encoding error: {}", e),
            SecuredMessageError::UnsupportedProtocolVersion => {
                write!(f, "unsupported protocol version")
            }
            SecuredMessageError::Malformed => write!(f, "malformed message"),
            SecuredMessageError::MalformedCertificate => write!(f, "malformed certificate"),
            SecuredMessageError::NoGenerationTime => write!(f, "no generation time"),
            SecuredMessageError::InvalidNumberOfCerts => {
                write!(f, "invalid number of certificates")
            }
            SecuredMessageError::NotSigned => write!(f, "message is not signed"),
            SecuredMessageError::SelfSigned => write!(f, "message is self signed"),
            SecuredMessageError::Signature(e) => write!(f, "signature error: {}", e),
            SecuredMessageError::UnsupportedSignerIdentifier => {
                write!(f, "unsupported signer identifier")
            }
            SecuredMessageError::UnsupportedAIDFormat => write!(f, "unsupported AID format"),
            SecuredMessageError::NoData => write!(f, "message does not contain data"),
            SecuredMessageError::DataContent => write!(f, "message data is of wrong type"),
        }
    }
}

/// Geonetworking secured message wrapper around an [EtsiTs103097DataSigned]
/// structure.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecuredMessage {
    /// Inner message structure.
    inner: EtsiTs103097DataSigned,
}

impl SecuredMessage {
    /// Constructs a [SecuredMessage] with the given `data`.
    /// The returned structure is not signed and does not contain a certificate.
    pub fn new(data: &[u8]) -> Self {
        let payload_content =
            Ieee1609Dot2Content::unsecuredData(Opaque(OctetString::copy_from_slice(data)));
        let payload_data = Box::new(Ieee1609Dot2Data::new(Uint8(3), payload_content));

        let signed_payload = SignedDataPayload::new(Some(payload_data), None);
        let header_info = HeaderInfo::new(
            Psid(0.into()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let tbs_data = ToBeSignedData::new(signed_payload, header_info);
        let signed_data = SignedData::new(
            HashAlgorithm::sha256,
            tbs_data,
            SignerIdentifier::Digest(super::HashedId8(0).into()).into(),
            Signature::ecdsaNistP256Signature(EcdsaP256Signature::new(
                EccP256CurvePoint::fill(()),
                FixedOctetString::new([0; 32]),
            )),
        );
        let content = Ieee1609Dot2Content::signedData(signed_data);
        let ieee_data = Ieee1609Dot2Data::new(Uint8(3), content);
        let inner = EtsiTs103097DataSigned(EtsiTs103097Data(ieee_data));

        Self { inner }
    }

    /// Constructs a [SecuredMessage] from bytes.
    pub fn from_bytes(bytes: &[u8]) -> SecuredMessageResult<Self> {
        Ok(Self {
            inner: Self::decode(bytes)?,
        })
    }

    /// Get the secured message as bytes, encoded as Asn.1 COER.
    pub fn as_bytes(&self) -> SecuredMessageResult<Vec<u8>> {
        Self::encode(&self.inner)
    }

    /// Get the secured message `to_be_signed` content bytes, encoded as Asn.1 COER.
    pub fn to_be_signed_bytes(&self) -> SecuredMessageResult<Vec<u8>> {
        let Ieee1609Dot2Content::signedData(sd) = &self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        Ok(rasn::coer::encode(&sd.tbs_data).map_err(SecuredMessageError::Asn1Encode)?)
    }

    /// Get a reference on the secured message payload.
    pub fn payload(&self) -> SecuredMessageResult<&OctetString> {
        let Ieee1609Dot2Content::signedData(sd) = &self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        let Some(data) = &sd.tbs_data.payload.data else {
            return Err(SecuredMessageError::NoData);
        };

        match &data.content {
            Ieee1609Dot2Content::unsecuredData(data) => Ok(&data.0),
            _ => Err(SecuredMessageError::DataContent),
        }
    }

    /// Get the AID of the secured message.
    pub fn application_id(&self) -> SecuredMessageResult<AID> {
        let Ieee1609Dot2Content::signedData(sd) = &self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        let aid = AID::try_from(&sd.tbs_data.header_info.psid.0)
            .map_err(|_| SecuredMessageError::UnsupportedAIDFormat)?;

        Ok(aid)
    }

    /// Set the AID of the secured message.
    pub fn set_application_id(&mut self, aid: AID) -> SecuredMessageResult<()> {
        let Ieee1609Dot2Content::signedData(sd) = &mut self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        sd.tbs_data.header_info.psid = Psid(aid.into());

        Ok(())
    }

    /// Get the generation location of the secured message.
    pub fn generation_location(&self) -> SecuredMessageResult<Option<ThreeDLocation>> {
        let Ieee1609Dot2Content::signedData(sd) = &self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        Ok(sd.tbs_data.header_info.generation_location.clone())
    }

    /// Set the generation location of the secured message.
    pub fn set_generation_location(
        &mut self,
        location: ThreeDLocation,
    ) -> SecuredMessageResult<()> {
        let Ieee1609Dot2Content::signedData(sd) = &mut self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        sd.tbs_data.header_info.generation_location = Some(location);

        Ok(())
    }

    /// Returns the generation time field of the secured message.
    pub fn generation_time(&self) -> SecuredMessageResult<TAI2004> {
        let Ieee1609Dot2Content::signedData(sd) = &self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        sd.tbs_data
            .header_info
            .generation_time
            .as_ref()
            .ok_or(SecuredMessageError::NoGenerationTime)
            .map(|gen_time| TAI2004::from_micros_const(gen_time.0 .0 as i64))
    }

    /// Sets the generation time field of the secured message.
    pub fn set_generation_time(&mut self, generation_time: TAI2004) -> SecuredMessageResult<()> {
        let Ieee1609Dot2Content::signedData(sd) = &mut self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        sd.tbs_data.header_info.generation_time =
            Some(Time64(Uint64(generation_time.total_micros() as u64)));

        Ok(())
    }

    /// Returns the message signature.
    pub fn signature(&self) -> SecuredMessageResult<EcdsaSignature> {
        let Ieee1609Dot2Content::signedData(ref sd) = self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        let sig =
            EcdsaSignature::try_from(&sd.signature).map_err(SecuredMessageError::Signature)?;

        Ok(sig)
    }

    /// Sets the message signature. See [EcdsaSignature].
    /// Content should be of type [Ieee1609Dot2Content::signedData] otherwise an error is returned.
    pub fn set_signature(&mut self, signature: EcdsaSignature) -> SecuredMessageResult<()> {
        let signed_data = match &mut self.inner.0 .0.content {
            Ieee1609Dot2Content::signedData(sd) => sd,
            _ => return Err(SecuredMessageError::NotSigned),
        };

        signed_data.hash_id = signature.hash_algorithm().into();
        signed_data.signature = signature
            .try_into()
            .map_err(SecuredMessageError::Signature)?;

        Ok(())
    }

    /// Returns the signer identifier field of the secured message.
    pub fn signer_identifier(&self) -> SecuredMessageResult<SignerIdentifier> {
        let Ieee1609Dot2Content::signedData(sd) = &self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        SignerIdentifier::try_from(&sd.signer)
    }

    /// Sets the signer identifier. See [SignerIdentifier].
    /// Content should be of type [Ieee1609Dot2Content::signedData] otherwise an error is returned.
    pub fn set_signer_identifier(&mut self, signer: SignerIdentifier) -> SecuredMessageResult<()> {
        let Ieee1609Dot2Content::signedData(sd) = &mut self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        sd.signer = signer.into();

        Ok(())
    }

    /// Get the list of p2p requested certificates.
    pub fn p2p_requested_certificates(&self) -> SecuredMessageResult<Vec<HashedId3>> {
        let Ieee1609Dot2Content::signedData(sd) = &self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        let res = sd
            .tbs_data
            .header_info
            .inline_p2pcd_request
            .as_ref()
            .map_or_else(|| Vec::new(), |p2pcd| p2pcd.0.clone());

        Ok(res)
    }

    /// Sets the P2P requested certificates hashes if the provided `certs` is not empty.
    /// Content should be of type [Ieee1609Dot2Content::signedData] otherwise an error is returned.
    pub fn set_p2p_requested_certificates(
        &mut self,
        certs: Vec<HashedId3>,
    ) -> SecuredMessageResult<()> {
        let Ieee1609Dot2Content::signedData(sd) = &mut self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        if !certs.is_empty() {
            sd.tbs_data.header_info.inline_p2pcd_request = Some(SequenceOfHashedId3(certs));
        }

        Ok(())
    }

    /// Get the requested certificate contained in the secure message, if any.
    pub fn requested_certificate(&self) -> SecuredMessageResult<Option<EtsiCertificate>> {
        let Ieee1609Dot2Content::signedData(sd) = &self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        Ok(sd.tbs_data.header_info.requested_certificate.clone())
    }

    /// Sets the requested certificate.
    /// Content should be of type [Ieee1609Dot2Content::signedData] otherwise an error is returned.
    pub fn set_requested_certificate(&mut self, cert: EtsiCertificate) -> SecuredMessageResult<()> {
        let Ieee1609Dot2Content::signedData(sd) = &mut self.inner.0 .0.content else {
            return Err(SecuredMessageError::NotSigned);
        };

        sd.tbs_data.header_info.requested_certificate = Some(cert);

        Ok(())
    }

    #[inline]
    fn decode(bytes: &[u8]) -> SecuredMessageResult<EtsiTs103097DataSigned> {
        let data = rasn::coer::decode::<EtsiTs103097DataSigned>(bytes)
            .map_err(SecuredMessageError::Asn1Decode)?;

        Self::verify_etsi_data_signed_constraints(&data)?;

        Ok(data)
    }

    #[inline]
    fn encode(data: &EtsiTs103097DataSigned) -> SecuredMessageResult<Vec<u8>> {
        Self::verify_etsi_data_signed_constraints(&data)?;
        rasn::coer::encode(data).map_err(SecuredMessageError::Asn1Encode)
    }

    /// Check `data` is valid according to EtsiTs103097Data Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    #[inline]
    fn verify_etsi_data_signed_constraints(
        data: &EtsiTs103097DataSigned,
    ) -> SecuredMessageResult<()> {
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
        use ieee1609Dot2::{RecipientInfo, SignerIdentifier};
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
