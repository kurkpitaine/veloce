use core::fmt;

use veloce_asn1::{
    defs::{
        etsi_102941_v221::{
            etsi_ts102941_trust_lists::{
                CtlCommand, CtlEntry, ToBeSignedCrl, ToBeSignedRcaCtl, ToBeSignedTlmCtl,
            },
            etsi_ts102941_types_enrolment::{
                EnrolmentResponseCode, InnerEcRequest, InnerEcResponse,
            },
        },
        etsi_103097_v211::{
            etsi_ts103097_module::{
                EtsiTs103097Data, EtsiTs103097DataEncrypted, EtsiTs103097DataEncryptedUnicast,
                EtsiTs103097DataSigned, EtsiTs103097DataSignedAndEncrypted,
                EtsiTs103097DataSignedAndEncryptedUnicast, EtsiTs103097DataSignedExternalPayload,
                EtsiTs103097DataUnsecured,
            },
            ieee1609_dot2::{
                self, HashedData, Ieee1609Dot2Content, RecipientInfo, SymmetricCiphertext,
            },
        },
    },
    prelude::rasn::{
        self,
        error::{DecodeError, EncodeError},
    },
};

use crate::security::{signature::EcdsaSignatureError, Certificate};

use super::SignerIdentifierError;

pub type Asn1WrapperResult<T> = core::result::Result<T, Asn1WrapperError>;

/// Asn1 Asn1Wrapper errors.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Asn1WrapperError {
    /// Asn.1 decoding error.
    Asn1Decode(DecodeError),
    /// Asn.1 encoding error.
    Asn1Encode(EncodeError),
    /// Security protocol version is not supported.
    UnsupportedProtocolVersion,
    /// Malformed, ie: a mandatory field
    /// is absent or a present field should be absent.
    Malformed,
    /// Enclosed certificate content is malformed.
    MalformedCertificate,
    /// Invalid number of certificates. [SignerIdentifier::certificate] shall contain
    /// exactly one certificate.
    InvalidNumberOfCerts,
    /// Asn1Wrapper does not contain signed data.
    NotSigned,
    /// Asn1Wrapper does not contain encrypted data.
    NotEncrypted,
    /// Asn1Wrapper does not contain data. [SignedDataPayload::data] should be present.
    NoData,
    /// Asn1Wrapper data is of wrong type. Should be [Ieee1609Dot2Content::unsecuredData].
    DataContent,
    /// Asn1Wrapper does not contain external data hash.
    NoExtDataHash,
    /// Invalid hash algorithm used.
    InvalidHashAlgorithm,
    /// Encryption algorithm is not supported.
    UnsupportedEncryptionAlgorithm,
    /// No recipient is present.
    NoRecipient,
    /// Recipient is not unique, where it should be as in unicast wrappers.
    RecipientNotUnique,
    /// Hash algorithm in the signature does not match the hash algorithm of the message.
    HashAlgorithmMismatch,
    /// Signature error.
    Signature(EcdsaSignatureError),
    /// No generation time value in message.
    NoGenerationTime,
    /// Signer identifier error.
    SignerIdentifier(SignerIdentifierError),
    /// AID format is not supported.
    UnsupportedAIDFormat,
}

impl fmt::Display for Asn1WrapperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Asn1WrapperError::Asn1Decode(e) => write!(f, "asn1 decoding error: {}", e),
            Asn1WrapperError::Asn1Encode(e) => write!(f, "asn1 encoding error: {}", e),
            Asn1WrapperError::Malformed => write!(f, "Malformed certificate"),
            Asn1WrapperError::UnsupportedProtocolVersion => {
                write!(f, "unsupported protocol version")
            }
            Asn1WrapperError::MalformedCertificate => write!(f, "malformed certificate"),
            Asn1WrapperError::InvalidNumberOfCerts => {
                write!(f, "invalid number of certificates")
            }
            Asn1WrapperError::NotSigned => write!(f, "wrapper data is not signed"),
            Asn1WrapperError::NotEncrypted => write!(f, "wrapper data is not encrypted"),
            Asn1WrapperError::NoData => write!(f, "wrapper does not contain data"),
            Asn1WrapperError::DataContent => write!(f, "wrapper data is of wrong type"),
            Asn1WrapperError::NoExtDataHash => {
                write!(f, "wrapper does not contain external data hash")
            }
            Asn1WrapperError::InvalidHashAlgorithm => write!(f, "invalid hash algorithm"),
            Asn1WrapperError::UnsupportedEncryptionAlgorithm => {
                write!(f, "unsupported encryption algorithm")
            }
            Asn1WrapperError::NoRecipient => write!(f, "no recipient is present"),
            Asn1WrapperError::RecipientNotUnique => write!(f, "recipient is not unique"),
            Asn1WrapperError::HashAlgorithmMismatch => write!(
                f,
                "hash algorithm in the signature does not match the hash algorithm of the message"
            ),
            Asn1WrapperError::Signature(e) => write!(f, "signature error: {}", e),
            Asn1WrapperError::NoGenerationTime => write!(f, "no generation time"),
            Asn1WrapperError::SignerIdentifier(e) => {
                write!(f, "signer identifier error: {}", e)
            }
            Asn1WrapperError::UnsupportedAIDFormat => write!(f, "unsupported AID format"),
        }
    }
}

pub trait Asn1WrapperTrait {
    type Wrapped;

    /// Check `data` is valid according to the ASN.1 wrapper definition.
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()>;
}

/// Asn1Wrapper used to perform encoding and decoding of ETSI defined Asn1 structures.
/// Main function is to provide an automatic constraint checking procedure, as some
/// custom constrains are not checked by the rasn crate.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Asn1Wrapper<T: rasn::Decode + rasn::Encode> {
    inner: T,
}

impl<T: rasn::Decode + rasn::Encode> Asn1Wrapper<T> {
    /// Encode `data` as COER bytes.
    #[inline]
    pub fn encode_coer(data: &T) -> Asn1WrapperResult<Vec<u8>> {
        rasn::coer::encode(data).map_err(Asn1WrapperError::Asn1Encode)
    }

    /// Decode `data` as COER bytes.
    #[inline]
    pub fn decode_coer(data: &[u8]) -> Asn1WrapperResult<T> {
        rasn::coer::decode(data).map_err(Asn1WrapperError::Asn1Decode)
    }
}

impl<T> Asn1Wrapper<T>
where
    T: Clone + rasn::Decode + rasn::Encode,
    Asn1Wrapper<T>: Asn1WrapperTrait<Wrapped = T>,
{
    /// Constructs a [Asn1Wrapper] from the raw type.
    pub fn from_raw(ty: T) -> Asn1WrapperResult<Asn1Wrapper<T>> {
        Self::verify_constraints(&ty)?;

        Ok(Asn1Wrapper { inner: ty })
    }

    /// Constructs a [Asn1Wrapper] from the raw wrapped type,
    /// without verifying constraints.
    pub fn from_raw_unverified(ty: T) -> Asn1Wrapper<T> {
        Asn1Wrapper { inner: ty }
    }

    /// Constructs a [Asn1Wrapper] from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Asn1WrapperResult<Asn1Wrapper<T>> {
        Ok(Asn1Wrapper {
            inner: Self::decode_and_verify(bytes)?,
        })
    }

    /// Get the [Asn1Wrapper] as bytes, encoded as Asn.1 COER.
    pub fn as_bytes(&self) -> Asn1WrapperResult<Vec<u8>> {
        Self::verify_and_encode(&self.inner)
    }

    /// Get the [Asn1Wrapper] as the raw type, verifying the Asn.1 constraints.
    pub fn as_raw(&self) -> Asn1WrapperResult<T> {
        Self::verify_constraints(&self.inner)?;

        Ok(self.inner.clone())
    }

    /// Get a reference on the inner wrapped data.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference on the inner wrapped data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Decode from ASN.1 COER `bytes` and verify constraints.
    #[inline]
    fn decode_and_verify(bytes: &[u8]) -> Asn1WrapperResult<T> {
        let data = Self::decode_coer(bytes)?;
        Self::verify_constraints(&data)?;

        Ok(data)
    }

    /// Verify constraints and encode `data` to ASN.1 COER.
    #[inline]
    fn verify_and_encode(data: &T) -> Asn1WrapperResult<Vec<u8>> {
        Self::verify_constraints(data)?;
        Self::encode_coer(data)
    }

    /// Check `data` is valid according to EtsiTs103097Data Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    #[inline]
    fn verify_etsi_wrapper_constraints(data: &EtsiTs103097Data) -> Asn1WrapperResult<()> {
        if data.0.protocol_version.0 != 3 {
            return Err(Asn1WrapperError::UnsupportedProtocolVersion);
        }

        match data.0.content {
            Ieee1609Dot2Content::signedData(ref sd) => {
                let header_info = &sd.tbs_data.header_info;
                if header_info.generation_time.is_none()
                    || header_info.p2pcd_learning_request.is_some()
                    || header_info.missing_crl_identifier.is_some()
                {
                    return Err(Asn1WrapperError::Malformed);
                }

                if let ieee1609_dot2::SignerIdentifier::certificate(ref seq_of_certs) = sd.signer {
                    if seq_of_certs.0.len() != 1 {
                        return Err(Asn1WrapperError::InvalidNumberOfCerts);
                    }

                    Certificate::verify_etsi_constraints(&seq_of_certs.0[0])
                        .map_err(|_| Asn1WrapperError::MalformedCertificate)?;
                }
            }
            Ieee1609Dot2Content::encryptedData(ref ed) => {
                for recipient in &ed.recipients.0 {
                    match recipient {
                        RecipientInfo::certRecipInfo(_)
                        | RecipientInfo::pskRecipInfo(_) // Marked as absent in the ASN.1 definition but should be used in PKI communications...
                        | RecipientInfo::signedDataRecipInfo(_) => {}
                        _ => return Err(Asn1WrapperError::Malformed),
                    }
                }
            }
            Ieee1609Dot2Content::unsecuredData(_)
            | Ieee1609Dot2Content::signedX509CertificateRequest(_) => {}
            Ieee1609Dot2Content::signedCertificateRequest(_) => {
                return Err(Asn1WrapperError::Malformed)
            }
            _ => {}
        }

        Ok(())
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<EtsiTs103097DataUnsecured> {
    type Wrapped = EtsiTs103097DataUnsecured;

    /// Check `data` is valid according to EtsiTs103097Data-Unsecured Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        Self::verify_etsi_wrapper_constraints(&data.0)?;

        match &data.0 .0.content {
            Ieee1609Dot2Content::unsecuredData(_) => Ok(()),
            _ => Err(Asn1WrapperError::Malformed),
        }
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<EtsiTs103097DataSigned> {
    type Wrapped = EtsiTs103097DataSigned;

    /// Check `data` is valid according to EtsiTs103097DataSigned Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        Self::verify_etsi_wrapper_constraints(&data.0)?;

        let signed_data = match data.0 .0.content {
            Ieee1609Dot2Content::signedData(ref sd) => sd,
            _ => return Err(Asn1WrapperError::NotSigned),
        };

        let Some(ref data) = signed_data.tbs_data.payload.data else {
            return Err(Asn1WrapperError::NoData);
        };

        match data.content {
            Ieee1609Dot2Content::unsecuredData(_) => {}
            _ => return Err(Asn1WrapperError::DataContent),
        };

        Ok(())
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<EtsiTs103097DataSignedExternalPayload> {
    type Wrapped = EtsiTs103097DataSignedExternalPayload;

    /// Check `data` is valid according to EtsiTs103097Data-SignedExternalPayload Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        Self::verify_etsi_wrapper_constraints(&data.0)?;

        match &data.0 .0.content {
            Ieee1609Dot2Content::signedData(signed_data) => {
                let Some(hashed_data) = &signed_data.tbs_data.payload.ext_data_hash else {
                    return Err(Asn1WrapperError::NoExtDataHash);
                };

                let HashedData::sha256HashedData(_) = hashed_data else {
                    return Err(Asn1WrapperError::InvalidHashAlgorithm);
                };
            }
            _ => return Err(Asn1WrapperError::NotSigned),
        }

        Ok(())
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<EtsiTs103097DataEncrypted> {
    type Wrapped = EtsiTs103097DataEncrypted;

    /// Check `data` is valid according to EtsiTs103097Data-Encrypted Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        Self::verify_etsi_wrapper_constraints(&data.0)?;

        match &data.0 .0.content {
            Ieee1609Dot2Content::encryptedData(encrypted) => match &encrypted.ciphertext {
                SymmetricCiphertext::aes128ccm(_) => {}
                _ => return Err(Asn1WrapperError::UnsupportedEncryptionAlgorithm),
            },
            _ => return Err(Asn1WrapperError::NotEncrypted),
        }

        Ok(())
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<EtsiTs103097DataEncryptedUnicast> {
    type Wrapped = EtsiTs103097DataEncryptedUnicast;

    /// Check `data` is valid according to EtsiTs103097Data-Encrypted-Unicast Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        Asn1Wrapper::<EtsiTs103097DataEncrypted>::verify_constraints(&data.0)?;

        match &data.0 .0 .0.content {
            Ieee1609Dot2Content::encryptedData(encrypted) => {
                if encrypted.recipients.0.is_empty() {
                    return Err(Asn1WrapperError::NoRecipient);
                }
                if encrypted.recipients.0.len() > 1 {
                    return Err(Asn1WrapperError::RecipientNotUnique);
                }
            }
            _ => return Err(Asn1WrapperError::NotEncrypted),
        }

        Ok(())
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<EtsiTs103097DataSignedAndEncrypted> {
    type Wrapped = EtsiTs103097DataSignedAndEncrypted;

    /// Check `data` is valid according to EtsiTs103097Data-SignedAndEncrypted Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        Asn1Wrapper::<EtsiTs103097DataEncrypted>::verify_constraints(&data.0)
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<EtsiTs103097DataSignedAndEncryptedUnicast> {
    type Wrapped = EtsiTs103097DataSignedAndEncryptedUnicast;

    /// Check `data` is valid according to EtsiTs103097Data-SignedAndEncrypted-Unicast Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        Asn1Wrapper::<EtsiTs103097DataEncrypted>::verify_constraints(&data.0)?;

        match &data.0 .0 .0.content {
            Ieee1609Dot2Content::encryptedData(encrypted) => {
                if encrypted.recipients.0.is_empty() {
                    return Err(Asn1WrapperError::NoRecipient);
                }
                if encrypted.recipients.0.len() > 1 {
                    return Err(Asn1WrapperError::RecipientNotUnique);
                }
            }
            _ => return Err(Asn1WrapperError::NotEncrypted),
        }

        Ok(())
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<InnerEcRequest> {
    type Wrapped = InnerEcRequest;

    /// Check `data` is valid according to InnerEcRequest Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    #[inline]
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        if data
            .requested_subject_attributes
            .cert_issue_permissions
            .is_some()
        {
            return Err(Asn1WrapperError::Malformed);
        }

        Ok(())
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<InnerEcResponse> {
    type Wrapped = InnerEcResponse;

    /// Check `data` is valid according to InnerEcResponse Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        match (data.response_code, &data.certificate) {
            (EnrolmentResponseCode::ok, Some(_)) => Ok(()),
            (_, None) => Ok(()),
            (_, _) => Err(Asn1WrapperError::Malformed),
        }
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<ToBeSignedTlmCtl> {
    type Wrapped = ToBeSignedTlmCtl;

    /// Check `data` is valid according to ToBeSignedTlmCtl Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    #[inline]
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        for command in &data.0.ctl_commands {
            match command {
                CtlCommand::add(CtlEntry::ea(_) | CtlEntry::aa(_)) => {
                    return Err(Asn1WrapperError::Malformed)
                }
                CtlCommand::delete(_) if data.0.is_full_ctl => {
                    return Err(Asn1WrapperError::Malformed)
                }
                _ => {}
            }
        }

        Ok(())
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<ToBeSignedRcaCtl> {
    type Wrapped = ToBeSignedRcaCtl;

    /// Check `data` is valid according to ToBeSignedRcaCtl Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    #[inline]
    fn verify_constraints(data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        for command in &data.0.ctl_commands {
            match command {
                CtlCommand::add(CtlEntry::rca(_) | CtlEntry::tlm(_)) => {
                    return Err(Asn1WrapperError::Malformed)
                }
                CtlCommand::delete(_) if data.0.is_full_ctl => {
                    return Err(Asn1WrapperError::Malformed)
                }
                _ => {}
            }
        }

        Ok(())
    }
}

impl Asn1WrapperTrait for Asn1Wrapper<ToBeSignedCrl> {
    type Wrapped = ToBeSignedCrl;

    /// Check `data` is valid according to ToBeSignedCrl Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    #[inline]
    fn verify_constraints(_data: &Self::Wrapped) -> Asn1WrapperResult<()> {
        Ok(())
    }
}
