use core::{fmt, marker::PhantomData};

use veloce_asn1::{
    defs::etsi_103097_v211::{
        etsi_ts103097_module::{EtsiTs103097Data, EtsiTs103097DataSigned},
        ieee1609_dot2::{
            HeaderInfo, Ieee1609Dot2Content, Ieee1609Dot2Data, SignedData as EtsiSignedData,
            SignedDataPayload, ToBeSignedData,
        },
        ieee1609_dot2_base_types::{
            EccP256CurvePoint, EcdsaP256Signature, HashAlgorithm, Opaque, Psid, Signature, Time64,
            Uint64, Uint8,
        },
    },
    prelude::rasn::types::{FixedOctetString, OctetString},
};

use crate::{
    security::{
        permission::AID,
        signature::{EcdsaSignature, EcdsaSignatureError},
    },
    time::TAI2004,
};

use super::{
    asn1_wrapper::{Asn1Wrapper, Asn1WrapperError},
    SignerIdentifier, SignerIdentifierError,
};

pub type SignedDataResult<T> = core::result::Result<T, SignedDataError>;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Secured message errors.
pub enum SignedDataError {
    /// Asn.1 wrapper error.
    Asn1Wrapper(Asn1WrapperError),
    /// No generation time value in message.
    NoGenerationTime,
    /// Message is not signed.
    NotSigned,
    /// Signature error.
    Signature(EcdsaSignatureError),
    /// Signer identifier error.
    SignerIdentifier(SignerIdentifierError),
    /// AID format is not supported.
    UnsupportedAIDFormat,
    /// Message does not contain data. [SignedDataPayload::data] should be present.
    NoData,
    /// Message data is of wrong type. Should be [Ieee1609Dot2Content::unsecuredData].
    DataContent,
    /// Hash algorithm in the signature does not match the hash algorithm of the message.
    HashAlgorithmMismatch,
    /// Hash algorithm is not supported.
    UnsupportedHashAlgorithm,
}

impl fmt::Display for SignedDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignedDataError::Asn1Wrapper(e) => write!(f, "asn1 wrapper error: {}", e),
            SignedDataError::NoGenerationTime => write!(f, "no generation time"),
            SignedDataError::NotSigned => write!(f, "message is not signed"),
            SignedDataError::Signature(e) => write!(f, "signature error: {}", e),
            SignedDataError::SignerIdentifier(e) => {
                write!(f, "signer identifier error: {}", e)
            }
            SignedDataError::UnsupportedAIDFormat => write!(f, "unsupported AID format"),
            SignedDataError::NoData => write!(f, "message does not contain data"),
            SignedDataError::DataContent => write!(f, "message data is of wrong type"),
            SignedDataError::UnsupportedHashAlgorithm => write!(f, "unsupported hash algorithm"),
            SignedDataError::HashAlgorithmMismatch => {
                write!(f, "hash algorithm in the signature does not match the hash algorithm of the message")
            }
        }
    }
}

/// Signed data message wrapper.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SignedData<T> {
    /// Inner message structure.
    inner: Asn1Wrapper<EtsiTs103097DataSigned>,
    /// Phantom marker for the type of the inner message.
    _phantom: PhantomData<T>,
}

impl<T> SignedData<T> {
    /// Constructs a [SignedData] with the given `data`.
    /// The returned structure is not signed and does not contain a certificate.
    pub fn new(data: Vec<u8>) -> Self {
        let payload_content = Ieee1609Dot2Content::unsecuredData(Opaque(OctetString::from(data)));
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
        let signed_data = EtsiSignedData::new(
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
        let data_signed = EtsiTs103097DataSigned(EtsiTs103097Data(ieee_data));

        Self {
            inner: Asn1Wrapper::from_raw_unverified(data_signed),
            _phantom: PhantomData,
        }
    }

    /// Constructs a [SignedData] from bytes.
    pub fn from_bytes(bytes: &[u8]) -> SignedDataResult<Self> {
        Ok(Self {
            inner: Asn1Wrapper::from_bytes(bytes).map_err(SignedDataError::Asn1Wrapper)?,
            _phantom: PhantomData,
        })
    }

    /// Get the secured message as bytes, encoded as Asn.1 COER.
    pub fn as_bytes(&self) -> SignedDataResult<Vec<u8>> {
        self.inner.as_bytes().map_err(SignedDataError::Asn1Wrapper)
    }

    /// Get the secured message `to_be_signed` content bytes, encoded as Asn.1 COER.
    pub fn to_be_signed_bytes(&self) -> SignedDataResult<Vec<u8>> {
        let inner = self.inner.inner();
        let Ieee1609Dot2Content::signedData(sd) = &inner.0 .0.content else {
            return Err(SignedDataError::NotSigned);
        };

        Asn1Wrapper::encode_coer(&sd.tbs_data).map_err(SignedDataError::Asn1Wrapper)
    }

    /// Get a reference on the secured message payload.
    pub fn payload(&self) -> SignedDataResult<&OctetString> {
        let inner = self.inner.inner();
        let Ieee1609Dot2Content::signedData(sd) = &inner.0 .0.content else {
            return Err(SignedDataError::NotSigned);
        };

        let Some(data) = &sd.tbs_data.payload.data else {
            return Err(SignedDataError::NoData);
        };

        match &data.content {
            Ieee1609Dot2Content::unsecuredData(data) => Ok(&data.0),
            _ => Err(SignedDataError::DataContent),
        }
    }

    /// Get the AID of the signed data.
    pub fn application_id(&self) -> SignedDataResult<AID> {
        let inner = self.inner.inner();
        let Ieee1609Dot2Content::signedData(sd) = &inner.0 .0.content else {
            return Err(SignedDataError::NotSigned);
        };

        let aid = AID::try_from(&sd.tbs_data.header_info.psid.0)
            .map_err(|_| SignedDataError::UnsupportedAIDFormat)?;

        Ok(aid)
    }

    /// Set the AID of the signed data.
    pub fn set_application_id(&mut self, aid: AID) -> SignedDataResult<()> {
        let inner = self.inner.inner_mut();
        let Ieee1609Dot2Content::signedData(sd) = &mut inner.0 .0.content else {
            return Err(SignedDataError::NotSigned);
        };

        sd.tbs_data.header_info.psid = Psid(aid.into());

        Ok(())
    }

    /// Returns the generation time field of the signed data.
    pub fn generation_time(&self) -> SignedDataResult<TAI2004> {
        let inner = self.inner.inner();
        let Ieee1609Dot2Content::signedData(sd) = &inner.0 .0.content else {
            return Err(SignedDataError::NotSigned);
        };

        sd.tbs_data
            .header_info
            .generation_time
            .as_ref()
            .ok_or(SignedDataError::NoGenerationTime)
            .map(|gen_time| TAI2004::from_micros_const(gen_time.0 .0 as i64))
    }

    /// Sets the generation time field of the signed data.
    pub fn set_generation_time(&mut self, generation_time: TAI2004) -> SignedDataResult<()> {
        let inner = self.inner.inner_mut();
        let Ieee1609Dot2Content::signedData(sd) = &mut inner.0 .0.content else {
            return Err(SignedDataError::NotSigned);
        };

        sd.tbs_data.header_info.generation_time =
            Some(Time64(Uint64(generation_time.total_micros() as u64)));

        Ok(())
    }

    /// Returns the message signature.
    pub fn signature(&self) -> SignedDataResult<EcdsaSignature> {
        let inner = self.inner.inner();
        let Ieee1609Dot2Content::signedData(sd) = &inner.0 .0.content else {
            return Err(SignedDataError::NotSigned);
        };

        let sig = EcdsaSignature::try_from(&sd.signature).map_err(SignedDataError::Signature)?;

        if sd.hash_id
            != sig
                .hash_algorithm()
                .try_into()
                .map_err(|_| SignedDataError::UnsupportedHashAlgorithm)?
        {
            return Err(SignedDataError::HashAlgorithmMismatch);
        }

        Ok(sig)
    }

    /// Sets the message signature. See [EcdsaSignature].
    /// Content should be of type [Ieee1609Dot2Content::signedData] otherwise an error is returned.
    pub fn set_signature(&mut self, signature: EcdsaSignature) -> SignedDataResult<()> {
        let inner = self.inner.inner_mut();
        let signed_data = match &mut inner.0 .0.content {
            Ieee1609Dot2Content::signedData(sd) => sd,
            _ => return Err(SignedDataError::NotSigned),
        };

        signed_data.hash_id = signature
            .hash_algorithm()
            .try_into()
            .map_err(|_| SignedDataError::UnsupportedHashAlgorithm)?;

        signed_data.signature = signature.try_into().map_err(SignedDataError::Signature)?;

        Ok(())
    }

    /// Returns the signer identifier field of the signed data.
    pub fn signer_identifier(&self) -> SignedDataResult<SignerIdentifier> {
        let inner = self.inner.inner();
        let Ieee1609Dot2Content::signedData(sd) = &inner.0 .0.content else {
            return Err(SignedDataError::NotSigned);
        };

        SignerIdentifier::try_from(&sd.signer).map_err(SignedDataError::SignerIdentifier)
    }

    /// Sets the signer identifier. See [SignerIdentifier].
    /// Content should be of type [Ieee1609Dot2Content::signedData] otherwise an error is returned.
    pub fn set_signer_identifier(&mut self, signer: SignerIdentifier) -> SignedDataResult<()> {
        let inner = self.inner.inner_mut();
        let Ieee1609Dot2Content::signedData(sd) = &mut inner.0 .0.content else {
            return Err(SignedDataError::NotSigned);
        };

        sd.signer = signer.into();

        Ok(())
    }
}

impl<T> TryFrom<EtsiTs103097DataSigned> for SignedData<T> {
    type Error = SignedDataError;

    fn try_from(value: EtsiTs103097DataSigned) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: Asn1Wrapper::from_raw(value).map_err(SignedDataError::Asn1Wrapper)?,
            _phantom: PhantomData,
        })
    }
}

impl<T> Into<EtsiTs103097DataSigned> for SignedData<T> {
    fn into(self) -> EtsiTs103097DataSigned {
        self.inner.into_inner()
    }
}
