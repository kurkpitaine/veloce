use core::fmt;

use veloce_asn1::defs::etsi_103097_v211::{
    etsi_ts103097_module::{EtsiTs103097Data, EtsiTs103097DataEncrypted},
    ieee1609_dot2::{
        EncryptedData as EtsiEncryptedData, Ieee1609Dot2Content, Ieee1609Dot2Data,
        SequenceOfRecipientInfo,
    },
    ieee1609_dot2_base_types::Uint8,
};

use crate::security::{
    ciphertext::{Ciphertext, CiphertextError},
    signature::EcdsaSignatureError,
};

use super::{
    asn1_wrapper::{Asn1Wrapper, Asn1WrapperError},
    message::{RecipientInfo, RecipientInfoError},
    SignerIdentifierError,
};

pub type EncryptedDataResult<T> = core::result::Result<T, EncryptedDataError>;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Secured message errors.
pub enum EncryptedDataError {
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
    /// Hash algorithm in the signature does not match the hash algorithm of the message.
    HashAlgorithmMismatch,
    /// Message data is of wrong type. Should be [Ieee1609Dot2Content::encryptedData].
    DataContent,
    /// Recipient information error.
    Recipient(RecipientInfoError),
    /// Ciphertext error.
    Ciphertext(CiphertextError),
}

impl fmt::Display for EncryptedDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptedDataError::Asn1Wrapper(e) => write!(f, "asn1 wrapper error: {}", e),
            EncryptedDataError::NoGenerationTime => write!(f, "no generation time"),
            EncryptedDataError::NotSigned => write!(f, "message is not signed"),
            EncryptedDataError::Signature(e) => write!(f, "signature error: {}", e),
            EncryptedDataError::SignerIdentifier(e) => {
                write!(f, "signer identifier error: {}", e)
            }
            EncryptedDataError::UnsupportedAIDFormat => write!(f, "unsupported AID format"),
            EncryptedDataError::NoData => write!(f, "message does not contain data"),
            EncryptedDataError::DataContent => write!(f, "message data is of wrong type"),
            EncryptedDataError::HashAlgorithmMismatch => {
                write!(f, "hash algorithm in the signature does not match the hash algorithm of the message")
            }
            EncryptedDataError::Recipient(e) => write!(f, "recipient information error: {}", e),
            EncryptedDataError::Ciphertext(e) => write!(f, "ciphertext error: {}", e),
        }
    }
}

/// Signed data message wrapper.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncryptedData {
    /// Inner message structure.
    inner: Asn1Wrapper<EtsiTs103097DataEncrypted>,
}

impl EncryptedData {
    /// Constructs a [EncryptedData] with the given `ciphertext` encrypted data and `recipients`.
    pub fn new(
        ciphertext: Ciphertext,
        recipients: Vec<RecipientInfo>,
    ) -> EncryptedDataResult<Self> {
        let mut seq_of_recipients = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            seq_of_recipients.push(
                recipient
                    .try_into()
                    .map_err(EncryptedDataError::Recipient)?,
            );
        }

        let seq_recip_info = SequenceOfRecipientInfo(seq_of_recipients);

        let encrypted_data = EtsiEncryptedData::new(
            seq_recip_info,
            ciphertext
                .try_into()
                .map_err(EncryptedDataError::Ciphertext)?,
        );
        let content = Ieee1609Dot2Content::encryptedData(encrypted_data);

        let ieee_data = Ieee1609Dot2Data::new(Uint8(3), content);
        let data_encrypted = EtsiTs103097DataEncrypted(EtsiTs103097Data(ieee_data));

        Ok(Self {
            inner: Asn1Wrapper::from_raw_unverified(data_encrypted),
        })
    }

    /// Constructs a [EncryptedData] from bytes.
    pub fn from_bytes(bytes: &[u8]) -> EncryptedDataResult<Self> {
        Ok(Self {
            inner: Asn1Wrapper::from_bytes(bytes).map_err(EncryptedDataError::Asn1Wrapper)?,
        })
    }

    /// Get the secured message as bytes, encoded as Asn.1 COER.
    pub fn as_bytes(&self) -> EncryptedDataResult<Vec<u8>> {
        self.inner
            .as_bytes()
            .map_err(EncryptedDataError::Asn1Wrapper)
    }

    /// Get the list of recipient information.
    pub fn recipients(&self) -> EncryptedDataResult<Vec<RecipientInfo>> {
        let inner = self.inner.inner();

        let recipients = match &inner.0 .0.content {
            Ieee1609Dot2Content::encryptedData(encrypted) => &encrypted.recipients,
            _ => return Err(EncryptedDataError::DataContent),
        };

        let mut res = Vec::with_capacity(recipients.0.len());
        for recipient in &recipients.0 {
            let r = RecipientInfo::try_from(recipient).map_err(EncryptedDataError::Recipient)?;
            res.push(r);
        }

        Ok(res)
    }

    /// Set the list of recipient information. Replaces the existing list.
    pub fn set_recipients(&mut self, recipients: Vec<RecipientInfo>) -> EncryptedDataResult<()> {
        let inner = self.inner.inner_mut();

        let mut seq_of_recipients = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            seq_of_recipients.push(
                recipient
                    .try_into()
                    .map_err(EncryptedDataError::Recipient)?,
            );
        }

        match &mut inner.0 .0.content {
            Ieee1609Dot2Content::encryptedData(encrypted) => {
                encrypted.recipients = SequenceOfRecipientInfo(seq_of_recipients);
            }
            _ => return Err(EncryptedDataError::DataContent),
        };

        Ok(())
    }

    /// Get a reference on the encrypted payload.
    pub fn ciphertext(&self) -> EncryptedDataResult<Ciphertext> {
        let inner = self.inner.inner();

        let ciphertext = match &inner.0 .0.content {
            Ieee1609Dot2Content::encryptedData(encrypted) => &encrypted.ciphertext,
            _ => return Err(EncryptedDataError::DataContent),
        };

        Ok(Ciphertext::try_from(ciphertext).map_err(EncryptedDataError::Ciphertext)?)
    }
}
