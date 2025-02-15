#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts103097_extension_module {
    extern crate alloc;
    use super::ieee1609_dot2_base_types::{HashedId8, Time32};
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EtsiOriginatingHeaderInfoExtension {
        #[rasn(value("0..=255"))]
        pub id: u8,
        pub content: Any,
    }
    impl EtsiOriginatingHeaderInfoExtension {
        pub fn new(id: u8, content: Any) -> Self {
            Self { id, content }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EtsiTs102941CrlRequest {
        #[rasn(identifier = "issuerId")]
        pub issuer_id: HashedId8,
        #[rasn(identifier = "lastKnownUpdate")]
        pub last_known_update: Option<Time32>,
    }
    impl EtsiTs102941CrlRequest {
        pub fn new(issuer_id: HashedId8, last_known_update: Option<Time32>) -> Self {
            Self {
                issuer_id,
                last_known_update,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EtsiTs102941CtlRequest {
        #[rasn(identifier = "issuerId")]
        pub issuer_id: HashedId8,
        #[rasn(value("0..=255"), identifier = "lastKnownCtlSequence")]
        pub last_known_ctl_sequence: Option<u8>,
    }
    impl EtsiTs102941CtlRequest {
        pub fn new(issuer_id: HashedId8, last_known_ctl_sequence: Option<u8>) -> Self {
            Self {
                issuer_id,
                last_known_ctl_sequence,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct EtsiTs102941DeltaCtlRequest(pub EtsiTs102941CtlRequest);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct EtsiTs103097HeaderInfoExtensionId(pub ExtId);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct ExtId(pub u8);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("1"))]
    pub struct ExtensionModuleVersion(pub u8);
    pub const ETSI_TS102941_CRL_REQUEST_ID: EtsiTs103097HeaderInfoExtensionId =
        EtsiTs103097HeaderInfoExtensionId(ExtId(1));
    #[doc = "'01'H"]
    pub const ETSI_TS102941_DELTA_CTL_REQUEST_ID: EtsiTs103097HeaderInfoExtensionId =
        EtsiTs103097HeaderInfoExtensionId(ExtId(2));
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts103097_module {
    extern crate alloc;
    use super::etsi_ts103097_extension_module::ExtensionModuleVersion;
    use super::ieee1609_dot2::{Certificate, Ieee1609Dot2Data};
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct EtsiTs103097Certificate(pub Certificate);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct EtsiTs103097Data(pub Ieee1609Dot2Data);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "EtsiTs103097Data-Encrypted")]
    pub struct EtsiTs103097DataEncrypted(pub EtsiTs103097Data);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "EtsiTs103097Data-Encrypted-Unicast")]
    pub struct EtsiTs103097DataEncryptedUnicast(pub EtsiTs103097DataEncrypted);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "EtsiTs103097Data-Signed")]
    pub struct EtsiTs103097DataSigned(pub EtsiTs103097Data);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "EtsiTs103097Data-SignedAndEncrypted")]
    pub struct EtsiTs103097DataSignedAndEncrypted(pub EtsiTs103097DataEncrypted);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "EtsiTs103097Data-SignedAndEncrypted-Unicast")]
    pub struct EtsiTs103097DataSignedAndEncryptedUnicast(pub EtsiTs103097DataEncrypted);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "EtsiTs103097Data-SignedExternalPayload")]
    pub struct EtsiTs103097DataSignedExternalPayload(pub EtsiTs103097Data);
    #[doc = " (WITH COMPONENTS {...,"]
    #[doc = "  content (WITH COMPONENTS {...,"]
    #[doc = "    signedData (WITH COMPONENTS {..., -- constraints on signed data headers"]
    #[doc = "      tbsData (WITH COMPONENTS {"]
    #[doc = "        headerInfo (WITH COMPONENTS {...,"]
    #[doc = "          generationTime PRESENT,"]
    #[doc = "          p2pcdLearningRequest ABSENT,"]
    #[doc = "          missingCrlIdentifier ABSENT"]
    #[doc = "        })"]
    #[doc = "      }),"]
    #[doc = "      signer (WITH COMPONENTS {...,  --constraints on the certificate"]
    #[doc = "        certificate ((WITH COMPONENT (EtsiTs103097Certificate))^(SIZE(1)))"]
    #[doc = "      })"]
    #[doc = "    }),"]
    #[doc = "    encryptedData (WITH COMPONENTS {..., -- constraints on encrypted data headers"]
    #[doc = "      recipients  (WITH COMPONENT ("]
    #[doc = "        (WITH COMPONENTS {...,"]
    #[doc = "          pskRecipInfo ABSENT,"]
    #[doc = "          symmRecipInfo ABSENT,"]
    #[doc = "          rekRecipInfo ABSENT"]
    #[doc = "        })"]
    #[doc = "      ))"]
    #[doc = "    }),"]
    #[doc = "    signedCertificateRequest ABSENT"]
    #[doc = "  })"]
    #[doc = "}) "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "EtsiTs103097Data-Unsecured")]
    pub struct EtsiTs103097DataUnsecured(pub EtsiTs103097Data);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2 {
    extern crate alloc;
    use super::etsi_ts103097_extension_module::EtsiOriginatingHeaderInfoExtension;
    use super::ieee1609_dot2_base_types::{
        CrlSeries, EccP256CurvePoint, EciesP256EncryptedKey, EncryptionKey, GeographicRegion,
        GroupLinkageValue, HashAlgorithm, HashedId3, HashedId8, Hostname, IValue, LinkageValue,
        Opaque, Psid, PsidSsp, PsidSspRange, PublicEncryptionKey, PublicVerificationKey,
        SequenceOfHashedId3, SequenceOfPsidSsp, SequenceOfPsidSspRange, ServiceSpecificPermissions,
        Signature, SubjectAssurance, SymmetricEncryptionKey, ThreeDLocation, Time64, Uint16, Uint3,
        Uint32, Uint8, ValidityPeriod,
    };
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @class AesCcmCiphertext"]
    #[doc = " *"]
    #[doc = " * @brief This data structure encapsulates an encrypted ciphertext for the"]
    #[doc = " * AES-CCM symmetric algorithm. It contains the following fields:"]
    #[doc = " *"]
    #[doc = " * <br><br>The ciphertext is 16 bytes longer than the corresponding plaintext."]
    #[doc = " *"]
    #[doc = " * <br><br>The plaintext resulting from a correct decryption of the"]
    #[doc = " * ciphertext is a COER-encoded Ieee1609Dot2Data structure."]
    #[doc = " *"]
    #[doc = " * @param nonce contains the nonce N as specified in 5.3.7."]
    #[doc = " *"]
    #[doc = " * @param ccmCiphertext contains the ciphertext C as specified in 5.3.7."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct AesCcmCiphertext {
        pub nonce: FixedOctetString<12>,
        #[rasn(identifier = "ccmCiphertext")]
        pub ccm_ciphertext: Opaque,
    }
    impl AesCcmCiphertext {
        pub fn new(nonce: FixedOctetString<12>, ccm_ciphertext: Opaque) -> Self {
            Self {
                nonce,
                ccm_ciphertext,
            }
        }
    }
    #[doc = "***************************************************************************"]
    #[doc = "                Certificates and other Security Management                 "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @class Certificate"]
    #[doc = " *"]
    #[doc = " * @brief This structure is a profile of the structure CertificateBase which"]
    #[doc = " * specifies the valid combinations of fields to transmit implicit and"]
    #[doc = " * explicit certificates."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Certificate(pub CertificateBase);
    #[doc = "*"]
    #[doc = " * @class CertificateBase"]
    #[doc = " *"]
    #[doc = " * @brief The fields in this structure have the following meaning:"]
    #[doc = " *"]
    #[doc = " * <br><br><b>Encoding considerations</b>: When a certificate is encoded for"]
    #[doc = " * hashing, for example to generate its HashedId8, or when it is to be used"]
    #[doc = " * as the <i>signer identifier information</i> for verification, it is"]
    #[doc = " * canonicalized as follows:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The encoding of toBeSigned uses the compressed form for all elliptic"]
    #[doc = " * curve points: that is, those points indicate a choice of compressed-y-0 or"]
    #[doc = " * compressed-y-1.</li>"]
    #[doc = " *"]
    #[doc = " * <li> The encoding of the signature, if present and if an ECDSA signature,"]
    #[doc = " * takes the r value to be an EccP256CurvePoint or EccP384CurvePoint"]
    #[doc = " * indicating the choice x-only.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <br><br><b>Whole-certificate hash</b>: If the entirety of a certificate is"]
    #[doc = " * hashed to calculate a HashedId3, HashedId8, or HashedId10, the algorithm"]
    #[doc = " * used for this purpose is known as the <i>whole-certificate hash</i>."]
    #[doc = " * <ul>"]
    #[doc = " * <li> The whole-certificate hash is SHA-256 if the certificate is an"]
    #[doc = " * implicit certificate.</li>"]
    #[doc = " *"]
    #[doc = " * <li> The whole-certificate hash is SHA-256 if the certificate is an"]
    #[doc = " * explicit certificate and toBeSigned.verifyKeyIndicator.verificationKey is"]
    #[doc = " * an EccP256CurvePoint.</li>"]
    #[doc = " *"]
    #[doc = " * <li> The whole-certificate hash is SHA-384 if the certificate is an"]
    #[doc = " * explicit certificate and toBeSigned.verifyKeyIndicator.verificationKey is"]
    #[doc = " * an EccP384CurvePoint.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <b>Parameters</b>:"]
    #[doc = " *"]
    #[doc = " * @param version contains the version of the certificate format. In this"]
    #[doc = " * version of the data structures, this field is set to 3."]
    #[doc = " *"]
    #[doc = " * @param type states whether the certificate is implicit or explicit. This"]
    #[doc = " * field is set to explicit for explicit certificates and to implicit for"]
    #[doc = " * implicit certificates. See ExplicitCertificate and ImplicitCertificate for"]
    #[doc = " * more details."]
    #[doc = " *"]
    #[doc = " * @param issuer identifies the issuer of the certificate."]
    #[doc = " *"]
    #[doc = " * @param toBeSigned is the certificate contents. This field is an input to"]
    #[doc = " * the hash when generating or verifying signatures for an explicit"]
    #[doc = " * certificate, or generating or verifying the public key from the"]
    #[doc = " * reconstruction value for an implicit certificate. The details of how this"]
    #[doc = " * field are encoded are given in the description of the"]
    #[doc = " * ToBeSignedCertificate type."]
    #[doc = " *"]
    #[doc = " * @param signature is included in an ExplicitCertificate. It is the"]
    #[doc = " * signature, calculated by the signer identified in the issuer field, over"]
    #[doc = " * the hash of toBeSigned. The hash is calculated as specified in 5.3.1, where:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> Data input is the encoding of toBeSigned following the COER.</li>"]
    #[doc = " *"]
    #[doc = " * <li> Signer identifier input depends on the verification type, which in"]
    #[doc = " * turn depends on the choice indicated by issuer. If the choice indicated by"]
    #[doc = " * issuer is self, the verification type is self-signed and the signer"]
    #[doc = " * identifier input is the empty string. If the choice indicated by issuer is"]
    #[doc = " * not self, the verification type is certificate and the signer identifier"]
    #[doc = " * input is the canonicalized COER encoding of the certificate indicated by"]
    #[doc = " * issuer. The canonicalization is carried out as specified in the <b>Encoding"]
    #[doc = " * consideration</b>s section of this subclause.</li>"]
    #[doc = " * </ul>"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CertificateBase {
        #[rasn(value("3"))]
        pub version: Uint8,
        #[rasn(identifier = "type")]
        pub r_type: CertificateType,
        pub issuer: IssuerIdentifier,
        #[rasn(identifier = "toBeSigned")]
        pub to_be_signed: ToBeSignedCertificate,
        pub signature: Option<Signature>,
    }
    impl CertificateBase {
        pub fn new(
            version: Uint8,
            r_type: CertificateType,
            issuer: IssuerIdentifier,
            to_be_signed: ToBeSignedCertificate,
            signature: Option<Signature>,
        ) -> Self {
            Self {
                version,
                r_type,
                issuer,
                to_be_signed,
                signature,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class CertificateId"]
    #[doc = " *"]
    #[doc = " * @brief This structure contains information that is used to identify the"]
    #[doc = " * certificate holder if necessary."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the choice indicated in this"]
    #[doc = " * field shall reject a signed SPDU as invalid.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <b>Parameters</b>:"]
    #[doc = " *"]
    #[doc = " * @param linkageData is used to identify the certificate for revocation"]
    #[doc = " * purposes in the case of certificates that appear on linked certificate"]
    #[doc = " * CRLs. See 5.1.3 and 7.3 for further discussion."]
    #[doc = " *"]
    #[doc = " * @param name is used to identify the certificate holder in the case of"]
    #[doc = " * non-anonymous certificates. The contents of this field are a matter of"]
    #[doc = " * policy and should be human-readable."]
    #[doc = " *"]
    #[doc = " * @param binaryId supports identifiers that are not human-readable."]
    #[doc = " *"]
    #[doc = " * @param none indicates that the certificate does not include an identifier."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CertificateId {
        linkageData(LinkageData),
        name(Hostname),
        #[rasn(size("1..=64"))]
        binaryId(OctetString),
        none(()),
    }
    #[doc = "*"]
    #[doc = " * @class CertificateType"]
    #[doc = " *"]
    #[doc = " * @brief This enumerated type indicates whether a certificate is explicit or"]
    #[doc = " * implicit."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum CertificateType {
        explicit = 0,
        implicit = 1,
    }
    #[doc = "*"]
    #[doc = " * @class ContributedExtensionBlock"]
    #[doc = " *"]
    #[doc = " * @brief This data structure defines the format of an extension block"]
    #[doc = " * provided by an identified contributor by using the temnplate provided"]
    #[doc = " * in the class IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION constraint"]
    #[doc = " * to the objects in the set Ieee1609Dot2HeaderInfoContributedExtensions."]
    #[doc = " *"]
    #[doc = " * @param contributorId uniquely identifies the contributor"]
    #[doc = " *"]
    #[doc = " * @param extns contains a list of extensions from that contributor."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct ContributedExtensionBlock {
        #[rasn(identifier = "contributorId")]
        pub contributor_id: HeaderInfoContributorId,
        #[rasn(size("1.."))]
        pub extns: SequenceOf<Any>,
    }
    impl ContributedExtensionBlock {
        pub fn new(contributor_id: HeaderInfoContributorId, extns: SequenceOf<Any>) -> Self {
            Self {
                contributor_id,
                extns,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class ContributedExtensionBlocks"]
    #[doc = " *"]
    #[doc = " * @brief This data structure defines a list of ContributedExtensionBlock"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("1.."))]
    pub struct ContributedExtensionBlocks(pub SequenceOf<ContributedExtensionBlock>);
    #[doc = "*"]
    #[doc = " * @class Countersignature"]
    #[doc = " *"]
    #[doc = " * @brief This data structure is used to perform a countersignature over an"]
    #[doc = " * already-signed SPDU. This is the profile of an Ieee1609Dot2Data containing"]
    #[doc = " * a signedData. The tbsData within content is composed of a payload"]
    #[doc = " * containing the hash (extDataHash) of the externally generated, pre-signed"]
    #[doc = " * SPDU over which the countersignature is performed."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Countersignature(pub Ieee1609Dot2Data);
    #[doc = "***************************************************************************"]
    #[doc = "                              Encrypted Data                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @class EncryptedData"]
    #[doc = " *"]
    #[doc = " * @brief This data structure encodes data that has been encrypted to one or"]
    #[doc = " * more recipients using the recipients’ public or symmetric keys as"]
    #[doc = " * specified in 1.1.1."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> If present, recipients is a critical information field as defined in"]
    #[doc = " * 5.2.6. An implementation that does not support the number of RecipientInfo"]
    #[doc = " * in recipients when decrypted shall indicate that the encrypted SPDU could"]
    #[doc = " * not be decrypted due to unsupported critical information fields. A"]
    #[doc = " * compliant implementation shall support recipients fields containing at"]
    #[doc = " * least eight entries.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <b>Parameters</b>:"]
    #[doc = " *"]
    #[doc = " * @param recipients contains one or more RecipientInfos. These entries may"]
    #[doc = " * be more than one RecipientInfo, and more than one type of RecipientInfo,"]
    #[doc = " * as long as they are all indicating or containing the same data encryption"]
    #[doc = " * key."]
    #[doc = " *"]
    #[doc = " * @param ciphertext contains the encrypted data. This is the encryption of"]
    #[doc = " * an encoded Ieee1609Dot2Data structure as specified in 5.3.4.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EncryptedData {
        pub recipients: SequenceOfRecipientInfo,
        pub ciphertext: SymmetricCiphertext,
    }
    impl EncryptedData {
        pub fn new(recipients: SequenceOfRecipientInfo, ciphertext: SymmetricCiphertext) -> Self {
            Self {
                recipients,
                ciphertext,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class EncryptedDataEncryptionKey"]
    #[doc = " *"]
    #[doc = " * @brief This data structure contains an encrypted data encryption key."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>: If present and applicable to"]
    #[doc = " * the receiving SDEE, this is a critical information field as defined in"]
    #[doc = " * 5.2.6. If an implementation receives an encrypted SPDU and determines that"]
    #[doc = " * one or more RecipientInfo fields are relevant to it, and if all of those"]
    #[doc = " * RecipientInfos contain an EncryptedDataEncryptionKey such that the"]
    #[doc = " * implementation does not recognize the indicated CHOICE, the implementation"]
    #[doc = " * shall indicate that the encrypted SPDU is not decryptable."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum EncryptedDataEncryptionKey {
        eciesNistP256(EciesP256EncryptedKey),
        eciesBrainpoolP256r1(EciesP256EncryptedKey),
    }
    #[doc = "*"]
    #[doc = " * @class EndEntityType"]
    #[doc = " *"]
    #[doc = " * @brief This type indicates which type of permissions may appear in"]
    #[doc = " * end-entity certificates the chain of whose permissions passes through the"]
    #[doc = " * PsidGroupPermissions field containing this value. If app is indicated, the"]
    #[doc = " * end-entity certificate may contain an appPermissions field. If enroll is"]
    #[doc = " * indicated, the end-entity certificate may contain a certRequestPermissions"]
    #[doc = " * field."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct EndEntityType(pub FixedBitString<8usize>);
    #[doc = "*"]
    #[doc = " * @class ExplicitCertificate"]
    #[doc = " *"]
    #[doc = " * @brief This is a profile of the CertificateBase structure providing all"]
    #[doc = " * the fields necessary for an explicit certificate, and no others."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct ExplicitCertificate(pub CertificateBase);
    #[doc = "*"]
    #[doc = " * @class HashedData"]
    #[doc = " *"]
    #[doc = " * @brief This structure contains the hash of some data with a specified hash"]
    #[doc = " * algorithm. The hash algorithms supported in this version of this"]
    #[doc = " * standard are SHA-256 (in the root) and SHA-384 (in the first extension)."]
    #[doc = " * The reserved extension is for future use."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum HashedData {
        sha256HashedData(FixedOctetString<32>),
        #[rasn(extension_addition)]
        sha384HashedData(FixedOctetString<48>),
        #[rasn(extension_addition)]
        reserved(FixedOctetString<32>),
    }
    #[doc = "*"]
    #[doc = " * @class HeaderInfo"]
    #[doc = " *"]
    #[doc = " * @brief This structure contains information that is used to establish"]
    #[doc = " * validity by the criteria of 5.2."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Encoding considerations</b>: When the structure is encoded in"]
    #[doc = " * order to be digested to generate or check a signature, if encryptionKey is"]
    #[doc = " * present, and indicates the choice public, and contains a"]
    #[doc = " * BasePublicEncryptionKey that is an elliptic curve point (i.e., of"]
    #[doc = " * typeEccP256CurvePoint or EccP384CurvePoint), then the elliptic curve point"]
    #[doc = " * is encoded in compressed form, i.e., such that the choice indicated within"]
    #[doc = " * the Ecc*CurvePoint is compressed-y-0 or compressed-y-1."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Parameters</b>:"]
    #[doc = " *"]
    #[doc = " * @param psid indicates the application area with which the sender is"]
    #[doc = " * claiming the payload should be associated."]
    #[doc = " *"]
    #[doc = " * @param generationTime indicates the time at which the structure was"]
    #[doc = " * generated. See 5.2.5.2.2 and 5.2.5.2.3 for discussion of the use of this"]
    #[doc = " * field."]
    #[doc = " *"]
    #[doc = " * @param expiryTime, if present, contains the time after which the data"]
    #[doc = " * should no longer be considered relevant. If both generationTime and"]
    #[doc = " * expiryTime are present, the signed SPDU is invalid if generationTime is"]
    #[doc = " * not strictly earlier than expiryTime."]
    #[doc = " *"]
    #[doc = " * @param generationLocation, if present, contains the location at which the"]
    #[doc = " * signature was generated."]
    #[doc = " *"]
    #[doc = " * @param p2pcdLearningRequest, if present, is used by the SDS to request"]
    #[doc = " * certificates for which it has seen identifiers but does not know the"]
    #[doc = " * entire certificate. A specification of this peer-to-peer certificate"]
    #[doc = " * distribution (P2PCD) mechanism is given in Clause 8. This field is used"]
    #[doc = " * for the out-of-band flavor of P2PCD and shall only be present if"]
    #[doc = " * inlineP2pcdRequest is not present. The HashedId3 is calculated with the"]
    #[doc = " * whole-certificate hash algorithm, determined as described in 6.4.3."]
    #[doc = " *"]
    #[doc = " * @param missingCrlIdentifier, if present, is used by the SDS to request"]
    #[doc = " * CRLs which it knows to have been issued but have not received. This is"]
    #[doc = " * provided for future use and the associated mechanism is not defined in"]
    #[doc = " * this version of this standard."]
    #[doc = " *"]
    #[doc = " * @param encryptionKey, if present, is used to indicate that a further"]
    #[doc = " * communication should be encrypted with the indicated key. One possible use"]
    #[doc = " * of this key to encrypt a response is specified in 6.3.35, 6.3.37, and"]
    #[doc = " * 6.3.34. An encryptionKey field of type symmetric should only be used if"]
    #[doc = " * the Signed¬Data containing this field is securely encrypted by some means."]
    #[doc = " *"]
    #[doc = " * @param inlineP2pcdRequest, if present, is used by the SDS to request"]
    #[doc = " * unknown certificates per the inline peer-to-peer certificate distribution"]
    #[doc = " * mechanism is given in Clause 8. This field shall only be present if"]
    #[doc = " * p2pcdLearningRequest is not present. The HashedId3 is calculated with the"]
    #[doc = " * whole-certificate hash algorithm, determined as described in 6.4.3."]
    #[doc = " *"]
    #[doc = " * @param requestedCertificate, if present, is used by the SDS to provide"]
    #[doc = " * certificates per the \"inline\" version of the peer-to-peer certificate"]
    #[doc = " * distribution mechanism given in Clause 8."]
    #[doc = " *"]
    #[doc = " * @param pduFunctionalType, if present, is used to indicate that the SPDU is"]
    #[doc = " * to be consumed by a process other than an application process as defined"]
    #[doc = " * in ISO 21177 [B14a]. See 6.3.23b for more details."]
    #[doc = " *"]
    #[doc = " * @param contributedExtensions, if present, is used to provide extension blocks"]
    #[doc = " * defined by identified contributing organizations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct HeaderInfo {
        pub psid: Psid,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Option<Time64>,
        #[rasn(identifier = "expiryTime")]
        pub expiry_time: Option<Time64>,
        #[rasn(identifier = "generationLocation")]
        pub generation_location: Option<ThreeDLocation>,
        #[rasn(identifier = "p2pcdLearningRequest")]
        pub p2pcd_learning_request: Option<HashedId3>,
        #[rasn(identifier = "missingCrlIdentifier")]
        pub missing_crl_identifier: Option<MissingCrlIdentifier>,
        #[rasn(identifier = "encryptionKey")]
        pub encryption_key: Option<EncryptionKey>,
        #[rasn(extension_addition, identifier = "inlineP2pcdRequest")]
        pub inline_p2pcd_request: Option<SequenceOfHashedId3>,
        #[rasn(extension_addition, identifier = "requestedCertificate")]
        pub requested_certificate: Option<Certificate>,
        #[rasn(extension_addition, identifier = "pduFunctionalType")]
        pub pdu_functional_type: Option<PduFunctionalType>,
        #[rasn(extension_addition, identifier = "contributedExtensions")]
        pub contributed_extensions: Option<ContributedExtensionBlocks>,
    }
    impl HeaderInfo {
        pub fn new(
            psid: Psid,
            generation_time: Option<Time64>,
            expiry_time: Option<Time64>,
            generation_location: Option<ThreeDLocation>,
            p2pcd_learning_request: Option<HashedId3>,
            missing_crl_identifier: Option<MissingCrlIdentifier>,
            encryption_key: Option<EncryptionKey>,
            inline_p2pcd_request: Option<SequenceOfHashedId3>,
            requested_certificate: Option<Certificate>,
            pdu_functional_type: Option<PduFunctionalType>,
            contributed_extensions: Option<ContributedExtensionBlocks>,
        ) -> Self {
            Self {
                psid,
                generation_time,
                expiry_time,
                generation_location,
                p2pcd_learning_request,
                missing_crl_identifier,
                encryption_key,
                inline_p2pcd_request,
                requested_certificate,
                pdu_functional_type,
                contributed_extensions,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class HeaderInfoContributorId"]
    #[doc = " *"]
    #[doc = " * @brief This data structure defines the header info contributor id type"]
    #[doc = " * and its values."]
    #[doc = " *"]
    #[doc = " * @param In this version of the standard, value 2 is assigned to ETSI."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct HeaderInfoContributorId(pub u8);
    #[doc = "*"]
    #[doc = " * @class Ieee1609Dot2Content"]
    #[doc = " *"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param unsecuredData indicates that the content is an OCTET STRING to be"]
    #[doc = " * consumed outside the SDS."]
    #[doc = " *"]
    #[doc = " * @param signedData indicates that the content has been signed according to"]
    #[doc = " * this standard."]
    #[doc = " *"]
    #[doc = " * @param encryptedData indicates that the content has been encrypted"]
    #[doc = " * according to this standard."]
    #[doc = " *"]
    #[doc = " * @param signedCertificateRequest indicates that the content is a"]
    #[doc = " * certificate request. Further specification of certificate requests is not"]
    #[doc = " * provided in this version of this standard."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum Ieee1609Dot2Content {
        unsecuredData(Opaque),
        signedData(SignedData),
        encryptedData(EncryptedData),
        signedCertificateRequest(Opaque),
        #[rasn(extension_addition)]
        signedX509CertificateRequest(Opaque),
    }
    #[doc = "***************************************************************************"]
    #[doc = "                               Secured Data                                "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @class Ieee1609Dot2Data"]
    #[doc = " *"]
    #[doc = " * @brief This data type is used to contain the other data types in this"]
    #[doc = " * clause. The fields in the Ieee1609Dot2Data have the following meanings:"]
    #[doc = " *"]
    #[doc = " * @param protocolVersion contains the current version of the protocol. The"]
    #[doc = " * version specified in this document is version 3, represented by the"]
    #[doc = " * integer 3. There are no major or minor version numbers."]
    #[doc = " *"]
    #[doc = " * @param content contains the content in the form of an Ieee1609Dot2Content."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct Ieee1609Dot2Data {
        #[rasn(value("3"), identifier = "protocolVersion")]
        pub protocol_version: Uint8,
        pub content: Ieee1609Dot2Content,
    }
    impl Ieee1609Dot2Data {
        pub fn new(protocol_version: Uint8, content: Ieee1609Dot2Content) -> Self {
            Self {
                protocol_version,
                content,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class ImplicitCertificate"]
    #[doc = " *"]
    #[doc = " * @brief This is a profile of the CertificateBase structure providing all"]
    #[doc = " * the fields necessary for an implicit certificate, and no others."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct ImplicitCertificate(pub CertificateBase);
    #[doc = "*"]
    #[doc = " * @class IssuerIdentifier"]
    #[doc = " *"]
    #[doc = " * @brief This structure allows the recipient of a certificate to determine"]
    #[doc = " * which keying material to use to authenticate the certificate."]
    #[doc = " *"]
    #[doc = " * <br><br>If the choice indicated is sha256AndDigest or sha384AndDigest:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The structure contains the HashedId8 of the issuing certificate,"]
    #[doc = " * where the certificate is canonicalized as specified in 6.4.3 before"]
    #[doc = " * hashing and the HashedId8 is calculated with the whole-certificate hash"]
    #[doc = " * algorithm, determined as described in 6.4.3.</li>"]
    #[doc = " *"]
    #[doc = " * <li> The hash algorithm to be used to generate the hash of the certificate"]
    #[doc = " * for verification is SHA-256 (in the case of sha256AndDigest) or SHA-384"]
    #[doc = " * (in the case of sha384AndDigest).</li>"]
    #[doc = " *"]
    #[doc = " * <li> The certificate is to be verified with the public key of the"]
    #[doc = " * indicated issuing certificate.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * If the choice indicated is self:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The structure indicates what hash algorithm is to be used to generate"]
    #[doc = " * the hash of the certificate for verification.</li>"]
    #[doc = " *"]
    #[doc = " * <li> The certificate is to be verified with the public key indicated by"]
    #[doc = " * the verifyKeyIndicator field in theToBeSignedCertificate.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum IssuerIdentifier {
        sha256AndDigest(HashedId8),
        #[rasn(identifier = "self")]
        R_self(HashAlgorithm),
        #[rasn(extension_addition)]
        sha384AndDigest(HashedId8),
    }
    #[doc = "*"]
    #[doc = " * @class LinkageData"]
    #[doc = " *"]
    #[doc = " * @brief This structure contains information that is matched against"]
    #[doc = " * information obtained from a linkage ID-based CRL to determine whether the"]
    #[doc = " * containing certificate has been revoked. See 5.1.3.4 and 7.3 for details"]
    #[doc = " * of use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct LinkageData {
        #[rasn(identifier = "iCert")]
        pub i_cert: IValue,
        #[rasn(identifier = "linkage-value")]
        pub linkage_value: LinkageValue,
        #[rasn(identifier = "group-linkage-value")]
        pub group_linkage_value: Option<GroupLinkageValue>,
    }
    impl LinkageData {
        pub fn new(
            i_cert: IValue,
            linkage_value: LinkageValue,
            group_linkage_value: Option<GroupLinkageValue>,
        ) -> Self {
            Self {
                i_cert,
                linkage_value,
                group_linkage_value,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class MissingCrlIdentifier"]
    #[doc = " *"]
    #[doc = " * @brief This structure may be used to request a CRL that the SSME knows to"]
    #[doc = " * have been issued but has not yet received. It is provided for future use"]
    #[doc = " * and its use is not defined in this version of this standard."]
    #[doc = " *"]
    #[doc = " * @param cracaId is the HashedId3 of the CRACA, as defined in 5.1.3. The"]
    #[doc = " * HashedId3 is calculated with the whole-certificate hash algorithm,"]
    #[doc = " * determined as described in 6.4.3."]
    #[doc = " *"]
    #[doc = " * @param crlSeries is the requested CRL Series value. See 5.1.3 for more"]
    #[doc = " * information."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct MissingCrlIdentifier {
        #[rasn(identifier = "cracaId")]
        pub craca_id: HashedId3,
        #[rasn(identifier = "crlSeries")]
        pub crl_series: CrlSeries,
    }
    impl MissingCrlIdentifier {
        pub fn new(craca_id: HashedId3, crl_series: CrlSeries) -> Self {
            Self {
                craca_id,
                crl_series,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class PKRecipientInfo"]
    #[doc = " *"]
    #[doc = " * @brief This data structure contains the following fields:"]
    #[doc = " *"]
    #[doc = " * @param recipientId contains the hash of the container for the encryption"]
    #[doc = " * public key as specified in the definition of RecipientInfo. Specifically,"]
    #[doc = " * depending on the choice indicated by the containing RecipientInfo structure:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> If the containing RecipientInfo structure indicates certRecipInfo,"]
    #[doc = " * this field contains the HashedId8 of the certificate. The HashedId8 is"]
    #[doc = " * calculated with the whole-certificate hash algorithm, determined as"]
    #[doc = " * described in 6.4.3.</li>"]
    #[doc = " *"]
    #[doc = " * <li> If the containing RecipientInfo structure indicates"]
    #[doc = " * signedDataRecipInfo, this field contains the HashedId8 of the"]
    #[doc = " * Ieee1609Dot2Data of type signed that contained the encryption key, with"]
    #[doc = " * that Ieee1609Dot2Data canonicalized per 6.3.4. The HashedId8 is calculated"]
    #[doc = " * with SHA-256.</li>"]
    #[doc = " *"]
    #[doc = " * <li> If the containing RecipientInfo structure indicates rekRecipInfo,"]
    #[doc = " * this field contains the HashedId8 of the COER encoding of a"]
    #[doc = " * PublicEncryptionKey structure containing the response encryption key. The"]
    #[doc = " * HashedId8 is calculated with SHA-256.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * @param encKey contains the encrypted key."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PKRecipientInfo {
        #[rasn(identifier = "recipientId")]
        pub recipient_id: HashedId8,
        #[rasn(identifier = "encKey")]
        pub enc_key: EncryptedDataEncryptionKey,
    }
    impl PKRecipientInfo {
        pub fn new(recipient_id: HashedId8, enc_key: EncryptedDataEncryptionKey) -> Self {
            Self {
                recipient_id,
                enc_key,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class PduFunctionalType"]
    #[doc = " *"]
    #[doc = " * @brief This data structure identifies the functional entity that is"]
    #[doc = " * intended to consume an SPDU, for the case where that functional entity is"]
    #[doc = " * not an application process but security support services for an"]
    #[doc = " * application process. Further details and the intended use of this field"]
    #[doc = " * are defined in ISO 21177 [B14a]."]
    #[doc = " *"]
    #[doc = " * <br><br>An SPDU in which the pduFunctionalType field is present conforms"]
    #[doc = " * to the security profile for that PduFunctionalType value (given in ISO"]
    #[doc = " * 21177 [B14a]), not to the security profile for Application SPDUs for the"]
    #[doc = " * PSID."]
    #[doc = " *"]
    #[doc = " * @param tlsHandshake indicates that the Signed SPDU is not to be directly"]
    #[doc = " * consumed as an application PDU but is to be used to provide information"]
    #[doc = " * about the holder’s permissions to a Transport Layer Security (TLS) (IETF"]
    #[doc = " * 5246 [B13], IETF 8446 [B13a]) handshake process operating to secure"]
    #[doc = " * communications to an application process. See IETF [B13b] and ISO 21177"]
    #[doc = " * [B14a] for further information."]
    #[doc = " *"]
    #[doc = " * @param iso21177ExtendedAuth indicates that the Signed SPDU is not to be"]
    #[doc = " * directly consumed as an application PDU but is to be used to provide"]
    #[doc = " * additional information about the holder’s permissions to the ISO 21177"]
    #[doc = " * Security Subsystem for an application process. See ISO 21177 [B14a] for"]
    #[doc = " * further information."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct PduFunctionalType(pub u8);
    #[doc = "*"]
    #[doc = " * @class PreSharedKeyRecipientInfo"]
    #[doc = " *"]
    #[doc = " * @brief This data structure is used to indicate a symmetric key that may be"]
    #[doc = " * used directly to decrypt a SymmetricCiphertext. It consists of the"]
    #[doc = " * low-order 8 bytes of the SHA-256 hash of the COER encoding of a"]
    #[doc = " * SymmetricEncryptionKey structure containing the symmetric key in question."]
    #[doc = " * The symmetric key may be established by any appropriate means agreed by"]
    #[doc = " * the two parties to the exchange."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct PreSharedKeyRecipientInfo(pub HashedId8);
    #[doc = "*"]
    #[doc = " * @class PsidGroupPermissions"]
    #[doc = " *"]
    #[doc = " * @brief This structure states the permissions that a certificate holder has"]
    #[doc = " * with respect to issuing and requesting certificates for a particular set"]
    #[doc = " * of PSIDs. In this structure:"]
    #[doc = " *"]
    #[doc = " * <br><br> For examples, see D.5.3 and D.5.4."]
    #[doc = " *"]
    #[doc = " * @param subjectPermissions indicates PSIDs and SSP Ranges covered by this"]
    #[doc = " * field."]
    #[doc = " *"]
    #[doc = " * @param minChainLength and chainLengthRange indicate how long the"]
    #[doc = " * certificate chain from this certificate to the end-entity certificate is"]
    #[doc = " * permitted to be. As specified in 5.1.2.1, the length of the certificate"]
    #[doc = " * chain is the number of certificates \"below\" this certificate in the chain,"]
    #[doc = " * down to and including the end-entity certificate. The length is permitted"]
    #[doc = " * to be (a) greater than or equal to minChainLength certificates and (b)"]
    #[doc = " * less than or equal to minChainLength + chainLengthRange certificates. A"]
    #[doc = " * value of 0 for minChainLength is not permitted when this type appears in"]
    #[doc = " * the certIssuePermissions field of a ToBeSignedCertificate; a certificate"]
    #[doc = " * that has a value of 0 for this field is invalid. The value -1 for"]
    #[doc = " * chainLengthRange is a special case: if the value of chainLengthRange is -1"]
    #[doc = " * it indicates that the certificate chain may be any length equal to or"]
    #[doc = " * greater than minChainLength. See the examples below for further discussion."]
    #[doc = " *"]
    #[doc = " * @param eeType takes one or more of the values app and enroll and indicates"]
    #[doc = " * the type of certificates or requests that this instance of"]
    #[doc = " * PsidGroupPermissions in the certificate is entitled to authorize. If this"]
    #[doc = " * field indicates app, the chain is allowed to end in an authorization"]
    #[doc = " * certificate, i.e., a certficate in which these permissions appear in an"]
    #[doc = " * appPermissions field (in other words, if the field does not indicate app"]
    #[doc = " * but the chain ends in an authorization certificate, the chain shall be"]
    #[doc = " * considered invalid). If this field indicates enroll, the chain is allowed"]
    #[doc = " * to end in an enrollment certificate, i.e., a certificate in which these"]
    #[doc = " * permissions appear in a certReqPermissions permissions field), or both (in"]
    #[doc = " * other words, if the field does not indicate app but the chain ends in an"]
    #[doc = " * authorization certificate, the chain shall be considered invalid)."]
    #[doc = " * Different instances of PsidGroupPermissions within a ToBeSignedCertificate"]
    #[doc = " * may have different values for eeType."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PsidGroupPermissions {
        #[rasn(identifier = "subjectPermissions")]
        pub subject_permissions: SubjectPermissions,
        #[rasn(
            default = "psid_group_permissions_min_chain_length_default",
            identifier = "minChainLength"
        )]
        pub min_chain_length: Integer,
        #[rasn(
            default = "psid_group_permissions_chain_length_range_default",
            identifier = "chainLengthRange"
        )]
        pub chain_length_range: Integer,
        #[rasn(
            default = "psid_group_permissions_ee_type_default",
            identifier = "eeType"
        )]
        pub ee_type: EndEntityType,
    }
    impl PsidGroupPermissions {
        pub fn new(
            subject_permissions: SubjectPermissions,
            min_chain_length: Integer,
            chain_length_range: Integer,
            ee_type: EndEntityType,
        ) -> Self {
            Self {
                subject_permissions,
                min_chain_length,
                chain_length_range,
                ee_type,
            }
        }
    }
    fn psid_group_permissions_min_chain_length_default() -> Integer {
        Integer::from(1)
    }
    fn psid_group_permissions_chain_length_range_default() -> Integer {
        Integer::from(0)
    }
    fn psid_group_permissions_ee_type_default() -> EndEntityType {
        EndEntityType(FixedBitString::new([0, 1, 0, 0, 0, 0, 0, 0]))
    }
    #[doc = "*"]
    #[doc = " * @class RecipientInfo"]
    #[doc = " *"]
    #[doc = " * @brief This data structure is used to transfer the data encryption key to"]
    #[doc = " * an individual recipient of an EncryptedData. The option pskRecipInfo is"]
    #[doc = " * selected if the EncryptedData was encrypted using the static encryption"]
    #[doc = " * key approach specified in 1.1.1.1. The other options are selected if the"]
    #[doc = " * EncryptedData was encrypted using the ephemeral encryption key approach"]
    #[doc = " * specified in 1.1.1.1. The meanings of the choices are:"]
    #[doc = " *"]
    #[doc = " * <br><br>See Annex C.7 for guidance on when it may be appropriate to use"]
    #[doc = " * each of these approaches."]
    #[doc = " *"]
    #[doc = " * @param pskRecipInfo: The ciphertext was encrypted directly using a"]
    #[doc = " * symmetric key."]
    #[doc = " *"]
    #[doc = " * @param symmRecipInfo: The data encryption key was encrypted using a"]
    #[doc = " * symmetric key."]
    #[doc = " *"]
    #[doc = " * @param certRecipInfo: The data encryption key was encrypted using a public"]
    #[doc = " * key encryption scheme, where the public encryption key was obtained from a"]
    #[doc = " * certificate. In this case, the parameter P1 to ECIES as defined in 5.3.4"]
    #[doc = " * is the hash of the certificate."]
    #[doc = " *"]
    #[doc = " * @param signedDataRecipInfo: The data encryption key was encrypted using a"]
    #[doc = " * public encryption key, where the encryption key was obtained as the public"]
    #[doc = " * response encryption key from a Signed-Data. In this case, the parameter P1"]
    #[doc = " * to ECIES as defined in 5.3.4 is the SHA-256 hash of the Ieee1609Dot2Data"]
    #[doc = " * containing the response encryption key."]
    #[doc = " *"]
    #[doc = " * @param rekRecipInfo: The data encryption key was encrypted using a public"]
    #[doc = " * key that was not obtained from a Signed¬Data. In this case, the parameter"]
    #[doc = " * P1 to ECIES as defined in 5.3.4 is the hash of the empty string."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum RecipientInfo {
        pskRecipInfo(PreSharedKeyRecipientInfo),
        symmRecipInfo(SymmRecipientInfo),
        certRecipInfo(PKRecipientInfo),
        signedDataRecipInfo(PKRecipientInfo),
        rekRecipInfo(PKRecipientInfo),
    }
    #[doc = "*"]
    #[doc = " * @class SequenceOfCertificate"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfCertificate(pub SequenceOf<Certificate>);
    #[doc = "*"]
    #[doc = " * @class SequenceOfPsidGroupPermissions"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfPsidGroupPermissions(pub SequenceOf<PsidGroupPermissions>);
    #[doc = "*"]
    #[doc = " * @class SequenceOfRecipientInfo"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfRecipientInfo(pub SequenceOf<RecipientInfo>);
    #[doc = "*"]
    #[doc = " * @class SignedData"]
    #[doc = " *"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param hashId indicates the hash algorithm to be used to generate the hash"]
    #[doc = " * of the message for signing and verification."]
    #[doc = " *"]
    #[doc = " * @param tbsData contains the data that is hashed as input to the signature."]
    #[doc = " *"]
    #[doc = " * @param signer determines the keying material and hash algorithm used to"]
    #[doc = " * sign the data."]
    #[doc = " *"]
    #[doc = " * @param signature contains the digital signature itself, calculated as"]
    #[doc = " * specified in 5.3.1."]
    #[doc = " * <ul>"]
    #[doc = " * <li> If signer indicates the choice self, then the signature calculation"]
    #[doc = " * is parameterized as follows:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> <i>Data input</i> is equal to the COER encoding of the tbsData field"]
    #[doc = " * canonicalized according to the encoding considerations given in 6.3.6.</li>"]
    #[doc = " *"]
    #[doc = " * <li> <i>Verification type</i> is equal to <i>self</i>.</li>"]
    #[doc = " *"]
    #[doc = " * <li> <i>Signer identifier input</i> is equal to the empty string.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <li> If signer indicates certificate or digest, then the signature"]
    #[doc = " * calculation is parameterized as follows:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> <i>Data input</i> is equal to the COER encoding of the tbsData field"]
    #[doc = " * canonicalized according to the encoding considerations given in 6.3.6.</li>"]
    #[doc = " *"]
    #[doc = " * <li> <i>Verification type</i> is equal to <i>certificate</i>.</li>"]
    #[doc = " *"]
    #[doc = " * <li> <i>Signer identifier input</i> equal to the COER-encoding of the"]
    #[doc = " * Certificate that is to be used to verify the SPDU, canonicalized according"]
    #[doc = " * to the encoding considerations given in 6.4.3.</li>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct SignedData {
        #[rasn(identifier = "hashId")]
        pub hash_id: HashAlgorithm,
        #[rasn(identifier = "tbsData")]
        pub tbs_data: ToBeSignedData,
        pub signer: SignerIdentifier,
        pub signature: Signature,
    }
    impl SignedData {
        pub fn new(
            hash_id: HashAlgorithm,
            tbs_data: ToBeSignedData,
            signer: SignerIdentifier,
            signature: Signature,
        ) -> Self {
            Self {
                hash_id,
                tbs_data,
                signer,
                signature,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class SignedDataPayload"]
    #[doc = " *"]
    #[doc = " * @brief This structure contains the data payload of a ToBeSignedData. This"]
    #[doc = " * structure contains at least one of data and extDataHash, and may contain"]
    #[doc = " * both."]
    #[doc = " *"]
    #[doc = " * @param data contains data that is explicitly transported within the"]
    #[doc = " * structure."]
    #[doc = " *"]
    #[doc = " * @param extDataHash contains the hash of data that is not explicitly"]
    #[doc = " * transported within the structure, and which the creator of the structure"]
    #[doc = " * wishes to cryptographically bind to the signature. For example, if a"]
    #[doc = " * creator wanted to indicate that some large message was still valid, they"]
    #[doc = " * could use the extDataHash field to send a Signed¬Data containing the hash"]
    #[doc = " * of that large message without having to resend the message itself. Whether"]
    #[doc = " * or not extDataHash is used, and how it is used, is SDEE-specific."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct SignedDataPayload {
        pub data: Option<alloc::boxed::Box<Ieee1609Dot2Data>>,
        #[rasn(identifier = "extDataHash")]
        pub ext_data_hash: Option<HashedData>,
    }
    impl SignedDataPayload {
        pub fn new(
            data: Option<alloc::boxed::Box<Ieee1609Dot2Data>>,
            ext_data_hash: Option<HashedData>,
        ) -> Self {
            Self {
                data,
                ext_data_hash,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class SignerIdentifier"]
    #[doc = " *"]
    #[doc = " * @brief This structure allows the recipient of data to determine which"]
    #[doc = " * keying material to use to authenticate the data. It also indicates the"]
    #[doc = " * verification type to be used to generate the hash for verification, as"]
    #[doc = " * specified in 5.3.1."]
    #[doc = " * <ul>"]
    #[doc = " * <li> If the choice indicated is digest:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The structure contains the HashedId8 of the relevant certificate. The"]
    #[doc = " * HashedId8 is calculated with the whole-certificate hash algorithm,"]
    #[doc = " * determined as described in 6.4.3.</li>"]
    #[doc = " *"]
    #[doc = " * <li> The verification type is <i>certificate</i> and the certificate data"]
    #[doc = " * passed to the hash function as specified in 5.3.1 is the authorization"]
    #[doc = " * certificate.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <li> If the choice indicated is certificate:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The structure contains one or more Certificate structures, in order"]
    #[doc = " * such that the first certificate is the authorization certificate and each"]
    #[doc = " * subsequent certificate is the issuer of the one before it.</li>"]
    #[doc = " *"]
    #[doc = " * <li> The verification type is <i>certificate</i> and the certificate data"]
    #[doc = " * passed to the hash function as specified in 5.3.1 is the authorization"]
    #[doc = " * certificate.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <li> If the choice indicated is self:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The structure does not contain any data beyond the indication that"]
    #[doc = " * the choice value is self.</li>"]
    #[doc = " *"]
    #[doc = " * <li> The verification type is <i>self-signed</i>.</li>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <b>Critical information fields</b>:"]
    #[doc = " * <ol>"]
    #[doc = " * <li> If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the CHOICE value for this type"]
    #[doc = " * when verifying a signed SPDU shall indicate that the signed SPDU is invalid."]
    #[doc = " * </li>"]
    #[doc = " *"]
    #[doc = " * <li> If present, certificate is a critical information field as defined in"]
    #[doc = " * 5.2.6. An implementation that does not support the number of certificates"]
    #[doc = " * in certificate when verifying a signed SPDU shall indicate that the signed"]
    #[doc = " * SPDU is invalid. A compliant implementation shall support certificate"]
    #[doc = " * fields containing at least one certificate.</li>"]
    #[doc = " * </ol>"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SignerIdentifier {
        digest(HashedId8),
        certificate(SequenceOfCertificate),
        #[rasn(identifier = "self")]
        R_self(()),
    }
    #[doc = "*"]
    #[doc = " * @class SubjectPermissions"]
    #[doc = " *"]
    #[doc = " * @brief This indicates the PSIDs and associated SSPs for which certificate"]
    #[doc = " * issuance or request permissions are granted by a PsidGroupPermissions"]
    #[doc = " * structure. If this takes the value explicit, the enclosing"]
    #[doc = " * PsidGroupPermissions structure grants certificate issuance or request"]
    #[doc = " * permissions for the indicated PSIDs and SSP Ranges. If this takes the"]
    #[doc = " * value all, the enclosing PsidGroupPermissions structure grants certificate"]
    #[doc = " * issuance or request permissions for all PSIDs not indicated by other"]
    #[doc = " * PsidGroupPermissions in the same certIssuePermissions or"]
    #[doc = " * certRequestPermissions field."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the indicated CHOICE when"]
    #[doc = " * verifying a signed SPDU shall indicate that the signed SPDU is"]
    #[doc = " * invalid.</li>"]
    #[doc = " *"]
    #[doc = " * <li> If present, explicit is a critical information field as defined in"]
    #[doc = " * 5.2.6. An implementation that does not support the number of PsidSspRange"]
    #[doc = " * in explicit when verifying a signed SPDU shall indicate that the signed"]
    #[doc = " * SPDU is invalid. A compliant implementation shall support explicit fields"]
    #[doc = " * containing at least eight entries.</li>"]
    #[doc = " * </ul>"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SubjectPermissions {
        explicit(SequenceOfPsidSspRange),
        all(()),
    }
    #[doc = "*"]
    #[doc = " * @class SymmRecipientInfo"]
    #[doc = " *"]
    #[doc = " * @brief This data structure contains the following fields:"]
    #[doc = " *"]
    #[doc = " * @param recipientId contains the hash of the symmetric key encryption key"]
    #[doc = " * that may be used to decrypt the data encryption key. It consists of the"]
    #[doc = " * low-order 8 bytes of the SHA-256 hash of the COER encoding of a"]
    #[doc = " * SymmetricEncryptionKey structure containing the symmetric key in question."]
    #[doc = " * The symmetric key may be established by any appropriate means agreed by"]
    #[doc = " * the two parties to the exchange."]
    #[doc = " *"]
    #[doc = " * @param encKey contains the encrypted data encryption key within an AES-CCM"]
    #[doc = " * ciphertext."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct SymmRecipientInfo {
        #[rasn(identifier = "recipientId")]
        pub recipient_id: HashedId8,
        #[rasn(identifier = "encKey")]
        pub enc_key: SymmetricCiphertext,
    }
    impl SymmRecipientInfo {
        pub fn new(recipient_id: HashedId8, enc_key: SymmetricCiphertext) -> Self {
            Self {
                recipient_id,
                enc_key,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class SymmetricCiphertext"]
    #[doc = " *"]
    #[doc = " * @brief This data structure encapsulates a ciphertext generated with an"]
    #[doc = " * approved symmetric algorithm."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE value for this type in an encrypted SPDU"]
    #[doc = " * shall reject the SPDU as invalid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SymmetricCiphertext {
        aes128ccm(AesCcmCiphertext),
    }
    #[doc = "*"]
    #[doc = " * @class ToBeSignedCertificate"]
    #[doc = " *"]
    #[doc = " * @brief The fields in the ToBeSignedCertificate structure have the"]
    #[doc = " * following meaning:"]
    #[doc = " *"]
    #[doc = " * <br><br><b>Encoding considerations</b>: The encoding of toBeSigned which"]
    #[doc = " * is input to the hash uses the compressed form for all public keys and"]
    #[doc = " * reconstruction values that are elliptic curve points: that is, those"]
    #[doc = " * points indicate a choice of compressed-y-0 or compressed-y-1. The encoding"]
    #[doc = " * of the issuing certificate uses the compressed form for all public key and"]
    #[doc = " * reconstruction values and takes the r value of an ECDSA signature, which"]
    #[doc = " * in this standard is an ECC curve point, to be of type x-only."]
    #[doc = " *"]
    #[doc = " * <br><br>For both implicit and explicit certificates, when the certificate"]
    #[doc = " * is hashed to create or recover the public key (in the case of an implicit"]
    #[doc = " * certificate) or to generate or verify the signature (in the case of an"]
    #[doc = " * explicit certificate), the hash is Hash (<i>Data input</i>) || Hash (<i>"]
    #[doc = " * Signer identifier input</i>), where:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> <i>Data input</i> is the COER encoding of toBeSigned, canonicalized"]
    #[doc = " * as described above.</li>"]
    #[doc = " *"]
    #[doc = " * <li> <i>Signer identifier input</i> depends on the verification type,"]
    #[doc = " * which in turn depends on the choice indicated by issuer. If the choice"]
    #[doc = " * indicated by issuer is self, the verification type is self-signed and the"]
    #[doc = " * signer identifier input is the empty string. If the choice indicated by"]
    #[doc = " * issuer is not self, the verification type is certificate and the signer"]
    #[doc = " * identifier input is the COER encoding of the canonicalization per 6.4.3 of"]
    #[doc = " * the certificate indicated by issuer.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * In other words, for implicit certificates, the value H (CertU) in SEC 4,"]
    #[doc = " * section 3, is for purposes of this standard taken to be H [H"]
    #[doc = " * (canonicalized ToBeSignedCertificate from the subordinate certificate) ||"]
    #[doc = " * H (entirety of issuer Certificate)]. See 5.3.2 for further discussion,"]
    #[doc = " * including material differences between this standard and SEC 4 regarding"]
    #[doc = " * how the hash function output is converted from a bit string to an integer."]
    #[doc = " *"]
    #[doc = " * <br><br>NOTE: This encoding of the implicit certificate for hashing has"]
    #[doc = " * been changed from the encoding specified in IEEE Std 1609.2-2013 for"]
    #[doc = " * consistency with the encoding of the explicit certificates. This"]
    #[doc = " * definition of the encoding results in implicit and explicit certificates"]
    #[doc = " * both being hashed as specified in 5.3.1."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> If present, appPermissions is a critical information field as defined"]
    #[doc = " * in 5.2.6. An implementation that does not support the number of PsidSsp in"]
    #[doc = " * appPermissions shall reject the signed SPDU as invalid. A compliant"]
    #[doc = " * implementation shall support appPermissions fields containing at least"]
    #[doc = " * eight entries.</li>"]
    #[doc = " *"]
    #[doc = " * <li> If present, certIssuePermissions is a critical information field as"]
    #[doc = " * defined in 5.2.6. An implementation that does not support the number of"]
    #[doc = " * PsidGroupPermissions in certIssuePermissions shall reject the signed SPDU"]
    #[doc = " * as invalid. A compliant implementation shall support certIssuePermissions"]
    #[doc = " * fields containing at least eight entries.</li>"]
    #[doc = " *"]
    #[doc = " * <li> If present, certRequestPermissions is a critical information field as"]
    #[doc = " * defined in 5.2.6. An implementation that does not support the number of"]
    #[doc = " * PsidGroupPermissions in certRequestPermissions shall reject the signed"]
    #[doc = " * SPDU as invalid. A compliant implementation shall support"]
    #[doc = " * certRequestPermissions fields containing at least eight entries.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <b>Parameters</b>:"]
    #[doc = " *"]
    #[doc = " * @param id contains information that is used to identify the certificate"]
    #[doc = " * holder if necessary."]
    #[doc = " *"]
    #[doc = " * @param cracaId identifies the Certificate Revocation Authorization CA"]
    #[doc = " * (CRACA) responsible for certificate revocation lists (CRLs) on which this"]
    #[doc = " * certificate might appear. Use of the cracaId is specified in 5.1.3. The"]
    #[doc = " * HashedId3 is calculated with the whole-certificate hash algorithm,"]
    #[doc = " * determined as described in 6.4.12."]
    #[doc = " *"]
    #[doc = " * @param crlSeries represents the CRL series relevant to a particular"]
    #[doc = " * Certificate Revocation Authorization CA (CRACA) on which the certificate"]
    #[doc = " * might appear. Use of this field is specified in 5.1.3."]
    #[doc = " *"]
    #[doc = " * @param validityPeriod contains the validity period of the certificate."]
    #[doc = " *"]
    #[doc = " * @param region, if present, indicates the validity region of the"]
    #[doc = " * certificate. If it is omitted the validity region is indicated as follows:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> If enclosing certificate is self-signed, i.e., the choice indicated"]
    #[doc = " * by the issuer field in the enclosing certificate structure is self, the"]
    #[doc = " * certificate is valid worldwide.</li>"]
    #[doc = " *"]
    #[doc = " * <li> Otherwise, the certificate has the same validity region as the"]
    #[doc = " * certificate that issued it.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * @param assuranceLevel indicates the assurance level of the certificate"]
    #[doc = " * holder."]
    #[doc = " *"]
    #[doc = " * @param appPermissions indicates the permissions that the certificate"]
    #[doc = " * holder has to sign application data with this certificate. A valid"]
    #[doc = " * instance of appPermissions contains any particular Psid value in at most"]
    #[doc = " * one entry."]
    #[doc = " *"]
    #[doc = " * @param certIssuePermissions indicates the permissions that the certificate"]
    #[doc = " * holder has to sign certificates with this certificate. A valid instance of"]
    #[doc = " * this array contains no more than one entry whose psidSspRange field"]
    #[doc = " * indicates all. If the array has multiple entries and one entry has its"]
    #[doc = " * psidSspRange field indicate all, then the entry indicating all specifies"]
    #[doc = " * the permissions for all PSIDs other than the ones explicitly specified in"]
    #[doc = " * the other entries. See the description of PsidGroupPermissions for further"]
    #[doc = " * discussion."]
    #[doc = " *"]
    #[doc = " * @param certRequestPermissions indicates the permissions that the"]
    #[doc = " * certificate holder has to sign certificate requests with this certificate."]
    #[doc = " * A valid instance of this array contains no more than one entry whose"]
    #[doc = " * psidSspRange field indicates all. If the array has multiple entries and"]
    #[doc = " * one entry has its psidSspRange field indicate all, then the entry"]
    #[doc = " * indicating all specifies the permissions for all PSIDs other than the ones"]
    #[doc = " * explicitly specified in the other entries. See the description of"]
    #[doc = " * PsidGroupPermissions for further discussion."]
    #[doc = " *"]
    #[doc = " * @param canRequestRollover indicates that the certificate may be used to"]
    #[doc = " * sign a request for another certificate with the same permissions. This"]
    #[doc = " * field is provided for future use and its use is not defined in this"]
    #[doc = " * version of this standard."]
    #[doc = " *"]
    #[doc = " * @param encryptionKey contains a public key for encryption for which the"]
    #[doc = " * certificate holder holds the corresponding private key."]
    #[doc = " *"]
    #[doc = " * @param verifyKeyIndicator contains material that may be used to recover"]
    #[doc = " * the public key that may be used to verify data signed by this certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedCertificate {
        pub id: CertificateId,
        #[rasn(identifier = "cracaId")]
        pub craca_id: HashedId3,
        #[rasn(identifier = "crlSeries")]
        pub crl_series: CrlSeries,
        #[rasn(identifier = "validityPeriod")]
        pub validity_period: ValidityPeriod,
        pub region: Option<GeographicRegion>,
        #[rasn(identifier = "assuranceLevel")]
        pub assurance_level: Option<SubjectAssurance>,
        #[rasn(identifier = "appPermissions")]
        pub app_permissions: Option<SequenceOfPsidSsp>,
        #[rasn(identifier = "certIssuePermissions")]
        pub cert_issue_permissions: Option<SequenceOfPsidGroupPermissions>,
        #[rasn(identifier = "certRequestPermissions")]
        pub cert_request_permissions: Option<SequenceOfPsidGroupPermissions>,
        #[rasn(identifier = "canRequestRollover")]
        pub can_request_rollover: Option<()>,
        #[rasn(identifier = "encryptionKey")]
        pub encryption_key: Option<PublicEncryptionKey>,
        #[rasn(identifier = "verifyKeyIndicator")]
        pub verify_key_indicator: VerificationKeyIndicator,
        #[rasn(extension_addition, size("8"))]
        pub flags: Option<BitString>,
    }
    impl ToBeSignedCertificate {
        pub fn new(
            id: CertificateId,
            craca_id: HashedId3,
            crl_series: CrlSeries,
            validity_period: ValidityPeriod,
            region: Option<GeographicRegion>,
            assurance_level: Option<SubjectAssurance>,
            app_permissions: Option<SequenceOfPsidSsp>,
            cert_issue_permissions: Option<SequenceOfPsidGroupPermissions>,
            cert_request_permissions: Option<SequenceOfPsidGroupPermissions>,
            can_request_rollover: Option<()>,
            encryption_key: Option<PublicEncryptionKey>,
            verify_key_indicator: VerificationKeyIndicator,
            flags: Option<BitString>,
        ) -> Self {
            Self {
                id,
                craca_id,
                crl_series,
                validity_period,
                region,
                assurance_level,
                app_permissions,
                cert_issue_permissions,
                cert_request_permissions,
                can_request_rollover,
                encryption_key,
                verify_key_indicator,
                flags,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class ToBeSignedData"]
    #[doc = " *"]
    #[doc = " * @brief This structure contains the data to be hashed when generating or"]
    #[doc = " * verifying a signature. See 6.3.4 for the specification of the input to the"]
    #[doc = " * hash."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Encoding considerations</b>: For encoding considerations"]
    #[doc = " * associated with the headerInfo field, see 6.3.9."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Parameters</b>:"]
    #[doc = " *"]
    #[doc = " * @param payload contains data that is provided by the entity that invokes"]
    #[doc = " * the SDS."]
    #[doc = " *"]
    #[doc = " * @param headerInfo contains additional data that is inserted by the SDS."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct ToBeSignedData {
        pub payload: SignedDataPayload,
        #[rasn(identifier = "headerInfo")]
        pub header_info: HeaderInfo,
    }
    impl ToBeSignedData {
        pub fn new(payload: SignedDataPayload, header_info: HeaderInfo) -> Self {
            Self {
                payload,
                header_info,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class VerificationKeyIndicator"]
    #[doc = " *"]
    #[doc = " * @brief The contents of this field depend on whether the certificate is an"]
    #[doc = " * implicit or an explicit certificate."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Parameters</b>:"]
    #[doc = " *"]
    #[doc = " * @param verificationKey is included in explicit certificates. It contains"]
    #[doc = " * the public key to be used to verify signatures generated by the holder of"]
    #[doc = " * the Certificate."]
    #[doc = " *"]
    #[doc = " * @param reconstructionValue is included in implicit certificates. It"]
    #[doc = " * contains the reconstruction value, which is used to recover the public key"]
    #[doc = " * as specified in SEC 4 and 5.3.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum VerificationKeyIndicator {
        verificationKey(PublicVerificationKey),
        reconstructionValue(EccP256CurvePoint),
    }
    pub const ETSI_HEADER_INFO_CONTRIBUTOR_ID: HeaderInfoContributorId = HeaderInfoContributorId(2);
    pub const ISO21177_EXTENDED_AUTH: PduFunctionalType = PduFunctionalType(2);
    pub const TLS_HANDSHAKE: PduFunctionalType = PduFunctionalType(1);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_base_types {
    extern crate alloc;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @class BasePublicEncryptionKey"]
    #[doc = " *"]
    #[doc = " * @brief This structure specifies the bytes of a public encryption key for a"]
    #[doc = " * particular algorithm. The only algorithm supported is ECIES over either"]
    #[doc = " * the NIST P256 or the Brainpool P256r1 curve as specified in 5.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum BasePublicEncryptionKey {
        eciesNistP256(EccP256CurvePoint),
        eciesBrainpoolP256r1(EccP256CurvePoint),
    }
    #[doc = "*"]
    #[doc = " * @class BitmapSsp"]
    #[doc = " *"]
    #[doc = " * @brief This structure represents a bitmap representation of a SSP. The"]
    #[doc = " * mapping of the bits of the bitmap to constraints on the signed SPDU is"]
    #[doc = " * PSID-specific."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Consistency with issuing certificate</b>."]
    #[doc = " *"]
    #[doc = " * <br><br>If a certificate has an appPermissions entry A for which the ssp"]
    #[doc = " * field is bitmapSsp, A is consistent with the issuing certificate if the"]
    #[doc = " * issuing certificate contains one of the following:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;</li>"]
    #[doc = " *"]
    #[doc = " * <li> (OPTION 2) A PsidSspRange P for which the following holds:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> EITHER The sspRange field in P indicates all</li>"]
    #[doc = " *"]
    #[doc = " * <li> OR The sspRange field in P indicates bitmapSspRange and for every"]
    #[doc = " * bit set to 1 in the sspBitmask in P, the bit in the identical position in"]
    #[doc = " * the sspValue in A is set equal to the bit in that position in the"]
    #[doc = " * sspValue in P.</li>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * NOTE: A BitmapSsp B is consistent with a BitmapSspRange R if for every"]
    #[doc = " * bit set to 1 in the sspBitmask in R, the bit in the identical position in"]
    #[doc = " * B is set equal to the bit in that position in the sspValue in R. For each"]
    #[doc = " * bit set to 0 in the sspBitmask in R, the corresponding bit in the"]
    #[doc = " * identical position in B may be freely set to 0 or 1, i.e., if a bit is"]
    #[doc = " * set to 0 in the sspBitmask in R, the value of corresponding bit in the"]
    #[doc = " * identical position in B has no bearing on whether B and R are consistent."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("0..=31"))]
    pub struct BitmapSsp(pub OctetString);
    #[doc = "*"]
    #[doc = " * @class BitmapSspRange"]
    #[doc = " *"]
    #[doc = " * @brief This structure represents a bitmap representation of a SSP. The"]
    #[doc = " * sspValue indicates permissions. The sspBitmask contains an octet string"]
    #[doc = " * used to permit or constrain sspValue fields in issued certificates. The"]
    #[doc = " * sspValue and sspBitmask fields shall be of the same length."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Consistency with issuing certificate</b>."]
    #[doc = " *"]
    #[doc = " * <br><br>If a certificate has an PsidSspRange value P for which the"]
    #[doc = " * sspRange field is bitmapSspRange, P is consistent with the issuing"]
    #[doc = " * certificate if the issuing certificate contains one of the following:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in P;</li>"]
    #[doc = " *"]
    #[doc = " * <li> (OPTION 2) A PsidSspRange R for which the following holds:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The psid field in R is equal to the psid field in P and one of the"]
    #[doc = " * following is true:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> EITHER The sspRange field in R indicates all</li>"]
    #[doc = " *"]
    #[doc = " * <li> OR The sspRange field in R indicates bitmapSspRange and for every"]
    #[doc = " * bit set to 1 in the sspBitmask in R:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The bit in the identical position in the sspBitmask in P is set"]
    #[doc = " * equal to 1, AND</li>"]
    #[doc = " *"]
    #[doc = " * <li> The bit in the identical position in the sspValue in P is set equal"]
    #[doc = " * to the bit in that position in the sspValue in R.</li>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <br>Reference ETSI TS 103 097 [B7] for more information on bitmask SSPs."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct BitmapSspRange {
        #[rasn(size("1..=32"), identifier = "sspValue")]
        pub ssp_value: OctetString,
        #[rasn(size("1..=32"), identifier = "sspBitmask")]
        pub ssp_bitmask: OctetString,
    }
    impl BitmapSspRange {
        pub fn new(ssp_value: OctetString, ssp_bitmask: OctetString) -> Self {
            Self {
                ssp_value,
                ssp_bitmask,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class CircularRegion"]
    #[doc = " *"]
    #[doc = " * @brief This structure specifies a circle with its center at center, its"]
    #[doc = " * radius given in meters, and located tangential to the reference ellipsoid."]
    #[doc = " * The indicated region is all the points on the surface of the reference"]
    #[doc = " * ellipsoid whose distance to the center point over the reference ellipsoid"]
    #[doc = " * is less than or equal to the radius. A point which contains an elevation"]
    #[doc = " * component is considered to be within the circular region if its horizontal"]
    #[doc = " * projection onto the reference ellipsoid lies within the region."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CircularRegion {
        pub center: TwoDLocation,
        pub radius: Uint16,
    }
    impl CircularRegion {
        pub fn new(center: TwoDLocation, radius: Uint16) -> Self {
            Self { center, radius }
        }
    }
    #[doc = "*"]
    #[doc = " * @class CountryAndRegions"]
    #[doc = " *"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param countryOnly is a CountryOnly as defined above."]
    #[doc = " *"]
    #[doc = " * @param region identifies one or more regions within the country. If"]
    #[doc = " * countryOnly indicates the United States of America, the values in this"]
    #[doc = " * field identify the state or statistically equivalent entity using the"]
    #[doc = " * integer version of the 2010 FIPS codes as provided by the U.S. Census"]
    #[doc = " * Bureau (see normative references in Clause 2). For other values of"]
    #[doc = " * countryOnly, the meaning of region is not defined in this version of this"]
    #[doc = " * standard."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CountryAndRegions {
        #[rasn(identifier = "countryOnly")]
        pub country_only: CountryOnly,
        pub regions: SequenceOfUint8,
    }
    impl CountryAndRegions {
        pub fn new(country_only: CountryOnly, regions: SequenceOfUint8) -> Self {
            Self {
                country_only,
                regions,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class CountryAndSubregions"]
    #[doc = " *"]
    #[doc = " * @brief In this structure:"]
    #[doc = " * <br><br><b>Critical information fields</b>:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize RegionAndSubregions or"]
    #[doc = " * CountryAndSubregions values when verifying a signed SPDU shall indicate"]
    #[doc = " * that the signed SPDU is invalid. A compliant implementation shall support"]
    #[doc = " * CountryAndSubregions containing at least eight RegionAndSubregions"]
    #[doc = " * entries.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <b>Parameters</b>:"]
    #[doc = " *"]
    #[doc = " * @param country is a CountryOnly as defined above."]
    #[doc = " *"]
    #[doc = " * @param regionAndSubregions identifies one or more subregions within"]
    #[doc = " * country. If country indicates the United States of America, the values in"]
    #[doc = " * this field identify the county or county equivalent entity using the"]
    #[doc = " * integer version of the 2010 FIPS codes as provided by the U.S. Census"]
    #[doc = " * Bureau (see normative references in Clause 2). For other values of"]
    #[doc = " * country, the meaning of regionAndSubregions is not defined in this version"]
    #[doc = " * of this standard."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CountryAndSubregions {
        pub country: CountryOnly,
        #[rasn(identifier = "regionAndSubregions")]
        pub region_and_subregions: SequenceOfRegionAndSubregions,
    }
    impl CountryAndSubregions {
        pub fn new(
            country: CountryOnly,
            region_and_subregions: SequenceOfRegionAndSubregions,
        ) -> Self {
            Self {
                country,
                region_and_subregions,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class CountryOnly"]
    #[doc = " *"]
    #[doc = " * @brief This is the integer representation of the country or area"]
    #[doc = " * identifier as defined by the United Nations Statistics Division in October"]
    #[doc = " * 2013 (see normative references in Clause 2)."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct CountryOnly(pub Uint16);
    #[doc = "*"]
    #[doc = " * @class CrlSeries"]
    #[doc = " *"]
    #[doc = " * @brief This integer identifies a series of CRLs issued under the authority"]
    #[doc = " * of a particular CRACA."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct CrlSeries(pub Uint16);
    #[doc = "*"]
    #[doc = " * @class Duration"]
    #[doc = " *"]
    #[doc = " * @brief This structure represents the duration of validity of a"]
    #[doc = " * certificate. The Uint16 value is the duration, given in the units denoted"]
    #[doc = " * by the indicated choice. A year is considered to be 31556952 seconds,"]
    #[doc = " * which is the average number of seconds in a year; if it is desired to map"]
    #[doc = " * years more closely to wall-clock days, this can be done using the hours"]
    #[doc = " * choice for up to seven years and the sixtyHours choice for up to 448. In"]
    #[doc = " * this structure:"]
    #[doc = " *"]
    #[doc = " * @param microseconds contains the duration in microseconds."]
    #[doc = " *"]
    #[doc = " * @param milliseconds contains the duration in milliseconds."]
    #[doc = " *"]
    #[doc = " * @param seconds contains the duration in seconds."]
    #[doc = " *"]
    #[doc = " * @param minutes contains the duration in minutes."]
    #[doc = " *"]
    #[doc = " * @param hours contains the duration in hours."]
    #[doc = " *"]
    #[doc = " * @param sixtyHours contains the duration in sixty-hour periods."]
    #[doc = " *"]
    #[doc = " * @param years contains the duration in years."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum Duration {
        microseconds(Uint16),
        milliseconds(Uint16),
        seconds(Uint16),
        minutes(Uint16),
        hours(Uint16),
        sixtyHours(Uint16),
        years(Uint16),
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EccP256CurvePointUncompressedP256 {
        pub x: FixedOctetString<32>,
        pub y: FixedOctetString<32>,
    }
    impl EccP256CurvePointUncompressedP256 {
        pub fn new(x: FixedOctetString<32>, y: FixedOctetString<32>) -> Self {
            Self { x, y }
        }
    }
    #[doc = "*"]
    #[doc = " * @class EccP256CurvePoint"]
    #[doc = " *"]
    #[doc = " * @brief This structure specifies a point on an elliptic curve in"]
    #[doc = " * Weierstrass form defined over a 256-bit prime number. This encompasses"]
    #[doc = " * both NIST p256 as defined in FIPS 186-4 and Brainpool p256r1 as defined in"]
    #[doc = " * RFC 5639. The fields in this structure are OCTET STRINGS produced with the"]
    #[doc = " * elliptic curve point encoding and decoding methods defined in subclause"]
    #[doc = " * 5.5.6 of IEEE Std 1363-2000. The x-coordinate is encoded as an unsigned"]
    #[doc = " * integer of length 32 octets in network byte order for all values of the"]
    #[doc = " * CHOICE; the encoding of the y-coordinate y depends on whether the point is"]
    #[doc = " * x-only, compressed, or uncompressed. If the point is x-only, y is omitted."]
    #[doc = " * If the point is compressed, the value of type depends on the least"]
    #[doc = " * significant bit of y: if the least significant bit of y is 0, type takes"]
    #[doc = " * the value compressed-y-0, and if the least significant bit of y is 1, type"]
    #[doc = " * takes the value compressed-y-1. If the point is uncompressed, y is encoded"]
    #[doc = " * explicitly as an unsigned integer of length 32 octets in network byte order."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum EccP256CurvePoint {
        #[rasn(identifier = "x-only")]
        x_only(FixedOctetString<32>),
        fill(()),
        #[rasn(identifier = "compressed-y-0")]
        compressed_y_0(FixedOctetString<32>),
        #[rasn(identifier = "compressed-y-1")]
        compressed_y_1(FixedOctetString<32>),
        uncompressedP256(EccP256CurvePointUncompressedP256),
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EccP384CurvePointUncompressedP384 {
        pub x: FixedOctetString<48>,
        pub y: FixedOctetString<48>,
    }
    impl EccP384CurvePointUncompressedP384 {
        pub fn new(x: FixedOctetString<48>, y: FixedOctetString<48>) -> Self {
            Self { x, y }
        }
    }
    #[doc = "*"]
    #[doc = " * @class EccP384CurvePoint"]
    #[doc = " *"]
    #[doc = " * @brief This structure specifies a point on an elliptic curve in"]
    #[doc = " * Weierstrass form defined over a 384-bit prime number. The only supported"]
    #[doc = " * such curve in this standard is Brainpool p384r1 as defined in RFC 5639."]
    #[doc = " * The fields in this structure are OCTET STRINGS produced with the elliptic"]
    #[doc = " * curve point encoding and decoding methods defined in subclause 5.5.6 of"]
    #[doc = " * IEEE Std 1363-2000. The x-coordinate is encoded as an unsigned integer of"]
    #[doc = " * length 48 octets in network byte order for all values of the CHOICE; the"]
    #[doc = " * encoding of the y-coordinate y depends on whether the point is x-only,"]
    #[doc = " * compressed, or uncompressed. If the point is x-only, y is omitted. If the"]
    #[doc = " * point is compressed, the value of type depends on the least significant"]
    #[doc = " * bit of y: if the least significant bit of y is 0, type takes the value"]
    #[doc = " * compressed-y-0, and if the least significant bit of y is 1, type takes the"]
    #[doc = " * value compressed-y-1. If the point is uncompressed, y is encoded"]
    #[doc = " * explicitly as an unsigned integer of length 48 octets in network byte order."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum EccP384CurvePoint {
        #[rasn(identifier = "x-only")]
        x_only(FixedOctetString<48>),
        fill(()),
        #[rasn(identifier = "compressed-y-0")]
        compressed_y_0(FixedOctetString<48>),
        #[rasn(identifier = "compressed-y-1")]
        compressed_y_1(FixedOctetString<48>),
        uncompressedP384(EccP384CurvePointUncompressedP384),
    }
    #[doc = "*"]
    #[doc = " * @class EcdsaP256Signature"]
    #[doc = " *"]
    #[doc = " * @brief This structure represents an ECDSA signature. The signature is"]
    #[doc = " * generated as specified in 5.3.1."]
    #[doc = " *"]
    #[doc = " * <br><br>If the signature process followed the specification of FIPS 186-4"]
    #[doc = " * and output the integer r, r is represented as an EccP256CurvePoint"]
    #[doc = " * indicating the selection x-only."]
    #[doc = " *"]
    #[doc = " * <br><br>If the signature process followed the specification of SEC 1 and"]
    #[doc = " * output the elliptic curve point R to allow for fast verification, R is"]
    #[doc = " * represented as an EccP256CurvePoint indicating the choice compressed-y-0,"]
    #[doc = " * compressed-y-1, or uncompressed at the sender’s discretion."]
    #[doc = " *"]
    #[doc = " * <br><br>Encoding considerations: If this structure is encoded for hashing,"]
    #[doc = " * the EccP256CurvePoint in rSig shall be taken to be of form x-only."]
    #[doc = " *"]
    #[doc = " * <br><br>NOTE: When the signature is of form x-only, the x-value in rSig is"]
    #[doc = " * an integer mod n, the order of the group; when the signature is of form"]
    #[doc = " * compressed-y-*, the x-value in rSig is an integer mod p, the underlying"]
    #[doc = " * prime defining the finite field. In principle this means that to convert a"]
    #[doc = " * signature from form compressed-y-* to form x-only, the x-value should be"]
    #[doc = " * checked to see if it lies between n and p and reduced mod n if so. In"]
    #[doc = " * practice this check is unnecessary: Haase’s Theorem states that difference"]
    #[doc = " * between n and p is always less than 2*square-root(p), and so the chance"]
    #[doc = " * that an integer lies between n and p, for a 256-bit curve, is bounded"]
    #[doc = " * above by approximately square-root(p)/p or 2^(−128). For the 256-bit"]
    #[doc = " * curves in this standard, the exact values of n and p in hexadecimal are:"]
    #[doc = " *"]
    #[doc = " * <br><br>NISTp256:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"]
    #[doc = " * </li>"]
    #[doc = " * <li> n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"]
    #[doc = " * </li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * Brainpoolp256:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> p = A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"]
    #[doc = " * </li>"]
    #[doc = " * <li> n = A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"]
    #[doc = " * </li>"]
    #[doc = " * </ul>"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EcdsaP256Signature {
        #[rasn(identifier = "rSig")]
        pub r_sig: EccP256CurvePoint,
        #[rasn(identifier = "sSig")]
        pub s_sig: FixedOctetString<32>,
    }
    impl EcdsaP256Signature {
        pub fn new(r_sig: EccP256CurvePoint, s_sig: FixedOctetString<32>) -> Self {
            Self { r_sig, s_sig }
        }
    }
    #[doc = "*"]
    #[doc = " * @class EcdsaP384Signature"]
    #[doc = " *"]
    #[doc = " * @brief This structure represents an ECDSA signature. The signature is"]
    #[doc = " * generated as specified in 5.3.1."]
    #[doc = " *"]
    #[doc = " * <br><br>If the signature process followed the specification of FIPS 186-4"]
    #[doc = " * and output the integer r, r is represented as an EccP384CurvePoint"]
    #[doc = " * indicating the selection x-only."]
    #[doc = " *"]
    #[doc = " * <br><br>If the signature process followed the specification of SEC 1 and"]
    #[doc = " * output the elliptic curve point R to allow for fast verification, R is"]
    #[doc = " * represented as an EccP384CurvePoint indicating the choice compressed-y-0,"]
    #[doc = " * compressed-y-1, or uncompressed at the sender’s discretion."]
    #[doc = " *"]
    #[doc = " * <br><br>Encoding considerations: If this structure is encoded for hashing,"]
    #[doc = " * the EccP256CurvePoint in rSig shall be taken to be of form x-only."]
    #[doc = " *"]
    #[doc = " * <br><br>NOTE: When the signature is of form x-only, the x-value in rSig is"]
    #[doc = " * an integer mod n, the order of the group; when the signature is of form"]
    #[doc = " * compressed-y-*, the x-value in rSig is an integer mod p, the underlying"]
    #[doc = " * prime defining the finite field. In principle this means that to convert a"]
    #[doc = " * signature from form compressed-y-* to form x-only, the x-value should be"]
    #[doc = " * checked to see if it lies between n and p and reduced mod n if so. In"]
    #[doc = " * practice this check is unnecessary: Haase’s Theorem states that difference"]
    #[doc = " * between n and p is always less than 2*square-root(p), and so the chance"]
    #[doc = " * that an integer lies between n and p, for a 384-bit curve, is bounded"]
    #[doc = " * above by approximately square-root(p)/p or 2^(−192). For the 384-bit curve"]
    #[doc = " * in this standard, the exact values of n and p in hexadecimal are:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> p = 8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123"]
    #[doc = " * ACD3A729901D1A71874700133107EC53</li>"]
    #[doc = " *"]
    #[doc = " * <li> n = 8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7"]
    #[doc = " * CF3AB6AF6B7FC3103B883202E9046565</li>"]
    #[doc = " * </ul>"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EcdsaP384Signature {
        #[rasn(identifier = "rSig")]
        pub r_sig: EccP384CurvePoint,
        #[rasn(identifier = "sSig")]
        pub s_sig: FixedOctetString<48>,
    }
    impl EcdsaP384Signature {
        pub fn new(r_sig: EccP384CurvePoint, s_sig: FixedOctetString<48>) -> Self {
            Self { r_sig, s_sig }
        }
    }
    #[doc = "*"]
    #[doc = " * @class EciesP256EncryptedKey"]
    #[doc = " *"]
    #[doc = " * @brief This data structure is used to transfer a 16-byte symmetric key"]
    #[doc = " * encrypted using ECIES as specified in IEEE Std 1363a-2004."]
    #[doc = " *"]
    #[doc = " * <br><br>Encryption and decryption are carried out as specified in 5.3.4."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Parameters</b>:"]
    #[doc = " *"]
    #[doc = " * @param v is the sender’s ephemeral public key, which is the output V from"]
    #[doc = " * encryption as specified in 5.3.4."]
    #[doc = " *"]
    #[doc = " * @param c is the encrypted symmetric key, which is the output C from"]
    #[doc = " * encryption as specified in 5.3.4. The algorithm for the symmetric key is"]
    #[doc = " * identified by the CHOICE indicated in the following SymmetricCiphertext."]
    #[doc = " *"]
    #[doc = " * @param t is the authentication tag, which is the output tag from"]
    #[doc = " * encryption as specified in 5.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EciesP256EncryptedKey {
        pub v: EccP256CurvePoint,
        pub c: FixedOctetString<16>,
        pub t: FixedOctetString<16>,
    }
    impl EciesP256EncryptedKey {
        pub fn new(v: EccP256CurvePoint, c: FixedOctetString<16>, t: FixedOctetString<16>) -> Self {
            Self { v, c, t }
        }
    }
    #[doc = "*"]
    #[doc = " * @class Elevation"]
    #[doc = " *"]
    #[doc = " * @brief This structure contains an estimate of the geodetic altitude above"]
    #[doc = " * or below the WGS84 ellipsoid. The 16-bit value is interpreted as an"]
    #[doc = " * integer number of decimeters representing the height above a minimum"]
    #[doc = " * height of -409.5 m, with the maximum height being 6143.9 m."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Elevation(pub Uint16);
    #[doc = "*"]
    #[doc = " * @class EncryptionKey"]
    #[doc = " *"]
    #[doc = " * @brief This structure contains an encryption key, which may be a public or"]
    #[doc = " * a symmetric key."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum EncryptionKey {
        public(PublicEncryptionKey),
        symmetric(SymmetricEncryptionKey),
    }
    #[doc = "***************************************************************************"]
    #[doc = "                           Location Structures                             "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @class GeographicRegion"]
    #[doc = " *"]
    #[doc = " * @brief This structure represents a geographic region of a specified form."]
    #[doc = " * A certificate is not valid if any part of the region indicated in its"]
    #[doc = " * scope field lies outside the region indicated in the scope of its issuer."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the indicated CHOICE when"]
    #[doc = " * verifying a signed SPDU shall indicate that the signed SPDU is invalid.</li>"]
    #[doc = " *"]
    #[doc = " * <li> If selected, rectangularRegion is a critical information field as"]
    #[doc = " * defined in 5.2.6. An implementation that does not support the number of"]
    #[doc = " * RectangularRegion in rectangularRegions when verifying a signed SPDU shall"]
    #[doc = " * indicate that the signed SPDU is invalid. A compliant implementation shall"]
    #[doc = " * support rectangularRegions fields containing at least eight entries.</li>"]
    #[doc = " *"]
    #[doc = " * <li> If selected, identifiedRegion is a critical information field as"]
    #[doc = " * defined in 5.2.6. An implementation that does not support the number of"]
    #[doc = " * IdentifiedRegion in identifiedRegion shall reject the signed SPDU as"]
    #[doc = " * invalid. A compliant implementation shall support identifiedRegion fields"]
    #[doc = " * containing at least eight entries.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <b>Parameters</b>:"]
    #[doc = " *"]
    #[doc = " * @param circularRegion contains a single instance of the CircularRegion"]
    #[doc = " * structure."]
    #[doc = " *"]
    #[doc = " * @param rectangularRegion is an array of RectangularRegion structures"]
    #[doc = " * containing at least one entry. This field is interpreted as a series of"]
    #[doc = " * rectangles, which may overlap or be disjoint. The permitted region is any"]
    #[doc = " * point within any of the rectangles."]
    #[doc = " *"]
    #[doc = " * @param polygonalRegion contains a single instance of the PolygonalRegion"]
    #[doc = " * structure."]
    #[doc = " *"]
    #[doc = " * @param identifiedRegion is an array of IdentifiedRegion structures"]
    #[doc = " * containing at least one entry. The permitted region is any point within"]
    #[doc = " * any of the identified regions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum GeographicRegion {
        circularRegion(CircularRegion),
        rectangularRegion(SequenceOfRectangularRegion),
        polygonalRegion(PolygonalRegion),
        identifiedRegion(SequenceOfIdentifiedRegion),
    }
    #[doc = "*"]
    #[doc = " * @class GroupLinkageValue"]
    #[doc = " *"]
    #[doc = " * @brief This is the group linkage value. See 5.1.3 and 7.3 for details of"]
    #[doc = " * use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct GroupLinkageValue {
        #[rasn(identifier = "jValue")]
        pub j_value: FixedOctetString<4>,
        pub value: FixedOctetString<9>,
    }
    impl GroupLinkageValue {
        pub fn new(j_value: FixedOctetString<4>, value: FixedOctetString<9>) -> Self {
            Self { j_value, value }
        }
    }
    #[doc = "*"]
    #[doc = " * @class HashAlgorithm"]
    #[doc = " *"]
    #[doc = " * @brief This structure identifies a hash algorithm. The value is sha256,"]
    #[doc = " * indicates SHA-256 as specified in 5.3.3. The value sha384 indicates"]
    #[doc = " * SHA-384 as specified in 5.3.3."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>: This is a critical information"]
    #[doc = " * field as defined in 5.2.6. An implementation that does not recognize the"]
    #[doc = " * enumerated value of this type in a signed SPDU when verifying a signed"]
    #[doc = " * SPDU shall indicate that the signed SPDU is invalid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum HashAlgorithm {
        sha256 = 0,
        #[rasn(extension_addition)]
        sha384 = 1,
    }
    #[doc = "*"]
    #[doc = " * @class HashedId10"]
    #[doc = " *"]
    #[doc = " * @brief This type contains the truncated hash of another data structure."]
    #[doc = " * The HashedId10 for a given data structure is calculated by calculating the"]
    #[doc = " * hash of the encoded data structure and taking the low-order ten bytes of"]
    #[doc = " * the hash output. If the data structure is subject to canonicalization it"]
    #[doc = " * is canonicalized before hashing. The low-order ten bytes are the last ten"]
    #[doc = " * bytes of the hash when represented in network byte order. See Example below."]
    #[doc = " *"]
    #[doc = " * <br><br>The hash algorithm to be used to calculate a HashedId10 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId10 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Example</b>: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * <br>SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b<b>934ca495991b7852b855</b>"]
    #[doc = " *"]
    #[doc = " * <br><br>The HashedId10 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * <br>HashedId10 = 934ca495991b7852b855."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct HashedId10(pub FixedOctetString<10usize>);
    #[doc = "*"]
    #[doc = " * @class HashedId3"]
    #[doc = " *"]
    #[doc = " * @brief This type contains the truncated hash of another data structure."]
    #[doc = " * The HashedId3 for a given data structure is calculated by calculating the"]
    #[doc = " * hash of the encoded data structure and taking the low-order three bytes of"]
    #[doc = " * the hash output. If the data structure is subject to canonicalization it"]
    #[doc = " * is canonicalized before hashing. The low-order three bytes are the last"]
    #[doc = " * three bytes of the hash when represented in network byte order. See"]
    #[doc = " * Example below."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Example</b>: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * <br>SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b78<b>52b855</b>"]
    #[doc = " *"]
    #[doc = " * <br><br>The HashedId3 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * <br>HashedId3 = 52b855."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct HashedId3(pub FixedOctetString<3usize>);
    #[doc = "*"]
    #[doc = " * @class HashedId32"]
    #[doc = " *"]
    #[doc = " * @brief This type contains the truncated hash of another data structure."]
    #[doc = " * The HashedId32 for a given data structure is calculated by calculating the"]
    #[doc = " * hash of the encoded data structure and taking the low-order thirty two"]
    #[doc = " * bytes of the hash output. If the data structure is subject to"]
    #[doc = " * canonicalization it is canonicalized before hashing. The low-order thirty"]
    #[doc = " * two bytes are the last thirty two bytes of the hash when represented in"]
    #[doc = " * network byte order. See Example below."]
    #[doc = " *"]
    #[doc = " * <br><br>The hash algorithm to be used to calculate a HashedId32 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId32 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Example</b>: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * <br>SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    #[doc = " *"]
    #[doc = " * <br><br>The HashedId32 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * <br>HashedId32 ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct HashedId32(pub FixedOctetString<32usize>);
    #[doc = "*"]
    #[doc = " * @class HashedId8"]
    #[doc = " *"]
    #[doc = " * @brief This type contains the truncated hash of another data structure."]
    #[doc = " * The HashedId8 for a given data structure is calculated by calculating the"]
    #[doc = " * hash of the encoded data structure and taking the low-order eight bytes of"]
    #[doc = " * the hash output. If the data structure is subject to canonicalization it"]
    #[doc = " * is canonicalized before hashing. The low-order eight bytes are the last"]
    #[doc = " * eight bytes of the hash when represented in network byte order. See"]
    #[doc = " * Example below."]
    #[doc = " *"]
    #[doc = " * <br><br>The hash algorithm to be used to calculate a HashedId8 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId8 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Example</b>: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * <br>SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934c<b>a495991b7852b855</b>"]
    #[doc = " *"]
    #[doc = " * <br><br>The HashedId8 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * <br>HashedId8 = a495991b7852b855."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct HashedId8(pub FixedOctetString<8usize>);
    #[doc = "*"]
    #[doc = " * @class Hostname"]
    #[doc = " *"]
    #[doc = " * @brief This is a UTF-8 string as defined in IETF RFC 3629. The contents"]
    #[doc = " * are determined by policy."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("0..=255"))]
    pub struct Hostname(pub Utf8String);
    #[doc = "***************************************************************************"]
    #[doc = "                             Pseudonym Linkage                             "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @class IValue"]
    #[doc = " *"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct IValue(pub Uint16);
    #[doc = "*"]
    #[doc = " * @class IdentifiedRegion"]
    #[doc = " *"]
    #[doc = " * @brief This structure indicates the region of validity of a certificate"]
    #[doc = " * using region identifiers."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the indicated CHOICE when"]
    #[doc = " * verifying a signed SPDU shall indicate that the signed SPDU is invalid.</li>"]
    #[doc = " * </ul>"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum IdentifiedRegion {
        countryOnly(CountryOnly),
        countryAndRegions(CountryAndRegions),
        countryAndSubregions(CountryAndSubregions),
    }
    #[doc = "*"]
    #[doc = " * @class KnownLatitude"]
    #[doc = " *"]
    #[doc = " * @brief The known latitudes are from -900,000,000 to +900,000,000 in 0.1"]
    #[doc = " * microdegree intervals."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("-900000000..=900000000"))]
    pub struct KnownLatitude(pub NinetyDegreeInt);
    #[doc = "*"]
    #[doc = " * @class KnownLongitude"]
    #[doc = " *"]
    #[doc = " * @brief The known longitudes are from -1,799,999,999 to +1,800,000,000 in"]
    #[doc = " * 0.1 microdegree intervals."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("-1799999999..=1800000000"))]
    pub struct KnownLongitude(pub OneEightyDegreeInt);
    #[doc = "*"]
    #[doc = " * @class LaId"]
    #[doc = " *"]
    #[doc = " * @brief This structure contains a LA Identifier for use in the algorithms"]
    #[doc = " * specified in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct LaId(pub FixedOctetString<2usize>);
    #[doc = "*"]
    #[doc = " * @class Latitude"]
    #[doc = " *"]
    #[doc = " * @brief This type contains an INTEGER encoding an estimate of the latitude"]
    #[doc = " * with precision 1/10th microdegree relative to the World Geodetic System"]
    #[doc = " * (WGS)-84 datum as defined in NIMA Technical Report TR8350.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Latitude(pub NinetyDegreeInt);
    #[doc = "*"]
    #[doc = " * @class LinkageSeed"]
    #[doc = " *"]
    #[doc = " * @brief This structure contains a linkage seed value for use in the"]
    #[doc = " * algorithms specified in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct LinkageSeed(pub FixedOctetString<16usize>);
    #[doc = "*"]
    #[doc = " * @class LinkageValue"]
    #[doc = " *"]
    #[doc = " * @brief This is the individual linkage value. See 5.1.3 and 7.3 for details"]
    #[doc = " * of use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct LinkageValue(pub FixedOctetString<9usize>);
    #[doc = "*"]
    #[doc = " * @class Longitude"]
    #[doc = " *"]
    #[doc = " * @brief This type contains an INTEGER encoding an estimate of the longitude"]
    #[doc = " * with precision 1/10th microdegree relative to the World Geodetic System"]
    #[doc = " * (WGS)-84 datum as defined in NIMA Technical Report TR8350.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Longitude(pub OneEightyDegreeInt);
    #[doc = "*"]
    #[doc = " * @class NinetyDegreeInt"]
    #[doc = " *"]
    #[doc = " * @brief The integer in the latitude field is no more than 900,000,000 and"]
    #[doc = " * no less than -900,000,000, except that the value 900,000,001 is used to"]
    #[doc = " * indicate the latitude was not available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("-900000000..=900000001"))]
    pub struct NinetyDegreeInt(pub i32);
    #[doc = "*"]
    #[doc = " * @class OneEightyDegreeInt"]
    #[doc = " *"]
    #[doc = " * @brief The integer in the longitude field is no more than 1,800,000,000"]
    #[doc = " * and no less than -1,799,999,999, except that the value 1,800,000,001 is"]
    #[doc = " * used to indicate that the longitude was not available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("-1799999999..=1800000001"))]
    pub struct OneEightyDegreeInt(pub i32);
    #[doc = "***************************************************************************"]
    #[doc = "                            OCTET STRING Types                             "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @class Opaque"]
    #[doc = " *"]
    #[doc = " * @brief This is a synonym for ASN.1 OCTET STRING, and is used in the"]
    #[doc = " * definition of other data structures."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Opaque(pub OctetString);
    #[doc = "*"]
    #[doc = " * @class PolygonalRegion"]
    #[doc = " *"]
    #[doc = " * @brief This structure defines a region using a series of distinct"]
    #[doc = " * geographic points, defined on the surface of the reference ellipsoid. The"]
    #[doc = " * region is specified by connecting the points in the order they appear,"]
    #[doc = " * with each pair of points connected by the geodesic on the reference"]
    #[doc = " * ellipsoid. The polygon is completed by connecting the final point to the"]
    #[doc = " * first point. The allowed region is the interior of the polygon and its"]
    #[doc = " * boundary."]
    #[doc = " *"]
    #[doc = " * <br><br>A point which contains an elevation component is considered to be"]
    #[doc = " * within the polygonal region if its horizontal projection onto the"]
    #[doc = " * reference ellipsoid lies within the region."]
    #[doc = " *"]
    #[doc = " * <br><br>A valid PolygonalRegion contains at least three points. In a valid"]
    #[doc = " * PolygonalRegion, the implied lines that make up the sides of the polygon"]
    #[doc = " * do not intersect."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not support the number of TwoDLocation in the"]
    #[doc = " * PolygonalRegion when verifying a signed SPDU shall indicate that the signed"]
    #[doc = " * SPDU is invalid. A compliant implementation shall support PolygonalRegions"]
    #[doc = " * containing at least eight TwoDLocation entries.</li>"]
    #[doc = " * </ul>"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("3.."))]
    pub struct PolygonalRegion(pub SequenceOf<TwoDLocation>);
    #[doc = "*"]
    #[doc = " * @class Psid"]
    #[doc = " *"]
    #[doc = " * @brief This type represents the PSID defined in IEEE Std 1609.12."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0.."))]
    pub struct Psid(pub Integer);
    #[doc = "***************************************************************************"]
    #[doc = "                              PSID / ITS-AID                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @class PsidSsp"]
    #[doc = " *"]
    #[doc = " * @brief This structure represents the permissions that the certificate"]
    #[doc = " * holder has with respect to data for a single application area, identified"]
    #[doc = " * by a Psid. If the ServiceSpecificPermissions field is omitted, it"]
    #[doc = " * indicates that the certificate holder has the default permissions"]
    #[doc = " * associated with that Psid."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Consistency with signed SPDU</b>. As noted in 5.1.1,"]
    #[doc = " * consistency between the SSP and the signed SPDU is defined by rules"]
    #[doc = " * specific to the given PSID and is out of scope for this standard."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Consistency with issuing certificate</b>."]
    #[doc = " *"]
    #[doc = " * <br><br>If a certificate has an appPermissions entry A for which the ssp"]
    #[doc = " * field is omitted, A is consistent with the issuing certificate if the"]
    #[doc = " * issuing certificate contains a PsidSspRange P for which the following holds:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The sspRange field in P indicates all.</li>"]
    #[doc = " *"]
    #[doc = " * <li> The sspRange field in P indicates opaque and one of the entries in"]
    #[doc = " * opaque is an OCTET STRING of length 0.</li>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * For consistency rules for other forms of the ssp field, see the"]
    #[doc = " * following subclauses."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PsidSsp {
        pub psid: Psid,
        pub ssp: Option<ServiceSpecificPermissions>,
    }
    impl PsidSsp {
        pub fn new(psid: Psid, ssp: Option<ServiceSpecificPermissions>) -> Self {
            Self { psid, ssp }
        }
    }
    #[doc = "*"]
    #[doc = " * @class PsidSspRange"]
    #[doc = " *"]
    #[doc = " * @brief This structure represents the certificate issuing or requesting"]
    #[doc = " * permissions of the certificate holder with respect to one particular set"]
    #[doc = " * of application permissions."]
    #[doc = " *"]
    #[doc = " * @param psid identifies the application area."]
    #[doc = " *"]
    #[doc = " * @param sspRange identifies the SSPs associated with that PSID for which"]
    #[doc = " * the holder may issue or request certificates. If sspRange is omitted, the"]
    #[doc = " * holder may issue or request certificates for any SSP for that PSID."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PsidSspRange {
        pub psid: Psid,
        #[rasn(identifier = "sspRange")]
        pub ssp_range: Option<SspRange>,
    }
    impl PsidSspRange {
        pub fn new(psid: Psid, ssp_range: Option<SspRange>) -> Self {
            Self { psid, ssp_range }
        }
    }
    #[doc = "*"]
    #[doc = " * @class PublicEncryptionKey"]
    #[doc = " *"]
    #[doc = " * @brief This structure specifies a public encryption key and the associated"]
    #[doc = " * symmetric algorithm which is used for bulk data encryption when encrypting"]
    #[doc = " * for that public key."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PublicEncryptionKey {
        #[rasn(identifier = "supportedSymmAlg")]
        pub supported_symm_alg: SymmAlgorithm,
        #[rasn(identifier = "publicKey")]
        pub public_key: BasePublicEncryptionKey,
    }
    impl PublicEncryptionKey {
        pub fn new(supported_symm_alg: SymmAlgorithm, public_key: BasePublicEncryptionKey) -> Self {
            Self {
                supported_symm_alg,
                public_key,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class PublicVerificationKey"]
    #[doc = " *"]
    #[doc = " * @brief This structure represents a public key and states with what"]
    #[doc = " * algorithm the public key is to be used. Cryptographic mechanisms are"]
    #[doc = " * defined in 5.3."]
    #[doc = " *"]
    #[doc = " * <br><br>An EccP256CurvePoint or EccP384CurvePoint within a"]
    #[doc = " * PublicVerificationKey structure is invalid if it indicates the choice"]
    #[doc = " * x-only."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE when verifying a signed SPDU shall indicate"]
    #[doc = " * that the signed SPDU is invalid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum PublicVerificationKey {
        ecdsaNistP256(EccP256CurvePoint),
        ecdsaBrainpoolP256r1(EccP256CurvePoint),
        #[rasn(extension_addition)]
        ecdsaBrainpoolP384r1(EccP384CurvePoint),
        #[rasn(extension_addition)]
        ecdsaNistP384(EccP384CurvePoint),
    }
    #[doc = "*"]
    #[doc = " * @class RectangularRegion"]
    #[doc = " *"]
    #[doc = " * @brief This structure specifies a rectangle formed by connecting in"]
    #[doc = " * sequence: (northWest.latitude, northWest.longitude), (southEast.latitude,"]
    #[doc = " * northWest.longitude), (southEast.latitude, southEast.longitude), and"]
    #[doc = " * (northWest.latitude, southEast.longitude). The points are connected by"]
    #[doc = " * lines of constant latitude or longitude. A point which contains an"]
    #[doc = " * elevation component is considered to be within the rectangular region if"]
    #[doc = " * its horizontal projection onto the reference ellipsoid lies within the"]
    #[doc = " * region. A RectangularRegion is valid only if the northWest value is north"]
    #[doc = " * and west of the southEast value, i.e., the two points cannot have equal"]
    #[doc = " * latitude or equal longitude."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct RectangularRegion {
        #[rasn(identifier = "northWest")]
        pub north_west: TwoDLocation,
        #[rasn(identifier = "southEast")]
        pub south_east: TwoDLocation,
    }
    impl RectangularRegion {
        pub fn new(north_west: TwoDLocation, south_east: TwoDLocation) -> Self {
            Self {
                north_west,
                south_east,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class RegionAndSubregions"]
    #[doc = " *"]
    #[doc = " * @brief In this structure:"]
    #[doc = " * <br><br><b>Critical information fields</b>:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> RegionAndSubregions is a critical information field as defined in"]
    #[doc = " * 5.2.5. An implementation that does not detect or recognize the the region"]
    #[doc = " * or subregions values when verifying a signed SPDU shall indicate that the"]
    #[doc = " * signed SPDU is invalid.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * <b>Parameters</b>:"]
    #[doc = " *"]
    #[doc = " * @param region identifies a region within a country as specified under"]
    #[doc = " * CountryAndRegions."]
    #[doc = " *"]
    #[doc = " * @param subregions identifies one or more subregions as specified under"]
    #[doc = " * CountryAndSubregions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct RegionAndSubregions {
        pub region: Uint8,
        pub subregions: SequenceOfUint16,
    }
    impl RegionAndSubregions {
        pub fn new(region: Uint8, subregions: SequenceOfUint16) -> Self {
            Self { region, subregions }
        }
    }
    #[doc = "*"]
    #[doc = " * @class SequenceOfHashedId3"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfHashedId3(pub SequenceOf<HashedId3>);
    #[doc = "*"]
    #[doc = " * @class SequenceOfIdentifiedRegion"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfIdentifiedRegion(pub SequenceOf<IdentifiedRegion>);
    #[doc = " Anonymous SEQUENCE OF member "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "OCTET_STRING")]
    pub struct AnonymousSequenceOfOctetString(pub OctetString);
    #[doc = "*"]
    #[doc = " * @class SequenceOfOctetString"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfOctetString(pub SequenceOf<AnonymousSequenceOfOctetString>);
    #[doc = "*"]
    #[doc = " * @class SequenceOfPsid"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfPsid(pub SequenceOf<Psid>);
    #[doc = "*"]
    #[doc = " * @class SequenceOfPsidSsp"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfPsidSsp(pub SequenceOf<PsidSsp>);
    #[doc = "*"]
    #[doc = " * @class SequenceOfPsidSspRange"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfPsidSspRange(pub SequenceOf<PsidSspRange>);
    #[doc = "*"]
    #[doc = " * @class SequenceOfRectangularRegion"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfRectangularRegion(pub SequenceOf<RectangularRegion>);
    #[doc = "*"]
    #[doc = " * @class SequenceOfRegionAndSubregions"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfRegionAndSubregions(pub SequenceOf<RegionAndSubregions>);
    #[doc = "*"]
    #[doc = " * @class SequenceOfUint16"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfUint16(pub SequenceOf<Uint16>);
    #[doc = "*"]
    #[doc = " * @class SequenceOfUint8"]
    #[doc = " *"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SequenceOfUint8(pub SequenceOf<Uint8>);
    #[doc = "*"]
    #[doc = " * @class ServiceSpecificPermissions"]
    #[doc = " *"]
    #[doc = " * @brief This structure represents the Service Specific Permissions (SSP)"]
    #[doc = " * relevant to a given entry in a PsidSsp. The meaning of the SSP is specific"]
    #[doc = " * to the associated Psid. SSPs may be PSID-specific octet strings or"]
    #[doc = " * bitmap-based. See Annex C for further discussion of how application"]
    #[doc = " * specifiers may choose which SSP form to use."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Consistency with issuing certificate</b>."]
    #[doc = " *"]
    #[doc = " * <br><br>If a certificate has an appPermissions entry A for which the ssp"]
    #[doc = " * field is opaque, A is consistent with the issuing certificate if the"]
    #[doc = " * issuing certificate contains one of the following:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;</li>"]
    #[doc = " *"]
    #[doc = " * <li> (OPTION 2) A PsidSspRange P for which the following holds:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The sspRange field in P indicates all.</li>"]
    #[doc = " *"]
    #[doc = " * <li> The sspRange field in P indicates opaque and one of the entries in"]
    #[doc = " * the opaque field in P is an OCTET STRING identical to the opaque field in"]
    #[doc = " * A.</li>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * For consistency rules for other types of ServiceSpecificPermissions,"]
    #[doc = " * see the following subclauses."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum ServiceSpecificPermissions {
        opaque(OctetString),
        #[rasn(extension_addition)]
        bitmapSsp(BitmapSsp),
    }
    #[doc = "***************************************************************************"]
    #[doc = "                            Crypto Structures                              "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @class Signature"]
    #[doc = " *"]
    #[doc = " * @brief This structure represents a signature for a supported public key"]
    #[doc = " * algorithm. It may be contained within SignedData or Certificate."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Critical information fields</b>: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum Signature {
        ecdsaNistP256Signature(EcdsaP256Signature),
        ecdsaBrainpoolP256r1Signature(EcdsaP256Signature),
        #[rasn(extension_addition)]
        ecdsaBrainpoolP384r1Signature(EcdsaP384Signature),
        #[rasn(extension_addition)]
        ecdsaNistP384Signature(EcdsaP384Signature),
    }
    #[doc = "*"]
    #[doc = " * @class SspRange"]
    #[doc = " *"]
    #[doc = " * @brief This structure identifies the SSPs associated with a PSID for"]
    #[doc = " * which the holder may issue or request certificates."]
    #[doc = " *"]
    #[doc = " * <br><br><b>Consistency with issuing certificate</b>."]
    #[doc = " *"]
    #[doc = " * <br><br>If a certificate has a PsidSspRange A for which the ssp field is"]
    #[doc = " * opaque, A is consistent with the issuing certificate if the issuing"]
    #[doc = " * certificate contains one of the following:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;</li>"]
    #[doc = " *"]
    #[doc = " * <li> (OPTION 2) a PsidSspRange P for which the following holds:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:</li>"]
    #[doc = " * <ul>"]
    #[doc = " * <li> The sspRange field in P indicates all.</li>"]
    #[doc = " *"]
    #[doc = " * <li> The sspRange field in P indicates opaque, and the sspRange field in"]
    #[doc = " * A indicates opaque, and every OCTET STRING within the opaque in A is a"]
    #[doc = " * duplicate of an OCTET STRING within the opaque in P.</li>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * If a certificate has a PsidSspRange A for which the ssp field is all,"]
    #[doc = " * A is consistent with the issuing certificate if the issuing certificate"]
    #[doc = " * contains a PsidSspRange P for which the following holds:"]
    #[doc = " * <ul>"]
    #[doc = " * <li> (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;</li>"]
    #[doc = " *"]
    #[doc = " * <li>(OPTION 2) A PsidSspRange P for which the psid field in P is equal to"]
    #[doc = " * the psid field in A and the sspRange field in P indicates all.</li>"]
    #[doc = " * </ul>"]
    #[doc = " *"]
    #[doc = " * For consistency rules for other types of SspRange, see the following"]
    #[doc = " * subclauses."]
    #[doc = " *"]
    #[doc = " * <br><br>NOTE: The choice \"all\" may also be indicated by omitting the"]
    #[doc = " * SspRange in the enclosing PsidSspRange structure. Omitting the SspRange is"]
    #[doc = " * preferred to explicitly indicating \"all\"."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SspRange {
        opaque(SequenceOfOctetString),
        all(()),
        #[rasn(extension_addition)]
        bitmapSspRange(BitmapSspRange),
    }
    #[doc = "***************************************************************************"]
    #[doc = "                          Certificate Components                           "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @class SubjectAssurance"]
    #[doc = " *"]
    #[doc = " * @brief This field contains the certificate holder’s assurance level, which"]
    #[doc = " * indicates the security of both the platform and storage of secret keys as"]
    #[doc = " * well as the confidence in this assessment."]
    #[doc = " *"]
    #[doc = " * <br><br>This field is encoded as defined in Table 1, where \"A\" denotes bit"]
    #[doc = " * fields specifying an assurance level, \"R\" reserved bit fields, and \"C\" bit"]
    #[doc = " * fields specifying the confidence."]
    #[doc = " *"]
    #[doc = " * <br><br>Table 1: Bitwise encoding of subject assurance"]
    #[doc = " *"]
    #[doc = " * <table>"]
    #[doc = " * <tr>"]
    #[doc = " * <td><b>Bit number</b></td> <td>7</td> <td>6</td> <td>5</td> <td>4</td>"]
    #[doc = " * <td>3</td> <td>2</td> <td>1</td> <td>0</td>"]
    #[doc = " * </tr>"]
    #[doc = " * <tr>"]
    #[doc = " * <td><b>Interpretation</b></td> <td>A</td> <td>A</td> <td>A</td> <td>R</td>"]
    #[doc = " * <td>R</td> <td>R</td> <td>C</td> <td>C</td>"]
    #[doc = " * </tr>"]
    #[doc = " * </table>"]
    #[doc = " *"]
    #[doc = " * In Table 1, bit number 0 denotes the least significant bit. Bit 7"]
    #[doc = " * to bit 5 denote the device's assurance levels, bit 4 to bit 2 are reserved"]
    #[doc = " * for future use, and bit 1 and bit 0 denote the confidence."]
    #[doc = " *"]
    #[doc = " * <br><br>The specification of these assurance levels as well as the"]
    #[doc = " * encoding of the confidence levels is outside the scope of the present"]
    #[doc = " * document. It can be assumed that a higher assurance value indicates that"]
    #[doc = " * the holder is more trusted than the holder of a certificate with lower"]
    #[doc = " * assurance value and the same confidence value."]
    #[doc = " *"]
    #[doc = " * <br><br>NOTE: This field was originally specified in ETSI TS 103 097 [B7]"]
    #[doc = " * and future uses of this field are anticipated to be consistent with future"]
    #[doc = " * versions of that document."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct SubjectAssurance(pub FixedOctetString<1usize>);
    #[doc = "*"]
    #[doc = " * @class SymmAlgorithm"]
    #[doc = " *"]
    #[doc = " * @brief This enumerated value indicates supported symmetric algorithms. The"]
    #[doc = " * only symmetric algorithm supported in this version of this standard is"]
    #[doc = " * AES-CCM as specified in 5.3.7."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum SymmAlgorithm {
        aes128Ccm = 0,
    }
    #[doc = "*"]
    #[doc = " * @class SymmetricEncryptionKey"]
    #[doc = " *"]
    #[doc = " * @brief This structure provides the key bytes for use with an identified"]
    #[doc = " * symmetric algorithm. The only supported symmetric algorithm is AES-128 in"]
    #[doc = " * CCM mode as specified in 5.3.7."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SymmetricEncryptionKey {
        aes128Ccm(FixedOctetString<16>),
    }
    #[doc = "*"]
    #[doc = " * @class ThreeDLocation"]
    #[doc = " *"]
    #[doc = " * @brief This structure contains an estimate of 3D location. The details of"]
    #[doc = " * the structure are given in the definitions of the individual fields below."]
    #[doc = " *"]
    #[doc = " * <br><br>NOTE: The units used in this data structure are consistent with the"]
    #[doc = " * location data structures used in SAE J2735, though the encoding is"]
    #[doc = " * incompatible."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct ThreeDLocation {
        pub latitude: Latitude,
        pub longitude: Longitude,
        pub elevation: Elevation,
    }
    impl ThreeDLocation {
        pub fn new(latitude: Latitude, longitude: Longitude, elevation: Elevation) -> Self {
            Self {
                latitude,
                longitude,
                elevation,
            }
        }
    }
    #[doc = "***************************************************************************"]
    #[doc = "                             Time Structures                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @class Time32"]
    #[doc = " *"]
    #[doc = " * @brief This type gives the number of (TAI) seconds since 00:00:00 UTC, 1"]
    #[doc = " * January, 2004."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Time32(pub Uint32);
    #[doc = "*"]
    #[doc = " * @class Time64"]
    #[doc = " *"]
    #[doc = " * @brief This type gives the number of (TAI) microseconds since 00:00:00"]
    #[doc = " * UTC, 1 January, 2004."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Time64(pub Uint64);
    #[doc = "*"]
    #[doc = " * @class TwoDLocation"]
    #[doc = " *"]
    #[doc = " * @brief This structure is used to define validity regions for use in"]
    #[doc = " * certificates. The latitude and longitude fields contain the latitude and"]
    #[doc = " * longitude as defined above."]
    #[doc = " *"]
    #[doc = " * <br><br>NOTE: This data structure is consistent with the location encoding"]
    #[doc = " * used in SAE J2735, except that values 900 000 001 for latitude (used to"]
    #[doc = " * indicate that the latitude was not available) and 1 800 000 001 for"]
    #[doc = " * longitude (used to indicate that the longitude was not available) are not"]
    #[doc = " * valid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct TwoDLocation {
        pub latitude: Latitude,
        pub longitude: Longitude,
    }
    impl TwoDLocation {
        pub fn new(latitude: Latitude, longitude: Longitude) -> Self {
            Self {
                latitude,
                longitude,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @class Uint16"]
    #[doc = " *"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 65,535, i.e., (hex)ff ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=65535"))]
    pub struct Uint16(pub u16);
    #[doc = "***************************************************************************"]
    #[doc = "                               Integer Types                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @class Uint3"]
    #[doc = " *"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 7, i.e., (hex)07."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=7"))]
    pub struct Uint3(pub u8);
    #[doc = "*"]
    #[doc = " * @class Uint32"]
    #[doc = " *"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 4,294,967,295, i.e.,"]
    #[doc = " * (hex)ff ff ff ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=4294967295"))]
    pub struct Uint32(pub u32);
    #[doc = "*"]
    #[doc = " * @class Uint64"]
    #[doc = " *"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 18,446,744,073,709,551,615, i.e.,"]
    #[doc = " * (hex)ff ff ff ff ff ff ff ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=18446744073709551615"))]
    pub struct Uint64(pub u64);
    #[doc = "*"]
    #[doc = " * @class Uint8"]
    #[doc = " *"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 255, i.e., (hex)ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct Uint8(pub u8);
    #[doc = "*"]
    #[doc = " * @class UnknownLatitude"]
    #[doc = " *"]
    #[doc = " * @brief The value 900,000,001 indicates that the latitude was not"]
    #[doc = " * available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("900000001"))]
    pub struct UnknownLatitude(pub NinetyDegreeInt);
    #[doc = "*"]
    #[doc = " * @class UnknownLongitude"]
    #[doc = " *"]
    #[doc = " * @brief The value 1,800,000,001 indicates that the longitude was not"]
    #[doc = " * available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("1800000001"))]
    pub struct UnknownLongitude(pub OneEightyDegreeInt);
    #[doc = "*"]
    #[doc = " * @class ValidityPeriod"]
    #[doc = " *"]
    #[doc = " * @brief This structure gives the validity period of a certificate. The"]
    #[doc = " * start of the validity period is given by start and the end is given by"]
    #[doc = " * start + duration."]
    #[doc = " *"]
    #[doc = " * @param start contains the starting time of the validity period."]
    #[doc = " *"]
    #[doc = " * @param duration contains the duration of the validity period."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct ValidityPeriod {
        pub start: Time32,
        pub duration: Duration,
    }
    impl ValidityPeriod {
        pub fn new(start: Time32, duration: Duration) -> Self {
            Self { start, duration }
        }
    }
}
