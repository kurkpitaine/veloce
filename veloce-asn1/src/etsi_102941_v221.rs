#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_base_types {
    extern crate alloc;
    use super::ieee1609_dot2::{CertificateId, HashedData, SequenceOfPsidGroupPermissions};
    use super::ieee1609_dot2_base_types::{
        GeographicRegion, HashedId8, PublicEncryptionKey, PublicVerificationKey, SequenceOfPsidSsp,
        Signature, SubjectAssurance, Time32, ValidityPeriod,
    };
    use crate::etsi_103097_v211::etsi_ts103097Module::{
        EtsiTs103097Data, EtsiTs103097DataEncrypted, EtsiTs103097DataEncryptedUnicast,
        EtsiTs103097DataSigned, EtsiTs103097DataSignedAndEncryptedUnicast,
        EtsiTs103097DataSignedExternalPayload, EtsiTs103097DataUnsecured,
    };
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("1..=255"))]
    pub struct CertificateFormat(pub u8);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CertificateSubjectAttributes {
        pub id: Option<CertificateId>,
        #[rasn(identifier = "validityPeriod")]
        pub validity_period: Option<ValidityPeriod>,
        pub region: Option<GeographicRegion>,
        #[rasn(identifier = "assuranceLevel")]
        pub assurance_level: Option<SubjectAssurance>,
        #[rasn(identifier = "appPermissions")]
        pub app_permissions: Option<SequenceOfPsidSsp>,
        #[rasn(identifier = "certIssuePermissions")]
        pub cert_issue_permissions: Option<SequenceOfPsidGroupPermissions>,
    }
    impl CertificateSubjectAttributes {
        pub fn new(
            id: Option<CertificateId>,
            validity_period: Option<ValidityPeriod>,
            region: Option<GeographicRegion>,
            assurance_level: Option<SubjectAssurance>,
            app_permissions: Option<SequenceOfPsidSsp>,
            cert_issue_permissions: Option<SequenceOfPsidGroupPermissions>,
        ) -> Self {
            Self {
                id,
                validity_period,
                region,
                assurance_level,
                app_permissions,
                cert_issue_permissions,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    pub enum EcSignature {
        #[rasn(value("0.."))]
        encryptedEcSignature(EtsiTs103097DataEncrypted),
        ecSignature(EtsiTs103097DataSignedExternalPayload),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct PublicKeys {
        #[rasn(identifier = "verificationKey")]
        pub verification_key: PublicVerificationKey,
        #[rasn(identifier = "encryptionKey")]
        pub encryption_key: Option<PublicEncryptionKey>,
    }
    impl PublicKeys {
        pub fn new(
            verification_key: PublicVerificationKey,
            encryption_key: Option<PublicEncryptionKey>,
        ) -> Self {
            Self {
                verification_key,
                encryption_key,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate)]
    pub struct Version(pub Integer);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_messages_ca {
    extern crate alloc;
    use super::etsi_ts102941_base_types::Version;
    use super::etsi_ts102941_trust_lists::{ToBeSignedCrl, ToBeSignedRcaCtl, ToBeSignedTlmCtl};
    use super::etsi_ts102941_types_authorization::{
        EtsiTs102941ButterflyAuthorizationRequestX509Signed, InnerAtRequest, InnerAtResponse,
    };
    use super::etsi_ts102941_types_authorization_validation::{
        AuthorizationValidationRequest, AuthorizationValidationResponse,
    };
    use super::etsi_ts102941_types_ca_management::CaCertificateRequest;
    use super::etsi_ts102941_types_enrolment::{InnerEcRequestSignedForPop, InnerEcResponse};
    use super::etsi_ts102941_types_link_certificate::{
        ToBeSignedLinkCertificate, ToBeSignedLinkCertificateRca, ToBeSignedLinkCertificateTlm,
    };
    use super::ieee1609_dot2_dot1_aca_ra_interface::{AcaRaCertResponse, RaAcaCertRequest};
    use super::ieee1609_dot2_dot1_ee_ra_interface::{
        EeRaCertRequest, EeRaDownloadRequest, RaEeCertInfo,
    };
    use crate::etsi_103097_v211::etsi_ts103097Module::{
        EtsiTs103097DataEncryptedUnicast, EtsiTs103097DataSigned,
        EtsiTs103097DataSignedAndEncryptedUnicast, EtsiTs103097DataSignedExternalPayload,
    };
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AuthorizationValidationRequestMessage(pub EtsiTs103097DataSignedAndEncryptedUnicast);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AuthorizationValidationResponseMessage(
        pub EtsiTs103097DataSignedAndEncryptedUnicast,
    );
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ButterflyCertRequestMessage(pub EtsiTs103097DataSignedAndEncryptedUnicast);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ButterflyCertResponseMessage(pub EtsiTs103097DataSignedAndEncryptedUnicast);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CaCertificateRekeyingMessage(pub EtsiTs103097DataSigned);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CaCertificateRequestMessage(pub EtsiTs103097DataSigned);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct RcaDoubleSignedLinkCertificateMessage(pub EtsiTs103097DataSigned);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct RcaSingleSignedLinkCertificateMessage(pub EtsiTs103097DataSigned);
    #[doc = "***********"]
    #[doc = "-- EtsiTs102941Data"]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct EtsiTs102941Data {
        #[rasn(value("1"))]
        pub version: Version,
        pub content: EtsiTs102941DataContent,
    }
    impl EtsiTs102941Data {
        pub fn new(version: Version, content: EtsiTs102941DataContent) -> Self {
            Self { version, content }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum EtsiTs102941DataContent {
        enrolmentRequest(InnerEcRequestSignedForPop),
        enrolmentResponse(InnerEcResponse),
        authorizationRequest(InnerAtRequest),
        authorizationResponse(InnerAtResponse),
        certificateRevocationList(ToBeSignedCrl),
        certificateTrustListTlm(ToBeSignedTlmCtl),
        certificateTrustListRca(ToBeSignedRcaCtl),
        authorizationValidationRequest(AuthorizationValidationRequest),
        authorizationValidationResponse(AuthorizationValidationResponse),
        caCertificateRequest(CaCertificateRequest),
        #[rasn(extension_addition)]
        linkCertificateTlm(ToBeSignedLinkCertificateTlm),
        #[rasn(extension_addition)]
        singleSignedLinkCertificateRca(ToBeSignedLinkCertificateRca),
        #[rasn(extension_addition)]
        doubleSignedlinkCertificateRca(RcaSingleSignedLinkCertificateMessage),
        #[rasn(extension_addition)]
        butterflyAuthorizationRequest(EeRaCertRequest),
        #[rasn(extension_addition)]
        x509SignedbutterflyAuthorizationRequest(
            EtsiTs102941ButterflyAuthorizationRequestX509Signed,
        ),
        #[rasn(extension_addition)]
        butterflyAuthorizationResponse(RaEeCertInfo),
        #[rasn(extension_addition)]
        butterflyCertificateRequest(RaAcaCertRequest),
        #[rasn(extension_addition)]
        butterflyCertificateResponse(AcaRaCertResponse),
        #[rasn(extension_addition)]
        butterflyAtDownloadRequest(EeRaDownloadRequest),
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_messages_itss {
    extern crate alloc;
    use super::etsi_ts102941_base_types::Version;
    use super::etsi_ts102941_trust_lists::{ToBeSignedCrl, ToBeSignedRcaCtl, ToBeSignedTlmCtl};
    use super::etsi_ts102941_types_authorization::{
        EtsiTs102941ButterflyAuthorizationRequestX509Signed, InnerAtRequest, InnerAtResponse,
    };
    use super::etsi_ts102941_types_enrolment::{InnerEcRequestSignedForPop, InnerEcResponse};
    use super::etsi_ts102941_types_link_certificate::{
        ToBeSignedLinkCertificate, ToBeSignedLinkCertificateTlm,
    };
    use super::ieee1609_dot2_dot1_ee_ra_interface::{
        EeRaCertRequest, EeRaDownloadRequest, RaEeCertInfo,
    };
    use crate::etsi_103097_v211::etsi_ts103097Module::{
        EtsiTs103097DataEncryptedUnicast, EtsiTs103097DataSigned,
        EtsiTs103097DataSignedAndEncryptedUnicast,
    };
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AuthorizationRequestMessage(pub EtsiTs103097DataEncryptedUnicast);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AuthorizationRequestMessageWithPop(pub EtsiTs103097DataSignedAndEncryptedUnicast);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AuthorizationResponseMessage(pub EtsiTs103097DataSignedAndEncryptedUnicast);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ButterflyAtDownloadRequestMessage(pub EtsiTs103097DataSignedAndEncryptedUnicast);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ButterflyAuthorizationRequestMessage(pub EtsiTs103097DataSignedAndEncryptedUnicast);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ButterflyAuthorizationResponseMessage(pub EtsiTs103097DataSigned);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CertificateRevocationListMessage(pub EtsiTs103097DataSigned);
    #[doc = "***********"]
    #[doc = "-- Messages"]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct EnrolmentRequestMessage(pub EtsiTs103097DataSignedAndEncryptedUnicast);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct EnrolmentResponseMessage(pub EtsiTs103097DataSignedAndEncryptedUnicast);
    #[doc = "***********"]
    #[doc = "-- EtsiTs102941Data"]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct EtsiTs102941Data {
        #[rasn(value("1"))]
        pub version: Version,
        pub content: EtsiTs102941DataContent,
    }
    impl EtsiTs102941Data {
        pub fn new(version: Version, content: EtsiTs102941DataContent) -> Self {
            Self { version, content }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum EtsiTs102941DataContent {
        enrolmentRequest(InnerEcRequestSignedForPop),
        enrolmentResponse(InnerEcResponse),
        authorizationRequest(InnerAtRequest),
        authorizationResponse(InnerAtResponse),
        certificateRevocationList(ToBeSignedCrl),
        certificateTrustListTlm(ToBeSignedTlmCtl),
        certificateTrustListRca(ToBeSignedRcaCtl),
        authorizationValidationRequest(()),
        authorizationValidationResponse(()),
        caCertificateRequest(()),
        #[rasn(extension_addition)]
        linkCertificateTlm(ToBeSignedLinkCertificateTlm),
        #[rasn(extension_addition)]
        singleSignedLinkCertificateRca(()),
        #[rasn(extension_addition)]
        doubleSignedlinkCertificateRca(()),
        #[rasn(extension_addition)]
        butterflyAuthorizationRequest(EeRaCertRequest),
        #[rasn(extension_addition)]
        x509SignedbutterflyAuthorizationRequest(
            EtsiTs102941ButterflyAuthorizationRequestX509Signed,
        ),
        #[rasn(extension_addition)]
        butterflyAuthorizationResponse(RaEeCertInfo),
        #[rasn(extension_addition)]
        butterflyCertificateRequest(()),
        #[rasn(extension_addition)]
        butterflyCertificateResponse(()),
        #[rasn(extension_addition)]
        butterflyAtDownloadRequest(EeRaDownloadRequest),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct RcaCertificateTrustListMessage(pub EtsiTs103097DataSigned);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct TlmCertificateTrustListMessage(pub EtsiTs103097DataSigned);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct TlmLinkCertificateMessage(pub EtsiTs103097DataSigned);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct X509SignedButterflyAuthorizationRequestMessage(pub EtsiTs103097DataEncryptedUnicast);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_trust_lists {
    extern crate alloc;
    use super::etsi_ts102941_base_types::Version;
    use super::ieee1609_dot2_base_types::{HashedId8, Time32};
    use crate::etsi_103097_v211::etsi_ts103097Module::{
        EtsiTs103097Certificate, EtsiTs103097DataSigned, EtsiTs103097DataSignedAndEncrypted,
    };
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct AaEntry {
        #[rasn(identifier = "aaCertificate")]
        pub aa_certificate: EtsiTs103097Certificate,
        #[rasn(identifier = "accessPoint")]
        pub access_point: Url,
    }
    impl AaEntry {
        pub fn new(aa_certificate: EtsiTs103097Certificate, access_point: Url) -> Self {
            Self {
                aa_certificate,
                access_point,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CrlEntry(pub HashedId8);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CtlCommand {
        add(CtlEntry),
        delete(CtlDelete),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CtlDelete {
        cert(HashedId8),
        dc(DcDelete),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CtlEntry {
        rca(RootCaEntry),
        ea(EaEntry),
        aa(AaEntry),
        dc(DcEntry),
        tlm(TlmEntry),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CtlFormat {
        pub version: Version,
        #[rasn(identifier = "nextUpdate")]
        pub next_update: Time32,
        #[rasn(identifier = "isFullCtl")]
        pub is_full_ctl: bool,
        #[rasn(value("0..=255"), identifier = "ctlSequence")]
        pub ctl_sequence: u8,
        #[rasn(identifier = "ctlCommands")]
        pub ctl_commands: SequenceOf<CtlCommand>,
    }
    impl CtlFormat {
        pub fn new(
            version: Version,
            next_update: Time32,
            is_full_ctl: bool,
            ctl_sequence: u8,
            ctl_commands: SequenceOf<CtlCommand>,
        ) -> Self {
            Self {
                version,
                next_update,
                is_full_ctl,
                ctl_sequence,
                ctl_commands,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct DcDelete(pub Url);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct DcEntry {
        pub url: Url,
        pub cert: SequenceOf<HashedId8>,
    }
    impl DcEntry {
        pub fn new(url: Url, cert: SequenceOf<HashedId8>) -> Self {
            Self { url, cert }
        }
    }
    #[doc = " ( WITH COMPONENTS {...,"]
    #[doc = "  isFullCtl ( TRUE ),"]
    #[doc = "  ctlCommands ( WITH COMPONENT("]
    #[doc = "    ( WITH COMPONENTS {...,"]
    #[doc = "      delete ABSENT"]
    #[doc = "    })"]
    #[doc = "  ))"]
    #[doc = "}) "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct DeltaCtl(pub CtlFormat);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct EaEntry {
        #[rasn(identifier = "eaCertificate")]
        pub ea_certificate: EtsiTs103097Certificate,
        #[rasn(identifier = "aaAccessPoint")]
        pub aa_access_point: Url,
        #[rasn(identifier = "itsAccessPoint")]
        pub its_access_point: Option<Url>,
    }
    impl EaEntry {
        pub fn new(
            ea_certificate: EtsiTs103097Certificate,
            aa_access_point: Url,
            its_access_point: Option<Url>,
        ) -> Self {
            Self {
                ea_certificate,
                aa_access_point,
                its_access_point,
            }
        }
    }
    #[doc = " ( WITH COMPONENTS {...,"]
    #[doc = "  ctlCommands ( WITH COMPONENT("]
    #[doc = "    ( WITH COMPONENTS {...,"]
    #[doc = "      add ( WITH COMPONENTS {...,"]
    #[doc = "        rca ABSENT,"]
    #[doc = "        tlm ABSENT"]
    #[doc = "      })"]
    #[doc = "    })"]
    #[doc = "  ))"]
    #[doc = "}) "]
    #[doc = "***********"]
    #[doc = "-- CTL"]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct FullCtl(pub CtlFormat);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct RootCaEntry {
        #[rasn(identifier = "selfsignedRootCa")]
        pub selfsigned_root_ca: EtsiTs103097Certificate,
        #[rasn(identifier = "successorTo")]
        pub successor_to: Option<EtsiTs103097Certificate>,
    }
    impl RootCaEntry {
        pub fn new(
            selfsigned_root_ca: EtsiTs103097Certificate,
            successor_to: Option<EtsiTs103097Certificate>,
        ) -> Self {
            Self {
                selfsigned_root_ca,
                successor_to,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct TlmEntry {
        #[rasn(identifier = "selfSignedTLMCertificate")]
        pub self_signed_tlmcertificate: EtsiTs103097Certificate,
        #[rasn(identifier = "successorTo")]
        pub successor_to: Option<EtsiTs103097Certificate>,
        #[rasn(identifier = "accessPoint")]
        pub access_point: Url,
    }
    impl TlmEntry {
        pub fn new(
            self_signed_tlmcertificate: EtsiTs103097Certificate,
            successor_to: Option<EtsiTs103097Certificate>,
            access_point: Url,
        ) -> Self {
            Self {
                self_signed_tlmcertificate,
                successor_to,
                access_point,
            }
        }
    }
    #[doc = "***********"]
    #[doc = "-- CRL"]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedCrl {
        pub version: Version,
        #[rasn(identifier = "thisUpdate")]
        pub this_update: Time32,
        #[rasn(identifier = "nextUpdate")]
        pub next_update: Time32,
        pub entries: SequenceOf<CrlEntry>,
    }
    impl ToBeSignedCrl {
        pub fn new(
            version: Version,
            this_update: Time32,
            next_update: Time32,
            entries: SequenceOf<CrlEntry>,
        ) -> Self {
            Self {
                version,
                this_update,
                next_update,
                entries,
            }
        }
    }
    #[doc = " (WITH COMPONENTS {...,"]
    #[doc = "  ctlCommands ( WITH COMPONENT("]
    #[doc = "    ( WITH COMPONENTS {...,"]
    #[doc = "      add ( WITH COMPONENTS {...,"]
    #[doc = "        ea ABSENT,"]
    #[doc = "        aa ABSENT"]
    #[doc = "      })"]
    #[doc = "    })"]
    #[doc = "  ))"]
    #[doc = "}) "]
    #[doc = "***********"]
    #[doc = "-- RCA CTL"]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ToBeSignedRcaCtl(pub CtlFormat);
    #[doc = "***********"]
    #[doc = "-- TLM CTL"]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ToBeSignedTlmCtl(pub CtlFormat);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct Url(pub Ia5String);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_authorization {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{
        CertificateFormat, CertificateSubjectAttributes, EcSignature, PublicKeys, Version,
    };
    use super::ieee1609_dot2_base_types::HashedId8;
    use super::ieee1609_dot2_dot1_ee_ra_interface::EeRaInterfacePdu;
    use super::ieee1609_dot2_dot1_protocol::{
        Ieee1609Dot2DataSignedX509AuthenticatedCertRequest, ScmsPduScoped, SignerSingleX509Cert,
    };
    use crate::etsi_103097_v211::etsi_ts103097Module::{
        EtsiTs103097Certificate, EtsiTs103097DataSigned,
    };
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "***********"]
    #[doc = "-- AuthorizationRequest/Response"]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum AuthorizationResponseCode {
        ok = 0,
        #[rasn(identifier = "its-aa-cantparse")]
        its_aa_cantparse = 1,
        #[rasn(identifier = "its-aa-badcontenttype")]
        its_aa_badcontenttype = 2,
        #[rasn(identifier = "its-aa-imnottherecipient")]
        its_aa_imnottherecipient = 3,
        #[rasn(identifier = "its-aa-unknownencryptionalgorithm")]
        its_aa_unknownencryptionalgorithm = 4,
        #[rasn(identifier = "its-aa-decryptionfailed")]
        its_aa_decryptionfailed = 5,
        #[rasn(identifier = "its-aa-keysdontmatch")]
        its_aa_keysdontmatch = 6,
        #[rasn(identifier = "its-aa-incompleterequest")]
        its_aa_incompleterequest = 7,
        #[rasn(identifier = "its-aa-invalidencryptionkey")]
        its_aa_invalidencryptionkey = 8,
        #[rasn(identifier = "its-aa-outofsyncrequest")]
        its_aa_outofsyncrequest = 9,
        #[rasn(identifier = "its-aa-unknownea")]
        its_aa_unknownea = 10,
        #[rasn(identifier = "its-aa-invalidea")]
        its_aa_invalidea = 11,
        #[rasn(identifier = "its-aa-deniedpermissions")]
        its_aa_deniedpermissions = 12,
        #[rasn(identifier = "aa-ea-cantreachea")]
        aa_ea_cantreachea = 13,
        #[rasn(identifier = "ea-aa-cantparse")]
        ea_aa_cantparse = 14,
        #[rasn(identifier = "ea-aa-badcontenttype")]
        ea_aa_badcontenttype = 15,
        #[rasn(identifier = "ea-aa-imnottherecipient")]
        ea_aa_imnottherecipient = 16,
        #[rasn(identifier = "ea-aa-unknownencryptionalgorithm")]
        ea_aa_unknownencryptionalgorithm = 17,
        #[rasn(identifier = "ea-aa-decryptionfailed")]
        ea_aa_decryptionfailed = 18,
        invalidaa = 19,
        invalidaasignature = 20,
        wrongea = 21,
        unknownits = 22,
        invalidsignature = 23,
        invalidencryptionkey = 24,
        deniedpermissions = 25,
        deniedtoomanycerts = 26,
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(
        delegate,
        identifier = "EtsiTs102941ButterflyAuthorizationRequest-X509Signed"
    )]
    pub struct EtsiTs102941ButterflyAuthorizationRequestX509Signed(
        pub Ieee1609Dot2DataSignedX509AuthenticatedCertRequest,
    );
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerAtRequest {
        #[rasn(identifier = "publicKeys")]
        pub public_keys: PublicKeys,
        #[rasn(identifier = "hmacKey")]
        pub hmac_key: FixedOctetString<32>,
        #[rasn(identifier = "sharedAtRequest")]
        pub shared_at_request: SharedAtRequest,
        #[rasn(identifier = "ecSignature")]
        pub ec_signature: EcSignature,
    }
    impl InnerAtRequest {
        pub fn new(
            public_keys: PublicKeys,
            hmac_key: FixedOctetString<32>,
            shared_at_request: SharedAtRequest,
            ec_signature: EcSignature,
        ) -> Self {
            Self {
                public_keys,
                hmac_key,
                shared_at_request,
                ec_signature,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerAtResponse {
        #[rasn(identifier = "requestHash")]
        pub request_hash: FixedOctetString<16>,
        #[rasn(identifier = "responseCode")]
        pub response_code: AuthorizationResponseCode,
        pub certificate: Option<EtsiTs103097Certificate>,
    }
    impl InnerAtResponse {
        pub fn new(
            request_hash: FixedOctetString<16>,
            response_code: AuthorizationResponseCode,
            certificate: Option<EtsiTs103097Certificate>,
        ) -> Self {
            Self {
                request_hash,
                response_code,
                certificate,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct SharedAtRequest {
        #[rasn(identifier = "eaId")]
        pub ea_id: HashedId8,
        #[rasn(identifier = "keyTag")]
        pub key_tag: FixedOctetString<16>,
        #[rasn(identifier = "certificateFormat")]
        pub certificate_format: CertificateFormat,
        #[rasn(value("0.."), identifier = "requestedSubjectAttributes")]
        pub requested_subject_attributes: CertificateSubjectAttributes,
    }
    impl SharedAtRequest {
        pub fn new(
            ea_id: HashedId8,
            key_tag: FixedOctetString<16>,
            certificate_format: CertificateFormat,
            requested_subject_attributes: CertificateSubjectAttributes,
        ) -> Self {
            Self {
                ea_id,
                key_tag,
                certificate_format,
                requested_subject_attributes,
            }
        }
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_authorization_validation {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{
        CertificateFormat, CertificateSubjectAttributes, EcSignature, PublicKeys, Version,
    };
    use super::etsi_ts102941_types_authorization::SharedAtRequest;
    use super::ieee1609_dot2_base_types::HashedId8;
    use crate::etsi_103097_v211::etsi_ts103097Module::EtsiTs103097Certificate;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct AuthorizationValidationRequest {
        #[rasn(identifier = "sharedAtRequest")]
        pub shared_at_request: SharedAtRequest,
        #[rasn(identifier = "ecSignature")]
        pub ec_signature: EcSignature,
    }
    impl AuthorizationValidationRequest {
        pub fn new(shared_at_request: SharedAtRequest, ec_signature: EcSignature) -> Self {
            Self {
                shared_at_request,
                ec_signature,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct AuthorizationValidationResponse {
        #[rasn(identifier = "requestHash")]
        pub request_hash: FixedOctetString<16>,
        #[rasn(identifier = "responseCode")]
        pub response_code: AuthorizationValidationResponseCode,
        #[rasn(value("0.."), identifier = "confirmedSubjectAttributes")]
        pub confirmed_subject_attributes: Option<CertificateSubjectAttributes>,
    }
    impl AuthorizationValidationResponse {
        pub fn new(
            request_hash: FixedOctetString<16>,
            response_code: AuthorizationValidationResponseCode,
            confirmed_subject_attributes: Option<CertificateSubjectAttributes>,
        ) -> Self {
            Self {
                request_hash,
                response_code,
                confirmed_subject_attributes,
            }
        }
    }
    #[doc = "***********"]
    #[doc = "-- AuthorizationValidationRequest/Response"]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum AuthorizationValidationResponseCode {
        ok = 0,
        cantparse = 1,
        badcontenttype = 2,
        imnottherecipient = 3,
        unknownencryptionalgorithm = 4,
        decryptionfailed = 5,
        invalidaa = 6,
        invalidaasignature = 7,
        wrongea = 8,
        unknownits = 9,
        invalidsignature = 10,
        invalidencryptionkey = 11,
        deniedpermissions = 12,
        deniedtoomanycerts = 13,
        deniedrequest = 14,
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_ca_management {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{CertificateSubjectAttributes, PublicKeys};
    use crate::etsi_103097_v211::etsi_ts103097Module::{
        EtsiTs103097Certificate, EtsiTs103097DataSigned,
    };
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "***********"]
    #[doc = "-- CA certificate request "]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CaCertificateRequest {
        #[rasn(identifier = "publicKeys")]
        pub public_keys: PublicKeys,
        #[rasn(identifier = "requestedSubjectAttributes")]
        pub requested_subject_attributes: CertificateSubjectAttributes,
    }
    impl CaCertificateRequest {
        pub fn new(
            public_keys: PublicKeys,
            requested_subject_attributes: CertificateSubjectAttributes,
        ) -> Self {
            Self {
                public_keys,
                requested_subject_attributes,
            }
        }
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_enrolment {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{
        CertificateFormat, CertificateSubjectAttributes, EcSignature, PublicKeys, Version,
    };
    use super::ieee1609_dot2_base_types::HashedId8;
    use crate::etsi_103097_v211::etsi_ts103097Module::{
        EtsiTs103097Certificate, EtsiTs103097DataSigned,
    };
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "***********"]
    #[doc = "-- EnrolmentRequest/Response"]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum EnrolmentResponseCode {
        ok = 0,
        cantparse = 1,
        badcontenttype = 2,
        imnottherecipient = 3,
        unknownencryptionalgorithm = 4,
        decryptionfailed = 5,
        unknownits = 6,
        invalidsignature = 7,
        invalidencryptionkey = 8,
        baditsstatus = 9,
        incompleterequest = 10,
        deniedpermissions = 11,
        invalidkeys = 12,
        deniedrequest = 13,
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerEcRequest {
        #[rasn(identifier = "itsId")]
        pub its_id: OctetString,
        #[rasn(identifier = "certificateFormat")]
        pub certificate_format: CertificateFormat,
        #[rasn(identifier = "publicKeys")]
        pub public_keys: PublicKeys,
        #[rasn(value("0.."), identifier = "requestedSubjectAttributes")]
        pub requested_subject_attributes: CertificateSubjectAttributes,
    }
    impl InnerEcRequest {
        pub fn new(
            its_id: OctetString,
            certificate_format: CertificateFormat,
            public_keys: PublicKeys,
            requested_subject_attributes: CertificateSubjectAttributes,
        ) -> Self {
            Self {
                its_id,
                certificate_format,
                public_keys,
                requested_subject_attributes,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct InnerEcRequestSignedForPop(pub EtsiTs103097DataSigned);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerEcResponse {
        #[rasn(identifier = "requestHash")]
        pub request_hash: FixedOctetString<16>,
        #[rasn(identifier = "responseCode")]
        pub response_code: EnrolmentResponseCode,
        pub certificate: Option<EtsiTs103097Certificate>,
    }
    impl InnerEcResponse {
        pub fn new(
            request_hash: FixedOctetString<16>,
            response_code: EnrolmentResponseCode,
            certificate: Option<EtsiTs103097Certificate>,
        ) -> Self {
            Self {
                request_hash,
                response_code,
                certificate,
            }
        }
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_link_certificate {
    extern crate alloc;
    use super::ieee1609_dot2::HashedData;
    use super::ieee1609_dot2_base_types::Time32;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "***********"]
    #[doc = "-- Link certificate messages  "]
    #[doc = "***********"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedLinkCertificate {
        #[rasn(identifier = "expiryTime")]
        pub expiry_time: Time32,
        #[rasn(identifier = "certificateHash")]
        pub certificate_hash: HashedData,
    }
    impl ToBeSignedLinkCertificate {
        pub fn new(expiry_time: Time32, certificate_hash: HashedData) -> Self {
            Self {
                expiry_time,
                certificate_hash,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ToBeSignedLinkCertificateRca(pub ToBeSignedLinkCertificate);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ToBeSignedLinkCertificateTlm(pub ToBeSignedLinkCertificate);
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
    use super::ieee1609_dot2_base_types::*;
    use crate::etsi_103097_v211::etsi_ts103097Extension_module::EtsiOriginatingHeaderInfoExtension;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This type is defined only for backwards compatibility."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct Aes128CcmCiphertext(pub One28BitCcmCiphertext);
    #[doc = "*"]
    #[doc = " * @brief This structure contains an individual AppExtension. AppExtensions"]
    #[doc = " * specified in this standard are drawn from the ASN.1 Information Object Set"]
    #[doc = " * SetCertExtensions. This set, and its use in the AppExtension type, is"]
    #[doc = " * structured so that each AppExtension is associated with a"]
    #[doc = " * CertIssueExtension and a CertRequestExtension and all are identified by"]
    #[doc = " * the same id value. In this structure:"]
    #[doc = " *"]
    #[doc = " * @param id: identifies the extension type."]
    #[doc = " *"]
    #[doc = " * @param content: provides the content of the extension."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct AppExtension {
        pub id: ExtId,
        pub content: Any,
    }
    impl AppExtension {
        pub fn new(id: ExtId, content: Any) -> Self {
            Self { id, content }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    pub enum CertIssueExtensionPermissions {
        specific(Any),
        all(()),
    }
    #[doc = "*"]
    #[doc = " * @brief This field contains an individual CertIssueExtension."]
    #[doc = " * CertIssueExtensions specified in this standard are drawn from the ASN.1"]
    #[doc = " * Information Object Set SetCertExtensions. This set, and its use in the"]
    #[doc = " * CertIssueExtension type, is structured so that each CertIssueExtension"]
    #[doc = " * is associated with a AppExtension and a CertRequestExtension and all are"]
    #[doc = " * identified by the same id value. In this structure:"]
    #[doc = " *"]
    #[doc = " * @param id: identifies the extension type."]
    #[doc = " *"]
    #[doc = " * @param permissions: indicates the permissions. Within this field."]
    #[doc = " *   - all indicates that the certificate is entitled to issue all values of"]
    #[doc = " * the extension."]
    #[doc = " *   - specific is used to specify which values of the extension may be"]
    #[doc = " * issued in the case where all does not apply."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct CertIssueExtension {
        pub id: ExtId,
        pub permissions: CertIssueExtensionPermissions,
    }
    impl CertIssueExtension {
        pub fn new(id: ExtId, permissions: CertIssueExtensionPermissions) -> Self {
            Self { id, permissions }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    pub enum CertRequestExtensionPermissions {
        content(Any),
        all(()),
    }
    #[doc = "*"]
    #[doc = " * @brief This field contains an individual CertRequestExtension."]
    #[doc = " * CertRequestExtensions specified in this standard are drawn from the"]
    #[doc = " * ASN.1 Information Object Set SetCertExtensions. This set, and its use in"]
    #[doc = " * the CertRequestExtension type, is structured so that each"]
    #[doc = " * CertRequestExtension is associated with a AppExtension and a"]
    #[doc = " * CertRequestExtension and all are identified by the same id value. In this"]
    #[doc = " * structure:"]
    #[doc = " *"]
    #[doc = " * @param id: identifies the extension type."]
    #[doc = " *"]
    #[doc = " * @param permissions: indicates the permissions. Within this field."]
    #[doc = " *   - all indicates that the certificate is entitled to issue all values of"]
    #[doc = " * the extension."]
    #[doc = " *   - specific is used to specify which values of the extension may be"]
    #[doc = " * issued in the case where all does not apply."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct CertRequestExtension {
        pub id: ExtId,
        pub permissions: CertRequestExtensionPermissions,
    }
    impl CertRequestExtension {
        pub fn new(id: ExtId, permissions: CertRequestExtensionPermissions) -> Self {
            Self { id, permissions }
        }
    }
    #[doc = "***************************************************************************"]
    #[doc = "                Certificates and other Security Management                 "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure is a profile of the structure CertificateBase which"]
    #[doc = " * specifies the valid combinations of fields to transmit implicit and"]
    #[doc = " * explicit certificates."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to the CertificateBase."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct Certificate(pub CertificateBase);
    #[doc = "*"]
    #[doc = " * @brief The fields in this structure have the following meaning:"]
    #[doc = " *"]
    #[doc = " * @param version: contains the version of the certificate format. In this"]
    #[doc = " * version of the data structures, this field is set to 3."]
    #[doc = " *"]
    #[doc = " * @param type: states whether the certificate is implicit or explicit. This"]
    #[doc = " * field is set to explicit for explicit certificates and to implicit for"]
    #[doc = " * implicit certificates. See ExplicitCertificate and ImplicitCertificate for"]
    #[doc = " * more details."]
    #[doc = " *"]
    #[doc = " * @param issuer: identifies the issuer of the certificate."]
    #[doc = " *"]
    #[doc = " * @param toBeSigned: is the certificate contents. This field is an input to"]
    #[doc = " * the hash when generating or verifying signatures for an explicit"]
    #[doc = " * certificate, or generating or verifying the public key from the"]
    #[doc = " * reconstruction value for an implicit certificate. The details of how this"]
    #[doc = " * field are encoded are given in the description of the"]
    #[doc = " * ToBeSignedCertificate type."]
    #[doc = " *"]
    #[doc = " * @param signature: is included in an ExplicitCertificate. It is the"]
    #[doc = " * signature, calculated by the signer identified in the issuer field, over"]
    #[doc = " * the hash of toBeSigned. The hash is calculated as specified in 5.3.1, where:"]
    #[doc = " *   - Data input is the encoding of toBeSigned following the COER."]
    #[doc = " *   - Signer identifier input depends on the verification type, which in"]
    #[doc = " * turn depends on the choice indicated by issuer. If the choice indicated by"]
    #[doc = " * issuer is self, the verification type is self-signed and the signer"]
    #[doc = " * identifier input is the empty string. If the choice indicated by issuer is"]
    #[doc = " * not self, the verification type is certificate and the signer identifier"]
    #[doc = " * input is the canonicalized COER encoding of the certificate indicated by"]
    #[doc = " * issuer. The canonicalization is carried out as specified in the"]
    #[doc = " * Canonicalization section of this subclause."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to the ToBeSignedCertificate and to the Signature."]
    #[doc = " *"]
    #[doc = " * @note Whole-certificate hash: If the entirety of a certificate is hashed"]
    #[doc = " * to calculate a HashedId3, HashedId8, or HashedId10, the algorithm used for"]
    #[doc = " * this purpose is known as the whole-certificate hash. The method used to"]
    #[doc = " * determine the whole-certificate hash algorithm is specified in 5.3.9.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure contains information that is used to identify the"]
    #[doc = " * certificate holder if necessary."]
    #[doc = " *"]
    #[doc = " * @param linkageData: is used to identify the certificate for revocation"]
    #[doc = " * purposes in the case of certificates that appear on linked certificate"]
    #[doc = " * CRLs. See 5.1.3 and 7.3 for further discussion."]
    #[doc = " *"]
    #[doc = " * @param name: is used to identify the certificate holder in the case of"]
    #[doc = " * non-anonymous certificates. The contents of this field are a matter of"]
    #[doc = " * policy and are expected to be human-readable."]
    #[doc = " *"]
    #[doc = " * @param binaryId: supports identifiers that are not human-readable."]
    #[doc = " *"]
    #[doc = " * @param none: indicates that the certificate does not include an identifier."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the choice indicated in this"]
    #[doc = " * field shall reject a signed SPDU as invalid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This enumerated type indicates whether a certificate is explicit or"]
    #[doc = " * implicit."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2,"]
    #[doc = " * that is, it is invalid in the sense that its validity cannot be"]
    #[doc = " * established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum CertificateType {
        explicit = 0,
        implicit = 1,
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure defines the format of an extension block"]
    #[doc = " * provided by an identified contributor by using the temnplate provided"]
    #[doc = " * in the class IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION constraint"]
    #[doc = " * to the objects in the set Ieee1609Dot2HeaderInfoContributedExtensions."]
    #[doc = " *"]
    #[doc = " * @param contributorId: uniquely identifies the contributor."]
    #[doc = " *"]
    #[doc = " * @param extns: contains a list of extensions from that contributor."]
    #[doc = " * Extensions are expected and not required to follow the format specified"]
    #[doc = " * in 6.5."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("1.."))]
    pub struct ContributedExtensionBlocks(pub SequenceOf<ContributedExtensionBlock>);
    #[doc = "*"]
    #[doc = " * @brief This data structure is used to perform a countersignature over an"]
    #[doc = " * already-signed SPDU. This is the profile of an Ieee1609Dot2Data containing"]
    #[doc = " * a signedData. The tbsData within content is composed of a payload"]
    #[doc = " * containing the hash (extDataHash) of the externally generated, pre-signed"]
    #[doc = " * SPDU over which the countersignature is performed."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct Countersignature(pub Ieee1609Dot2Data);
    #[doc = "***************************************************************************"]
    #[doc = "                              Encrypted Data                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This data structure encodes data that has been encrypted to one or"]
    #[doc = " * more recipients using the recipients public or symmetric keys as"]
    #[doc = " * specified in 5.3.4."]
    #[doc = " *"]
    #[doc = " * @param recipients: contains one or more RecipientInfos. These entries may"]
    #[doc = " * be more than one RecipientInfo, and more than one type of RecipientInfo,"]
    #[doc = " * as long as all entries are indicating or containing the same data encryption"]
    #[doc = " * key."]
    #[doc = " *"]
    #[doc = " * @param ciphertext: contains the encrypted data. This is the encryption of"]
    #[doc = " * an encoded Ieee1609Dot2Data structure as specified in 5.3.4.2."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, recipients is a critical information field as defined in"]
    #[doc = " * 5.2.6. An implementation that does not support the number of RecipientInfo"]
    #[doc = " * in recipients when decrypted shall indicate that the encrypted SPDU could"]
    #[doc = " * not be decrypted due to unsupported critical information fields. A"]
    #[doc = " * compliant implementation shall support recipients fields containing at"]
    #[doc = " * least eight entries."]
    #[doc = " *"]
    #[doc = " * @note If the plaintext is raw data, i.e., it has not been output from a"]
    #[doc = " * previous operation of the SDS, then it is trivial to encapsulate it in an"]
    #[doc = " * Ieee1609Dot2Data of type unsecuredData as noted in 4.2.2.2.2. For example,"]
    #[doc = " * '03 80 08 01 23 45 67 89 AB CD EF' is the C-OER encoding of '01 23 45 67"]
    #[doc = " * 89 AB CD EF' encapsulated in an Ieee1609Dot2Data of type unsecuredData."]
    #[doc = " * The first byte of the encoding 03 is the protocolVersion, the second byte"]
    #[doc = " * 80 indicates the choice unsecuredData, and the third byte 08 is the length"]
    #[doc = " * of the raw data '01 23 45 67 89 AB CD EF'."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This data structure contains an encrypted data encryption key,"]
    #[doc = " * where the data encryption key is input to the data encryption key"]
    #[doc = " * encryption process with no headers, encapsulation, or length indication."]
    #[doc = " *"]
    #[doc = " * Critical information fields: If present and applicable to"]
    #[doc = " * the receiving SDEE, this is a critical information field as defined in"]
    #[doc = " * 5.2.6. If an implementation receives an encrypted SPDU and determines that"]
    #[doc = " * one or more RecipientInfo fields are relevant to it, and if all of those"]
    #[doc = " * RecipientInfos contain an EncryptedDataEncryptionKey such that the"]
    #[doc = " * implementation does not recognize the indicated CHOICE, the implementation"]
    #[doc = " * shall indicate that the encrypted SPDU is not decryptable."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum EncryptedDataEncryptionKey {
        eciesNistP256(EciesP256EncryptedKey),
        eciesBrainpoolP256r1(EciesP256EncryptedKey),
        #[rasn(extension_addition)]
        ecencSm2256(EcencP256EncryptedKey),
    }
    #[doc = "*"]
    #[doc = " * @brief This type indicates which type of permissions may appear in"]
    #[doc = " * end-entity certificates the chain of whose permissions passes through the"]
    #[doc = " * PsidGroupPermissions field containing this value. If app is indicated, the"]
    #[doc = " * end-entity certificate may contain an appPermissions field. If enroll is"]
    #[doc = " * indicated, the end-entity certificate may contain a certRequestPermissions"]
    #[doc = " * field."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("8"))]
    pub struct EndEntityType(pub BitString);
    #[doc = "*"]
    #[doc = " * @brief This is a profile of the CertificateBase structure providing all"]
    #[doc = " * the fields necessary for an explicit certificate, and no others."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ExplicitCertificate(pub CertificateBase);
    #[doc = "*"]
    #[doc = " * @brief This structure contains the hash of some data with a specified hash"]
    #[doc = " * algorithm. See 5.3.3 for specification of the permitted hash algorithms."]
    #[doc = " *"]
    #[doc = " * @param sha256HashedData: indicates data hashed with SHA-256."]
    #[doc = " *"]
    #[doc = " * @param sha384HashedData: indicates data hashed with SHA-384."]
    #[doc = " *"]
    #[doc = " * @param sm3HashedData: indicates data hashed with SM3."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2,"]
    #[doc = " * that is, it is invalid in the sense that its validity cannot be established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum HashedData {
        sha256HashedData(HashedId32),
        #[rasn(extension_addition)]
        sha384HashedData(HashedId48),
        #[rasn(extension_addition)]
        sm3HashedData(HashedId32),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains information that is used to establish"]
    #[doc = " * validity by the criteria of 5.2."]
    #[doc = " *"]
    #[doc = " * @param psid: indicates the application area with which the sender is"]
    #[doc = " * claiming the payload is to be associated."]
    #[doc = " *"]
    #[doc = " * @param generationTime: indicates the time at which the structure was"]
    #[doc = " * generated. See 5.2.5.2.2 and 5.2.5.2.3 for discussion of the use of this"]
    #[doc = " * field."]
    #[doc = " *"]
    #[doc = " * @param expiryTime: if present, contains the time after which the data"]
    #[doc = " * is no longer considered relevant. If both generationTime and"]
    #[doc = " * expiryTime are present, the signed SPDU is invalid if generationTime is"]
    #[doc = " * not strictly earlier than expiryTime."]
    #[doc = " *"]
    #[doc = " * @param generationLocation: if present, contains the location at which the"]
    #[doc = " * signature was generated."]
    #[doc = " *"]
    #[doc = " * @param p2pcdLearningRequest: if present, is used by the SDS to request"]
    #[doc = " * certificates for which it has seen identifiers and does not know the"]
    #[doc = " * entire certificate. A specification of this peer-to-peer certificate"]
    #[doc = " * distribution (P2PCD) mechanism is given in Clause 8. This field is used"]
    #[doc = " * for the separate-certificate-pdu flavor of P2PCD and shall only be present"]
    #[doc = " * if inlineP2pcdRequest is not present. The HashedId3 is calculated with the"]
    #[doc = " * whole-certificate hash algorithm, determined as described in 6.4.3,"]
    #[doc = " * applied to the COER-encoded certificate, canonicalized as defined in the"]
    #[doc = " * definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @param missingCrlIdentifier: if present, is used by the SDS to request"]
    #[doc = " * CRLs which it knows to have been issued and have not received. This is"]
    #[doc = " * provided for future use and the associated mechanism is not defined in"]
    #[doc = " * this version of this standard."]
    #[doc = " *"]
    #[doc = " * @param encryptionKey: if present, is used to provide a key that is to"]
    #[doc = " * be used to encrypt at least one response to this SPDU. The SDEE"]
    #[doc = " * specification is expected to specify which response SPDUs are to be"]
    #[doc = " * encrypted with this key. One possible use of this key to encrypt a"]
    #[doc = " * response is specified in 6.3.35, 6.3.37, and 6.3.34. An encryptionKey"]
    #[doc = " * field of type symmetric should only be used if the SignedData containing"]
    #[doc = " * this field is securely encrypted by some means."]
    #[doc = " *"]
    #[doc = " * @param inlineP2pcdRequest: if present, is used by the SDS to request"]
    #[doc = " * unknown certificates per the inline peer-to-peer certificate distribution"]
    #[doc = " * mechanism is given in Clause 8. This field shall only be present if"]
    #[doc = " * p2pcdLearningRequest is not present. The HashedId3 is calculated with the"]
    #[doc = " * whole-certificate hash algorithm, determined as described in 6.4.3, applied"]
    #[doc = " * to the COER-encoded certificate, canonicalized as defined in the definition"]
    #[doc = " * of Certificate."]
    #[doc = " *"]
    #[doc = " * @param requestedCertificate: if present, is used by the SDS to provide"]
    #[doc = " * certificates per the \"inline\" version of the peer-to-peer certificate"]
    #[doc = " * distribution mechanism given in Clause 8."]
    #[doc = " *"]
    #[doc = " * @param pduFunctionalType: if present, is used to indicate that the SPDU is"]
    #[doc = " * to be consumed by a process other than an application process as defined"]
    #[doc = " * in ISO 21177 [B14a]. See 6.3.23b for more details."]
    #[doc = " *"]
    #[doc = " * @param contributedExtensions: if present, is used to contain additional"]
    #[doc = " * extensions defined using the ContributedExtensionBlocks structure."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to the EncryptionKey. If encryptionKey is present, and indicates"]
    #[doc = " * the choice public, and contains a BasePublicEncryptionKey that is an"]
    #[doc = " * elliptic curve point (i.e., of type EccP256CurvePoint or"]
    #[doc = " * EccP384CurvePoint), then the elliptic curve point is encoded in compressed"]
    #[doc = " * form, i.e., such that the choice indicated within the Ecc*CurvePoint is"]
    #[doc = " * compressed-y-0 or compressed-y-1."]
    #[doc = " * The canonicalization does not apply to any fields after the extension"]
    #[doc = " * marker, including any fields in contributedExtensions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This is an integer used to identify a HeaderInfo extension"]
    #[doc = " * contributing organization. In this version of this standard two values are"]
    #[doc = " * defined:"]
    #[doc = " *   - ieee1609OriginatingExtensionId indicating extensions originating with"]
    #[doc = " * IEEE 1609."]
    #[doc = " *   - etsiOriginatingExtensionId indicating extensions originating with"]
    #[doc = " * ETSI TC ITS."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct HeaderInfoContributorId(pub u8);
    #[doc = "*"]
    #[doc = " * @brief This structure uses the parameterized type Extension to define an"]
    #[doc = " * Ieee1609ContributedHeaderInfoExtension as an open Extension Content field"]
    #[doc = " * identified by an extension identifier. The extension identifier value is"]
    #[doc = " * unique to extensions defined by ETSI and need not be unique among all"]
    #[doc = " * extension identifier values defined by all contributing organizations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct Ieee1609ContributedHeaderInfoExtension {
        pub id: ExtId,
        pub content: Any,
    }
    impl Ieee1609ContributedHeaderInfoExtension {
        pub fn new(id: ExtId, content: Any) -> Self {
            Self { id, content }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param unsecuredData: indicates that the content is an OCTET STRING to be"]
    #[doc = " * consumed outside the SDS."]
    #[doc = " *"]
    #[doc = " * @param signedData: indicates that the content has been signed according to"]
    #[doc = " * this standard."]
    #[doc = " *"]
    #[doc = " * @param encryptedData: indicates that the content has been encrypted"]
    #[doc = " * according to this standard."]
    #[doc = " *"]
    #[doc = " * @param signedCertificateRequest: indicates that the content is a"]
    #[doc = " * certificate request signed by an IEEE 1609.2 certificate or self-signed."]
    #[doc = " *"]
    #[doc = " * @param signedX509CertificateRequest: indicates that the content is a"]
    #[doc = " * certificate request signed by an ITU-T X.509 certificate."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2 if it is of type signedData."]
    #[doc = " * The canonicalization applies to the SignedData."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This data type is used to contain the other data types in this"]
    #[doc = " * clause. The fields in the Ieee1609Dot2Data have the following meanings:"]
    #[doc = " *"]
    #[doc = " * @param protocolVersion: contains the current version of the protocol. The"]
    #[doc = " * version specified in this standard is version 3, represented by the"]
    #[doc = " * integer 3. There are no major or minor version numbers."]
    #[doc = " *"]
    #[doc = " * @param content: contains the content in the form of an Ieee1609Dot2Content."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to the Ieee1609Dot2Content."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This is an integer used to identify an"]
    #[doc = " * Ieee1609ContributedHeaderInfoExtension."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct Ieee1609HeaderInfoExtensionId(pub ExtId);
    #[doc = "*"]
    #[doc = " * @brief This is a profile of the CertificateBase structure providing all"]
    #[doc = " * the fields necessary for an implicit certificate, and no others."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ImplicitCertificate(pub CertificateBase);
    #[doc = "*"]
    #[doc = " * @brief This structure allows the recipient of a certificate to determine"]
    #[doc = " * which keying material to use to authenticate the certificate."]
    #[doc = " *"]
    #[doc = " * If the choice indicated is sha256AndDigest, sha384AndDigest, or"]
    #[doc = " * sm3AndDigest:"]
    #[doc = " *   - The structure contains the HashedId8 of the issuing certificate. The"]
    #[doc = " * HashedId8 is calculated with the whole-certificate hash algorithm,"]
    #[doc = " * determined as described in 6.4.3, applied to the COER-encoded certificate,"]
    #[doc = " * canonicalized as defined in the definition of Certificate."]
    #[doc = " *   - The hash algorithm to be used to generate the hash of the certificate"]
    #[doc = " * for verification is SHA-256 (in the case of sha256AndDigest), SM3 (in the"]
    #[doc = " * case of sm3AndDigest) or SHA-384 (in the case of sha384AndDigest)."]
    #[doc = " *   - The certificate is to be verified with the public key of the"]
    #[doc = " * indicated issuing certificate."]
    #[doc = " *"]
    #[doc = " * If the choice indicated is self:"]
    #[doc = " *   - The structure indicates what hash algorithm is to be used to generate"]
    #[doc = " * the hash of the certificate for verification."]
    #[doc = " *   - The certificate is to be verified with the public key indicated by"]
    #[doc = " * the verifyKeyIndicator field in theToBeSignedCertificate."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2,"]
    #[doc = " * that is, it is invalid in the sense that its validity cannot be"]
    #[doc = " * established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum IssuerIdentifier {
        sha256AndDigest(HashedId8),
        #[rasn(identifier = "self")]
        R_self(HashAlgorithm),
        #[rasn(extension_addition)]
        sha384AndDigest(HashedId8),
        #[rasn(extension_addition)]
        sm3AndDigest(HashedId8),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains information that is matched against"]
    #[doc = " * information obtained from a linkage ID-based CRL to determine whether the"]
    #[doc = " * containing certificate has been revoked. See 5.1.3.4 and 7.3 for details"]
    #[doc = " * of use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure may be used to request a CRL that the SSME knows to"]
    #[doc = " * have been issued and has not yet received. It is provided for future use"]
    #[doc = " * and its use is not defined in this version of this standard."]
    #[doc = " *"]
    #[doc = " * @param cracaId: is the HashedId3 of the CRACA, as defined in 5.1.3. The"]
    #[doc = " * HashedId3 is calculated with the whole-certificate hash algorithm,"]
    #[doc = " * determined as described in 6.4.3, applied to the COER-encoded certificate,"]
    #[doc = " * canonicalized as defined in the definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @param crlSeries: is the requested CRL Series value. See 5.1.3 for more"]
    #[doc = " * information."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This data structure encapsulates an encrypted ciphertext for any"]
    #[doc = " * symmetric algorithm with 128-bit blocks in CCM mode. The ciphertext is"]
    #[doc = " * 16 bytes longer than the corresponding plaintext due to the inclusion of"]
    #[doc = " * the message authentication code (MAC). The plaintext resulting from a"]
    #[doc = " * correct decryption of the ciphertext is either a COER-encoded"]
    #[doc = " * Ieee1609Dot2Data structure (see 6.3.41), or a 16-byte symmetric key"]
    #[doc = " * (see 6.3.44)."]
    #[doc = " *"]
    #[doc = " * The ciphertext is 16 bytes longer than the corresponding plaintext."]
    #[doc = " *"]
    #[doc = " * The plaintext resulting from a correct decryption of the"]
    #[doc = " * ciphertext is a COER-encoded Ieee1609Dot2Data structure."]
    #[doc = " *"]
    #[doc = " * @param nonce: contains the nonce N as specified in 5.3.8."]
    #[doc = " *"]
    #[doc = " * @param ccmCiphertext: contains the ciphertext C as specified in 5.3.8."]
    #[doc = " *"]
    #[doc = " * @note In the name of this structure, \"One28\" indicates that the"]
    #[doc = " * symmetric cipher block size is 128 bits. It happens to also be the case"]
    #[doc = " * that the keys used for both AES-128-CCM and SM4-CCM are also 128 bits long."]
    #[doc = " * This is, however, not what One28 refers to. Since the cipher is used in"]
    #[doc = " * counter mode, i.e., as a stream cipher, the fact that that block size is 128"]
    #[doc = " * bits affects only the size of the MAC and does not affect the size of the"]
    #[doc = " * raw ciphertext."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct One28BitCcmCiphertext {
        pub nonce: FixedOctetString<12>,
        #[rasn(identifier = "ccmCiphertext")]
        pub ccm_ciphertext: Opaque,
    }
    impl One28BitCcmCiphertext {
        pub fn new(nonce: FixedOctetString<12>, ccm_ciphertext: Opaque) -> Self {
            Self {
                nonce,
                ccm_ciphertext,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This type is the AppExtension used to identify an operating"]
    #[doc = " * organization. The associated CertIssueExtension and CertRequestExtension"]
    #[doc = " * are both of type OperatingOrganizationId."]
    #[doc = " * To determine consistency between this type and an SPDU, the SDEE"]
    #[doc = " * specification for that SPDU is required to specify how the SPDU can be"]
    #[doc = " * used to determine an OBJECT IDENTIFIER (for example, by including the"]
    #[doc = " * full OBJECT IDENTIFIER in the SPDU, or by including a RELATIVE-OID with"]
    #[doc = " * clear instructions about how a full OBJECT IDENTIFIER can be obtained from"]
    #[doc = " * the RELATIVE-OID). The SPDU is then consistent with this type if the"]
    #[doc = " * OBJECT IDENTIFIER determined from the SPDU is identical to the OBJECT"]
    #[doc = " * IDENTIFIER contained in this field."]
    #[doc = " * This AppExtension does not have consistency conditions with a"]
    #[doc = " * corresponding CertIssueExtension. It can appear in a certificate issued"]
    #[doc = " * by any CA."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct OperatingOrganizationId(pub ObjectIdentifier);
    #[doc = "*"]
    #[doc = " * @brief This data structure contains the following fields:"]
    #[doc = " *"]
    #[doc = " * @param recipientId: contains the hash of the container for the encryption"]
    #[doc = " * public key as specified in the definition of RecipientInfo. Specifically,"]
    #[doc = " * depending on the choice indicated by the containing RecipientInfo structure:"]
    #[doc = " *   - If the containing RecipientInfo structure indicates certRecipInfo,"]
    #[doc = " * this field contains the HashedId8 of the certificate. The HashedId8 is"]
    #[doc = " * calculated with the whole-certificate hash algorithm, determined as"]
    #[doc = " * described in 6.4.3, applied to the COER-encoded certificate, canonicalized"]
    #[doc = " * as defined in the definition of Certificate."]
    #[doc = " *   - If the containing RecipientInfo structure indicates"]
    #[doc = " * signedDataRecipInfo, this field contains the HashedId8 of the"]
    #[doc = " * Ieee1609Dot2Data of type signedData that contained the encryption key,"]
    #[doc = " * with that Ieee1609Dot2Data canonicalized per 6.3.4. The HashedId8 is"]
    #[doc = " * calculated with the hash algorithm determined as specified in 5.3.9.5."]
    #[doc = " *   - If the containing RecipientInfo structure indicates rekRecipInfo, this"]
    #[doc = " * field contains the HashedId8 of the COER encoding of a PublicEncryptionKey"]
    #[doc = " * structure containing the response encryption key. The HashedId8 is"]
    #[doc = " * calculated with the hash algorithm determined as specified in 5.3.9.5."]
    #[doc = " *"]
    #[doc = " * @param encKey: contains the encrypted data encryption key, where the data"]
    #[doc = " * encryption key is input to the data encryption key encryption process with"]
    #[doc = " * no headers, encapsulation, or length indication."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This data structure identifies the functional entity that is"]
    #[doc = " * intended to consume an SPDU, for the case where that functional entity is"]
    #[doc = " * not an application process, and are instead security support services for an"]
    #[doc = " * application process. Further details and the intended use of this field are"]
    #[doc = " * defined in ISO 21177 [B20]."]
    #[doc = " *"]
    #[doc = " * @param tlsHandshake: indicates that the Signed SPDU is not to be directly"]
    #[doc = " * consumed as an application PDU and is to be used to provide information"]
    #[doc = " * about the holders permissions to a Transport Layer Security (TLS)"]
    #[doc = " * (IETF 5246 [B15], IETF 8446 [B16]) handshake process operating to secure"]
    #[doc = " * communications to an application process. See IETF [B15] and ISO 21177"]
    #[doc = " * [B20] for further information."]
    #[doc = " *"]
    #[doc = " * @param iso21177ExtendedAuth: indicates that the Signed SPDU is not to be"]
    #[doc = " * directly consumed as an application PDU and is to be used to provide"]
    #[doc = " * additional information about the holders permissions to the ISO 21177"]
    #[doc = " * Security Subsystem for an application process. See ISO 21177 [B20] for"]
    #[doc = " * further information."]
    #[doc = " *"]
    #[doc = " * @param iso21177SessionExtension: indicates that the Signed SPDU is not to"]
    #[doc = " * be directly consumed as an application PDU and is to be used to extend an"]
    #[doc = " * existing ISO 21177 secure session. This enables a secure session to"]
    #[doc = " * persist beyond the lifetime of the certificates used to establish that"]
    #[doc = " * session."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct PduFunctionalType(pub u8);
    #[doc = "*"]
    #[doc = " * @brief This data structure is used to indicate a symmetric key that may"]
    #[doc = " * be used directly to decrypt a SymmetricCiphertext. It consists of the"]
    #[doc = " * low-order 8 bytes of the hash of the COER encoding of a"]
    #[doc = " * SymmetricEncryptionKey structure containing the symmetric key in question."]
    #[doc = " * The HashedId8 is calculated with the hash algorithm determined as"]
    #[doc = " * specified in 5.3.9.3. The symmetric key may be established by any"]
    #[doc = " * appropriate means agreed by the two parties to the exchange."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct PreSharedKeyRecipientInfo(pub HashedId8);
    #[doc = "*"]
    #[doc = " * @brief This structure states the permissions that a certificate holder has"]
    #[doc = " * with respect to issuing and requesting certificates for a particular set"]
    #[doc = " * of PSIDs. For examples, see D.5.3 and D.5.4."]
    #[doc = " *"]
    #[doc = " * @param subjectPermissions: indicates PSIDs and SSP Ranges covered by this"]
    #[doc = " * field."]
    #[doc = " *"]
    #[doc = " * @param minChainLength: and chainLengthRange indicate how long the"]
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
    #[doc = " * @param eeType: takes one or more of the values app and enroll and indicates"]
    #[doc = " * the type of certificates or requests that this instance of"]
    #[doc = " * PsidGroupPermissions in the certificate is entitled to authorize."]
    #[doc = " * Different instances of PsidGroupPermissions within a ToBeSignedCertificate"]
    #[doc = " * may have different values for eeType."]
    #[doc = " *   - If this field indicates app, the chain is allowed to end in an"]
    #[doc = " * authorization certificate, i.e., a certficate in which these permissions"]
    #[doc = " * appear in an appPermissions field (in other words, if the field does not"]
    #[doc = " * indicate app and the chain ends in an authorization certificate, the"]
    #[doc = " * chain shall be considered invalid)."]
    #[doc = " *   - If this field indicates enroll, the chain is allowed to end in an"]
    #[doc = " * enrollment certificate, i.e., a certificate in which these permissions"]
    #[doc = " * appear in a certReqPermissions permissions field (in other words, if the"]
    #[doc = " * field does not indicate enroll and the chain ends in an enrollment"]
    #[doc = " * certificate, the chain shall be considered invalid)."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
        EndEntityType(BitString::from_slice(&[1u8]))
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure is used to transfer the data encryption key to"]
    #[doc = " * an individual recipient of an EncryptedData. The option pskRecipInfo is"]
    #[doc = " * selected if the EncryptedData was encrypted using the static encryption"]
    #[doc = " * key approach specified in 5.3.4. The other options are selected if the"]
    #[doc = " * EncryptedData was encrypted using the ephemeral encryption key approach"]
    #[doc = " * specified in 5.3.4. The meanings of the choices are:"]
    #[doc = " *"]
    #[doc = " * See Annex C.7 for guidance on when it may be appropriate to use"]
    #[doc = " * each of these approaches."]
    #[doc = " *"]
    #[doc = " * @param pskRecipInfo: The data was encrypted directly using a pre-shared"]
    #[doc = " * symmetric key."]
    #[doc = " *"]
    #[doc = " * @param symmRecipInfo: The data was encrypted with a data encryption key,"]
    #[doc = " * and the data encryption key was encrypted using a symmetric key."]
    #[doc = " *"]
    #[doc = " * @param certRecipInfo: The data was encrypted with a data encryption key,"]
    #[doc = " * the data encryption key was encrypted using a public key encryption scheme,"]
    #[doc = " * where the public encryption key was obtained from a certificate. In this"]
    #[doc = " * case, the parameter P1 to ECIES as defined in 5.3.5 is the hash of the"]
    #[doc = " * certificate, calculated with the whole-certificate hash algorithm,"]
    #[doc = " * determined as described in 6.4.3, applied to the COER-encoded certificate,"]
    #[doc = " * canonicalized as defined in the definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @note If the encryption algorithm is SM2, there is no equivalent of the"]
    #[doc = " * parameter P1 and so no input to the encryption process that uses the hash"]
    #[doc = " * of the certificate."]
    #[doc = " *"]
    #[doc = " * @param signedDataRecipInfo: The data was encrypted with a data encryption"]
    #[doc = " * key, the data encryption key was encrypted using a public key encryption"]
    #[doc = " * scheme, where the public encryption key was obtained as the public response"]
    #[doc = " * encryption key from a SignedData. In this case, if ECIES is the encryption"]
    #[doc = " * algorithm, then the parameter P1 to ECIES as defined in 5.3.5 is the"]
    #[doc = " * SHA-256 hash of the Ieee1609Dot2Data of type signedData containing the"]
    #[doc = " * response encryption key, canonicalized as defined in the definition of"]
    #[doc = " * Ieee1609Dot2Data."]
    #[doc = " *"]
    #[doc = " * @note If the encryption algorithm is SM2, there is no equivalent of the"]
    #[doc = " * parameter P1 and so no input to the encryption process that uses the hash"]
    #[doc = " * of the Ieee1609Dot2Data."]
    #[doc = " *"]
    #[doc = " * @param rekRecipInfo: The data was encrypted with a data encryption key,"]
    #[doc = " * the data encryption key was encrypted using a public key encryption scheme,"]
    #[doc = " * where the public encryption key was not obtained from a Signed-Data or a"]
    #[doc = " * certificate. In this case, the SDEE specification is expected to specify"]
    #[doc = " * how the public key is obtained, and if ECIES is the encryption algorithm,"]
    #[doc = " * then the parameter P1 to ECIES as defined in 5.3.5 is the hash of the"]
    #[doc = " * empty string."]
    #[doc = " *"]
    #[doc = " * @note If the encryption algorithm is SM2, there is no equivalent of the"]
    #[doc = " * parameter P1 and so no input to the encryption process that uses the hash"]
    #[doc = " * of the empty string."]
    #[doc = " *"]
    #[doc = " * @note The material input to encryption is the bytes of the encryption key"]
    #[doc = " * with no headers, encapsulation, or length indication. Contrast this to"]
    #[doc = " * encryption of data, where the data is encapsulated in an Ieee1609Dot2Data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    pub enum RecipientInfo {
        pskRecipInfo(PreSharedKeyRecipientInfo),
        symmRecipInfo(SymmRecipientInfo),
        certRecipInfo(PKRecipientInfo),
        signedDataRecipInfo(PKRecipientInfo),
        rekRecipInfo(PKRecipientInfo),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains any AppExtensions that apply to the"]
    #[doc = " * certificate holder. As specified in 5.2.4.2.3, each individual"]
    #[doc = " * AppExtension type is associated with consistency conditions, specific to"]
    #[doc = " * that extension, that govern its consistency with SPDUs signed by the"]
    #[doc = " * certificate holder and with the CertIssueExtensions in the CA certificates"]
    #[doc = " * in that certificate holders chain. Those consistency conditions are"]
    #[doc = " * specified for each individual AppExtension below."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("1.."))]
    pub struct SequenceOfAppExtensions(pub SequenceOf<AppExtension>);
    #[doc = "*"]
    #[doc = " * @brief This field contains any CertIssueExtensions that apply to the"]
    #[doc = " * certificate holder. As specified in 5.2.4.2.3, each individual"]
    #[doc = " * CertIssueExtension type is associated with consistency conditions,"]
    #[doc = " * specific to that extension, that govern its consistency with"]
    #[doc = " * AppExtensions in certificates issued by the certificate holder and with"]
    #[doc = " * the CertIssueExtensions in the CA certificates in that certificate"]
    #[doc = " * holders chain. Those consistency conditions are specified for each"]
    #[doc = " * individual CertIssueExtension below."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("1.."))]
    pub struct SequenceOfCertIssueExtensions(pub SequenceOf<CertIssueExtension>);
    #[doc = "*"]
    #[doc = " * @brief This field contains any CertRequestExtensions that apply to the"]
    #[doc = " * certificate holder. As specified in 5.2.4.2.3, each individual"]
    #[doc = " * CertRequestExtension type is associated with consistency conditions,"]
    #[doc = " * specific to that extension, that govern its consistency with"]
    #[doc = " * AppExtensions in certificates issued by the certificate holder and with"]
    #[doc = " * the CertRequestExtensions in the CA certificates in that certificate"]
    #[doc = " * holders chain. Those consistency conditions are specified for each"]
    #[doc = " * individual CertRequestExtension below."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("1.."))]
    pub struct SequenceOfCertRequestExtensions(pub SequenceOf<CertRequestExtension>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfCertificate(pub SequenceOf<Certificate>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfPsidGroupPermissions(pub SequenceOf<PsidGroupPermissions>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfRecipientInfo(pub SequenceOf<RecipientInfo>);
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param hashId: indicates the hash algorithm to be used to generate the hash"]
    #[doc = " * of the message for signing and verification."]
    #[doc = " *"]
    #[doc = " * @param tbsData: contains the data that is hashed as input to the signature."]
    #[doc = " *"]
    #[doc = " * @param signer: determines the keying material and hash algorithm used to"]
    #[doc = " * sign the data."]
    #[doc = " *"]
    #[doc = " * @param signature: contains the digital signature itself, calculated as"]
    #[doc = " * specified in 5.3.1."]
    #[doc = " *   - If signer indicates the choice self, then the signature calculation"]
    #[doc = " * is parameterized as follows:"]
    #[doc = " *     - Data input is equal to the COER encoding of the tbsData field"]
    #[doc = " * canonicalized according to the encoding considerations given in 6.3.6."]
    #[doc = " *     - Verification type is equal to self."]
    #[doc = " *     - Signer identifier input is equal to the empty string."]
    #[doc = " *   - If signer indicates certificate or digest, then the signature"]
    #[doc = " * calculation is parameterized as follows:"]
    #[doc = " *     - Data input is equal to the COER encoding of the tbsData field"]
    #[doc = " * canonicalized according to the encoding considerations given in 6.3.6."]
    #[doc = " *     - Verification type is equal to certificate."]
    #[doc = " *     - Signer identifier input equal to the COER-encoding of the"]
    #[doc = " * Certificate that is to be used to verify the SPDU, canonicalized according"]
    #[doc = " * to the encoding considerations given in 6.4.3."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to the ToBeSignedData and the Signature."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure contains the data payload of a ToBeSignedData. This"]
    #[doc = " * structure contains at least one of the optional elements, and may contain"]
    #[doc = " * more than one. See 5.2.4.3.4 for more details."]
    #[doc = " * The security profile in Annex C allows an implementation of this standard"]
    #[doc = " * to state which forms of SignedDataPayload are supported by that"]
    #[doc = " * implementation, and also how the signer and verifier are intended to obtain"]
    #[doc = " * the external data for hashing. The specification of an SDEE that uses"]
    #[doc = " * external data is expected to be explicit and unambiguous about how this"]
    #[doc = " * data is obtained and how it is formatted prior to processing by the hash"]
    #[doc = " * function."]
    #[doc = " *"]
    #[doc = " * @param data: contains data that is explicitly transported within the"]
    #[doc = " * structure."]
    #[doc = " *"]
    #[doc = " * @param extDataHash: contains the hash of data that is not explicitly"]
    #[doc = " * transported within the structure, and which the creator of the structure"]
    #[doc = " * wishes to cryptographically bind to the signature."]
    #[doc = " *"]
    #[doc = " * @param omitted: indicates that there is external data to be included in the"]
    #[doc = " * hash calculation for the signature.The mechanism for including the external"]
    #[doc = " * data in the hash calculation is specified in 6.3.6."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to the Ieee1609Dot2Data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct SignedDataPayload {
        pub data: Option<alloc::boxed::Box<Ieee1609Dot2Data>>,
        #[rasn(identifier = "extDataHash")]
        pub ext_data_hash: Option<HashedData>,
        #[rasn(extension_addition)]
        pub omitted: Option<()>,
    }
    impl SignedDataPayload {
        pub fn new(
            data: Option<alloc::boxed::Box<Ieee1609Dot2Data>>,
            ext_data_hash: Option<HashedData>,
            omitted: Option<()>,
        ) -> Self {
            Self {
                data,
                ext_data_hash,
                omitted,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure allows the recipient of data to determine which"]
    #[doc = " * keying material to use to authenticate the data. It also indicates the"]
    #[doc = " * verification type to be used to generate the hash for verification, as"]
    #[doc = " * specified in 5.3.1."]
    #[doc = " *"]
    #[doc = " * @param digest: If the choice indicated is digest:"]
    #[doc = " *   - The structure contains the HashedId8 of the relevant certificate. The"]
    #[doc = " * HashedId8 is calculated with the whole-certificate hash algorithm,"]
    #[doc = " * determined as described in 6.4.3."]
    #[doc = " *   - The verification type is certificate and the certificate data"]
    #[doc = " * passed to the hash function as specified in 5.3.1 is the authorization"]
    #[doc = " * certificate."]
    #[doc = " *"]
    #[doc = " * @param certificate: If the choice indicated is certificate:"]
    #[doc = " *   - The structure contains one or more Certificate structures, in order"]
    #[doc = " * such that the first certificate is the authorization certificate and each"]
    #[doc = " * subsequent certificate is the issuer of the one before it."]
    #[doc = " *   - The verification type is certificate and the certificate data"]
    #[doc = " * passed to the hash function as specified in 5.3.1 is the authorization"]
    #[doc = " * certificate."]
    #[doc = " *"]
    #[doc = " * @param self: If the choice indicated is self:"]
    #[doc = " *   - The structure does not contain any data beyond the indication that"]
    #[doc = " * the choice value is self."]
    #[doc = " *   - The verification type is self-signed."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the CHOICE value for this type"]
    #[doc = " * when verifying a signed SPDU shall indicate that the signed SPDU is invalid."]
    #[doc = " *   - If present, certificate is a critical information field as defined in"]
    #[doc = " * 5.2.6. An implementation that does not support the number of certificates"]
    #[doc = " * in certificate when verifying a signed SPDU shall indicate that the signed"]
    #[doc = " * SPDU is invalid. A compliant implementation shall support certificate"]
    #[doc = " * fields containing at least one certificate."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to every Certificate in the certificate field."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SignerIdentifier {
        digest(HashedId8),
        certificate(SequenceOfCertificate),
        #[rasn(identifier = "self")]
        R_self(()),
    }
    #[doc = "*"]
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
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the indicated CHOICE when"]
    #[doc = " * verifying a signed SPDU shall indicate that the signed SPDU is"]
    #[doc = " * invalidin the sense of 4.2.2.3.2, that is, it is invalid in the sense that"]
    #[doc = " * its validity cannot be established."]
    #[doc = " *   - If present, explicit is a critical information field as defined in"]
    #[doc = " * 5.2.6. An implementation that does not support the number of PsidSspRange"]
    #[doc = " * in explicit when verifying a signed SPDU shall indicate that the signed"]
    #[doc = " * SPDU is invalid in the sense of 4.2.2.3.2, that is, it is invalid in the"]
    #[doc = " * sense that its validity cannot be established. A conformant implementation"]
    #[doc = " * shall support explicit fields containing at least eight entries."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SubjectPermissions {
        explicit(SequenceOfPsidSspRange),
        all(()),
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure contains the following fields:"]
    #[doc = " *"]
    #[doc = " * @param recipientId: contains the hash of the symmetric key encryption key"]
    #[doc = " * that may be used to decrypt the data encryption key. It consists of the"]
    #[doc = " * low-order 8 bytes of the hash of the COER encoding of a"]
    #[doc = " * SymmetricEncryptionKey structure containing the symmetric key in question."]
    #[doc = " * The HashedId8 is calculated with the hash algorithm determined as"]
    #[doc = " * specified in 5.3.9.4. The symmetric key may be established by any"]
    #[doc = " * appropriate means agreed by the two parties to the exchange."]
    #[doc = " *"]
    #[doc = " * @param encKey: contains the encrypted data encryption key within a"]
    #[doc = " * SymmetricCiphertext, where the data encryption key is input to the data"]
    #[doc = " * encryption key encryption process with no headers, encapsulation, or"]
    #[doc = " * length indication."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This data structure encapsulates a ciphertext generated with an"]
    #[doc = " * approved symmetric algorithm."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE value for this type in an encrypted SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2,"]
    #[doc = " * that is, it is invalid in the sense that its validity cannot be established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SymmetricCiphertext {
        aes128ccm(One28BitCcmCiphertext),
        #[rasn(extension_addition)]
        sm4Ccm(One28BitCcmCiphertext),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct TestCertificate(pub Certificate);
    #[doc = "*"]
    #[doc = " * @brief The fields in the ToBeSignedCertificate structure have the"]
    #[doc = " * following meaning:"]
    #[doc = " *"]
    #[doc = " * For both implicit and explicit certificates, when the certificate"]
    #[doc = " * is hashed to create or recover the public key (in the case of an implicit"]
    #[doc = " * certificate) or to generate or verify the signature (in the case of an"]
    #[doc = " * explicit certificate), the hash is Hash (Data input) || Hash ("]
    #[doc = " * Signer identifier input), where:"]
    #[doc = " *   - Data input is the COER encoding of toBeSigned, canonicalized"]
    #[doc = " * as described above."]
    #[doc = " *   - Signer identifier input depends on the verification type,"]
    #[doc = " * which in turn depends on the choice indicated by issuer. If the choice"]
    #[doc = " * indicated by issuer is self, the verification type is self-signed and the"]
    #[doc = " * signer identifier input is the empty string. If the choice indicated by"]
    #[doc = " * issuer is not self, the verification type is certificate and the signer"]
    #[doc = " * identifier input is the COER encoding of the canonicalization per 6.4.3 of"]
    #[doc = " * the certificate indicated by issuer."]
    #[doc = " *"]
    #[doc = " * In other words, for implicit certificates, the value H (CertU) in SEC 4,"]
    #[doc = " * section 3, is for purposes of this standard taken to be H [H"]
    #[doc = " * (canonicalized ToBeSignedCertificate from the subordinate certificate) ||"]
    #[doc = " * H (entirety of issuer Certificate)]. See 5.3.2 for further discussion,"]
    #[doc = " * including material differences between this standard and SEC 4 regarding"]
    #[doc = " * how the hash function output is converted from a bit string to an integer."]
    #[doc = " *"]
    #[doc = " * @param id: contains information that is used to identify the certificate"]
    #[doc = " * holder if necessary."]
    #[doc = " *"]
    #[doc = " * @param cracaId: identifies the Certificate Revocation Authorization CA"]
    #[doc = " * (CRACA) responsible for certificate revocation lists (CRLs) on which this"]
    #[doc = " * certificate might appear. Use of the cracaId is specified in 5.1.3. The"]
    #[doc = " * HashedId3 is calculated with the whole-certificate hash algorithm,"]
    #[doc = " * determined as described in 6.4.3, applied to the COER-encoded certificate,"]
    #[doc = " * canonicalized as defined in the definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @param crlSeries: represents the CRL series relevant to a particular"]
    #[doc = " * Certificate Revocation Authorization CA (CRACA) on which the certificate"]
    #[doc = " * might appear. Use of this field is specified in 5.1.3."]
    #[doc = " *"]
    #[doc = " * @param validityPeriod: contains the validity period of the certificate."]
    #[doc = " *"]
    #[doc = " * @param region: if present, indicates the validity region of the"]
    #[doc = " * certificate. If it is omitted the validity region is indicated as follows:"]
    #[doc = " *   - If enclosing certificate is self-signed, i.e., the choice indicated"]
    #[doc = " * by the issuer field in the enclosing certificate structure is self, the"]
    #[doc = " * certificate is valid worldwide."]
    #[doc = " *   - Otherwise, the certificate has the same validity region as the"]
    #[doc = " * certificate that issued it."]
    #[doc = " *"]
    #[doc = " * @param assuranceLevel: indicates the assurance level of the certificate"]
    #[doc = " * holder."]
    #[doc = " *"]
    #[doc = " * @param appPermissions: indicates the permissions that the certificate"]
    #[doc = " * holder has to sign application data with this certificate. A valid"]
    #[doc = " * instance of appPermissions contains any particular Psid value in at most"]
    #[doc = " * one entry."]
    #[doc = " *"]
    #[doc = " * @param certIssuePermissions: indicates the permissions that the certificate"]
    #[doc = " * holder has to sign certificates with this certificate. A valid instance of"]
    #[doc = " * this array contains no more than one entry whose psidSspRange field"]
    #[doc = " * indicates all. If the array has multiple entries and one entry has its"]
    #[doc = " * psidSspRange field indicate all, then the entry indicating all specifies"]
    #[doc = " * the permissions for all PSIDs other than the ones explicitly specified in"]
    #[doc = " * the other entries. See the description of PsidGroupPermissions for further"]
    #[doc = " * discussion."]
    #[doc = " *"]
    #[doc = " * @param certRequestPermissions: indicates the permissions that the"]
    #[doc = " * certificate holder can request in its certificate. A valid instance of this"]
    #[doc = " * array contains no more than one entry whose psidSspRange field indicates"]
    #[doc = " * all. If the array has multiple entries and one entry has its psidSspRange"]
    #[doc = " * field indicate all, then the entry indicating all specifies the permissions"]
    #[doc = " * for all PSIDs other than the ones explicitly specified in the other entries."]
    #[doc = " * See the description of PsidGroupPermissions for further discussion."]
    #[doc = " *"]
    #[doc = " * @param canRequestRollover: indicates that the certificate may be used to"]
    #[doc = " * sign a request for another certificate with the same permissions. This"]
    #[doc = " * field is provided for future use and its use is not defined in this"]
    #[doc = " * version of this standard."]
    #[doc = " *"]
    #[doc = " * @param encryptionKey: contains a public key for encryption for which the"]
    #[doc = " * certificate holder holds the corresponding private key."]
    #[doc = " *"]
    #[doc = " * @param verifyKeyIndicator: contains material that may be used to recover"]
    #[doc = " * the public key that may be used to verify data signed by this certificate."]
    #[doc = " *"]
    #[doc = " * @param flags: indicates additional yes/no properties of the certificate"]
    #[doc = " * holder. The only bit with defined semantics in this string in this version"]
    #[doc = " * of this standard is usesCubk. If set, the usesCubk bit indicates that the"]
    #[doc = " * certificate holder supports the compact unified butterfly key response."]
    #[doc = " * Further material about the compact unified butterfly key response can be"]
    #[doc = " * found in IEEE Std 1609.2.1."]
    #[doc = " *"]
    #[doc = " * @note usesCubk is only relevant for CA certificates, and the only"]
    #[doc = " * functionality defined associated with this field is associated with"]
    #[doc = " * consistency checks on received certificate responses. No functionality"]
    #[doc = " * associated with communications between peer SDEEs is defined associated"]
    #[doc = " * with this field."]
    #[doc = " *"]
    #[doc = " * @param appExtensions: indicates additional permissions that may be applied"]
    #[doc = " * to application activities that the certificate holder is carrying out."]
    #[doc = " *"]
    #[doc = " * @param certIssueExtensions: indicates additional permissions to issue"]
    #[doc = " * certificates containing endEntityExtensions."]
    #[doc = " *"]
    #[doc = " * @param certRequestExtensions: indicates additional permissions to request"]
    #[doc = " * certificates containing endEntityExtensions."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to the PublicEncryptionKey and to the VerificationKeyIndicator."]
    #[doc = " *"]
    #[doc = " * If the PublicEncryptionKey contains a BasePublicEncryptionKey that is an"]
    #[doc = " * elliptic curve point (i.e., of type EccP256CurvePoint or EccP384CurvePoint),"]
    #[doc = " * then the elliptic curve point is encoded in compressed form, i.e., such"]
    #[doc = " * that the choice indicated within the Ecc*CurvePoint is compressed-y-0 or"]
    #[doc = " * compressed-y-1."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, appPermissions is a critical information field as defined"]
    #[doc = " * in 5.2.6. If an implementation of verification does not support the number"]
    #[doc = " * of PsidSsp in the appPermissions field of a certificate that signed a"]
    #[doc = " * signed SPDU, that implementation shall indicate that the signed SPDU is"]
    #[doc = " * invalid in the sense of 4.2.2.3.2, that is, it is invalid in the sense"]
    #[doc = " * that its validity cannot be established.. A conformant implementation"]
    #[doc = " * shall support appPermissions fields containing at least eight entries."]
    #[doc = " * It may be the case that an implementation of verification does not support"]
    #[doc = " * the number of entries in  the appPermissions field and the appPermissions"]
    #[doc = " * field is not relevant to the verification: this will occur, for example,"]
    #[doc = " * if the certificate in question is a CA certificate and so the"]
    #[doc = " * certIssuePermissions field is relevant to the verification and the"]
    #[doc = " * appPermissions field is not. In this case, whether the implementation"]
    #[doc = " * indicates that the signed SPDU is valid (because it could validate all"]
    #[doc = " * relevant fields) or invalid (because it could not parse the entire"]
    #[doc = " * certificate) is implementation-specific."]
    #[doc = " *   - If present, certIssuePermissions is a critical information field as"]
    #[doc = " * defined in 5.2.6. If an implementation of verification does not support"]
    #[doc = " * the number of PsidGroupPermissions in the certIssuePermissions field of a"]
    #[doc = " * CA certificate in the chain of a signed SPDU, the implementation shall"]
    #[doc = " * indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, that"]
    #[doc = " * is, it is invalid in the sense that its validity cannot be established."]
    #[doc = " * A conformant implementation shall support certIssuePermissions fields"]
    #[doc = " * containing at least eight entries."]
    #[doc = " * It may be the case that an implementation of verification does not support"]
    #[doc = " * the number of entries in  the certIssuePermissions field and the"]
    #[doc = " * certIssuePermissions field is not relevant to the verification: this will"]
    #[doc = " * occur, for example, if the certificate in question is the signing"]
    #[doc = " * certificate for the SPDU and so the appPermissions field is relevant to"]
    #[doc = " * the verification and the certIssuePermissions field is not. In this case,"]
    #[doc = " * whether the implementation indicates that the signed SPDU is valid"]
    #[doc = " * (because it could validate all relevant fields) or invalid (because it"]
    #[doc = " * could not parse the entire certificate) is implementation-specific."]
    #[doc = " *   - If present, certRequestPermissions is a critical information field as"]
    #[doc = " * defined in 5.2.6. If an implementaiton of verification of a certificate"]
    #[doc = " * request does not support the number of PsidGroupPermissions in"]
    #[doc = " * certRequestPermissions, the implementation shall indicate that the signed"]
    #[doc = " * SPDU is invalid in the sense of 4.2.2.3.2, that is, it is invalid in the"]
    #[doc = " * sense that its validity cannot be established. A conformant implementation"]
    #[doc = " * shall support certRequestPermissions fields containing at least eight"]
    #[doc = " * entries."]
    #[doc = " * It may be the case that an implementation of verification does not support"]
    #[doc = " * the number of entries in  the certRequestPermissions field and the"]
    #[doc = " * certRequestPermissions field is not relevant to the verification: this will"]
    #[doc = " * occur, for example, if the certificate in question is the signing"]
    #[doc = " * certificate for the SPDU and so the appPermissions field is relevant to"]
    #[doc = " * the verification and the certRequestPermissions field is not. In this"]
    #[doc = " * case, whether the implementation indicates that the signed SPDU is valid"]
    #[doc = " * (because it could validate all relevant fields) or invalid (because it"]
    #[doc = " * could not parse the entire certificate) is implementation-specific."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
        #[rasn(extension_addition, identifier = "appExtensions")]
        pub app_extensions: SequenceOfAppExtensions,
        #[rasn(extension_addition, identifier = "certIssueExtensions")]
        pub cert_issue_extensions: SequenceOfCertIssueExtensions,
        #[rasn(extension_addition, identifier = "certRequestExtension")]
        pub cert_request_extension: SequenceOfCertRequestExtensions,
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
            app_extensions: SequenceOfAppExtensions,
            cert_issue_extensions: SequenceOfCertIssueExtensions,
            cert_request_extension: SequenceOfCertRequestExtensions,
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
                app_extensions,
                cert_issue_extensions,
                cert_request_extension,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains the data to be hashed when generating or"]
    #[doc = " * verifying a signature. See 6.3.4 for the specification of the input to the"]
    #[doc = " * hash."]
    #[doc = " *"]
    #[doc = " * @param payload: contains data that is provided by the entity that invokes"]
    #[doc = " * the SDS."]
    #[doc = " *"]
    #[doc = " * @param headerInfo: contains additional data that is inserted by the SDS."]
    #[doc = " * This structure is used as follows to determine the \"data input\" to the"]
    #[doc = " * hash operation for signing or verification as specified in 5.3.1.2.2 or"]
    #[doc = " * 5.3.1.3."]
    #[doc = " *   - If payload does not contain the field omitted, the data input to the"]
    #[doc = " * hash operation is the COER encoding of the ToBeSignedData."]
    #[doc = " *   - If payload field in this ToBeSignedData instance contains the field"]
    #[doc = " * omitted, the data input to the hash operation is the COER encoding of the"]
    #[doc = " * ToBeSignedData, concatenated with the hash of the omitted payload. The hash"]
    #[doc = " * of the omitted payload is calculated with the same hash algorithm that is"]
    #[doc = " * used to calculate the hash of the data input for signing or verification."]
    #[doc = " * The data input to the hash operation is simply the COER enocding of the"]
    #[doc = " * ToBeSignedData, concatenated with the hash of the omitted payload: there is"]
    #[doc = " * no additional wrapping or length indication. As noted in 5.2.4.3.4, the"]
    #[doc = " * means by which the signer and verifier establish the contents of the"]
    #[doc = " * omitted payload are out of scope for this standard."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to the SignedDataPayload if it is of type data, and to the"]
    #[doc = " * HeaderInfo."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief The contents of this field depend on whether the certificate is an"]
    #[doc = " * implicit or an explicit certificate."]
    #[doc = " *"]
    #[doc = " * @param verificationKey: is included in explicit certificates. It contains"]
    #[doc = " * the public key to be used to verify signatures generated by the holder of"]
    #[doc = " * the Certificate."]
    #[doc = " *"]
    #[doc = " * @param reconstructionValue: is included in implicit certificates. It"]
    #[doc = " * contains the reconstruction value, which is used to recover the public key"]
    #[doc = " * as specified in SEC 4 and 5.3.2."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid indicate that the signed"]
    #[doc = " * SPDU is invalid in the sense of 4.2.2.3.2, that is, it is invalid in the"]
    #[doc = " * sense that its validity cannot be established."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to the PublicVerificationKey and to the EccP256CurvePoint. The"]
    #[doc = " * EccP256CurvePoint is encoded in compressed form, i.e., such that the"]
    #[doc = " * choice indicated within the EccP256CurvePoint is compressed-y-0 or"]
    #[doc = " * compressed-y-1."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum VerificationKeyIndicator {
        verificationKey(PublicVerificationKey),
        reconstructionValue(EccP256CurvePoint),
    }
    pub const CERT_EXT_ID__OPERATING_ORGANIZATION: ExtId = ExtId(1);
    pub const ETSI_HEADER_INFO_CONTRIBUTOR_ID: HeaderInfoContributorId = HeaderInfoContributorId(2);
    pub const IEEE1609_HEADER_INFO_CONTRIBUTOR_ID: HeaderInfoContributorId =
        HeaderInfoContributorId(1);
    pub const ISO21177_EXTENDED_AUTH: PduFunctionalType = PduFunctionalType(2);
    pub const ISO21177_SESSION_EXTENSION: PduFunctionalType = PduFunctionalType(3);
    pub const P2PCD8_BYTE_LEARNING_REQUEST_ID: Ieee1609HeaderInfoExtensionId =
        Ieee1609HeaderInfoExtensionId(ExtId(1));
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
    #[doc = " * @brief This structure specifies the bytes of a public encryption key for"]
    #[doc = " * a particular algorithm. Supported public key encryption algorithms are"]
    #[doc = " * defined in 5.3.5."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2 if it appears in a"]
    #[doc = " * HeaderInfo or in a ToBeSignedCertificate. See the definitions of HeaderInfo"]
    #[doc = " * and ToBeSignedCertificate for a specification of the canonicalization"]
    #[doc = " * operations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum BasePublicEncryptionKey {
        eciesNistP256(EccP256CurvePoint),
        eciesBrainpoolP256r1(EccP256CurvePoint),
        #[rasn(extension_addition)]
        ecencSm2(EccP256CurvePoint),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure represents a bitmap representation of a SSP. The"]
    #[doc = " * mapping of the bits of the bitmap to constraints on the signed SPDU is"]
    #[doc = " * PSID-specific."]
    #[doc = " *"]
    #[doc = " * @note Consistency with issuing certificate: If a certificate has an"]
    #[doc = " * appPermissions entry A for which the ssp field is bitmapSsp, A is"]
    #[doc = " * consistent with the issuing certificate if the  certificate contains one"]
    #[doc = " * of the following:"]
    #[doc = " *   - (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;"]
    #[doc = " *   - (OPTION 2) A PsidSspRange P for which the following holds:"]
    #[doc = " *     - The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:"]
    #[doc = " *       - EITHER The sspRange field in P indicates all"]
    #[doc = " *       - OR The sspRange field in P indicates bitmapSspRange and for every"]
    #[doc = " * bit set to 1 in the sspBitmask in P, the bit in the identical position in"]
    #[doc = " * the sspValue in A is set equal to the bit in that position in the"]
    #[doc = " * sspValue in P."]
    #[doc = " *"]
    #[doc = " * @note A BitmapSsp B is consistent with a BitmapSspRange R if for every"]
    #[doc = " * bit set to 1 in the sspBitmask in R, the bit in the identical position in"]
    #[doc = " * B is set equal to the bit in that position in the sspValue in R. For each"]
    #[doc = " * bit set to 0 in the sspBitmask in R, the corresponding bit in the"]
    #[doc = " * identical position in B may be freely set to 0 or 1, i.e., if a bit is"]
    #[doc = " * set to 0 in the sspBitmask in R, the value of corresponding bit in the"]
    #[doc = " * identical position in B has no bearing on whether B and R are consistent."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("0..=31"))]
    pub struct BitmapSsp(pub OctetString);
    #[doc = "*"]
    #[doc = " * @brief This structure represents a bitmap representation of a SSP. The"]
    #[doc = " * sspValue indicates permissions. The sspBitmask contains an octet string"]
    #[doc = " * used to permit or constrain sspValue fields in issued certificates. The"]
    #[doc = " * sspValue and sspBitmask fields shall be of the same length."]
    #[doc = " *"]
    #[doc = " * @note Consistency with issuing certificate: If a certificate has an"]
    #[doc = " * PsidSspRange value P for which the sspRange field is bitmapSspRange,"]
    #[doc = " * P is consistent with the issuing certificate if the issuing certificate"]
    #[doc = " * contains one of the following:"]
    #[doc = " *   - (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in P;"]
    #[doc = " *   - (OPTION 2) A PsidSspRange R for which the following holds:"]
    #[doc = " *     - The psid field in R is equal to the psid field in P and one of the"]
    #[doc = " * following is true:"]
    #[doc = " *       - EITHER The sspRange field in R indicates all"]
    #[doc = " *       - OR The sspRange field in R indicates bitmapSspRange and for every"]
    #[doc = " * bit set to 1 in the sspBitmask in R:"]
    #[doc = " *         - The bit in the identical position in the sspBitmask in P is set"]
    #[doc = " * equal to 1, AND"]
    #[doc = " *         - The bit in the identical position in the sspValue in P is set equal"]
    #[doc = " * to the bit in that position in the sspValue in R."]
    #[doc = " *"]
    #[doc = " * Reference ETSI TS 103 097 for more information on bitmask SSPs."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure specifies a circle with its center at center, its"]
    #[doc = " * radius given in meters, and located tangential to the reference ellipsoid."]
    #[doc = " * The indicated region is all the points on the surface of the reference"]
    #[doc = " * ellipsoid whose distance to the center point over the reference ellipsoid"]
    #[doc = " * is less than or equal to the radius. A point which contains an elevation"]
    #[doc = " * component is considered to be within the circular region if its horizontal"]
    #[doc = " * projection onto the reference ellipsoid lies within the region."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief A conformant implementation that supports CountryAndRegions shall"]
    #[doc = " * support a regions field containing at least eight entries."]
    #[doc = " * A conformant implementation that implements this type shall recognize"]
    #[doc = " * (in the sense of \"be able to determine whether a two dimensional location"]
    #[doc = " * lies inside or outside the borders identified by\") at least one value of"]
    #[doc = " * UnCountryId and at least one value for a region within the country"]
    #[doc = " * indicated by that recognized UnCountryId value. In this version of this"]
    #[doc = " * standard, the only means to satisfy this is for a conformant"]
    #[doc = " * implementation to recognize the value of UnCountryId indicating USA and"]
    #[doc = " * at least one of the FIPS state codes for US states. The Protocol"]
    #[doc = " * Implementation Conformance Statement (PICS) provided in Annex A allows"]
    #[doc = " * an implementation to state which UnCountryId values it recognizes and"]
    #[doc = " * which region values are recognized within that country."]
    #[doc = " * If a verifying implementation is required to check that an relevant"]
    #[doc = " * geographic information in a signed SPDU is consistent with a certificate"]
    #[doc = " * containing one or more instances of this type, then the SDS is permitted"]
    #[doc = " * to indicate that the signed SPDU is valid even if some values of country"]
    #[doc = " * or within regions are unrecognized in the sense defined above, so long"]
    #[doc = " * as the recognized instances of this type completely contain the relevant"]
    #[doc = " * geographic information. Informally, if the recognized values in the"]
    #[doc = " * certificate allow the SDS to determine that the SPDU is valid, then it"]
    #[doc = " * can make that determination even if there are also unrecognized values"]
    #[doc = " * in the certificate. This field is therefore not a \"critical information"]
    #[doc = " * field\" as defined in 5.2.6, because unrecognized values are permitted so"]
    #[doc = " * long as the validity of the SPDU can be established with the recognized"]
    #[doc = " * values. However, as discussed in 5.2.6, the presence of an unrecognized"]
    #[doc = " * value in a certificate can make it impossible to determine whether the"]
    #[doc = " * certificate is valid and so whether the SPDU is valid."]
    #[doc = " * In this type:"]
    #[doc = " *"]
    #[doc = " * @param countryOnly: is a UnCountryId as defined above."]
    #[doc = " *"]
    #[doc = " * @param regions: identifies one or more regions within the country. If"]
    #[doc = " * country indicates the United States of America, the values in this field"]
    #[doc = " * identify the state or statistically equivalent entity using the integer"]
    #[doc = " * version of the 2010 FIPS codes as provided by the U.S. Census Bureau"]
    #[doc = " * (see normative references in Clause 0). For other values of country, the"]
    #[doc = " * meaning of region is not defined in this version of this standard."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct CountryAndRegions {
        #[rasn(identifier = "countryOnly")]
        pub country_only: UnCountryId,
        pub regions: SequenceOfUint8,
    }
    impl CountryAndRegions {
        pub fn new(country_only: UnCountryId, regions: SequenceOfUint8) -> Self {
            Self {
                country_only,
                regions,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief A conformant implementation that supports CountryAndSubregions"]
    #[doc = " * shall support a regionAndSubregions field containing at least eight"]
    #[doc = " * entries."]
    #[doc = " * A conformant implementation that implements this type shall recognize"]
    #[doc = " * (in the sense of be able to determine whether a two dimensional location"]
    #[doc = " * lies inside or outside the borders identified by) at least one value of"]
    #[doc = " * country and at least one value for a region within the country indicated"]
    #[doc = " * by that recognized country value. In this version of this standard, the"]
    #[doc = " * only means to satisfy this is for a conformant implementation to recognize"]
    #[doc = " * the value of UnCountryId indicating USA and at least one of the FIPS state"]
    #[doc = " * codes for US states. The Protocol Implementation Conformance Statement"]
    #[doc = " * (PICS) provided in Annex A allows an implementation to state which"]
    #[doc = " * UnCountryId values it recognizes and which region values are recognized"]
    #[doc = " * within that country."]
    #[doc = " * If a verifying implementation is required to check that an relevant"]
    #[doc = " * geographic information in a signed SPDU is consistent with a certificate"]
    #[doc = " * containing one or more instances of this type, then the SDS is permitted"]
    #[doc = " * to indicate that the signed SPDU is valid even if some values of country"]
    #[doc = " * or within regionAndSubregions are unrecognized in the sense defined above,"]
    #[doc = " * so long as the recognized instances of this type completely contain the"]
    #[doc = " * relevant geographic information. Informally, if the recognized values in"]
    #[doc = " * the certificate allow the SDS to determine that the SPDU is valid, then"]
    #[doc = " * it can make that determination even if there are also unrecognized values"]
    #[doc = " * in the certificate. This field is therefore not a \"critical information"]
    #[doc = " * field\" as defined in 5.2.6, because unrecognized values are permitted so"]
    #[doc = " * long as the validity of the SPDU can be established with the recognized"]
    #[doc = " * values. However, as discussed in 5.2.6, the presence of an unrecognized"]
    #[doc = " * value in a certificate can make it impossible to determine whether the"]
    #[doc = " * certificate is valid and so whether the SPDU is valid."]
    #[doc = " * In this structure:"]
    #[doc = " *"]
    #[doc = " * @param countryOnly: is a UnCountryId as defined above."]
    #[doc = " *"]
    #[doc = " * @param regionAndSubregions: identifies one or more subregions within"]
    #[doc = " * country."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct CountryAndSubregions {
        #[rasn(identifier = "countryOnly")]
        pub country_only: UnCountryId,
        #[rasn(identifier = "regionAndSubregions")]
        pub region_and_subregions: SequenceOfRegionAndSubregions,
    }
    impl CountryAndSubregions {
        pub fn new(
            country_only: UnCountryId,
            region_and_subregions: SequenceOfRegionAndSubregions,
        ) -> Self {
            Self {
                country_only,
                region_and_subregions,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This type is defined only for backwards compatibility."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CountryOnly(pub UnCountryId);
    #[doc = "*"]
    #[doc = " * @brief This integer identifies a series of CRLs issued under the authority"]
    #[doc = " * of a particular CRACA."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CrlSeries(pub Uint16);
    #[doc = "*"]
    #[doc = " * @brief This structure represents the duration of validity of a"]
    #[doc = " * certificate. The Uint16 value is the duration, given in the units denoted"]
    #[doc = " * by the indicated choice. A year is considered to be 31556952 seconds,"]
    #[doc = " * which is the average number of seconds in a year."]
    #[doc = " *"]
    #[doc = " * @note Years can be mapped more closely to wall-clock days using the hours"]
    #[doc = " * choice for up to 7 years and the sixtyHours choice for up to 448 years."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure specifies a point on an elliptic curve in Weierstrass"]
    #[doc = " * form defined over a 256-bit prime number. The curves supported in this"]
    #[doc = " * standard are NIST p256 as defined in FIPS 186-4, Brainpool p256r1 as"]
    #[doc = " * defined in RFC 5639, and the SM2 curve as defined in GB/T 32918.5-2017."]
    #[doc = " * The fields in this structure are OCTET STRINGS produced with the elliptic"]
    #[doc = " * curve point encoding and decoding methods defined in subclause 5.5.6 of"]
    #[doc = " * IEEE Std 1363-2000. The x-coordinate is encoded as an unsigned integer of"]
    #[doc = " * length 32 octets in network byte order for all values of the CHOICE; the"]
    #[doc = " * encoding of the y-coordinate y depends on whether the point is x-only,"]
    #[doc = " * compressed, or uncompressed. If the point is x-only, y is omitted. If the"]
    #[doc = " * point is compressed, the value of type depends on the least significant"]
    #[doc = " * bit of y: if the least significant bit of y is 0, type takes the value"]
    #[doc = " * compressed-y-0, and if the least significant bit of y is 1, type takes the"]
    #[doc = " * value compressed-y-1. If the point is uncompressed, y is encoded explicitly"]
    #[doc = " * as an unsigned integer of length 32 octets in network byte order."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2 if it appears in a"]
    #[doc = " * HeaderInfo or in a ToBeSignedCertificate. See the definitions of HeaderInfo"]
    #[doc = " * and ToBeSignedCertificate for a specification of the canonicalization"]
    #[doc = " * operations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure specifies a point on an elliptic curve in"]
    #[doc = " * Weierstrass form defined over a 384-bit prime number. The only supported"]
    #[doc = " * such curve in this standard is Brainpool p384r1 as defined in RFC 5639."]
    #[doc = " * The fields in this structure are octet strings produced with the elliptic"]
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
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2 if it appears in a"]
    #[doc = " * HeaderInfo or in a ToBeSignedCertificate. See the definitions of HeaderInfo"]
    #[doc = " * and ToBeSignedCertificate for a specification of the canonicalization"]
    #[doc = " * operations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure represents an ECDSA signature. The signature is"]
    #[doc = " * generated as specified in 5.3.1."]
    #[doc = " *"]
    #[doc = " * If the signature process followed the specification of FIPS 186-4"]
    #[doc = " * and output the integer r, r is represented as an EccP256CurvePoint"]
    #[doc = " * indicating the selection x-only."]
    #[doc = " *"]
    #[doc = " * If the signature process followed the specification of SEC 1 and"]
    #[doc = " * output the elliptic curve point R to allow for fast verification, R is"]
    #[doc = " * represented as an EccP256CurvePoint indicating the choice compressed-y-0,"]
    #[doc = " * compressed-y-1, or uncompressed at the sender's discretion."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. When this data structure"]
    #[doc = " * is canonicalized, the EccP256CurvePoint in rSig is represented in the"]
    #[doc = " * form x-only."]
    #[doc = " *"]
    #[doc = " * @note When the signature is of form x-only, the x-value in rSig is"]
    #[doc = " * an integer mod n, the order of the group; when the signature is of form"]
    #[doc = " * compressed-y-\\*, the x-value in rSig is an integer mod p, the underlying"]
    #[doc = " * prime defining the finite field. In principle this means that to convert a"]
    #[doc = " * signature from form compressed-y-\\* to form x-only, the converter checks"]
    #[doc = " * the x-value to see if it lies between n and p and reduces it mod n if so."]
    #[doc = " * In practice this check is unnecessary: Haase's Theorem states that"]
    #[doc = " * difference between n and p is always less than 2*square-root(p), and so the"]
    #[doc = " * chance that an integer lies between n and p, for a 256-bit curve, is"]
    #[doc = " * bounded above by approximately square-root(p)/p or 2^(-128). For the"]
    #[doc = " * 256-bit curves in this standard, the exact values of n and p in hexadecimal"]
    #[doc = " * are:"]
    #[doc = " *"]
    #[doc = " * NISTp256:"]
    #[doc = " *   - p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"]
    #[doc = " *   - n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"]
    #[doc = " *"]
    #[doc = " * Brainpoolp256:"]
    #[doc = " *   - p = A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"]
    #[doc = " *   - n = A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure represents an ECDSA signature. The signature is"]
    #[doc = " * generated as specified in 5.3.1."]
    #[doc = " *"]
    #[doc = " * If the signature process followed the specification of FIPS 186-4"]
    #[doc = " * and output the integer r, r is represented as an EccP384CurvePoint"]
    #[doc = " * indicating the selection x-only."]
    #[doc = " *"]
    #[doc = " * If the signature process followed the specification of SEC 1 and"]
    #[doc = " * output the elliptic curve point R to allow for fast verification, R is"]
    #[doc = " * represented as an EccP384CurvePoint indicating the choice compressed-y-0,"]
    #[doc = " * compressed-y-1, or uncompressed at the sender's discretion."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. When this data structure"]
    #[doc = " * is canonicalized, the EccP384CurvePoint in rSig is represented in the"]
    #[doc = " * form x-only."]
    #[doc = " *"]
    #[doc = " * @note When the signature is of form x-only, the x-value in rSig is"]
    #[doc = " * an integer mod n, the order of the group; when the signature is of form"]
    #[doc = " * compressed-y-\\*, the x-value in rSig is an integer mod p, the underlying"]
    #[doc = " * prime defining the finite field. In principle this means that to convert a"]
    #[doc = " * signature from form compressed-y-* to form x-only, the converter checks the"]
    #[doc = " * x-value to see if it lies between n and p and reduces it mod n if so. In"]
    #[doc = " * practice this check is unnecessary: Haase's Theorem states that difference"]
    #[doc = " * between n and p is always less than 2*square-root(p), and so the chance"]
    #[doc = " * that an integer lies between n and p, for a 384-bit curve, is bounded"]
    #[doc = " * above by approximately square-root(p)/p or 2^(-192). For the 384-bit curve"]
    #[doc = " * in this standard, the exact values of n and p in hexadecimal are:"]
    #[doc = " *   - p = 8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123"]
    #[doc = " * ACD3A729901D1A71874700133107EC53"]
    #[doc = " *   - n = 8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7"]
    #[doc = " * CF3AB6AF6B7FC3103B883202E9046565"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This data structure is used to transfer a 16-byte symmetric key"]
    #[doc = " * encrypted using SM2 encryption as specified in 5.3.3. The symmetric key is"]
    #[doc = " * input to the key encryption process with no headers, encapsulation, or"]
    #[doc = " * length indication. Encryption and decryption are carried out as specified"]
    #[doc = " * in 5.3.5.2."]
    #[doc = " *"]
    #[doc = " * @param v: is the sender's ephemeral public key, which is the output V from"]
    #[doc = " * encryption as specified in 5.3.5.2."]
    #[doc = " *"]
    #[doc = " * @param c: is the encrypted symmetric key, which is the output C from"]
    #[doc = " * encryption as specified in 5.3.5.2. The algorithm for the symmetric key"]
    #[doc = " * is identified by the CHOICE indicated in the following SymmetricCiphertext."]
    #[doc = " * For SM2 this algorithm shall be SM4."]
    #[doc = " *"]
    #[doc = " * @param t: is the authentication tag, which is the output tag from"]
    #[doc = " * encryption as specified in 5.3.5.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct EcencP256EncryptedKey {
        pub v: EccP256CurvePoint,
        pub c: FixedOctetString<16>,
        pub t: FixedOctetString<32>,
    }
    impl EcencP256EncryptedKey {
        pub fn new(v: EccP256CurvePoint, c: FixedOctetString<16>, t: FixedOctetString<32>) -> Self {
            Self { v, c, t }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure is used to transfer a 16-byte symmetric key"]
    #[doc = " * encrypted using ECIES as specified in IEEE Std 1363a-2004. The symmetric"]
    #[doc = " * key is input to the key encryption process with no headers, encapsulation,"]
    #[doc = " * or length indication. Encryption and decryption are carried out as"]
    #[doc = " * specified in 5.3.5.1."]
    #[doc = " *"]
    #[doc = " * @param v: is the sender's ephemeral public key, which is the output V from"]
    #[doc = " * encryption as specified in 5.3.5.1."]
    #[doc = " *"]
    #[doc = " * @param c: is the encrypted symmetric key, which is the output C from"]
    #[doc = " * encryption as specified in 5.3.5.1. The algorithm for the symmetric key"]
    #[doc = " * is identified by the CHOICE indicated in the following SymmetricCiphertext."]
    #[doc = " * For ECIES this shall be AES-128."]
    #[doc = " *"]
    #[doc = " * @param t: is the authentication tag, which is the output tag from"]
    #[doc = " * encryption as specified in 5.3.5.1."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure represents a elliptic curve signature where the"]
    #[doc = " * component r is constrained to be an integer. This structure supports SM2"]
    #[doc = " * signatures as specified in 5.3.1.3."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct EcsigP256Signature {
        #[rasn(identifier = "rSig")]
        pub r_sig: FixedOctetString<32>,
        #[rasn(identifier = "sSig")]
        pub s_sig: FixedOctetString<32>,
    }
    impl EcsigP256Signature {
        pub fn new(r_sig: FixedOctetString<32>, s_sig: FixedOctetString<32>) -> Self {
            Self { r_sig, s_sig }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains an estimate of the geodetic altitude above"]
    #[doc = " * or below the WGS84 ellipsoid. The 16-bit value is interpreted as an"]
    #[doc = " * integer number of decimeters representing the height above a minimum"]
    #[doc = " * height of -409.5 m, with the maximum height being 6143.9 m."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct Elevation(pub Uint16);
    #[doc = "*"]
    #[doc = " * @brief This structure contains an encryption key, which may be a public or"]
    #[doc = " * a symmetric key."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2 if it appears in a"]
    #[doc = " * HeaderInfo or in a ToBeSignedCertificate. The canonicalization applies to"]
    #[doc = " * the PublicEncryptionKey. See the definitions of HeaderInfo and"]
    #[doc = " * ToBeSignedCertificate for a specification of the canonicalization"]
    #[doc = " * operations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    pub enum EncryptionKey {
        public(PublicEncryptionKey),
        symmetric(SymmetricEncryptionKey),
    }
    #[doc = "*"]
    #[doc = " * @brief This type is used as an identifier for instances of ExtContent"]
    #[doc = " * within an EXT-TYPE."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct ExtId(pub u8);
    #[doc = "***************************************************************************"]
    #[doc = "                           Location Structures                             "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure represents a geographic region of a specified form."]
    #[doc = " * A certificate is not valid if any part of the region indicated in its"]
    #[doc = " * scope field lies outside the region indicated in the scope of its issuer."]
    #[doc = " *"]
    #[doc = " * @param circularRegion: contains a single instance of the CircularRegion"]
    #[doc = " * structure."]
    #[doc = " *"]
    #[doc = " * @param rectangularRegion: is an array of RectangularRegion structures"]
    #[doc = " * containing at least one entry. This field is interpreted as a series of"]
    #[doc = " * rectangles, which may overlap or be disjoint. The permitted region is any"]
    #[doc = " * point within any of the rectangles."]
    #[doc = " *"]
    #[doc = " * @param polygonalRegion: contains a single instance of the PolygonalRegion"]
    #[doc = " * structure."]
    #[doc = " *"]
    #[doc = " * @param identifiedRegion: is an array of IdentifiedRegion structures"]
    #[doc = " * containing at least one entry. The permitted region is any point within"]
    #[doc = " * any of the identified regions."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields:"]
    #[doc = " *   - If present, this is a critical information field as defined in 5.2.6."]
    #[doc = " * An implementation that does not recognize the indicated CHOICE when"]
    #[doc = " * verifying a signed SPDU shall indicate that the signed SPDU is invalid in"]
    #[doc = " * the sense of 4.2.2.3.2, that is, it is invalid in the sense that its"]
    #[doc = " * validity cannot be established."]
    #[doc = " *   - If selected, rectangularRegion is a critical information field as"]
    #[doc = " * defined in 5.2.6. An implementation that does not support the number of"]
    #[doc = " * RectangularRegion in rectangularRegions when verifying a signed SPDU shall"]
    #[doc = " * indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, that"]
    #[doc = " * is, it is invalid in the sense that its validity cannot be established."]
    #[doc = " * A conformant implementation shall support rectangularRegions fields"]
    #[doc = " * containing at least eight entries."]
    #[doc = " *   - If selected, identifiedRegion is a critical information field as"]
    #[doc = " * defined in 5.2.6. An implementation that does not support the number of"]
    #[doc = " * IdentifiedRegion in identifiedRegion shall reject the signed SPDU as"]
    #[doc = " * invalid in the sense of 4.2.2.3.2, that is, it is invalid in the sense"]
    #[doc = " * that its validity cannot be established. A conformant implementation shall"]
    #[doc = " * support identifiedRegion fields containing at least eight entries."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum GeographicRegion {
        circularRegion(CircularRegion),
        rectangularRegion(SequenceOfRectangularRegion),
        polygonalRegion(PolygonalRegion),
        identifiedRegion(SequenceOfIdentifiedRegion),
    }
    #[doc = "*"]
    #[doc = " * @brief This is the group linkage value. See 5.1.3 and 7.3 for details of"]
    #[doc = " * use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure identifies a hash algorithm. The value sha256,"]
    #[doc = " * indicates SHA-256. The value sha384 indicates SHA-384. The value sm3"]
    #[doc = " * indicates SM3. See 5.3.3 for more details."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: This is a critical information field as"]
    #[doc = " * defined in 5.2.6. An implementation that does not recognize the enumerated"]
    #[doc = " * value of this type in a signed SPDU when verifying a signed SPDU shall"]
    #[doc = " * indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, that"]
    #[doc = " * is, it is invalid in the sense that its validity cannot be established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum HashAlgorithm {
        sha256 = 0,
        #[rasn(extension_addition)]
        sha384 = 1,
        #[rasn(extension_addition)]
        sm3 = 2,
    }
    #[doc = "*"]
    #[doc = " * @brief This type contains the truncated hash of another data structure."]
    #[doc = " * The HashedId10 for a given data structure is calculated by calculating the"]
    #[doc = " * hash of the encoded data structure and taking the low-order ten bytes of"]
    #[doc = " * the hash output. The low-order ten bytes are the last ten bytes of the"]
    #[doc = " * hash when represented in network byte order. If the data structure"]
    #[doc = " * is subject to canonicalization it is canonicalized before hashing. See"]
    #[doc = " * Example below."]
    #[doc = " *"]
    #[doc = " * The hash algorithm to be used to calculate a HashedId10 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId10 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined. See also the discussion in 5.3.9."]
    #[doc = " *"]
    #[doc = " * Example: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    #[doc = " *"]
    #[doc = " * The HashedId10 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * HashedId10 = 934ca495991b7852b855."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct HashedId10(pub FixedOctetString<10>);
    #[doc = "*"]
    #[doc = " * @brief This type contains the truncated hash of another data structure."]
    #[doc = " * The HashedId3 for a given data structure is calculated by calculating the"]
    #[doc = " * hash of the encoded data structure and taking the low-order three bytes of"]
    #[doc = " * the hash output. The low-order three bytes are the last three bytes of the"]
    #[doc = " * 32-byte hash when represented in network byte order. If the data structure"]
    #[doc = " * is subject to canonicalization it is canonicalized before hashing. See"]
    #[doc = " * Example below."]
    #[doc = " *"]
    #[doc = " * The hash algorithm to be used to calculate a HashedId3 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId3 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined. See also the discussion in 5.3.9."]
    #[doc = " *"]
    #[doc = " * Example: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    #[doc = " *"]
    #[doc = " * The HashedId3 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * HashedId3 = 52b855."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct HashedId3(pub FixedOctetString<3>);
    #[doc = "*"]
    #[doc = " * @brief This data structure contains the truncated hash of another data"]
    #[doc = " * structure. The HashedId32 for a given data structure is calculated by"]
    #[doc = " * calculating the hash of the encoded data structure and taking the"]
    #[doc = " * low-order 32 bytes of the hash output. The low-order 32 bytes are the last"]
    #[doc = " * 32 bytes of the hash when represented in network byte order. If the data"]
    #[doc = " * structure is subject to canonicalization it is canonicalized before"]
    #[doc = " * hashing. See Example below."]
    #[doc = " *"]
    #[doc = " * The hash algorithm to be used to calculate a HashedId32 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId32 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined. See also the discussion in 5.3.9."]
    #[doc = " *"]
    #[doc = " * Example: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    #[doc = " *"]
    #[doc = " * The HashedId32 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * HashedId32 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8"]
    #[doc = " * 55."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct HashedId32(pub FixedOctetString<32>);
    #[doc = "*"]
    #[doc = " * @brief This data structure contains the truncated hash of another data"]
    #[doc = " * structure. The HashedId48 for a given data structure is calculated by"]
    #[doc = " * calculating the hash of the encoded data structure and taking the"]
    #[doc = " * low-order 48 bytes of the hash output. The low-order 48 bytes are the last"]
    #[doc = " * 48 bytes of the hash when represented in network byte order. If the data"]
    #[doc = " * structure is subject to canonicalization it is canonicalized before"]
    #[doc = " * hashing. See Example below."]
    #[doc = " *"]
    #[doc = " * The hash algorithm to be used to calculate a HashedId48 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId48 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined. See also the discussion in 5.3.9."]
    #[doc = " *"]
    #[doc = " * Example: Consider the SHA-384 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * SHA-384(\"\") = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6"]
    #[doc = " * e1da274edebfe76f65fbd51ad2f14898b95b"]
    #[doc = " *"]
    #[doc = " * The HashedId48 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * HashedId48 = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e"]
    #[doc = " * 1da274edebfe76f65fbd51ad2f14898b95b."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct HashedId48(pub FixedOctetString<48>);
    #[doc = "*"]
    #[doc = " * @brief This type contains the truncated hash of another data structure."]
    #[doc = " * The HashedId8 for a given data structure is calculated by calculating the"]
    #[doc = " * hash of the encoded data structure and taking the low-order eight bytes of"]
    #[doc = " * the hash output. The low-order eight bytes are the last eight bytes of the"]
    #[doc = " * hash when represented in network byte order. If the data structure"]
    #[doc = " * is subject to canonicalization it is canonicalized before hashing. See"]
    #[doc = " * Example below."]
    #[doc = " *"]
    #[doc = " * The hash algorithm to be used to calculate a HashedId8 within a"]
    #[doc = " * structure depends on the context. In this standard, for each structure"]
    #[doc = " * that includes a HashedId8 field, the corresponding text indicates how the"]
    #[doc = " * hash algorithm is determined. See also the discussion in 5.3.9."]
    #[doc = " *"]
    #[doc = " * Example: Consider the SHA-256 hash of the empty string:"]
    #[doc = " *"]
    #[doc = " * SHA-256(\"\") ="]
    #[doc = " * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    #[doc = " *"]
    #[doc = " * The HashedId8 derived from this hash corresponds to the following:"]
    #[doc = " *"]
    #[doc = " * HashedId8 = a495991b7852b855."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct HashedId8(pub FixedOctetString<8>);
    #[doc = "*"]
    #[doc = " * @brief This is a UTF-8 string as defined in IETF RFC 3629. The contents"]
    #[doc = " * are determined by policy."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("0..=255"))]
    pub struct Hostname(pub Utf8String);
    #[doc = "***************************************************************************"]
    #[doc = "                             Pseudonym Linkage                             "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct IValue(pub Uint16);
    #[doc = "*"]
    #[doc = " * @brief This structure indicates the region of validity of a certificate"]
    #[doc = " * using region identifiers."]
    #[doc = " * A conformant implementation that supports this type shall support at least"]
    #[doc = " * one of the possible CHOICE values. The Protocol Implementation Conformance"]
    #[doc = " * Statement (PICS) provided in Annex A allows an implementation to state"]
    #[doc = " * which CountryOnly values it recognizes."]
    #[doc = " *"]
    #[doc = " * @param countryOnly: indicates that only a country (or a geographic entity"]
    #[doc = " * included in a country list) is given."]
    #[doc = " *"]
    #[doc = " * @param countryAndRegions: indicates that one or more top-level regions"]
    #[doc = " * within a country (as defined by the region listing associated with that"]
    #[doc = " * country) is given."]
    #[doc = " *"]
    #[doc = " * @param countryAndSubregions: indicates that one or more regions smaller"]
    #[doc = " * than the top-level regions within a country (as defined by the region"]
    #[doc = " * listing associated with that country) is given."]
    #[doc = " *"]
    #[doc = " * Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE when verifying a signed SPDU shall indicate"]
    #[doc = " * that the signed SPDU is invalid in the sense of 4.2.2.3.2, that is, it is"]
    #[doc = " * invalid in the sense that its validity cannot be established."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum IdentifiedRegion {
        countryOnly(UnCountryId),
        countryAndRegions(CountryAndRegions),
        countryAndSubregions(CountryAndSubregions),
    }
    #[doc = "*"]
    #[doc = " * @brief The known latitudes are from -900,000,000 to +900,000,000 in 0.1"]
    #[doc = " * microdegree intervals."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, value("-900000000..=900000000"))]
    pub struct KnownLatitude(pub NinetyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief The known longitudes are from -1,799,999,999 to +1,800,000,000 in"]
    #[doc = " * 0.1 microdegree intervals."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, value("-1799999999..=1800000000"))]
    pub struct KnownLongitude(pub OneEightyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief This structure contains a LA Identifier for use in the algorithms"]
    #[doc = " * specified in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("2"))]
    pub struct LaId(pub FixedOctetString<2>);
    #[doc = "*"]
    #[doc = " * @brief This type contains an INTEGER encoding an estimate of the latitude"]
    #[doc = " * with precision 1/10th microdegree relative to the World Geodetic System"]
    #[doc = " * (WGS)-84 datum as defined in NIMA Technical Report TR8350.2."]
    #[doc = " * The integer in the latitude field is no more than 900 000 000 and no less"]
    #[doc = " * than ?900 000 000, except that the value 900 000 001 is used to indicate"]
    #[doc = " * the latitude was not available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct Latitude(pub NinetyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief This structure contains a linkage seed value for use in the"]
    #[doc = " * algorithms specified in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct LinkageSeed(pub FixedOctetString<16>);
    #[doc = "*"]
    #[doc = " * @brief This is the individual linkage value. See 5.1.3 and 7.3 for details"]
    #[doc = " * of use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct LinkageValue(pub FixedOctetString<9>);
    #[doc = "*"]
    #[doc = " * @brief This type contains an INTEGER encoding an estimate of the longitude"]
    #[doc = " * with precision 1/10th microdegree relative to the World Geodetic System"]
    #[doc = " * (WGS)-84 datum as defined in NIMA Technical Report TR8350.2."]
    #[doc = " * The integer in the longitude field is no more than 1 800 000 000 and no"]
    #[doc = " * less than ?1 799 999 999, except that the value 1 800 000 001 is used to"]
    #[doc = " * indicate that the longitude was not available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct Longitude(pub OneEightyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief The integer in the latitude field is no more than 900,000,000 and"]
    #[doc = " * no less than -900,000,000, except that the value 900,000,001 is used to"]
    #[doc = " * indicate the latitude was not available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("-900000000..=900000001"))]
    pub struct NinetyDegreeInt(pub i32);
    #[doc = "*"]
    #[doc = " * @brief The integer in the longitude field is no more than 1,800,000,000"]
    #[doc = " * and no less than -1,799,999,999, except that the value 1,800,000,001 is"]
    #[doc = " * used to indicate that the longitude was not available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("-1799999999..=1800000001"))]
    pub struct OneEightyDegreeInt(pub i32);
    #[doc = "***************************************************************************"]
    #[doc = "                            OCTET STRING Types                             "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This is a synonym for ASN.1 OCTET STRING, and is used in the"]
    #[doc = " * definition of other data structures."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct Opaque(pub OctetString);
    #[doc = "*"]
    #[doc = " * @brief This structure defines a region using a series of distinct"]
    #[doc = " * geographic points, defined on the surface of the reference ellipsoid. The"]
    #[doc = " * region is specified by connecting the points in the order they appear,"]
    #[doc = " * with each pair of points connected by the geodesic on the reference"]
    #[doc = " * ellipsoid. The polygon is completed by connecting the final point to the"]
    #[doc = " * first point. The allowed region is the interior of the polygon and its"]
    #[doc = " * boundary."]
    #[doc = " *"]
    #[doc = " * A point which contains an elevation component is considered to be"]
    #[doc = " * within the polygonal region if its horizontal projection onto the"]
    #[doc = " * reference ellipsoid lies within the region."]
    #[doc = " *"]
    #[doc = " * A valid PolygonalRegion contains at least three points. In a valid"]
    #[doc = " * PolygonalRegion, the implied lines that make up the sides of the polygon"]
    #[doc = " * do not intersect."]
    #[doc = " *"]
    #[doc = " * @note This type does not support enclaves / exclaves. This might be"]
    #[doc = " * addressed in a future version of this standard."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not"]
    #[doc = " * support the number of TwoDLocation in the PolygonalRegion when verifying a"]
    #[doc = " * signed SPDU shall indicate that the signed SPDU is invalid. A compliant"]
    #[doc = " * implementation shall support PolygonalRegions containing at least eight"]
    #[doc = " * TwoDLocation entries."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("3.."))]
    pub struct PolygonalRegion(pub SequenceOf<TwoDLocation>);
    #[doc = "*"]
    #[doc = " * @brief This type represents the PSID defined in IEEE Std 1609.12."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("0.."))]
    pub struct Psid(pub Integer);
    #[doc = "***************************************************************************"]
    #[doc = "                              PSID / ITS-AID                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure represents the permissions that the certificate"]
    #[doc = " * holder has with respect to activities for a single application area,"]
    #[doc = " * identified by a Psid."]
    #[doc = " *"]
    #[doc = " * @note The determination as to whether the activities are consistent with"]
    #[doc = " * the permissions indicated by the PSID and ServiceSpecificPermissions is"]
    #[doc = " * made by the SDEE and not by the SDS; the SDS provides the PSID and SSP"]
    #[doc = " * information to the SDEE to enable the SDEE to make that determination."]
    #[doc = " * See 5.2.4.3.3 for more information."]
    #[doc = " *"]
    #[doc = " * @note The SDEE specification is expected to specify what application"]
    #[doc = " * activities are permitted by particular ServiceSpecificPermissions values."]
    #[doc = " * The SDEE specification is also expected EITHER to specify application"]
    #[doc = " * activities that are permitted if the ServiceSpecificPermissions is"]
    #[doc = " * omitted, OR to state that the ServiceSpecificPermissions need to always be"]
    #[doc = " * present."]
    #[doc = " *"]
    #[doc = " * @note Consistency with signed SPDU: As noted in 5.1.1,"]
    #[doc = " * consistency between the SSP and the signed SPDU is defined by rules"]
    #[doc = " * specific to the given PSID and is out of scope for this standard."]
    #[doc = " *"]
    #[doc = " * @note Consistency with issuing certificate: If a certificate has an"]
    #[doc = " * appPermissions entry A for which the ssp field is omitted, A is consistent"]
    #[doc = " * with the issuing certificate if the issuing certificate contains a"]
    #[doc = " * PsidSspRange P for which the following holds:"]
    #[doc = " *   - The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:"]
    #[doc = " *     - The sspRange field in P indicates all."]
    #[doc = " *     - The sspRange field in P indicates opaque and one of the entries in"]
    #[doc = " * opaque is an OCTET STRING of length 0."]
    #[doc = " *"]
    #[doc = " * For consistency rules for other forms of the ssp field, see the"]
    #[doc = " * following subclauses."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure represents the certificate issuing or requesting"]
    #[doc = " * permissions of the certificate holder with respect to one particular set"]
    #[doc = " * of application permissions."]
    #[doc = " *"]
    #[doc = " * @param psid: identifies the application area."]
    #[doc = " *"]
    #[doc = " * @param sspRange: identifies the SSPs associated with that PSID for which"]
    #[doc = " * the holder may issue or request certificates. If sspRange is omitted, the"]
    #[doc = " * holder may issue or request certificates for any SSP for that PSID."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure specifies a public encryption key and the associated"]
    #[doc = " * symmetric algorithm which is used for bulk data encryption when encrypting"]
    #[doc = " * for that public key."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2 if it appears in a"]
    #[doc = " * HeaderInfo or in a ToBeSignedCertificate. The canonicalization applies to"]
    #[doc = " * the BasePublicEncryptionKey. See the definitions of HeaderInfo and"]
    #[doc = " * ToBeSignedCertificate for a specification of the canonicalization"]
    #[doc = " * operations."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure represents a public key and states with what"]
    #[doc = " * algorithm the public key is to be used. Cryptographic mechanisms are"]
    #[doc = " * defined in 5.3."]
    #[doc = " * An EccP256CurvePoint or EccP384CurvePoint within a PublicVerificationKey"]
    #[doc = " * structure is invalid if it indicates the choice x-only."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.6. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE when verifying a signed SPDU shall indicate"]
    #[doc = " * that the signed SPDU is invalid indicate that the signed SPDU is invalid"]
    #[doc = " * in the sense of 4.2.2.3.2, that is, it is invalid in the sense that its"]
    #[doc = " * validity cannot be established."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to the EccP256CurvePoint and the Ecc384CurvePoint. Both forms of"]
    #[doc = " * point are encoded in compressed form, i.e., such that the choice indicated"]
    #[doc = " * within the Ecc*CurvePoint is compressed-y-0 or compressed-y-1."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum PublicVerificationKey {
        ecdsaNistP256(EccP256CurvePoint),
        ecdsaBrainpoolP256r1(EccP256CurvePoint),
        #[rasn(extension_addition)]
        ecdsaBrainpoolP384r1(EccP384CurvePoint),
        #[rasn(extension_addition)]
        ecdsaNistP384(EccP384CurvePoint),
        #[rasn(extension_addition)]
        ecsigSm2(EccP256CurvePoint),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure specifies a rectangle on the surface of the WGS84 ellipsoid where the"]
    #[doc = " * sides are given by lines of constant latitude or longitude."]
    #[doc = " * A point which contains an elevation component is considered to be within the rectangular region"]
    #[doc = " * if its horizontal projection onto the reference ellipsoid lies within the region."]
    #[doc = " * A RectangularRegion is invalid if the northWest value is south of the southEast value, or if the"]
    #[doc = " * latitude values in the two points are equal, or if the longitude values in the two points are"]
    #[doc = " * equal; otherwise it is valid. A certificate that contains an invalid RectangularRegion is invalid."]
    #[doc = " *"]
    #[doc = " * @param northWest: is the north-west corner of the rectangle."]
    #[doc = " *"]
    #[doc = " * @param southEast is the south-east corner of the rectangle."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief The meanings of the fields in this structure are to be interpreted"]
    #[doc = " * in the context of a country within which the region is located, referred"]
    #[doc = " * to as the \"enclosing country\". If this structure is used in a"]
    #[doc = " * CountryAndSubregions structure, the enclosing country is the one indicated"]
    #[doc = " * by the country field in the CountryAndSubregions structure. If other uses"]
    #[doc = " * are defined for this structure in future, it is expected that that"]
    #[doc = " * definition will include a specification of how the enclosing country can"]
    #[doc = " * be determined."]
    #[doc = " * If the enclosing country is the United States of America:"]
    #[doc = " * - The region field identifies the state or statistically equivalent"]
    #[doc = " * entity using the integer version of the 2010 FIPS codes as provided by the"]
    #[doc = " * U.S. Census Bureau (see normative references in Clause 0)."]
    #[doc = " * - The values in the subregions field identify the county or county"]
    #[doc = " * equivalent entity using the integer version of the 2010 FIPS codes as"]
    #[doc = " * provided by the U.S. Census Bureau."]
    #[doc = " * If the enclosing country is a different country from the USA, the meaning"]
    #[doc = " * of regionAndSubregions is not defined in this version of this standard."]
    #[doc = " * A conformant implementation that implements this type shall recognize (in"]
    #[doc = " * the sense of \"be able to determine whether a two-dimensional location lies"]
    #[doc = " * inside or outside the borders identified by\"), for at least one enclosing"]
    #[doc = " * country, at least one value for a region within that country and at least"]
    #[doc = " * one subregion for the indicated region. In this version of this standard,"]
    #[doc = " * the only means to satisfy this is for a conformant implementation to"]
    #[doc = " * recognize, for the USA, at least one of the FIPS state codes for US"]
    #[doc = " * states, and at least one of the county codes in at least one of the"]
    #[doc = " * recognized states. The Protocol Implementation Conformance Statement"]
    #[doc = " * (PICS) provided in Annex A allows an implementation to state which"]
    #[doc = " * UnCountryId values it recognizes and which region values are recognized"]
    #[doc = " * within that country."]
    #[doc = " * If a verifying implementation is required to check that an relevant"]
    #[doc = " * geographic information in a signed SPDU is consistent with a certificate"]
    #[doc = " * containing one or more instances of this type, then the SDS is permitted"]
    #[doc = " * to indicate that the signed SPDU is valid even if some values within"]
    #[doc = " * subregions are unrecognized in the sense defined above, so long as the"]
    #[doc = " * recognized instances of this type completely contain the relevant"]
    #[doc = " * geographic information. Informally, if the recognized values in the"]
    #[doc = " * certificate allow the SDS to determine that the SPDU is valid, then it"]
    #[doc = " * can make that determination even if there are also unrecognized values"]
    #[doc = " * in the certificate. This field is therefore not not a \"critical"]
    #[doc = " * information field\" as defined in 5.2.6, because unrecognized values are"]
    #[doc = " * permitted so long as the validity of the SPDU can be established with the"]
    #[doc = " * recognized values. However, as discussed in 5.2.6, the presence of an"]
    #[doc = " * unrecognized value in a certificate can make it impossible to determine"]
    #[doc = " * whether the certificate is valid and so whether the SPDU is valid."]
    #[doc = " * In this structure:"]
    #[doc = " *"]
    #[doc = " * @param region: identifies a region within a country."]
    #[doc = " *"]
    #[doc = " * @param subregions: identifies one or more subregions within region. A"]
    #[doc = " * conformant implementation that supports RegionAndSubregions shall support"]
    #[doc = " * a subregions field containing at least eight entries."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfHashedId3(pub SequenceOf<HashedId3>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfIdentifiedRegion(pub SequenceOf<IdentifiedRegion>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfLinkageSeed(pub SequenceOf<LinkageSeed>);
    #[doc = " Anonymous SEQUENCE OF member "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, identifier = "OCTET_STRING")]
    pub struct AnonymousSequenceOfOctetString(pub OctetString);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfOctetString(pub SequenceOf<AnonymousSequenceOfOctetString>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfPsid(pub SequenceOf<Psid>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfPsidSsp(pub SequenceOf<PsidSsp>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfPsidSspRange(pub SequenceOf<PsidSspRange>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfRectangularRegion(pub SequenceOf<RectangularRegion>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfRegionAndSubregions(pub SequenceOf<RegionAndSubregions>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfUint16(pub SequenceOf<Uint16>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfUint8(pub SequenceOf<Uint8>);
    #[doc = "*"]
    #[doc = " * @brief This structure represents the Service Specific Permissions (SSP)"]
    #[doc = " * relevant to a given entry in a PsidSsp. The meaning of the SSP is specific"]
    #[doc = " * to the associated Psid. SSPs may be PSID-specific octet strings or"]
    #[doc = " * bitmap-based. See Annex C for further discussion of how application"]
    #[doc = " * specifiers may choose which SSP form to use."]
    #[doc = " *"]
    #[doc = " * @note Consistency with issuing certificate: If a certificate has an"]
    #[doc = " * appPermissions entry A for which the ssp field is opaque, A is consistent"]
    #[doc = " * with the issuing certificate if the issuing certificate contains one of"]
    #[doc = " * the following:"]
    #[doc = " *   - (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;"]
    #[doc = " *   - (OPTION 2) A PsidSspRange P for which the following holds:"]
    #[doc = " *     - The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:"]
    #[doc = " *       - The sspRange field in P indicates all."]
    #[doc = " *       - The sspRange field in P indicates opaque and one of the entries in"]
    #[doc = " * the opaque field in P is an OCTET STRING identical to the opaque field in"]
    #[doc = " * A."]
    #[doc = " *"]
    #[doc = " * For consistency rules for other types of ServiceSpecificPermissions,"]
    #[doc = " * see the following subclauses."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This structure represents a signature for a supported public key"]
    #[doc = " * algorithm. It may be contained within SignedData or Certificate."]
    #[doc = " *"]
    #[doc = " * @note Critical information fields: If present, this is a critical"]
    #[doc = " * information field as defined in 5.2.5. An implementation that does not"]
    #[doc = " * recognize the indicated CHOICE for this type when verifying a signed SPDU"]
    #[doc = " * shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2,"]
    #[doc = " * that is, it is invalid in the sense that its validity cannot be"]
    #[doc = " * established."]
    #[doc = " *"]
    #[doc = " * @note Canonicalization: This data structure is subject to canonicalization"]
    #[doc = " * for the relevant operations specified in 6.1.2. The canonicalization"]
    #[doc = " * applies to instances of this data structure of form EcdsaP256Signature"]
    #[doc = " * and EcdsaP384Signature."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum Signature {
        ecdsaNistP256Signature(EcdsaP256Signature),
        ecdsaBrainpoolP256r1Signature(EcdsaP256Signature),
        #[rasn(extension_addition)]
        ecdsaBrainpoolP384r1Signature(EcdsaP384Signature),
        #[rasn(extension_addition)]
        ecdsaNistP384Signature(EcdsaP384Signature),
        #[rasn(extension_addition)]
        sm2Signature(EcsigP256Signature),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure identifies the SSPs associated with a PSID for"]
    #[doc = " * which the holder may issue or request certificates."]
    #[doc = " *"]
    #[doc = " * @note Consistency with issuing certificate: If a certificate has a"]
    #[doc = " * PsidSspRange A for which the ssp field is opaque, A is consistent with"]
    #[doc = " * the issuing certificate if the issuing certificate contains one of the"]
    #[doc = " * following:"]
    #[doc = " *   - (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;"]
    #[doc = " *   - (OPTION 2) A PsidSspRange P for which the following holds:"]
    #[doc = " *     - The psid field in P is equal to the psid field in A and one of the"]
    #[doc = " * following is true:"]
    #[doc = " *       - The sspRange field in P indicates all."]
    #[doc = " *       - The sspRange field in P indicates opaque, and the sspRange field in"]
    #[doc = " * A indicates opaque, and every OCTET STRING within the opaque in A is a"]
    #[doc = " * duplicate of an OCTET STRING within the opaque in P."]
    #[doc = " *"]
    #[doc = " * If a certificate has a PsidSspRange A for which the ssp field is all,"]
    #[doc = " * A is consistent with the issuing certificate if the issuing certificate"]
    #[doc = " * contains a PsidSspRange P for which the following holds:"]
    #[doc = " *   - (OPTION 1) A SubjectPermissions field indicating the choice all and"]
    #[doc = " * no PsidSspRange field containing the psid field in A;"]
    #[doc = " *   - (OPTION 2) A PsidSspRange P for which the psid field in P is equal to"]
    #[doc = " * the psid field in A and the sspRange field in P indicates all."]
    #[doc = " *"]
    #[doc = " * For consistency rules for other types of SspRange, see the following"]
    #[doc = " * subclauses."]
    #[doc = " *"]
    #[doc = " * @note The choice \"all\" may also be indicated by omitting the"]
    #[doc = " * SspRange in the enclosing PsidSspRange structure. Omitting the SspRange is"]
    #[doc = " * preferred to explicitly indicating \"all\"."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This field contains the certificate holder's assurance level, which"]
    #[doc = " * indicates the security of both the platform and storage of secret keys as"]
    #[doc = " * well as the confidence in this assessment."]
    #[doc = " *"]
    #[doc = " * This field is encoded as defined in Table 1, where \"A\" denotes bit"]
    #[doc = " * fields specifying an assurance level, \"R\" reserved bit fields, and \"C\" bit"]
    #[doc = " * fields specifying the confidence."]
    #[doc = " *"]
    #[doc = " * Table 1: Bitwise encoding of subject assurance"]
    #[doc = " *"]
    #[doc = " * | Bit number     |  7  |  6  |  5  |  4  |  3  |  2  |  1  |  0  |"]
    #[doc = " * | -------------- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    #[doc = " * | Interpretation |  A  |  A  |  A  |  R  |  R  |  R  |  C  |  C  |"]
    #[doc = " *"]
    #[doc = " * In Table 1, bit number 0 denotes the least significant bit. Bit 7"]
    #[doc = " * to bit 5 denote the device's assurance levels, bit 4 to bit 2 are reserved"]
    #[doc = " * for future use, and bit 1 and bit 0 denote the confidence."]
    #[doc = " *"]
    #[doc = " * The specification of these assurance levels as well as the"]
    #[doc = " * encoding of the confidence levels is outside the scope of the present"]
    #[doc = " * standard. It can be assumed that a higher assurance value indicates that"]
    #[doc = " * the holder is more trusted than the holder of a certificate with lower"]
    #[doc = " * assurance value and the same confidence value."]
    #[doc = " *"]
    #[doc = " * @note This field was originally specified in ETSI TS 103 097 and"]
    #[doc = " * future uses of this field are anticipated to be consistent with future"]
    #[doc = " * versions of that standard."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SubjectAssurance(pub FixedOctetString<1>);
    #[doc = "*"]
    #[doc = " * @brief This enumerated value indicates supported symmetric algorithms. The"]
    #[doc = " * algorithm identifier identifies both the algorithm itself and a specific"]
    #[doc = " * mode of operation. The symmetric algorithms supported in this version of"]
    #[doc = " * this standard are AES-128 and SM4. The only mode of operation supported is"]
    #[doc = " * Counter Mode Encryption With Cipher Block Chaining Message Authentication"]
    #[doc = " * Code (CCM). Full details are given in 5.3.8."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum SymmAlgorithm {
        aes128Ccm = 0,
        #[rasn(extension_addition)]
        sm4Ccm = 1,
    }
    #[doc = "*"]
    #[doc = " * @brief This structure provides the key bytes for use with an identified"]
    #[doc = " * symmetric algorithm. The supported symmetric algorithms are AES-128 and"]
    #[doc = " * SM4 in CCM mode as specified in 5.3.8."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SymmetricEncryptionKey {
        aes128Ccm(FixedOctetString<16>),
        #[rasn(extension_addition)]
        sm4Ccm(FixedOctetString<16>),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains an estimate of 3D location. The details of"]
    #[doc = " * the structure are given in the definitions of the individual fields below."]
    #[doc = " *"]
    #[doc = " * @note The units used in this data structure are consistent with the"]
    #[doc = " * location data structures used in \tSAE J2735 [B26], though the encoding is"]
    #[doc = " * incompatible."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This type gives the number of (TAI) seconds since 00:00:00 UTC, 1"]
    #[doc = " * January, 2004."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct Time32(pub Uint32);
    #[doc = "*"]
    #[doc = " * @brief This data structure is a 64-bit integer giving an estimate of the"]
    #[doc = " * number of (TAI) microseconds since 00:00:00 UTC, 1 January, 2004."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct Time64(pub Uint64);
    #[doc = "*"]
    #[doc = " * @brief This structure is used to define validity regions for use in"]
    #[doc = " * certificates. The latitude and longitude fields contain the latitude and"]
    #[doc = " * longitude as defined above."]
    #[doc = " *"]
    #[doc = " * @note This data structure is consistent with the location encoding"]
    #[doc = " * used in SAE J2735, except that values 900 000 001 for latitude (used to"]
    #[doc = " * indicate that the latitude was not available) and 1 800 000 001 for"]
    #[doc = " * longitude (used to indicate that the longitude was not available) are not"]
    #[doc = " * valid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 65,535, i.e., (hex)ff ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("0..=65535"))]
    pub struct Uint16(pub u16);
    #[doc = "***************************************************************************"]
    #[doc = "                               Integer Types                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 7, i.e., (hex)07."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("0..=7"))]
    pub struct Uint3(pub u8);
    #[doc = "*"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 4,294,967,295, i.e.,"]
    #[doc = " * (hex)ff ff ff ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("0..=4294967295"))]
    pub struct Uint32(pub u32);
    #[doc = "*"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 18,446,744,073,709,551,615, i.e.,"]
    #[doc = " * (hex)ff ff ff ff ff ff ff ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("0..=18446744073709551615"))]
    pub struct Uint64(pub u64);
    #[doc = "*"]
    #[doc = " * @brief This atomic type is used in the definition of other data structures."]
    #[doc = " * It is for non-negative integers up to 255, i.e., (hex)ff."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct Uint8(pub u8);
    #[doc = "*"]
    #[doc = " * @brief This type contains the integer representation of the country or"]
    #[doc = " * area identifier as defined by the United Nations Statistics Division in"]
    #[doc = " * October 2013 (see normative references in Clause 0)."]
    #[doc = " * A conformant implementation that implements IdentifiedRegion shall"]
    #[doc = " * recognize (in the sense of be able to determine whether a two dimensional"]
    #[doc = " * location lies inside or outside the borders identified by) at least one"]
    #[doc = " * value of UnCountryId. The Protocol Implementation Conformance Statement"]
    #[doc = " * (PICS) provided in Annex A allows an implementation to state which"]
    #[doc = " * UnCountryId values it recognizes."]
    #[doc = " * Since 2013 and before the publication of this version of this standard,"]
    #[doc = " * three changes have been made to the country code list, to define the"]
    #[doc = " * region \"sub-Saharan Africa\" and remove the \"developed regions\", and"]
    #[doc = " * \"developing regions\". A conformant implementation may recognize these"]
    #[doc = " * region identifiers in the sense defined in the previous paragraph."]
    #[doc = " * If a verifying implementation is required to check that relevant"]
    #[doc = " * geographic information in a signed SPDU is consistent with a certificate"]
    #[doc = " * containing one or more instances of this type, then the SDS is permitted"]
    #[doc = " * to indicate that the signed SPDU is valid even if some instances of this"]
    #[doc = " * type are unrecognized in the sense defined above, so long as the"]
    #[doc = " * recognized instances of this type completely contain the relevant"]
    #[doc = " * geographic information. Informally, if the recognized values in the"]
    #[doc = " * certificate allow the SDS to determine that the SPDU is valid, then it"]
    #[doc = " * can make that determination even if there are also unrecognized values in"]
    #[doc = " * the certificate. This field is therefore not a \"critical information"]
    #[doc = " * field\" as defined in 5.2.6, because unrecognized values are permitted so"]
    #[doc = " * long as the validity of the SPDU can be established with the recognized"]
    #[doc = " * values. However, as discussed in 5.2.6, the presence of an unrecognized"]
    #[doc = " * value in a certificate can make it impossible to determine whether the"]
    #[doc = " * certificate and the SPDU are valid."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct UnCountryId(pub Uint16);
    #[doc = "*"]
    #[doc = " * @brief The value 900,000,001 indicates that the latitude was not"]
    #[doc = " * available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, value("900000001"))]
    pub struct UnknownLatitude(pub NinetyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief The value 1,800,000,001 indicates that the longitude was not"]
    #[doc = " * available to the sender."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, value("1800000001"))]
    pub struct UnknownLongitude(pub OneEightyDegreeInt);
    #[doc = "*"]
    #[doc = " * @brief This type gives the validity period of a certificate. The start of"]
    #[doc = " * the validity period is given by start and the end is given by"]
    #[doc = " * start + duration."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
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
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_crl {
    extern crate alloc;
    use super::ieee1609_dot2::Ieee1609Dot2Data;
    use super::ieee1609_dot2_base_types::{Opaque, Psid};
    use super::ieee1609_dot2_crl_base_types::CrlContents;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This is the PSID for the CRL application."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, value("256"))]
    pub struct CrlPsid(pub Psid);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to contain a signed CRL. A valid "]
    #[doc = " * signed CRL meets the validity criteria of 7.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SecuredCrl(pub Ieee1609Dot2Data);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_crl_base_types {
    extern crate alloc;
    use super::ieee1609_dot2_base_types::{
        CrlSeries, Duration, GeographicRegion, HashedId10, HashedId8, IValue, LaId, LinkageSeed,
        Opaque, Psid, SequenceOfLinkageSeed, Signature, Time32, Uint16, Uint3, Uint32, Uint8,
        ValidityPeriod,
    };
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief The fields in this structure have the following meaning:"]
    #[doc = " *"]
    #[doc = " * @param version: is the version number of the CRL. For this version of this"]
    #[doc = " * standard it is 1."]
    #[doc = " *"]
    #[doc = " * @param crlSeries: represents the CRL series to which this CRL belongs. This"]
    #[doc = " * is used to determine whether the revocation information in a CRL is relevant"]
    #[doc = " * to a particular certificate as specified in 5.1.3.2."]
    #[doc = " *"]
    #[doc = " * @param crlCraca: contains the low-order eight octets of the hash of the"]
    #[doc = " * certificate of the Certificate Revocation Authorization CA (CRACA) that"]
    #[doc = " * ultimately authorized the issuance of this CRL. This is used to determine"]
    #[doc = " * whether the revocation information in a CRL is relevant to a particular"]
    #[doc = " * certificate as specified in 5.1.3.2. In a valid signed CRL as specified in"]
    #[doc = " * 7.4 the crlCraca is consistent with the associatedCraca field in the"]
    #[doc = " * Service Specific Permissions as defined in 7.4.3.3. The HashedId8 is"]
    #[doc = " * calculated with the whole-certificate hash algorithm, determined as"]
    #[doc = " * described in 6.4.3, applied to the COER-encoded certificate, canonicalized "]
    #[doc = " * as defined in the definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @param issueDate: specifies the time when the CRL was issued."]
    #[doc = " *"]
    #[doc = " * @param nextCrl: contains the time when the next CRL with the same crlSeries"]
    #[doc = " * and cracaId is expected to be issued. The CRL is invalid unless nextCrl is"]
    #[doc = " * strictly after issueDate. This field is used to set the expected update time"]
    #[doc = " * for revocation information associated with the (crlCraca, crlSeries) pair as"]
    #[doc = " * specified in 5.1.3.6."]
    #[doc = " *"]
    #[doc = " * @param priorityInfo: contains information that assists devices with limited"]
    #[doc = " * storage space in determining which revocation information to retain and"]
    #[doc = " * which to discard."]
    #[doc = " *"]
    #[doc = " * @param\ttypeSpecific: contains the CRL body."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct CrlContents {
        #[rasn(value("1"))]
        pub version: Uint8,
        #[rasn(identifier = "crlSeries")]
        pub crl_series: CrlSeries,
        #[rasn(identifier = "crlCraca")]
        pub crl_craca: HashedId8,
        #[rasn(identifier = "issueDate")]
        pub issue_date: Time32,
        #[rasn(identifier = "nextCrl")]
        pub next_crl: Time32,
        #[rasn(identifier = "priorityInfo")]
        pub priority_info: CrlPriorityInfo,
        #[rasn(identifier = "typeSpecific")]
        pub type_specific: TypeSpecificCrlContents,
    }
    impl CrlContents {
        pub fn new(
            version: Uint8,
            crl_series: CrlSeries,
            crl_craca: HashedId8,
            issue_date: Time32,
            next_crl: Time32,
            priority_info: CrlPriorityInfo,
            type_specific: TypeSpecificCrlContents,
        ) -> Self {
            Self {
                version,
                crl_series,
                crl_craca,
                issue_date,
                next_crl,
                priority_info,
                type_specific,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This data structure contains information that assists devices with"]
    #[doc = " * limited storage space in determining which revocation information to retain"]
    #[doc = " * and which to discard."]
    #[doc = " *"]
    #[doc = " * @param priority: indicates the priority of the revocation information"]
    #[doc = " * relative to other CRLs issued for certificates with the same cracaId and"]
    #[doc = " * crlSeries values. A higher value for this field indicates higher importance"]
    #[doc = " * of this revocation information."]
    #[doc = " *"]
    #[doc = " * @note This mechanism is for future use; details are not specified in this"]
    #[doc = " * version of the standard."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CrlPriorityInfo {
        pub priority: Option<Uint8>,
    }
    impl CrlPriorityInfo {
        pub fn new(priority: Option<Uint8>) -> Self {
            Self { priority }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains an identifier for the algorithms specified "]
    #[doc = " * in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum ExpansionAlgorithmIdentifier {
        #[rasn(identifier = "sha256ForI-aesForJ")]
        sha256ForI_aesForJ = 0,
        #[rasn(identifier = "sm3ForI-sm4ForJ")]
        sm3ForI_sm4ForJ = 1,
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param iMax: indicates that for these certificates, revocation information "]
    #[doc = " * need no longer be calculated once iCert > iMax as the holders are known "]
    #[doc = " * to have no more valid certs for that (crlCraca, crlSeries) at that point."]
    #[doc = " *"]
    #[doc = " * @param la1Id: is the value LinkageAuthorityIdentifier1 used in the "]
    #[doc = " * algorithm given in 5.1.3.4. This value applies to all linkage-based "]
    #[doc = " * revocation information included within contents."]
    #[doc = " *"]
    #[doc = " * @param linkageSeed1: is the value LinkageSeed1 used in the algorithm given "]
    #[doc = " * in 5.1.3.4."]
    #[doc = " *"]
    #[doc = " * @param la2Id: is the value LinkageAuthorityIdentifier2 used in the "]
    #[doc = " * algorithm given in 5.1.3.4. This value applies to all linkage-based "]
    #[doc = " * revocation information included within contents."]
    #[doc = " *"]
    #[doc = " * @param linkageSeed2: is the value LinkageSeed2 used in the algorithm given "]
    #[doc = " * in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct GroupCrlEntry {
        #[rasn(identifier = "iMax")]
        pub i_max: Uint16,
        #[rasn(identifier = "la1Id")]
        pub la1_id: LaId,
        #[rasn(identifier = "linkageSeed1")]
        pub linkage_seed1: LinkageSeed,
        #[rasn(identifier = "la2Id")]
        pub la2_id: LaId,
        #[rasn(identifier = "linkageSeed2")]
        pub linkage_seed2: LinkageSeed,
    }
    impl GroupCrlEntry {
        pub fn new(
            i_max: Uint16,
            la1_id: LaId,
            linkage_seed1: LinkageSeed,
            la2_id: LaId,
            linkage_seed2: LinkageSeed,
        ) -> Self {
            Self {
                i_max,
                la1_id,
                linkage_seed1,
                la2_id,
                linkage_seed2,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains the linkage seed for group revocation with "]
    #[doc = " * a single seed. The seed is used as specified in the algorithms in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct GroupSingleSeedCrlEntry {
        #[rasn(identifier = "iMax")]
        pub i_max: Uint16,
        #[rasn(identifier = "laId")]
        pub la_id: LaId,
        #[rasn(identifier = "linkageSeed")]
        pub linkage_seed: LinkageSeed,
    }
    impl GroupSingleSeedCrlEntry {
        pub fn new(i_max: Uint16, la_id: LaId, linkage_seed: LinkageSeed) -> Self {
            Self {
                i_max,
                la_id,
                linkage_seed,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param\tid: is the HashedId10 identifying the revoked certificate. The "]
    #[doc = " * HashedId10 is calculated with the whole-certificate hash algorithm, "]
    #[doc = " * determined as described in 6.4.3, applied to the COER-encoded certificate,"]
    #[doc = " * canonicalized as defined in the definition of Certificate."]
    #[doc = " *"]
    #[doc = " * @param expiry: is the value computed from the validity period's start and"]
    #[doc = " * duration values in that certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct HashBasedRevocationInfo {
        pub id: HashedId10,
        pub expiry: Time32,
    }
    impl HashBasedRevocationInfo {
        pub fn new(id: HashedId10, expiry: Time32) -> Self {
            Self { id, expiry }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param iMax indicates that for the entries in contents, revocation "]
    #[doc = " * information need no longer be calculated once iCert > iMax as the holder "]
    #[doc = " * is known to have no more valid certs at that point. iMax is not directly "]
    #[doc = " * used in the calculation of the linkage values, it is used to determine "]
    #[doc = " * when revocation information can safely be deleted."]
    #[doc = " *"]
    #[doc = " * @param contents contains individual linkage data for certificates that are "]
    #[doc = " * revoked using two seeds, per the algorithm given in per the mechanisms "]
    #[doc = " * given in 5.1.3.4 and with seedEvolutionFunctionIdentifier and "]
    #[doc = " * linkageValueGenerationFunctionIdentifier obtained as specified in 7.3.3."]
    #[doc = " *"]
    #[doc = " * @param singleSeed contains individual linkage data for certificates that "]
    #[doc = " * are revoked using a single seed, per the algorithm given in per the "]
    #[doc = " * mechanisms given in 5.1.3.4 and with seedEvolutionFunctionIdentifier and "]
    #[doc = " * linkageValueGenerationFunctionIdentifier obtained as specified in 7.3.3."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct IMaxGroup {
        #[rasn(identifier = "iMax")]
        pub i_max: Uint16,
        pub contents: SequenceOfIndividualRevocation,
        #[rasn(extension_addition, identifier = "singleSeed")]
        pub single_seed: Option<SequenceOfLinkageSeed>,
    }
    impl IMaxGroup {
        pub fn new(
            i_max: Uint16,
            contents: SequenceOfIndividualRevocation,
            single_seed: Option<SequenceOfLinkageSeed>,
        ) -> Self {
            Self {
                i_max,
                contents,
                single_seed,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param linkageSeed1 is the value LinkageSeed1 used in the algorithm given "]
    #[doc = " * in 5.1.3.4."]
    #[doc = " *"]
    #[doc = " * @param linkageSeed2 is the value LinkageSeed2 used in the algorithm given "]
    #[doc = " * in 5.1.3.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct IndividualRevocation {
        #[rasn(identifier = "linkageSeed1")]
        pub linkage_seed1: LinkageSeed,
        #[rasn(identifier = "linkageSeed2")]
        pub linkage_seed2: LinkageSeed,
    }
    impl IndividualRevocation {
        pub fn new(linkage_seed1: LinkageSeed, linkage_seed2: LinkageSeed) -> Self {
            Self {
                linkage_seed1,
                linkage_seed2,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param\tjMax: is the value jMax used in the algorithm given in 5.1.3.4. This"]
    #[doc = " * value applies to all linkage-based revocation information included within"]
    #[doc = " * contents."]
    #[doc = " *"]
    #[doc = " * @param contents: contains individual linkage data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct JMaxGroup {
        pub jmax: Uint8,
        pub contents: SequenceOfLAGroup,
    }
    impl JMaxGroup {
        pub fn new(jmax: Uint8, contents: SequenceOfLAGroup) -> Self {
            Self { jmax, contents }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param la1Id: is the value LinkageAuthorityIdentifier1 used in the"]
    #[doc = " * algorithm given in 5.1.3.4. This value applies to all linkage-based"]
    #[doc = " * revocation information included within contents."]
    #[doc = " *"]
    #[doc = " * @param la2Id: is the value LinkageAuthorityIdentifier2 used in the"]
    #[doc = " * algorithm given in 5.1.3.4. This value applies to all linkage-based"]
    #[doc = " * revocation information included within contents."]
    #[doc = " *"]
    #[doc = " * @param contents: contains individual linkage data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct LAGroup {
        #[rasn(identifier = "la1Id")]
        pub la1_id: LaId,
        #[rasn(identifier = "la2Id")]
        pub la2_id: LaId,
        pub contents: SequenceOfIMaxGroup,
    }
    impl LAGroup {
        pub fn new(la1_id: LaId, la2_id: LaId, contents: SequenceOfIMaxGroup) -> Self {
            Self {
                la1_id,
                la2_id,
                contents,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is the identifier for the linkage value generation function. "]
    #[doc = " * See 5.1.3 for details of use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct LvGenerationFunctionIdentifier(());
    #[doc = "*"]
    #[doc = " * @brief This is the identifier for the seed evolution function. See 5.1.3 "]
    #[doc = " * for details of use."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SeedEvolutionFunctionIdentifier(());
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfGroupCrlEntry(pub SequenceOf<GroupCrlEntry>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfGroupSingleSeedCrlEntry(pub SequenceOf<GroupSingleSeedCrlEntry>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfHashBasedRevocationInfo(pub SequenceOf<HashBasedRevocationInfo>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfIMaxGroup(pub SequenceOf<IMaxGroup>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfIndividualRevocation(pub SequenceOf<IndividualRevocation>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfJMaxGroup(pub SequenceOf<JMaxGroup>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfLAGroup(pub SequenceOf<LAGroup>);
    #[doc = "*"]
    #[doc = " * @brief This data structure represents information about a revoked"]
    #[doc = " * certificate."]
    #[doc = " *"]
    #[doc = " * @param crlSerial: is a counter that increments by 1 every time a new full"]
    #[doc = " * or delta CRL is issued for the indicated crlCraca and crlSeries values."]
    #[doc = " *"]
    #[doc = " * @param entries: contains the individual revocation information items."]
    #[doc = " *"]
    #[doc = " * @note To indicate that a hash-based CRL contains no individual revocation "]
    #[doc = " * information items, the recommended approach is for the SEQUENCE OF in the "]
    #[doc = " * SequenceOfHashBasedRevocationInfo in this field to indicate zero entries."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedHashIdCrl {
        #[rasn(identifier = "crlSerial")]
        pub crl_serial: Uint32,
        pub entries: SequenceOfHashBasedRevocationInfo,
    }
    impl ToBeSignedHashIdCrl {
        pub fn new(crl_serial: Uint32, entries: SequenceOfHashBasedRevocationInfo) -> Self {
            Self {
                crl_serial,
                entries,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " *"]
    #[doc = " * @param\tiRev: is the value iRev used in the algorithm given in 5.1.3.4. This"]
    #[doc = " * value applies to all linkage-based revocation information included within"]
    #[doc = " * either indvidual or groups."]
    #[doc = " *"]
    #[doc = " * @param\tindexWithinI: is a counter that is set to 0 for the first CRL issued"]
    #[doc = " * for the indicated combination of crlCraca, crlSeries, and iRev, and"]
    #[doc = " * increments by 1 every time a new full or delta CRL is issued for the"]
    #[doc = " * indicated crlCraca and crlSeries values without changing iRev."]
    #[doc = " *"]
    #[doc = " * @param individual: contains individual linkage data."]
    #[doc = " *"]
    #[doc = " * @note To indicate that a linkage ID-based CRL contains no individual"]
    #[doc = " * linkage data, the recommended approach is for the SEQUENCE OF in the"]
    #[doc = " * SequenceOfJMaxGroup in this field to indicate zero entries."]
    #[doc = " *"]
    #[doc = " * @param groups: contains group linkage data."]
    #[doc = " *"]
    #[doc = " * @note To indicate that a linkage ID-based CRL contains no group linkage"]
    #[doc = " * data, the recommended approach is for the SEQUENCE OF in the"]
    #[doc = " * SequenceOfGroupCrlEntry in this field to indicate zero entries."]
    #[doc = " *"]
    #[doc = " * @param groupsSingleSeed: contains group linkage data generated with a single "]
    #[doc = " * seed."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedLinkageValueCrl {
        #[rasn(identifier = "iRev")]
        pub i_rev: IValue,
        #[rasn(identifier = "indexWithinI")]
        pub index_within_i: Uint8,
        pub individual: Option<SequenceOfJMaxGroup>,
        pub groups: Option<SequenceOfGroupCrlEntry>,
        #[rasn(extension_addition, identifier = "groupsSingleSeed")]
        pub groups_single_seed: Option<SequenceOfGroupSingleSeedCrlEntry>,
    }
    impl ToBeSignedLinkageValueCrl {
        pub fn new(
            i_rev: IValue,
            index_within_i: Uint8,
            individual: Option<SequenceOfJMaxGroup>,
            groups: Option<SequenceOfGroupCrlEntry>,
            groups_single_seed: Option<SequenceOfGroupSingleSeedCrlEntry>,
        ) -> Self {
            Self {
                i_rev,
                index_within_i,
                individual,
                groups,
                groups_single_seed,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief In this structure:"]
    #[doc = " * "]
    #[doc = " * @param iRev is the value iRev used in the algorithm given in 5.1.3.4. This "]
    #[doc = " * value applies to all linkage-based revocation information included within "]
    #[doc = " * either indvidual or groups."]
    #[doc = " * "]
    #[doc = " * @param indexWithinI is a counter that is set to 0 for the first CRL issued "]
    #[doc = " * for the indicated combination of crlCraca, crlSeries, and iRev, and increments by 1 every time a new full or delta CRL is issued for the indicated crlCraca and crlSeries values without changing iRev."]
    #[doc = " * "]
    #[doc = " * @param seedEvolution contains an identifier for the seed evolution "]
    #[doc = " * function, used as specified in  5.1.3.4."]
    #[doc = " * "]
    #[doc = " * @param lvGeneration contains an identifier for the linkage value "]
    #[doc = " * generation function, used as specified in  5.1.3.4."]
    #[doc = " * "]
    #[doc = " * @param individual contains individual linkage data."]
    #[doc = " * "]
    #[doc = " * @param groups contains group linkage data for linkage value generation "]
    #[doc = " * with two seeds."]
    #[doc = " * "]
    #[doc = " * @param groupsSingleSeed contains group linkage data for linkage value "]
    #[doc = " * generation with one seed."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedLinkageValueCrlWithAlgIdentifier {
        #[rasn(identifier = "iRev")]
        pub i_rev: IValue,
        #[rasn(identifier = "indexWithinI")]
        pub index_within_i: Uint8,
        #[rasn(identifier = "seedEvolution")]
        pub seed_evolution: SeedEvolutionFunctionIdentifier,
        #[rasn(identifier = "lvGeneration")]
        pub lv_generation: LvGenerationFunctionIdentifier,
        pub individual: Option<SequenceOfJMaxGroup>,
        pub groups: Option<SequenceOfGroupCrlEntry>,
        #[rasn(identifier = "groupsSingleSeed")]
        pub groups_single_seed: Option<SequenceOfGroupSingleSeedCrlEntry>,
    }
    impl ToBeSignedLinkageValueCrlWithAlgIdentifier {
        pub fn new(
            i_rev: IValue,
            index_within_i: Uint8,
            seed_evolution: SeedEvolutionFunctionIdentifier,
            lv_generation: LvGenerationFunctionIdentifier,
            individual: Option<SequenceOfJMaxGroup>,
            groups: Option<SequenceOfGroupCrlEntry>,
            groups_single_seed: Option<SequenceOfGroupSingleSeedCrlEntry>,
        ) -> Self {
            Self {
                i_rev,
                index_within_i,
                seed_evolution,
                lv_generation,
                individual,
                groups,
                groups_single_seed,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains type-specific CRL contents."]
    #[doc = " *"]
    #[doc = " * @param fullHashCrl: contains a full hash-based CRL, i.e., a listing of the"]
    #[doc = " * hashes of all certificates that:"]
    #[doc = " *  - contain the indicated cracaId and crlSeries values, and"]
    #[doc = " *  - are revoked by hash, and"]
    #[doc = " *  - have been revoked, and"]
    #[doc = " *  - have not expired."]
    #[doc = " *"]
    #[doc = " * @param deltaHashCrl: contains a delta hash-based CRL, i.e., a listing of"]
    #[doc = " * the hashes of all certificates that:"]
    #[doc = " *  - contain the indicated cracaId and crlSeries values, and"]
    #[doc = " *  - are revoked by hash, and"]
    #[doc = " *  - have been revoked since the previous CRL that contained the indicated"]
    #[doc = " * cracaId and crlSeries values."]
    #[doc = " *"]
    #[doc = " * @param fullLinkedCrl and fullLinkedCrlWithAlg: contain a full linkage"]
    #[doc = " * ID-based CRL, i.e., a listing of the individual and/or group linkage data"]
    #[doc = " * for all certificates that:"]
    #[doc = " *  - contain the indicated cracaId and crlSeries values, and"]
    #[doc = " *  - are revoked by linkage value, and"]
    #[doc = " *  - have been revoked, and"]
    #[doc = " *  - have not expired."]
    #[doc = " * The difference between fullLinkedCrl and fullLinkedCrlWithAlg is in how"]
    #[doc = " * the cryptographic algorithms to be used in the seed evolution function and"]
    #[doc = " * linkage value generation function of 5.1.3.4 are communicated to the"]
    #[doc = " * receiver of the CRL. See below in this subclause for details."]
    #[doc = " *"]
    #[doc = " * @param deltaLinkedCrl and deltaLinkedCrlWithAlg: contain a delta linkage"]
    #[doc = " * ID-based CRL, i.e., a listing of the individual and/or group linkage data"]
    #[doc = " * for all certificates that:"]
    #[doc = " *  - contain the specified cracaId and crlSeries values, and"]
    #[doc = " *  -\tare revoked by linkage data, and"]
    #[doc = " *  -\thave been revoked since the previous CRL that contained the indicated"]
    #[doc = " * cracaId and crlSeries values."]
    #[doc = " * The difference between deltaLinkedCrl and deltaLinkedCrlWithAlg is in how"]
    #[doc = " * the cryptographic algorithms to be used in the seed evolution function"]
    #[doc = " * and linkage value generation function of 5.1.3.4 are communicated to the"]
    #[doc = " * receiver of the CRL. See below in this subclause for details."]
    #[doc = " *"]
    #[doc = " * @note It is the intent of this standard that once a certificate is revoked,"]
    #[doc = " * it remains revoked for the rest of its lifetime. CRL signers are expected "]
    #[doc = " * to include a revoked certificate on all CRLs issued between the "]
    #[doc = " * certificate's revocation and its expiry."]
    #[doc = " *"]
    #[doc = " * @note Seed evolution function and linkage value generation function"]
    #[doc = " * identification. In order to derive linkage values per the mechanisms given"]
    #[doc = " * in 5.1.3.4, a receiver needs to know the seed evolution function and the"]
    #[doc = " * linkage value generation function."]
    #[doc = " *"]
    #[doc = " * If the contents of this structure is a"]
    #[doc = " * ToBeSignedLinkageValueCrlWithAlgIdentifier, then the seed evolution function"]
    #[doc = " * and linkage value generation function are given explicitly as specified in"]
    #[doc = " * the specification of ToBeSignedLinkageValueCrlWithAlgIdentifier."]
    #[doc = " *"]
    #[doc = " * If the contents of this structure is a ToBeSignedLinkageValueCrl, then the"]
    #[doc = " * seed evolution function and linkage value generation function are obtained"]
    #[doc = " * based on the crlCraca field in the CrlContents:"]
    #[doc = " *  - If crlCraca was obtained with SHA-256 or SHA-384, then"]
    #[doc = " * seedEvolutionFunctionIdentifier is seedEvoFn1-sha256 and"]
    #[doc = " * linkageValueGenerationFunctionIdentifier is lvGenFn1-aes128."]
    #[doc = " *  - If crlCraca was obtained with SM3, then seedEvolutionFunctionIdentifier"]
    #[doc = " * is seedEvoFn1-sm3 and linkageValueGenerationFunctionIdentifier is"]
    #[doc = " * lvGenFn1-sm4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum TypeSpecificCrlContents {
        fullHashCrl(ToBeSignedHashIdCrl),
        deltaHashCrl(ToBeSignedHashIdCrl),
        fullLinkedCrl(ToBeSignedLinkageValueCrl),
        deltaLinkedCrl(ToBeSignedLinkageValueCrl),
        #[rasn(extension_addition)]
        fullLinkedCrlWithAlg(ToBeSignedLinkageValueCrlWithAlgIdentifier),
        #[rasn(extension_addition)]
        deltaLinkedCrlWithAlg(ToBeSignedLinkageValueCrlWithAlgIdentifier),
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_aca_ee_interface {
    extern crate alloc;
    use super::ieee1609_dot2::Certificate;
    use super::ieee1609_dot2_base_types::{Time32, Uint8};
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This structure contains a certificate and associated data as"]
    #[doc = " * generated by the ACA for the EE that will be the holder of that"]
    #[doc = " * certificate. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @note In the case where the butterfly expansion function is used"]
    #[doc = " * to set certEncKey in RaAcaCertRequest, the value j is not communicated to"]
    #[doc = " * the ACA. However, the EE that receives the certificate response can only"]
    #[doc = " * decrypt the response if it knows j. The RA is therefore anticipated to"]
    #[doc = " * store j so that it can be associated with the appropriate certificate"]
    #[doc = " * response. The RA encodes j in the filename."]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param generationTime: contains the generation time of AcaEeCertResponse."]
    #[doc = " *"]
    #[doc = " * @param certificate: contains an authorization certificate generated by the"]
    #[doc = " * ACA. It is of the type indicated by the type field in the corresponding"]
    #[doc = " * request (if the requester requested an incorrect type, the response would"]
    #[doc = " * be an error not an instance of this structure)."]
    #[doc = " *"]
    #[doc = " * @param privateKeyInfo: shall be:"]
    #[doc = " *   - Present and contain the private key randomization value, if the field"]
    #[doc = " * certificate.type is explicit and the butterfly key mechanism was used to"]
    #[doc = " * generate the certificate. This is used by the EE in deriving the butterfly"]
    #[doc = " * private key for explicit certificates as specified in 9.3."]
    #[doc = " *   - Present and contain the private key reconstruction value, if the field"]
    #[doc = " * certificate.type is implicit. This is used by the EE as specified in 5.3.2"]
    #[doc = " * of IEEE Std 1609.2a-2017 (also 9.3 if the butterfly key mechanism is used)."]
    #[doc = " *   - Absent otherwise."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct AcaEeCertResponse {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Time32,
        pub certificate: Certificate,
        #[rasn(identifier = "privateKeyInfo")]
        pub private_key_info: Option<FixedOctetString<32>>,
    }
    impl AcaEeCertResponse {
        pub fn new(
            version: Uint8,
            generation_time: Time32,
            certificate: Certificate,
            private_key_info: Option<FixedOctetString<32>>,
        ) -> Self {
            Self {
                version,
                generation_time,
                certificate,
                private_key_info,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is the parent structure for all structures exchanged between"]
    #[doc = " * the ACA and the EE. The ACA - EE interface is a logical interface rather"]
    #[doc = " * than a direct communications interface in that there is no direct message"]
    #[doc = " * flow between the ACA and the EE: Messages from the ACA are stored"]
    #[doc = " * by the RA and subsequently forwarded to the EE. The PDUs are identified as"]
    #[doc = " * ACA-EE PDUs even though the RA acts as a forwarder for them because those"]
    #[doc = " * PDUs are created by the ACA and encrypted for the EE, and not modified and"]
    #[doc = " * frequently not read by the RA. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param acaEeCertResponse: contains the ACA's response to"]
    #[doc = " * RaAcaCertRequestSPDU, which is meant for the EE and sent via the RA."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum AcaEeInterfacePdu {
        acaEeCertResponse(AcaEeCertResponse),
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_aca_la_interface {
    extern crate alloc;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This structure is not used by EEs, so it is defined as NULL for"]
    #[doc = " * purposes of this document."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AcaLaInterfacePdu(());
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_aca_ma_interface {
    extern crate alloc;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This structure is not used by EEs, so it is defined as NULL for"]
    #[doc = " * purposes of this document."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AcaMaInterfacePdu(());
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_aca_ra_interface {
    extern crate alloc;
    use super::ieee1609_dot2::{CertificateType, ToBeSignedCertificate};
    use super::ieee1609_dot2_base_types::{
        HashAlgorithm, HashedId8, LaId, PublicEncryptionKey, Time32, Uint8,
    };
    use super::ieee1609_dot2_dot1_protocol::{
        AcaEeCertResponseCubkSpdu, AcaEeCertResponsePlainSpdu, AcaEeCertResponsePrivateSpdu,
        Ieee1609Dot2DataSymmEncryptedSingleRecipient,
    };
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This structure contains a certificate response by the ACA,"]
    #[doc = " * encapsulated for consumption by the EE, as well as associated data for"]
    #[doc = " * consumption by the RA. The response is of form AcaEeCertResponsePlainSpdu,"]
    #[doc = " * AcaEeCertResponsePrivateSpdu, or AcaEeCertResponseCubkSpdu, and is"]
    #[doc = " * generated in response to a successful RaAcaCertRequestSpdu. In this"]
    #[doc = " * structure:"]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param generationTime: contains the generation time of AcaRaCertResponse."]
    #[doc = " *"]
    #[doc = " * @param requestHash: contains the hash of the corresponding"]
    #[doc = " * RaAcaCertRequestSPDU."]
    #[doc = " *"]
    #[doc = " * @param acaResponse: contains the certificate for the EE in a suitable form"]
    #[doc = " * as determined from the corresponding RaAcaCertRequestSPDU."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct AcaRaCertResponse {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Time32,
        #[rasn(identifier = "requestHash")]
        pub request_hash: HashedId8,
        #[rasn(identifier = "acaResponse")]
        pub aca_response: AcaResponse,
    }
    impl AcaRaCertResponse {
        pub fn new(
            version: Uint8,
            generation_time: Time32,
            request_hash: HashedId8,
            aca_response: AcaResponse,
        ) -> Self {
            Self {
                version,
                generation_time,
                request_hash,
                aca_response,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is the parent structure for all structures exchanged between"]
    #[doc = " * the ACA and the RA. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param raAcaCertRequest: contains the request for an authorization"]
    #[doc = " * certificate from the RA to the ACA on behalf of the EE."]
    #[doc = " *"]
    #[doc = " * @param acaRaCertResponse: contains the ACA's response to RaAcaCertRequest."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum AcaRaInterfacePdu {
        raAcaCertRequest(RaAcaCertRequest),
        acaRaCertResponse(AcaRaCertResponse),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains the certificate for the EE in a suitable"]
    #[doc = " * form as determined from the corresponding RaAcaCertRequestSPDU. In this"]
    #[doc = " * structure:"]
    #[doc = " *"]
    #[doc = " * @param plain: contains the certificate for the EE in plain, that is, without"]
    #[doc = " * encryption or signature. This choice is used only when the field"]
    #[doc = " * certEncKey is absent and flags.cubk is not set in the corresponding"]
    #[doc = " * RaAcaCertRequest."]
    #[doc = " *"]
    #[doc = " * @param private: contains the certificate for the EE in an encrypted then"]
    #[doc = " * signed form to protect the EE's privacy from the RA. This choice is used"]
    #[doc = " * only when the field certEncKey is present and flags.cubk is not set in the"]
    #[doc = " * corresponding RaAcaCertRequest."]
    #[doc = " *"]
    #[doc = " * @param cubk: contains the certificate for the EE in an encrypted form. This"]
    #[doc = " * choice is used only when the field certEncKey is absent and flags.cubk is"]
    #[doc = " * set in the corresponding RaAcaCertRequest."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum AcaResponse {
        plain(AcaEeCertResponsePlainSpdu),
        private(AcaEeCertResponsePrivateSpdu),
        cubk(AcaEeCertResponseCubkSpdu),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains an individual prelinkage value encrypted by"]
    #[doc = " * the LA for the ACA using the shared secret key. An overview of this"]
    #[doc = " * structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @note How the ACA obtains the shared symmetric key and how the RA"]
    #[doc = " * associates the encPlv1 and encPlv2 with the correct certificate request are"]
    #[doc = " * outside the scope of this document."]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param laId: contains the ID of the LA that created the prelinkage value."]
    #[doc = " * See Annex D for further discussion of LA IDs."]
    #[doc = " *"]
    #[doc = " * @param encPlv: contains the encrypted individual prelinkage value, that is,"]
    #[doc = " * the ciphertext field decrypts to a PreLinkageValue. It contains a pointer"]
    #[doc = " * (hash of the shared symmetric key) to the used shared secret encryption key."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct EncryptedIndividualPLV {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "laId")]
        pub la_id: LaId,
        #[rasn(value("0.."), identifier = "encPlv")]
        pub enc_plv: Ieee1609Dot2DataSymmEncryptedSingleRecipient,
    }
    impl EncryptedIndividualPLV {
        pub fn new(
            version: Uint8,
            la_id: LaId,
            enc_plv: Ieee1609Dot2DataSymmEncryptedSingleRecipient,
        ) -> Self {
            Self {
                version,
                la_id,
                enc_plv,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains parameters needed to generate a linkage"]
    #[doc = " * value for a given (EE, i, j). An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @note See Annex D for further discussion of LAs."]
    #[doc = " *"]
    #[doc = " * @param encPlv1: contains the EncryptedIndividualPLV from one of the LAs."]
    #[doc = " *"]
    #[doc = " * @param encPlv2: contains the EncryptedIndividualPLV from the other LA."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct LinkageInfo {
        #[rasn(identifier = "encPlv1")]
        pub enc_plv1: EncryptedIndividualPLV,
        #[rasn(identifier = "encPlv2")]
        pub enc_plv2: EncryptedIndividualPLV,
    }
    impl LinkageInfo {
        pub fn new(enc_plv1: EncryptedIndividualPLV, enc_plv2: EncryptedIndividualPLV) -> Self {
            Self { enc_plv1, enc_plv2 }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains an individual prelinkage value. It is an"]
    #[doc = " * octet string of length 9 octets."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct PreLinkageValue(pub FixedOctetString<9>);
    #[doc = "*"]
    #[doc = " * @brief This structure contains parameters needed to request an individual"]
    #[doc = " * authorization certificate. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @note:"]
    #[doc = " *   - In the case where the butterfly key mechanism is used to set"]
    #[doc = " * certEncKey, the value of j is not communicated to the ACA. However, the EE"]
    #[doc = " * that receives the certificate response can only decrypt the response if it"]
    #[doc = " * knows j. The RA is therefore anticipated to store j so that it can be"]
    #[doc = " * associated with the appropriate certificate response."]
    #[doc = " *"]
    #[doc = " *   - The cracaId and crlSeries are set to the indicated values"]
    #[doc = " * in the request. The ACA replaces these values with the appropriate values"]
    #[doc = " * in the response."]
    #[doc = " *"]
    #[doc = " *   - The ACA is not bound by the contents of the request and can"]
    #[doc = " * issue certificates that are different from those requested, if so directed"]
    #[doc = " * by policy."]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param generationTime: contains the generation time of RaAcaCertRequest."]
    #[doc = " *"]
    #[doc = " * @param type: indicates whether the request is for an explicit or implicit"]
    #[doc = " * certificate (see 4.1.1, 4.1.3.3.1)."]
    #[doc = " *"]
    #[doc = " * @param flags: contains the flags related to the use of the butterfly key"]
    #[doc = " * mechanism, and provides the following instructions to the ACA as to how"]
    #[doc = " * to generate the response:"]
    #[doc = " *   - If the flag butterflyExplicit is set, the request is valid only if"]
    #[doc = " * the type field is set to explicit. In this case, the ACA uses the"]
    #[doc = " * butterfly key derivation for explicit certificates as specified in 9.3."]
    #[doc = " * The field tbsCert.verifyKeyIndicator.verificationKey is used by the ACA as"]
    #[doc = " * the cocoon public key for signing. The field privateKeyInfo in the"]
    #[doc = " * corresponding AcaEeCertResponse is used by the EE as the random integer to"]
    #[doc = " * recover the butterfly private key for signing."]
    #[doc = " *   - If the flag cubk is set, the request is valid only if the certEncKey"]
    #[doc = " * field is absent. In this case, the ACA uses the compact unified variation"]
    #[doc = " * of the butterfly key mechanism as specified in 9.3. This means that the"]
    #[doc = " * ACA generates an AcaEeCertResponseCubkSpdu instead of an"]
    #[doc = " * AcaEeCertResponsePrivateSpdu, and the response is valid only if the ACA"]
    #[doc = " * certificate has the flag cubk set."]
    #[doc = " *"]
    #[doc = " * @param linkageInfo: contains the encrypted prelinkage values needed to"]
    #[doc = " * generate the linkage value for the certificate. If linkageInfo is present,"]
    #[doc = " * the field tbsCert.id is of type LinkageData, where the iCert field is set"]
    #[doc = " * to the actual i-period value and the linkage-value field is set to a dummy"]
    #[doc = " * value to be replaced by the ACA with the actual linkage value. The"]
    #[doc = " * encrypted prelinkage values are encrypted for the ACA by the LAs."]
    #[doc = " *"]
    #[doc = " * @param certEncKey: is used in combination with flags.cubk to indicate"]
    #[doc = " * the type of response that is expected from the ACA. It is as follows:"]
    #[doc = " *   - Absent and flags.cubk is not set if the ACA's response doesn't need"]
    #[doc = " * to be encrypted. In this case, the ACA responds with"]
    #[doc = " * AcaEeCertResponsePlainSpdu."]
    #[doc = " *   - Absent and flags.cubk is set if the ACA's response is to be encrypted"]
    #[doc = " * with the verification key from the request and not signed. In this case,"]
    #[doc = " * the ACA responds with AcaEeCertResponseCubkSpdu."]
    #[doc = " *   - Present and flags.cubk is not set if the ACA's response is to be"]
    #[doc = " * encrypted with certEncKey and then signed by the ACA. In this case, the"]
    #[doc = " * ACA responds with AcaEeCertResponsePrivateSpdu."]
    #[doc = " *"]
    #[doc = " * @param tbsCert: contains parameters of the requested certificate. The"]
    #[doc = " * certificate type depends on the field type, as follows:"]
    #[doc = " *   - If type is explicit, the request is valid only if"]
    #[doc = " * tbsCert.verifyKeyIndicator is a verificationKey."]
    #[doc = " *   - If type is implicit, the request is valid only if"]
    #[doc = " * tbsCert.verifyKeyIndicator is a reconstructionValue."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct RaAcaCertRequest {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Time32,
        #[rasn(identifier = "type")]
        pub r_type: CertificateType,
        pub flags: RaAcaCertRequestFlags,
        #[rasn(identifier = "linkageInfo")]
        pub linkage_info: Option<LinkageInfo>,
        #[rasn(identifier = "certEncKey")]
        pub cert_enc_key: Option<PublicEncryptionKey>,
        #[rasn(value("0.."), identifier = "tbsCert")]
        pub tbs_cert: ToBeSignedCertificate,
    }
    impl RaAcaCertRequest {
        pub fn new(
            version: Uint8,
            generation_time: Time32,
            r_type: CertificateType,
            flags: RaAcaCertRequestFlags,
            linkage_info: Option<LinkageInfo>,
            cert_enc_key: Option<PublicEncryptionKey>,
            tbs_cert: ToBeSignedCertificate,
        ) -> Self {
            Self {
                version,
                generation_time,
                r_type,
                flags,
                linkage_info,
                cert_enc_key,
                tbs_cert,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure is used to convey information from the RA to the ACA"]
    #[doc = " * about operations to be carried out when generating the certificate. For"]
    #[doc = " * more details see the specification of RaAcaCertRequest. An overview of"]
    #[doc = " * this structure is as follows:"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("8"))]
    pub struct RaAcaCertRequestFlags(pub BitString);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_acpc {
    extern crate alloc;
    use super::ieee1609_dot2_base_types::{HashAlgorithm, IValue, Psid, Time32, Uint8};
    use super::ieee1609_dot2_dot1_protocol::{Ieee1609Dot2DataSigned, Ieee1609Dot2DataUnsecured};
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This is a 16 byte string that represents the value of a node in the"]
    #[doc = " * ACPC tree."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AcpcNodeValue(pub FixedOctetString<16>);
    #[doc = "*"]
    #[doc = " * @brief This structure contains an APrV structure produced by the CAM. An"]
    #[doc = " * overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param tree: contains an AprvBinaryTree."]
    #[doc = " *"]
    #[doc = " * @param aprv: contains a single IndividualAprv."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum AcpcPdu {
        tree(AprvBinaryTree),
        aprv(IndividualAprv),
    }
    #[doc = "*"]
    #[doc = " * @brief This is the PSID used to indicate activities in ACPC as specified in"]
    #[doc = " * this document."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, value("2113696"))]
    pub struct AcpcPsid(pub Psid);
    #[doc = "*"]
    #[doc = " * @brief This is an 8 byte string that identifies an ACPC tree series. It is"]
    #[doc = " * required to be globally unique within the system and is the same for all"]
    #[doc = " * ACPC tree instances within the ACPC tree series. Registration of AcpcTreeId"]
    #[doc = " * values is managed by the IEEE RA; see http://standards.ieee.org/regauth. A"]
    #[doc = " * list of assigned AcpcTreeId values is provided in L.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AcpcTreeId(pub FixedOctetString<8>);
    #[doc = "*"]
    #[doc = " * @brief This structure encodes a binary tree. An overview of this structure"]
    #[doc = " * is as follows:"]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param generationTime: contains the generation time of AprvBinaryTree."]
    #[doc = " *"]
    #[doc = " * @param currentI: contains the i-value associated with the batch of"]
    #[doc = " * certificates."]
    #[doc = " *"]
    #[doc = " * @param acpcTreeId: contains an identifier for the CAM creating this binary"]
    #[doc = " * tree."]
    #[doc = " *"]
    #[doc = " * @param hashAlgorithmId: contains the identifier of the hash algorithm used"]
    #[doc = " * inside the binary tree."]
    #[doc = " *"]
    #[doc = " * @param tree: contains a bit string indicating which nodes of the tree are"]
    #[doc = " * present. It is calculated as specified in 9.5.4.2, and can be used by the"]
    #[doc = " * EE to determine which entry in nodeValueList to use to derive that EE's"]
    #[doc = " * APrV as specified in 9.5.2."]
    #[doc = " *"]
    #[doc = " * @param nodeValueList: contains the values of the nodes that are present in"]
    #[doc = " * the order indicated by tree."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct AprvBinaryTree {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Time32,
        #[rasn(identifier = "currentI")]
        pub current_i: IValue,
        #[rasn(identifier = "acpcTreeId")]
        pub acpc_tree_id: AcpcTreeId,
        #[rasn(identifier = "hashAlgorithmId")]
        pub hash_algorithm_id: HashAlgorithm,
        pub tree: BitString,
        #[rasn(size("1.."), identifier = "nodeValueList")]
        pub node_value_list: SequenceOf<AcpcNodeValue>,
    }
    impl AprvBinaryTree {
        pub fn new(
            version: Uint8,
            generation_time: Time32,
            current_i: IValue,
            acpc_tree_id: AcpcTreeId,
            hash_algorithm_id: HashAlgorithm,
            tree: BitString,
            node_value_list: SequenceOf<AcpcNodeValue>,
        ) -> Self {
            Self {
                version,
                generation_time,
                current_i,
                acpc_tree_id,
                hash_algorithm_id,
                tree,
                node_value_list,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure, C-OER encoded, is the input to the hash function to"]
    #[doc = " * calculate child node values from a parent node. By including the ID fields"]
    #[doc = " * it \"firewalls\" the hash function so that an attacker who inverts the hash"]
    #[doc = " * has only found the hash preimage for a specific node, in a specific tree,"]
    #[doc = " * for a specific time period. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param acpcTreeId: contains an identifier for this ACPC tree series."]
    #[doc = " *"]
    #[doc = " * @param acpcPeriod: contains an identifier for the time period for this tree."]
    #[doc = " * If the certificates for which this set of APrVs are intended have an IValue"]
    #[doc = " * field, acpcPeriod in this structure shall be the IValue field in the"]
    #[doc = " * certificates. How the RA and the CAM synchronize on this value is outside"]
    #[doc = " * the scope of this document."]
    #[doc = " *"]
    #[doc = " * @param childNodeId: contains a bit string of length l encoding the node"]
    #[doc = " * location within the l'th level."]
    #[doc = " *"]
    #[doc = " * @param parentNodeValue: contains the value of the parent node."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct AprvHashCalculationInput {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "acpcTreeId")]
        pub acpc_tree_id: AcpcTreeId,
        #[rasn(identifier = "acpcPeriod")]
        pub acpc_period: IValue,
        #[rasn(identifier = "childNodeId")]
        pub child_node_id: BitString,
        #[rasn(identifier = "parentNodeValue")]
        pub parent_node_value: FixedOctetString<16>,
    }
    impl AprvHashCalculationInput {
        pub fn new(
            version: Uint8,
            acpc_tree_id: AcpcTreeId,
            acpc_period: IValue,
            child_node_id: BitString,
            parent_node_value: FixedOctetString<16>,
        ) -> Self {
            Self {
                version,
                acpc_tree_id,
                acpc_period,
                child_node_id,
                parent_node_value,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains an individual APrV. An overview of this"]
    #[doc = " * structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param generationTime: contains the generation time of IndividualAprv."]
    #[doc = " *"]
    #[doc = " * @param currentI: contains the i-value associated with the batch of"]
    #[doc = " * certificates."]
    #[doc = " *"]
    #[doc = " * @param acpcTreeId: contains an identifier for the CAM creating this binary"]
    #[doc = " * tree."]
    #[doc = " *"]
    #[doc = " * @param nodeId: contains the identifier of the node."]
    #[doc = " *"]
    #[doc = " * @param nodeValue: contains the value of the node."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct IndividualAprv {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Time32,
        #[rasn(identifier = "currentI")]
        pub current_i: IValue,
        #[rasn(identifier = "acpcTreeId")]
        pub acpc_tree_id: AcpcTreeId,
        #[rasn(identifier = "nodeId")]
        pub node_id: BitString,
        #[rasn(identifier = "nodeValue")]
        pub node_value: AcpcNodeValue,
    }
    impl IndividualAprv {
        pub fn new(
            version: Uint8,
            generation_time: Time32,
            current_i: IValue,
            acpc_tree_id: AcpcTreeId,
            node_id: BitString,
            node_value: AcpcNodeValue,
        ) -> Self {
            Self {
                version,
                generation_time,
                current_i,
                acpc_tree_id,
                node_id,
                node_value,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is used to wrap an AprvBinaryTree in an Ieee1609Dot2Data for"]
    #[doc = " * transmission if the policy is that the AprvBinaryTree be signed. See 9.5.6"]
    #[doc = " * for discussion."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SignedAprvBinaryTree(pub Ieee1609Dot2DataSigned);
    #[doc = "*"]
    #[doc = " * @brief This is used to wrap an IndividualAprv in an Ieee1609Dot2Data for"]
    #[doc = " * transmission if the policy is that the IndividualAprv be signed. See 9.5.6"]
    #[doc = " * for discussion."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SignedIndividualAprv(pub Ieee1609Dot2DataSigned);
    #[doc = "*"]
    #[doc = " * @brief This is used to wrap an AprvBinaryTree in an Ieee1609Dot2Data for"]
    #[doc = " * transmission if the policy is that the AprvBinaryTree need not be signed."]
    #[doc = " * See 9.5.6 for discussion."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct UnsecuredAprvBinaryTree(pub Ieee1609Dot2DataUnsecured);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_cam_ra_interface {
    extern crate alloc;
    use super::ieee1609_dot2_base_types::{EccP256CurvePoint, HashedId8, IValue, Uint8};
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This is a blinded ACPC encryption key produced by the CAM."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct BlindedKey(pub EccP256CurvePoint);
    #[doc = "*"]
    #[doc = " * @brief This structure contains a blinded batch of keys for the EE during"]
    #[doc = " * ACPC enrollment. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param requestHash: contains the hash of the corresponding request"]
    #[doc = " * RaCamBatchRequest."]
    #[doc = " *"]
    #[doc = " * @param batch: contains a sequence of blinded keys, each mapped to one"]
    #[doc = " * IValue from the periodList field of the request."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CamRaBatchResponse {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "requestHash")]
        pub request_hash: HashedId8,
        pub batch: SequenceOf<BlindedKey>,
    }
    impl CamRaBatchResponse {
        pub fn new(version: Uint8, request_hash: HashedId8, batch: SequenceOf<BlindedKey>) -> Self {
            Self {
                version,
                request_hash,
                batch,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is the parent structure for all structures exchanged between"]
    #[doc = " * the CAM and the RA during ACPC enrollment. An overview of this structure"]
    #[doc = " * is as follows:"]
    #[doc = " *"]
    #[doc = " * @param raCamBatchRequest: contains the ACPC blinded key batch request sent"]
    #[doc = " * by the RA to the CAM."]
    #[doc = " *"]
    #[doc = " * @param camRaBatchResponse: contains the CAM's response to RaCamBatchRequest."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CamRaInterfacePdu {
        raCamBatchRequest(RaCamBatchRequest),
        camRaBatchResponse(CamRaBatchResponse),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains parameters needed to request a blinded batch"]
    #[doc = " * of keys for the EE during ACPC enrollment. An overview of this structure"]
    #[doc = " * is as follows:"]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param eeId: contains the EE's ID generated by the RA for the production of"]
    #[doc = " * ACPC batch keys by the CAM."]
    #[doc = " *"]
    #[doc = " * @param periodList: contains the list of i-periods covered by the batch."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct RaCamBatchRequest {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "eeId")]
        pub ee_id: FixedOctetString<5>,
        #[rasn(identifier = "periodList")]
        pub period_list: SequenceOf<IValue>,
    }
    impl RaCamBatchRequest {
        pub fn new(
            version: Uint8,
            ee_id: FixedOctetString<5>,
            period_list: SequenceOf<IValue>,
        ) -> Self {
            Self {
                version,
                ee_id,
                period_list,
            }
        }
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_cert_management {
    extern crate alloc;
    use super::ieee1609_dot2::{Certificate, SequenceOfCertificate};
    use super::ieee1609_dot2_base_types::{
        CrlSeries, HashedId32, HashedId48, HashedId8, SequenceOfPsid, Time32, Uint8,
    };
    use super::ieee1609_dot2_crl::SecuredCrl;
    use super::ieee1609_dot2_dot1_protocol::{CtlSignatureSpdu, MultiSignedCtlSpdu};
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This is the parent structure for all SCMS component certificate"]
    #[doc = " * management structures. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param compositeCrl: contains zero or more SecuredCrl as defined in IEEE"]
    #[doc = " * Std 1609.2, and the CTL."]
    #[doc = " *"]
    #[doc = " * @param certificateChain: contains a collection of certificates and the CTL."]
    #[doc = " *"]
    #[doc = " * @param multiSignedCtl: contains the CTL signed by multiple"]
    #[doc = " * signers, the electors."]
    #[doc = " *"]
    #[doc = " * @param tbsCtlSignature: contains the CTL-instance-specific information used"]
    #[doc = " * to generate a signature on the CTL."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CertManagementPdu {
        compositeCrl(CompositeCrl),
        certificateChain(CertificateChain),
        multiSignedCtl(MultiSignedCtl),
        tbsCtlSignature(ToBeSignedCtlSignature),
        infoStatus(CertificateManagementInfoStatus),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure is used to encapsulate certificates and a CTL. An"]
    #[doc = " * overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param homeCtl: contains a CTL. If the certificate chain was requested via"]
    #[doc = " * the mechanisms given in 6.3.5.7, the CtlSeriesId in this CTL is the"]
    #[doc = " * same as the CtlSeriesId provided in the request. The intent is that"]
    #[doc = " * this is the \"home\" CTL of the requester, but this field can in practice be"]
    #[doc = " * used to provide any CTL."]
    #[doc = " *"]
    #[doc = " * @param others: contains additional valid certificates of the CAs and the"]
    #[doc = " * MAs chosen by means outside the scope of this document."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CertificateChain {
        #[rasn(identifier = "homeCtl")]
        pub home_ctl: MultiSignedCtlSpdu,
        pub others: SequenceOf<Certificate>,
    }
    impl CertificateChain {
        pub fn new(home_ctl: MultiSignedCtlSpdu, others: SequenceOf<Certificate>) -> Self {
            Self { home_ctl, others }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains the status of different certificate"]
    #[doc = " * management information, including CRLs, CTLs, and individual certificates"]
    #[doc = " * of CAs, MAs, and the RA."]
    #[doc = " *"]
    #[doc = " * @param crl: contains the status information for CRLs."]
    #[doc = " *"]
    #[doc = " * @param ctl: contains the status information for CTLs."]
    #[doc = " *"]
    #[doc = " * @param caCcf: contains the time of the last update of any of the CA"]
    #[doc = " * certificates in the CCF."]
    #[doc = " *"]
    #[doc = " * @param ma: contains the status information for MA certificates."]
    #[doc = " *"]
    #[doc = " * @param ra: shall be present and contain the time of last update of the RA's"]
    #[doc = " * certificate, if this structure is sent by an RA."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CertificateManagementInfoStatus {
        pub crl: SequenceOfCrlInfoStatus,
        pub ctl: SequenceOfCtlInfoStatus,
        #[rasn(identifier = "caCcf")]
        pub ca_ccf: Time32,
        pub ma: SequenceOfMaInfoStatus,
        pub ra: Option<Time32>,
    }
    impl CertificateManagementInfoStatus {
        pub fn new(
            crl: SequenceOfCrlInfoStatus,
            ctl: SequenceOfCtlInfoStatus,
            ca_ccf: Time32,
            ma: SequenceOfMaInfoStatus,
            ra: Option<Time32>,
        ) -> Self {
            Self {
                crl,
                ctl,
                ca_ccf,
                ma,
                ra,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure is used to encapsulate CRLs and a CTL. An overview"]
    #[doc = " * of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param crl: contains a list of signed CRLs for different (CRACA ID, CRL"]
    #[doc = " * series) pairs. The CRLs are signed individually, and this document does not"]
    #[doc = " * specify the order in which they should appear."]
    #[doc = " *"]
    #[doc = " * @param homeCtl: contains a CTL. If the composite CRL was requested via the"]
    #[doc = " * mechanisms given in 6.3.5.8, the CtlSeriesId in this CTL is the same as"]
    #[doc = " * the CtlSeriesId provided in the request. The intent is that this is the"]
    #[doc = " * \"home\" CTL of the requester, but this field can in practice be used to"]
    #[doc = " * provide any CTL with any CtlSeriesId value."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CompositeCrl {
        pub crl: SequenceOf<SecuredCrl>,
        #[rasn(identifier = "homeCtl")]
        pub home_ctl: MultiSignedCtlSpdu,
    }
    impl CompositeCrl {
        pub fn new(crl: SequenceOf<SecuredCrl>, home_ctl: MultiSignedCtlSpdu) -> Self {
            Self { crl, home_ctl }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains the status information for a CRL."]
    #[doc = " *"]
    #[doc = " * @param cracaId: contains the CRACA ID of the CRL."]
    #[doc = " *"]
    #[doc = " * @param series: contains the CRL series of the CRL."]
    #[doc = " *"]
    #[doc = " * @param issueDate: contains the time of the last update of the CRL."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CrlInfoStatus {
        #[rasn(identifier = "cracaId")]
        pub craca_id: HashedId8,
        pub series: CrlSeries,
        #[rasn(identifier = "issueDate")]
        pub issue_date: Time32,
    }
    impl CrlInfoStatus {
        pub fn new(craca_id: HashedId8, series: CrlSeries, issue_date: Time32) -> Self {
            Self {
                craca_id,
                series,
                issue_date,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains the hash of an elector certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CtlElectorEntry(pub HashedId48);
    #[doc = "*"]
    #[doc = " * @brief This structure contains the status information for a CTL."]
    #[doc = " *"]
    #[doc = " * @param ctlSeriesId: contains the elector group ID of the CTL."]
    #[doc = " *"]
    #[doc = " * @param sequenceNumber: contains the sequence number of the CTL."]
    #[doc = " *"]
    #[doc = " * @param lastUpdate: contains the time of the last update of the CTL."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CtlInfoStatus {
        #[rasn(identifier = "ctlSeriesId")]
        pub ctl_series_id: CtlSeriesId,
        #[rasn(identifier = "sequenceNumber")]
        pub sequence_number: CtlSequenceNumber,
        #[rasn(identifier = "lastUpdate")]
        pub last_update: Time32,
    }
    impl CtlInfoStatus {
        pub fn new(
            ctl_series_id: CtlSeriesId,
            sequence_number: CtlSequenceNumber,
            last_update: Time32,
        ) -> Self {
            Self {
                ctl_series_id,
                sequence_number,
                last_update,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains the hash of a root CA certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CtlRootCaEntry(pub HashedId32);
    #[doc = "*"]
    #[doc = " * @brief This structure is used to encode the CTL sequence number. This"]
    #[doc = " * document does not specify semantics of this type once it reaches its"]
    #[doc = " * maximum value."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("0..=65535"))]
    pub struct CtlSequenceNumber(pub u16);
    #[doc = "*"]
    #[doc = " * @brief This structure identifies a group of electors that sign a series of"]
    #[doc = " * CTLs for a specific purpose. Registration of CtlSeriesId values is"]
    #[doc = " * managed by the IEEE RA; see http://standards.ieee.org/regauth. A list of"]
    #[doc = " * assigned CtlSeriesId values is provided in K.1."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CtlSeriesId(pub FixedOctetString<8>);
    #[doc = "*"]
    #[doc = " * @brief This structure specifies a CTL that contains information about the"]
    #[doc = " * complete set of certificates trusted by the electors that sign the CTL. An"]
    #[doc = " * overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @note:"]
    #[doc = " *   - If in future CTL types are defined that contain the same"]
    #[doc = " * information as, or a subset of the information in, the fullIeeeCtl, those"]
    #[doc = " * types are anticipated to contain the same sequence number as the"]
    #[doc = " * corresponding fullIeeeCtl."]
    #[doc = " *"]
    #[doc = " *   - Any root CA or elector certificate that is not on the CTL is"]
    #[doc = " * not trusted. The electorRemove and rootCaRemove are intended to be used"]
    #[doc = " * only if the SCMS manager wants to explicitly indicate that a previously"]
    #[doc = " * trusted entity (elector or root CA) is now not trusted even though that"]
    #[doc = " * entity's certificate is still within its validity period. In practice, it"]
    #[doc = " * is anticipated that the remove fields (electorRemove and rootCaRemove)"]
    #[doc = " * will almost always be sequences of length 0."]
    #[doc = " *"]
    #[doc = " * @param type: contains the type of the CTL. It is identical to the type"]
    #[doc = " * field that appears in the enclosing MultiSignedCtl. The field is included"]
    #[doc = " * here as well to provide the simplest mechanism to help ensure that the"]
    #[doc = " * type is included in the calculated CTL hash."]
    #[doc = " *"]
    #[doc = " * @param CtlSeriesId: contains the group of electors that have signed the"]
    #[doc = " * CTL. It plays a role similar to CrlSeries in a CRL. This field is intended"]
    #[doc = " * to be globally unique in the universe of all systems that use the"]
    #[doc = " * MultiSignedCtl. See the specification of CtlSeriesId for discussion of"]
    #[doc = " * a convention that can be followed to enable uniqueness."]
    #[doc = " *"]
    #[doc = " * @param sequenceNumber: contains the sequence number of the CTL. This is"]
    #[doc = " * incremented by 1 every time a new FullIeeeTbsCtl is issued."]
    #[doc = " *"]
    #[doc = " * @param effectiveDate: contains the time when the CTL is to take effect."]
    #[doc = " * This is to be greater than or equal to the effectiveDate field in the CTL"]
    #[doc = " * with the same CtlSeriesId and the previous sequence number."]
    #[doc = " *"]
    #[doc = " * @param electorApprove: contains the list of hashes of the elector"]
    #[doc = " * certificates that are approved as of the effective date. The hash is"]
    #[doc = " * calculated with the same hash algorithm that is used to hash the elector"]
    #[doc = " * certificate for signing."]
    #[doc = " *"]
    #[doc = " * @param electorRemove: contains the list of hashes of the elector"]
    #[doc = " * certificates that are valid (that is, not expired) on the effective date and"]
    #[doc = " * are not approved, as of the effective date, to sign a CTL. The hash is"]
    #[doc = " * calculated with the same hash algorithm that is used to hash the elector"]
    #[doc = " * certificate for signing. This field is to be considered informational as a"]
    #[doc = " * certificate that is not included in electorApprove is not valid even if it"]
    #[doc = " * does not appear in electorRemove."]
    #[doc = " *"]
    #[doc = " * @param rootCaApprove: contains the list of root CA certificates that are"]
    #[doc = " * approved as of the effective date. The hash is calculated with the same"]
    #[doc = " * hash algorithm that is used to hash the root certificate for signing. If"]
    #[doc = " * the root certificate is signed with a hash function with a 48 octet"]
    #[doc = " * output, this is truncated to the low-order 32 bytes for inclusion in the"]
    #[doc = " * CTL."]
    #[doc = " *"]
    #[doc = " * @param rootCaRemove: contains the list of root CA certificates that are"]
    #[doc = " * valid (that is, not expired) on the effective date and are not approved, as"]
    #[doc = " * of the effective date, to issue certificates or carry out other"]
    #[doc = " * activities. If the root certificate is signed with a hash function"]
    #[doc = " * with a 48 octet output, this is truncated to the low-order 32 bytes for"]
    #[doc = " * inclusion in the CTL. This field is to be considered informational as a"]
    #[doc = " * certificate that is not included in rootCaApprove is not valid even if it"]
    #[doc = " * does not appear in rootCaRemove."]
    #[doc = " *"]
    #[doc = " * @param quorum: contains the quorum, that is, the number of the electors"]
    #[doc = " * required to sign the next CTL with the same CtlSeriesId value for that"]
    #[doc = " * CTL to be trusted. If this field is absent, the quorum for the next CTL"]
    #[doc = " * shall be the quorum for the current CTL."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct FullIeeeTbsCtl {
        #[rasn(value("1"), identifier = "type")]
        pub r_type: Ieee1609dot2dot1MsctlType,
        #[rasn(identifier = "ctlSeriesId")]
        pub ctl_series_id: CtlSeriesId,
        #[rasn(identifier = "sequenceNumber")]
        pub sequence_number: CtlSequenceNumber,
        #[rasn(identifier = "effectiveDate")]
        pub effective_date: Time32,
        #[rasn(identifier = "electorApprove")]
        pub elector_approve: SequenceOf<CtlElectorEntry>,
        #[rasn(identifier = "electorRemove")]
        pub elector_remove: SequenceOf<CtlElectorEntry>,
        #[rasn(identifier = "rootCaApprove")]
        pub root_ca_approve: SequenceOf<CtlRootCaEntry>,
        #[rasn(identifier = "rootCaRemove")]
        pub root_ca_remove: SequenceOf<CtlRootCaEntry>,
        #[rasn(extension_addition)]
        pub quorum: Integer,
    }
    impl FullIeeeTbsCtl {
        pub fn new(
            r_type: Ieee1609dot2dot1MsctlType,
            ctl_series_id: CtlSeriesId,
            sequence_number: CtlSequenceNumber,
            effective_date: Time32,
            elector_approve: SequenceOf<CtlElectorEntry>,
            elector_remove: SequenceOf<CtlElectorEntry>,
            root_ca_approve: SequenceOf<CtlRootCaEntry>,
            root_ca_remove: SequenceOf<CtlRootCaEntry>,
            quorum: Integer,
        ) -> Self {
            Self {
                r_type,
                ctl_series_id,
                sequence_number,
                effective_date,
                elector_approve,
                elector_remove,
                root_ca_approve,
                root_ca_remove,
                quorum,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is the integer used to identify the type of the CTL."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, PartialOrd, Eq, Ord, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct Ieee1609dot2dot1MsctlType(pub u8);
    #[doc = "*"]
    #[doc = " * @brief This structure contains the status information for an MA's"]
    #[doc = " * certificate."]
    #[doc = " *"]
    #[doc = " * @param psids: contains the PSIDs associated with the misbehavior that is to"]
    #[doc = " * be reported to that MA."]
    #[doc = " *"]
    #[doc = " * @param updated: contains the time of the last update of the MA's certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct MaInfoStatus {
        pub psids: SequenceOfPsid,
        pub updated: Time32,
    }
    impl MaInfoStatus {
        pub fn new(psids: SequenceOfPsid, updated: Time32) -> Self {
            Self { psids, updated }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure a certificate trust list (CTL) signed by multiple"]
    #[doc = " * signers, the electors. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param type: contains the type of the multi-signed CTL. Only one type of"]
    #[doc = " * multi-signed CTL is supported in this version of this document."]
    #[doc = " *"]
    #[doc = " * @param tbsCtl: contains the CTL contents."]
    #[doc = " *"]
    #[doc = " * @param unsigned: contains data that are associated with the CTL and that"]
    #[doc = " * are not included directly in tbsCtl. For example, if the type is"]
    #[doc = " * fullIeeeCtlType, the FullIeeeTbsCtl contains the hashes of the"]
    #[doc = " * certificates, and the certificates themselves are contained in unsigned."]
    #[doc = " *"]
    #[doc = " * @param signatures: contains the signatures. How the signatures are"]
    #[doc = " * calculated is specified in the definition of ToBeSignedCtlSignature. The"]
    #[doc = " * number of signatures shall be no more than the number of electors. Each"]
    #[doc = " * signature shall have been generated by a distinct elector."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct MultiSignedCtl {
        #[rasn(identifier = "type")]
        pub r_type: Ieee1609dot2dot1MsctlType,
        #[rasn(identifier = "tbsCtl")]
        pub tbs_ctl: Any,
        pub unsigned: Any,
        #[rasn(size("1.."))]
        pub signatures: SequenceOf<CtlSignatureSpdu>,
    }
    impl MultiSignedCtl {
        pub fn new(
            r_type: Ieee1609dot2dot1MsctlType,
            tbs_ctl: Any,
            unsigned: Any,
            signatures: SequenceOf<CtlSignatureSpdu>,
        ) -> Self {
            Self {
                r_type,
                tbs_ctl,
                unsigned,
                signatures,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfCrlInfoStatus(pub SequenceOf<CrlInfoStatus>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfCtlInfoStatus(pub SequenceOf<CtlInfoStatus>);
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SequenceOfMaInfoStatus(pub SequenceOf<MaInfoStatus>);
    #[doc = "*"]
    #[doc = " * @brief This structure contains the CTL-instance-specific information used"]
    #[doc = " * to generate a signature on the CTL. An overview of this structure is as"]
    #[doc = " * follows:"]
    #[doc = " *"]
    #[doc = " * @param ctlSeriesId: contains the CtlSeriesId that appears in the CTL."]
    #[doc = " *"]
    #[doc = " * @param ctlType: identifies the type of the CTL."]
    #[doc = " *"]
    #[doc = " * @param sequenceNumber: contains the sequence number of the CTL being signed."]
    #[doc = " *"]
    #[doc = " * @param tbsCtlHash: contains the hash of the C-OER encoded tbsCtl field"]
    #[doc = " * in the MultiSignedCtl. The hash is calculated using the same hash"]
    #[doc = " * algorithm that is used to generate the signature on this structure when it"]
    #[doc = " * is contained in a CtlSignatureSpdu. This algorithm can be determined from"]
    #[doc = " * the headers of the CtlSignatureSpdu."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct ToBeSignedCtlSignature {
        #[rasn(identifier = "ctlSeriesId")]
        pub ctl_series_id: CtlSeriesId,
        #[rasn(identifier = "ctlType")]
        pub ctl_type: Ieee1609dot2dot1MsctlType,
        #[rasn(identifier = "sequenceNumber")]
        pub sequence_number: CtlSequenceNumber,
        #[rasn(identifier = "tbsCtlHash")]
        pub tbs_ctl_hash: HashedId48,
    }
    impl ToBeSignedCtlSignature {
        pub fn new(
            ctl_series_id: CtlSeriesId,
            ctl_type: Ieee1609dot2dot1MsctlType,
            sequence_number: CtlSequenceNumber,
            tbs_ctl_hash: HashedId48,
        ) -> Self {
            Self {
                ctl_series_id,
                ctl_type,
                sequence_number,
                tbs_ctl_hash,
            }
        }
    }
    pub const FULL_IEEE_CTL: Ieee1609dot2dot1MsctlType = Ieee1609dot2dot1MsctlType(1);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_eca_ee_interface {
    extern crate alloc;
    use super::ieee1609_dot2::{
        Certificate, CertificateType, SequenceOfCertificate, ToBeSignedCertificate,
    };
    use super::ieee1609_dot2_base_types::{
        EccP256CurvePoint, HashedId8, PublicVerificationKey, Time32, Uint8,
    };
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This structure is used by the ECA to respond to an EE's enrollment"]
    #[doc = " * certificate request. Additional bootstrapping information including the"]
    #[doc = " * RA's certificate are provided by the DCM. The specification of the DCM is"]
    #[doc = " * outside the scope of this document. An overview of this structure is as"]
    #[doc = " * follows:"]
    #[doc = " *"]
    #[doc = " *  The definition of validity for a certificate request, including"]
    #[doc = " * constraints on the fields in this structure, is specified in 10.1."]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param generationTime: contains the generation time of EcaEeCertResponse."]
    #[doc = " *"]
    #[doc = " * @param requestHash: contains the following hash:"]
    #[doc = " *   - EeEcaCertRequestSPDU, if the corresponding request was"]
    #[doc = " * EeEcaCertRequestSPDU. This is calculated without \"canonicalizing\" the"]
    #[doc = " * signature, i.e., it is calculated over the signature as given in the"]
    #[doc = " * EeEcaCertRequestSpdu without re-encoding the signature's r component in"]
    #[doc = " * x-coordinate-only form. See IEEE Std 1609.2 for further details on"]
    #[doc = " * canonicalization."]
    #[doc = " *   - EeRaSuccessorEnrollmentCertRequestSpd, if the corresponding request"]
    #[doc = " * was EeRaSuccessorEnrollmentCertRequestSpd."]
    #[doc = " *"]
    #[doc = " * @param ecaCertChain: contains the ECA's currently valid certificate and the"]
    #[doc = " * certificate chain, up to and including the root CA."]
    #[doc = " *"]
    #[doc = " * @param certificate: contains the enrollment certificate generated by the"]
    #[doc = " * ECA, which shall be of the type indicated by the type field in the"]
    #[doc = " * corresponding request."]
    #[doc = " *"]
    #[doc = " * @param privateKeyInfo: shall be present and contain the private key"]
    #[doc = " * reconstruction value, if certificate.type is implicit. This is used by the"]
    #[doc = " * EE as specified in 9.3.5.1."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct EcaEeCertResponse {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Time32,
        #[rasn(identifier = "requestHash")]
        pub request_hash: HashedId8,
        #[rasn(identifier = "ecaCertChain")]
        pub eca_cert_chain: SequenceOfCertificate,
        pub certificate: Certificate,
        #[rasn(identifier = "privateKeyInfo")]
        pub private_key_info: Option<FixedOctetString<32>>,
    }
    impl EcaEeCertResponse {
        pub fn new(
            version: Uint8,
            generation_time: Time32,
            request_hash: HashedId8,
            eca_cert_chain: SequenceOfCertificate,
            certificate: Certificate,
            private_key_info: Option<FixedOctetString<32>>,
        ) -> Self {
            Self {
                version,
                generation_time,
                request_hash,
                eca_cert_chain,
                certificate,
                private_key_info,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is the parent structure for all structures exchanged between"]
    #[doc = " * the ECA and the EE. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param eeEcaCertRequest: contains the enrollment certificate request sent"]
    #[doc = " * by the EE to the ECA."]
    #[doc = " *"]
    #[doc = " * @param ecaEeCertResponse: contains the enrollment certificate response sent"]
    #[doc = " * by the ECA to the EE."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum EcaEeInterfacePdu {
        eeEcaCertRequest(EeEcaCertRequest),
        ecaEeCertResponse(EcaEeCertResponse),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains parameters needed to request an enrollment"]
    #[doc = " * certificate from the ECA. The ECA may, subject to policy, issue an"]
    #[doc = " * enrollment certificate with different contents than the contents requested."]
    #[doc = " * An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @note:"]
    #[doc = " *   - The tbsCert.cracaId and tbsCert.crlSeries are set to the"]
    #[doc = " * indicated values in the corresponding EeEcaCertRequest. In the issued"]
    #[doc = " * enrollment certificate, they may have different values, set by the ECA."]
    #[doc = " *   - The EE uses the type field to indicate whether it is"]
    #[doc = " * requesting an explicit or an implicit enrollment certificate. A policy is"]
    #[doc = " * anticipated that determines what type of certificate is appropriate for a"]
    #[doc = " * given set of circumstances (such as PSIDs, other end entity information,"]
    #[doc = " * and locality) and that if the EE has requested a kind of certificate that"]
    #[doc = " * is not allowed by policy, the ECA returns an error to the EE."]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param generationTime: contains the generation time of EeEcaCertRequest."]
    #[doc = " *"]
    #[doc = " * @param type: indicates whether the request is for an explicit or implicit"]
    #[doc = " * certificate (see 4.1.1, 4.1.4.3.1)."]
    #[doc = " *"]
    #[doc = " * @param tbsCert: contains the parameters used by the ECA to generate the"]
    #[doc = " * enrollment certificate. tbsCert.verifyKeyIndicator.verificationKey"]
    #[doc = " * contains the public key information sent by the requester. The"]
    #[doc = " * verifyKeyIndicator field indicates the choice verificationKey even if type"]
    #[doc = " * is implicit, as this allows the requester to indicate which signature"]
    #[doc = " * algorithm and curve they are requesting. The value in this field is used"]
    #[doc = " * as the verification key in the certificate if the certificate issued in"]
    #[doc = " * response to this request is explicit, and as the input public key value"]
    #[doc = " * for implicit certificate generation if the certificate issued in response"]
    #[doc = " * to this request is implicit."]
    #[doc = " *"]
    #[doc = " * @param canonicalId: shall be present and contain the canonical identifier"]
    #[doc = " * for the device per 4.1.4.2, if the enclosing EeEcaCertRequestSpdu was"]
    #[doc = " * signed by the canonical private key. The receiver is intended to use the"]
    #[doc = " * canonicalId to look up the canonical public key to verify the certificate"]
    #[doc = " * request."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct EeEcaCertRequest {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Time32,
        #[rasn(identifier = "type")]
        pub r_type: CertificateType,
        #[rasn(value("0.."), identifier = "tbsCert")]
        pub tbs_cert: ToBeSignedCertificate,
        #[rasn(identifier = "canonicalId")]
        pub canonical_id: Option<Ia5String>,
    }
    impl EeEcaCertRequest {
        pub fn new(
            version: Uint8,
            generation_time: Time32,
            r_type: CertificateType,
            tbs_cert: ToBeSignedCertificate,
            canonical_id: Option<Ia5String>,
        ) -> Self {
            Self {
                version,
                generation_time,
                r_type,
                tbs_cert,
                canonical_id,
            }
        }
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_ee_ma_interface {
    extern crate alloc;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This structure is currently being defined outside of this document,"]
    #[doc = " * so it is defined as NULL for purposes of this document."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct EeMaInterfacePdu(());
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_ee_ra_interface {
    extern crate alloc;
    use super::ieee1609_dot2::{CertificateType, ToBeSignedCertificate};
    use super::ieee1609_dot2_base_types::{
        HashedId8, IValue, PublicEncryptionKey, PublicVerificationKey, Time32, Uint8,
    };
    use super::ieee1609_dot2_dot1_acpc::AcpcTreeId;
    use super::ieee1609_dot2_dot1_protocol::EeEcaCertRequestSpdu;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This structure contains parameters for the butterfly key mechanism."]
    #[doc = " * An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param original: contains the parameters for the original variant."]
    #[doc = " *"]
    #[doc = " * @param unified: contains the expansion function for signing to be used for"]
    #[doc = " * the unified variant. The caterpillar public key and expansion function for"]
    #[doc = " * encryption are the same as those for signing."]
    #[doc = " *"]
    #[doc = " * @param compactUnified: contains the expansion function for signing to be"]
    #[doc = " * used for the compact unified variant. The caterpillar public key and"]
    #[doc = " * expansion function for encryption are the same as those for signing."]
    #[doc = " *"]
    #[doc = " * @param encryptionKey: contains the public key for encrypting the"]
    #[doc = " * certificate if the butterfly key mechanism is not used."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum AdditionalParams {
        original(ButterflyParamsOriginal),
        unified(ButterflyExpansion),
        compactUnified(ButterflyExpansion),
        encryptionKey(PublicEncryptionKey),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains material used in the butterfly key"]
    #[doc = " * calculations as specified in 9.3.5.1 and 9.3.5.2. An overview of this"]
    #[doc = " * structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param aes128: indicates that the symmetric algorithm used in the expansion"]
    #[doc = " * function is AES-128 with the indicated 16 byte string used as the key."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum ButterflyExpansion {
        aes128(FixedOctetString<16>),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains parameters for the original variation of the"]
    #[doc = " * butterfly key mechanism. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param signingExpansion: contains the expansion function for signing."]
    #[doc = " *"]
    #[doc = " * @param encryptionKey: contains the caterpillar public key for encryption."]
    #[doc = " *"]
    #[doc = " * @param encryptionExpansion: contains the expansion function for encryption."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct ButterflyParamsOriginal {
        #[rasn(identifier = "signingExpansion")]
        pub signing_expansion: ButterflyExpansion,
        #[rasn(identifier = "encryptionKey")]
        pub encryption_key: PublicEncryptionKey,
        #[rasn(identifier = "encryptionExpansion")]
        pub encryption_expansion: ButterflyExpansion,
    }
    impl ButterflyParamsOriginal {
        pub fn new(
            signing_expansion: ButterflyExpansion,
            encryption_key: PublicEncryptionKey,
            encryption_expansion: ButterflyExpansion,
        ) -> Self {
            Self {
                signing_expansion,
                encryption_key,
                encryption_expansion,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains parameters needed to request different types"]
    #[doc = " * of authorization certificates. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " *  The definition of validity for a certificate request, including"]
    #[doc = " * constraints on the fields in this structure, is specified in 10.1."]
    #[doc = " *"]
    #[doc = " * @note:"]
    #[doc = " *   - In the case where the butterfly key mechanism is used to"]
    #[doc = " * derive the certificate encryption key, the value j is not communicated to"]
    #[doc = " * the ACA. However, the EE that receives the certificate response can only"]
    #[doc = " * decrypt the response if it knows j. The RA is therefore anticipated to"]
    #[doc = " * store j so that it can be associated with the appropriate certificate"]
    #[doc = " * response."]
    #[doc = " *   - If the type of id is LinkageData, the contents of the"]
    #[doc = " * field in the request are replaced by random data by the RA when it sends"]
    #[doc = " * the individual certificate requests to the ACA. The ACA then in turn"]
    #[doc = " * replaces that data with the linkage values generated with the help of the"]
    #[doc = " * LAs; see Annex D."]
    #[doc = " *   - This document does not specify a method to include an"]
    #[doc = " * encryptionKey in the requested certificates, if the butterfly key"]
    #[doc = " * mechanism is used. The EE using such a certificate to sign a message"]
    #[doc = " * cannot request that the response is encrypted to the certificate. Instead,"]
    #[doc = " * it can request an encrypted response using the"]
    #[doc = " * tbsData.headerInfo.encryptionKey field of the SignedData; see 6.3.9,"]
    #[doc = " * 6.3.33, 6.3.34, and 6.3.36 of IEEE Std 1609.2 for more details."]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param generationTime: contains the generation time of EeRaCertRequest."]
    #[doc = " *"]
    #[doc = " * @param type: indicates whether the request is for an explicit or implicit"]
    #[doc = " * certificate (see 4.1.1 and 4.1.4.3.1)."]
    #[doc = " *"]
    #[doc = " * @param tbsCert: contains the parameters to be used by the ACA to generate"]
    #[doc = " * authorization certificate(s)."]
    #[doc = " *   - id contains the identity information sent by the requester. If the"]
    #[doc = " * type is LinkageData, the contents of the field are chosen by the EE using"]
    #[doc = " * any appropriate means. RA replaces that in the certificates with the"]
    #[doc = " * linkage values generated with the help of the LAs and the ACA; see Annex D."]
    #[doc = " *   - validityPeriod contains the requested validity period of the first"]
    #[doc = " * batch of certificates."]
    #[doc = " *   - region, assuranceLevel, canRequestRollover, and encryptionKey, if"]
    #[doc = " * present, contain the information sent by the requester for the requested"]
    #[doc = " * certificates."]
    #[doc = " *   - verifyKeyIndicator.verificationKey contains the public key"]
    #[doc = " * information sent by the requester. The verifyKeyIndicator field indicates"]
    #[doc = " * the choice verificationKey even if type is implicit, as this allows the"]
    #[doc = " * requester to indicate which signature algorithm and curve they are"]
    #[doc = " * requesting."]
    #[doc = " *     - If the certificate issued in response to this request is explicit and"]
    #[doc = " * butterfly expansion is not used, the value in this field is the"]
    #[doc = " * verification key that appears in that certificate."]
    #[doc = " *     - If the certificate issued in response to this request is implicit and"]
    #[doc = " * butterfly expansion is not used, the value in this field is the input"]
    #[doc = " * public key value for implicit certificate generation."]
    #[doc = " *     - If butterfly expansion is used, that is, if one of (original, unified,"]
    #[doc = " * compactUnified) options is present in the field additionalParams, the"]
    #[doc = " * value in this field is combined with the values in the additionalParams"]
    #[doc = " * field as specified in 9.3."]
    #[doc = " *"]
    #[doc = " * @param additionalParams: shall be present and contain relevant parameters if"]
    #[doc = " * the requested certificates are to be generated using the butterfly key"]
    #[doc = " * mechanism as specified in 9.3, or if the requested certificates are to be"]
    #[doc = " * encrypted without using the butterfly key mechanism. If present, the field"]
    #[doc = " * tbsCert.verifyKeyIndicator shall be used as the caterpillar public key for"]
    #[doc = " * signing in the butterfly key mechanism."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct EeRaCertRequest {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Time32,
        #[rasn(identifier = "type")]
        pub r_type: CertificateType,
        #[rasn(value("0.."), identifier = "tbsCert")]
        pub tbs_cert: ToBeSignedCertificate,
        #[rasn(identifier = "additionalParams")]
        pub additional_params: Option<AdditionalParams>,
    }
    impl EeRaCertRequest {
        pub fn new(
            version: Uint8,
            generation_time: Time32,
            r_type: CertificateType,
            tbs_cert: ToBeSignedCertificate,
            additional_params: Option<AdditionalParams>,
        ) -> Self {
            Self {
                version,
                generation_time,
                r_type,
                tbs_cert,
                additional_params,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains parameters needed to request the download of"]
    #[doc = " * certificates from the RA. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param generationTime: contains the generation time of EeRaDownloadRequest."]
    #[doc = " *"]
    #[doc = " * @param filename: contains the name of the file requested for download,"]
    #[doc = " * formed as specified in 8.2.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct EeRaDownloadRequest {
        #[rasn(identifier = "generationTime")]
        pub generation_time: Time32,
        #[rasn(size("0..=255"))]
        pub filename: Utf8String,
    }
    impl EeRaDownloadRequest {
        pub fn new(generation_time: Time32, filename: Utf8String) -> Self {
            Self {
                generation_time,
                filename,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is the parent structure for all structures exchanged between"]
    #[doc = " * the EE and the RA. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @note This CHOICE does not include a PDU type for encrypted"]
    #[doc = " * misbehavior report upload; see 4.1.5."]
    #[doc = " *"]
    #[doc = " * @param eeRaCertRequest: contains the certificate generation request sent by"]
    #[doc = " * the EE to the RA."]
    #[doc = " *"]
    #[doc = " * @param raEeCertAck: contains the RA's acknowledgement of the receipt of"]
    #[doc = " * EeRaCertRequestSpdu."]
    #[doc = " *"]
    #[doc = " * @param raEeCertInfo: contains the information about certificate download."]
    #[doc = " *"]
    #[doc = " * @param eeRaDownloadRequest: contains the download request sent by the EE to"]
    #[doc = " * the RA."]
    #[doc = " *"]
    #[doc = " * @param eeRaSuccessorEnrollmentCertRequest: contains a self-signed request"]
    #[doc = " * for an enrollment certificate, identical in format to the one submitted"]
    #[doc = " * for an initial enrollment certificate. (This becomes a request for a"]
    #[doc = " * successor enrollment certificate by virtue of being signed by the current"]
    #[doc = " * enrollment certificate.)"]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum EeRaInterfacePdu {
        eeRaCertRequest(EeRaCertRequest),
        raEeCertAck(RaEeCertAck),
        raEeCertInfo(RaEeCertInfo),
        eeRaDownloadRequest(EeRaDownloadRequest),
        eeRaSuccessorEnrollmentCertRequest(EeEcaCertRequestSpdu),
    }
    #[doc = "*"]
    #[doc = " * @brief This structure is used to create the acknowledgement for certificate"]
    #[doc = " * requests. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param generationTime: contains the generation time of RaEeCertAck."]
    #[doc = " *"]
    #[doc = " * @param requestHash: contains the hash of the corresponding"]
    #[doc = " * EeRaCertRequestSpdu."]
    #[doc = " *"]
    #[doc = " * @param firstI: shall be present and contain the i-value that will be"]
    #[doc = " * associated with the first certificate or the certificate batch that will be"]
    #[doc = " * made available to the EE, if the corresponding EeRaCertRequest uses the"]
    #[doc = " * butterfly key mechanism as indicated in the field additionalParams. The EE"]
    #[doc = " * uses this to form the download filename for the download request as"]
    #[doc = " * specified in 8.2.2."]
    #[doc = " *"]
    #[doc = " * @param nextDlTime: contains the time after which the EE should connect to"]
    #[doc = " * the RA to download the certificates."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct RaEeCertAck {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Time32,
        #[rasn(identifier = "requestHash")]
        pub request_hash: HashedId8,
        #[rasn(identifier = "firstI")]
        pub first_i: Option<IValue>,
        #[rasn(identifier = "nextDlTime")]
        pub next_dl_time: Time32,
    }
    impl RaEeCertAck {
        pub fn new(
            version: Uint8,
            generation_time: Time32,
            request_hash: HashedId8,
            first_i: Option<IValue>,
            next_dl_time: Time32,
        ) -> Self {
            Self {
                version,
                generation_time,
                request_hash,
                first_i,
                next_dl_time,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure is used to create the info file that accompanies a"]
    #[doc = " * batch of certificates for download as specified in 8.2.3. It is used when"]
    #[doc = " * certificates were generated using the butterfly key expansion mechanism"]
    #[doc = " * specified in 9.3. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " *"]
    #[doc = " * @param generationTime: contains the generation time of RaEeCertInfo."]
    #[doc = " *"]
    #[doc = " * @param currentI: contains the i-value associated with the batch of"]
    #[doc = " * certificates."]
    #[doc = " *"]
    #[doc = " * @param requestHash: contains the hash of the corresponding"]
    #[doc = " * EeRaCertRequestSpdu."]
    #[doc = " *"]
    #[doc = " * @param nextDlTime: contains the time after which the EE should connect to"]
    #[doc = " * the RA to download the certificates."]
    #[doc = " *"]
    #[doc = " * @param acpcTreeId: shall be present and contain the ACPC Tree Id, if the"]
    #[doc = " * certificates were generated using ACPC as specified in 9.5."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct RaEeCertInfo {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "generationTime")]
        pub generation_time: Time32,
        #[rasn(identifier = "currentI")]
        pub current_i: IValue,
        #[rasn(identifier = "requestHash")]
        pub request_hash: HashedId8,
        #[rasn(identifier = "nextDlTime")]
        pub next_dl_time: Time32,
        #[rasn(identifier = "acpcTreeId")]
        pub acpc_tree_id: Option<AcpcTreeId>,
    }
    impl RaEeCertInfo {
        pub fn new(
            version: Uint8,
            generation_time: Time32,
            current_i: IValue,
            request_hash: HashedId8,
            next_dl_time: Time32,
            acpc_tree_id: Option<AcpcTreeId>,
        ) -> Self {
            Self {
                version,
                generation_time,
                current_i,
                request_hash,
                next_dl_time,
                acpc_tree_id,
            }
        }
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_la_ma_interface {
    extern crate alloc;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This structure is not used by EEs, so it is defined as NULL for"]
    #[doc = " * purposes of this document."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct LaMaInterfacePdu(());
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_la_ra_interface {
    extern crate alloc;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This structure is not used by EEs, so it is defined as NULL for"]
    #[doc = " * purposes of this document."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct LaRaInterfacePdu(());
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_ma_ra_interface {
    extern crate alloc;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This structure is not used by EEs, so it is defined as NULL for"]
    #[doc = " * purposes of this document."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct MaRaInterfacePdu(());
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod ieee1609_dot2_dot1_protocol {
    extern crate alloc;
    use super::ieee1609_dot2::{
        Certificate, CertificateId, Ieee1609Dot2Data, SequenceOfCertificate,
        SequenceOfPsidGroupPermissions, SignerIdentifier, ToBeSignedCertificate,
        VerificationKeyIndicator,
    };
    use super::ieee1609_dot2_base_types::{
        CrlSeries, EccP256CurvePoint, EccP384CurvePoint, EcdsaP256Signature, EcdsaP384Signature,
        GeographicRegion, HashAlgorithm, HashedId3, Psid, PublicEncryptionKey,
        PublicVerificationKey, SequenceOfPsid, SequenceOfPsidSsp, Signature, SubjectAssurance,
        Uint16, Uint8, ValidityPeriod,
    };
    use super::ieee1609_dot2_dot1_aca_ee_interface::AcaEeInterfacePdu;
    use super::ieee1609_dot2_dot1_aca_la_interface::AcaLaInterfacePdu;
    use super::ieee1609_dot2_dot1_aca_ma_interface::AcaMaInterfacePdu;
    use super::ieee1609_dot2_dot1_aca_ra_interface::AcaRaInterfacePdu;
    use super::ieee1609_dot2_dot1_acpc::AcpcTreeId;
    use super::ieee1609_dot2_dot1_cert_management::CertManagementPdu;
    use super::ieee1609_dot2_dot1_eca_ee_interface::EcaEeInterfacePdu;
    use super::ieee1609_dot2_dot1_ee_ma_interface::EeMaInterfacePdu;
    use super::ieee1609_dot2_dot1_ee_ra_interface::EeRaInterfacePdu;
    use super::ieee1609_dot2_dot1_la_ma_interface::LaMaInterfacePdu;
    use super::ieee1609_dot2_dot1_la_ra_interface::LaRaInterfacePdu;
    use super::ieee1609_dot2_dot1_ma_ra_interface::MaRaInterfacePdu;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[doc = "*"]
    #[doc = " * @brief This structure contains a certificate response for consumption by"]
    #[doc = " * the EE. In the architecture of this document, although it is created by"]
    #[doc = " * the ACA, it is made available to the EE via the RA as described in 8.2."]
    #[doc = " *"]
    #[doc = " * The ACA creates a certificate response in this form when the"]
    #[doc = " * compact unified butterfly key mechanism is being used. If the"]
    #[doc = " * RaAcaCertRequest structure was used to communicate between the RA and the"]
    #[doc = " * ACA, the RA indicated use of compact unified butterfly keys by setting the"]
    #[doc = " * cubk (1) bit in the bkType field in the corresponding RaAcaCertRequest."]
    #[doc = " *"]
    #[doc = " * The AcaEeCertResponse is encrypted by the ACA using the cocoon"]
    #[doc = " * public key for encryption. See 9.3.4.2 for how the ACA derives the cocoon"]
    #[doc = " * public key for encryption, using the tbsCert.verifyKeyIndicator field in the"]
    #[doc = " * corresponding RaAcaCertRequest as the input cocoon public key for signing"]
    #[doc = " * Bt. See 9.3.4.1 for how the EE derives the corresponding cocoon private"]
    #[doc = " * key for encryption."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AcaEeCertResponseCubkSpdu(pub Ieee1609Dot2DataEncrypted);
    #[doc = "***************************************************************************"]
    #[doc = "                             ACA - EE Interface                            "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure contains a certificate response for consumption by"]
    #[doc = " * the EE. In the architecture of this document, although it is created by the"]
    #[doc = " * ACA, it is made available to the EE via the RA as described in 8.2."]
    #[doc = " *"]
    #[doc = " * The ACA creates this response when 1) the compact unified"]
    #[doc = " * butterfly key mechanism is not being used (that is, some other flavor of"]
    #[doc = " * butterfly key is being used, or butterfly keys are not being used) and 2)"]
    #[doc = " * it is not necessary to protect the EE's privacy from the RA, for example,"]
    #[doc = " * when the certificate being returned is not a pseudonym certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AcaEeCertResponsePlainSpdu(pub Ieee1609Dot2DataUnsecured);
    #[doc = "*"]
    #[doc = " * @brief This structure contains a certificate response for consumption by"]
    #[doc = " * the EE. In the architecture of this document, although it is created by the"]
    #[doc = " * ACA, it is made available to the EE via the RA as described in 8.2."]
    #[doc = " *"]
    #[doc = " * The ACA creates this response when 1) the compact unified"]
    #[doc = " * butterfly key mechanism is not being used (that is, some other flavor of"]
    #[doc = " * butterfly key is being used, or butterfly keys are not being used) and 2)"]
    #[doc = " * it is necessary to protect the EE's privacy from the RA, for example when"]
    #[doc = " * the certificate being returned is a pseudonym certificate."]
    #[doc = " *"]
    #[doc = " * The structure consists of a signed SPDU containing an encrypted"]
    #[doc = " * SPDU."]
    #[doc = " *"]
    #[doc = " * The encrypted SPDU is encrypted with the response"]
    #[doc = " * encryption key that was provided to the ACA for that purpose. This key is"]
    #[doc = " * determined as follows:"]
    #[doc = " *   - If the original EeRaCertRequest from the end entity indicated a single"]
    #[doc = " * response encryption key, that is, if the additionalParams.encryptionKey"]
    #[doc = " * field was present in the request, then the response is encrypted with that"]
    #[doc = " * key."]
    #[doc = " *   - If the original EeRaCertRequest from the end entity indicated a"]
    #[doc = " * response encryption key generated with the \"original\" butterfly key"]
    #[doc = " * mechanism, that is, the additionalParams.original field was provided in the"]
    #[doc = " * request, then the response is encrypted with the cocoon encryption key"]
    #[doc = " * derived from additionalParams.original.encryptionKey and"]
    #[doc = " * additionalParams.original.encryptionExpansion as specified in 9.3.4.2"]
    #[doc = " * and the corresponding decryption private key is derived as specified in"]
    #[doc = " * 9.3.4.1."]
    #[doc = " *   - If the original EeRaCertRequest from the end entity indicated a"]
    #[doc = " * response encryption key generated with the \"unified\" butterfly key"]
    #[doc = " * mechanism, that is, the additionalParams.unified field was provided in the"]
    #[doc = " * request, then the response is encrypted with the cocoon encryption key"]
    #[doc = " * derived from tbsCert.verifyKeyIndicator and additionalParams.unified as"]
    #[doc = " * specified in 9.3.4.2 and the corresponding decryption private key is"]
    #[doc = " * derived as specified in 9.3.4.1."]
    #[doc = " *"]
    #[doc = " * See 9.3 for more material about butterfly keys."]
    #[doc = " *"]
    #[doc = " * The resulting Ieee1609Dot2Data of content type encryptedData is"]
    #[doc = " * signed by the same ACA certificate that was used to issue the certificate"]
    #[doc = " * field in the AcaEeCertResponse. If this structure is signed by a different"]
    #[doc = " * ACA certificate, it is invalid. The ACA certificate shall follow the ACA"]
    #[doc = " * certificate profile given in 7.7.3.2."]
    #[doc = " *"]
    #[doc = " * @note:"]
    #[doc = " *   - Other potential responses to an authorization certificate"]
    #[doc = " * request: If the original request indicated the use of \"compact unified\""]
    #[doc = " * butterfly key mechanism by including the additionalParams.compactUnified"]
    #[doc = " * field, the response shall be a AcaEeCertResponseCubkSpdu, not a"]
    #[doc = " * AcaEeCertResponsePrivateSpdu."]
    #[doc = " *"]
    #[doc = " *   - How the ACA obtains the response encryption key: This"]
    #[doc = " * document provides the RaAcaCertRequest structure to allow the RA to"]
    #[doc = " * indicate whether the original or unified butterfly key mechanism is to be"]
    #[doc = " * used via the flags field. The encryption key for encrypting"]
    #[doc = " * AcaEeCertResponse is calculated by the indicated method even if the RA"]
    #[doc = " * does not use an RaAcaCertRequest as defined in this document to"]
    #[doc = " * communicate the certificate request to the ACA."]
    #[doc = " *"]
    #[doc = " *   - Consistency between inner and outer signers, and the IEEE"]
    #[doc = " * Std 1609.2 model. This SPDU introduces a new type of validity condition"]
    #[doc = " * by requiring that the ACA that signs the outer signed SPDU is also the ACA"]
    #[doc = " * that issued the certificate inside the encrypted SPDU. This requires that"]
    #[doc = " * to verify the inner \"SPDU\", that is, the certificate, the verifier"]
    #[doc = " * needs to store the information from the outer SPDU. This is not a violation"]
    #[doc = " * of the IEEE 1609.2 model: Subclause 4.2.2.3 of IEEE Std 1609.2 considers all"]
    #[doc = " * operations carried out on received data to be atomic and does not put any"]
    #[doc = " * restrictions on the information that is stored between operations. However,"]
    #[doc = " * it should be noted that because the IEEE 1609.2 approach enables SPDUs to"]
    #[doc = " * be nested within one another as Ieee1609Dot2Data, in principle an"]
    #[doc = " * implementation could be built that iterated through the layers of a nested"]
    #[doc = " * SPDU within a single call from the invoking application instance. (And it"]
    #[doc = " * should also be noted that IEEE Std 1609.2 was consciously designed to"]
    #[doc = " * enable this approach: Although the primitives provided in IEEE Std 1609.2"]
    #[doc = " * only support the series-of-single-operations approach, an implementation"]
    #[doc = " * could layer this \"one-invocation processing\" on top of the IEEE 1609.2"]
    #[doc = " * interface as an optimization.) A \"one-invocation processing\" implementation"]
    #[doc = " * of that type would have to anticipate situations of coupling between inner"]
    #[doc = " * and outer SPDUs like the one created by this AcaEeCertResponsePrivateSpdu,"]
    #[doc = " * and allow the invoking certificate management service to check consistency"]
    #[doc = " * at the application layer, perhaps by (for example) returning the signing"]
    #[doc = " * certificates for all nested signed SPDUs. How this is to be implemented is"]
    #[doc = " * implementation specific; this note is intended as a notification of this"]
    #[doc = " * potential issue to implementers planning to implement one-invocation"]
    #[doc = " * processing."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AcaEeCertResponsePrivateSpdu(pub Ieee1609Dot2DataEncryptedSigned);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed AcaRaCertResponse."]
    #[doc = " * For the signature to be valid the signing certificate shall contain a PSID"]
    #[doc = " * equal to SecurityMgmtPsid and a corresponding SSP containing the C-OER"]
    #[doc = " * encoding of a SecurityMgmtSsp indicating AcaSsp."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct AcaRaCertResponseSpdu(pub Ieee1609Dot2DataSigned);
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for an authorization CA when it is"]
    #[doc = " * authorizing SecurityMgmtPsid messages. It has no parameters other than the"]
    #[doc = " * version number."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct AcaSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl AcaSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This is a container for ACPC-related SSPs, specifying one SSP for"]
    #[doc = " * each role. The only SSP defined in this document is the CamSsp, used in"]
    #[doc = " * the CAM certificate that signs a SignedAprvBinaryTree or a"]
    #[doc = " * SignedIndividualAprv. The SSP shall be C-OER encoded for inclusion in the"]
    #[doc = " * CAM certificate. New versions of the CAM SSP should be handled by"]
    #[doc = " * extending this structure rather than by use of a version number in the"]
    #[doc = " * CamSsp structure."]
    #[doc = " *"]
    #[doc = " * The AcpcSsp is associated with the AcpcPsid in the CAM certificate's"]
    #[doc = " * appPermissions field."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum AcpcSsp {
        cam(CamSsp),
    }
    #[doc = "*"]
    #[doc = " * @brief This is a list of the ACPC Tree IDs for which the containing CAM"]
    #[doc = " * certificate is entitled to sign a SignedAprvBinaryTree or a"]
    #[doc = " * SignedIndividualAprv. The SSP entitles the certificate holder to sign"]
    #[doc = " * either of these structures."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("1.."))]
    pub struct CamSsp(pub SequenceOf<AcpcTreeId>);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send an unsecured"]
    #[doc = " * CertificateChain. It is used to create certificate chain files as"]
    #[doc = " * specified in 8.4."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CertificateChainSpdu(pub Ieee1609Dot2DataUnsecured);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed"]
    #[doc = " * CertManagementInfoStatus. For the signature to be valid the signing"]
    #[doc = " * certificate shall conform to the RA certificate profile given in 7.7.3.9 or"]
    #[doc = " * the DC certificate profile given in 7.7.3.10."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CertificateManagementInformationStatusSpdu(pub Ieee1609Dot2DataSigned);
    #[doc = "***************************************************************************"]
    #[doc = "                           Certificate Management                          "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send an unsecured CompositeCrl."]
    #[doc = " * It is used to create composite CRL files as specified in 8.5."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CompositeCrlSpdu(pub Ieee1609Dot2DataUnsecured);
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for a CRL signer when it is"]
    #[doc = " * authorizing SecurityMgmtPsid messages. It has no parameters other than the"]
    #[doc = " * version number."]
    #[doc = " *"]
    #[doc = " * @note The SSP for a CRL signer when signing CRLs is associated with"]
    #[doc = " * PSID 0x0100 and is defined in IEEE Std 1609.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CrlSignerSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl CrlSignerSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed"]
    #[doc = " * ToBeSignedCtlSignature. For the signature to be valid, the signing"]
    #[doc = " * certificate shall match the elector certificate profile in 7.7.3.7. This"]
    #[doc = " * means that the signature is calculated as specified in IEEE Std 1609.2,"]
    #[doc = " * with the data input to the hash process consisting of the C-OER encoding"]
    #[doc = " * of the tbsData that includes the ToBeSignedCtlSignature."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct CtlSignatureSpdu(pub Ieee1609Dot2DataSigned);
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for a distribution center when it is"]
    #[doc = " * authorizing SecurityMgmtPsid messages. It has no parameters other than the"]
    #[doc = " * version number."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct DcSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl DcSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for a device configuration manager"]
    #[doc = " * when it is authorizing SecurityMgmtPsid messages. It has no parameters"]
    #[doc = " * other than the version number."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct DcmSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl DcmSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed EcaEeCertResponse."]
    #[doc = " * For the signature to be valid, the signing certificate shall contain a PSID"]
    #[doc = " * equal to SecurityMgmtPsid and a corresponding SSP containing the C-OER"]
    #[doc = " * encoding of a SecurityMgmtSsp indicating EcaSsp."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct EcaEeCertResponseSpdu(pub Ieee1609Dot2DataSigned);
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for an enrollment CA when it is"]
    #[doc = " * authorizing SecurityMgmtPsid messages. It has no parameters other than the"]
    #[doc = " * version number."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct EcaSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl EcaSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = "***************************************************************************"]
    #[doc = "                             ECA - EE Interface                            "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed EeEcaCertRequest,"]
    #[doc = " * as follows:"]
    #[doc = " *   - If eeEcaCertRequest.canonicalId is not present, the EE signs this"]
    #[doc = " * structure using the private key corresponding to the"]
    #[doc = " * tbsCert.verifyKeyIndicator field of the EeEcaCertRequest."]
    #[doc = " *   - If eeEcaCertRequest.canonicalId is present, the EE signs this"]
    #[doc = " * structure using the canonical private key as specified in 4.1.4.2."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct EeEcaCertRequestSpdu(pub Ieee1609Dot2DataSignedCertRequest);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed then encrypted IEEE"]
    #[doc = " * 1609.2 authenticated certificate request. The EE signs this structure"]
    #[doc = " * using its enrollment certificate. The enrollment certificate shall conform"]
    #[doc = " * to the enrollment certificate profile given in 7.7.3.5. The EE encrypts"]
    #[doc = " * the signed structure using the encryptionKey from the RA's certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct EeRa1609Dot2AuthenticatedCertRequestSpdu(
        pub Ieee1609Dot2DataSignedEncryptedCertRequest,
    );
    #[doc = "***************************************************************************"]
    #[doc = "                              EE - MA Interface                            "]
    #[doc = "***************************************************************************"]
    #[doc = "***************************************************************************"]
    #[doc = "                              EE - RA Interface                            "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed then encrypted"]
    #[doc = " * EeRaCertRequest. It is a choice of the IEEE 1609.2 authenticated"]
    #[doc = " * certificate request, which may be any kind of EE-RA certificate request,"]
    #[doc = " * and the ITU-T X.509 certificate request, which is required to be an"]
    #[doc = " * authorization certificate request."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct EeRaCertRequestSpdu(pub Ieee1609Dot2Data);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send an unsecured"]
    #[doc = " * EeRaDownloadRequest."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct EeRaDownloadRequestPlainSpdu(pub Ieee1609Dot2DataUnsecured);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed then encrypted"]
    #[doc = " * EeRaDownloadRequest. The EE signs this structure using its enrollment"]
    #[doc = " * certificate. The enrollment certificate shall conform to the enrollment"]
    #[doc = " * certificate profile given in 7.7.3.5. The EE encrypts the signed"]
    #[doc = " * structure using the encryptionKey from the RA's certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct EeRaDownloadRequestSpdu(pub Ieee1609Dot2DataSignedEncrypted);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed then encrypted"]
    #[doc = " * EeEcaCertRequestSpdu. The EE signs this structure using its enrollment"]
    #[doc = " * certificate. The enrollment certificate shall conform to the enrollment"]
    #[doc = " * certificate profile given in 7.7.3.5. The EE encrypts the signed"]
    #[doc = " * structure using the encryptionKey from the RA's certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct EeRaSuccessorEnrollmentCertRequestSpdu(
        pub Ieee1609Dot2DataSignedEncryptedCertRequest,
    );
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed then encrypted ITU-T"]
    #[doc = " * X.509authenticated certificate request. The EE signs this structure"]
    #[doc = " * using its enrollment certificate. The enrollment certificate shall conform"]
    #[doc = " * to the enrollment certificate profile given in 7.7.3.6. The EE encrypts"]
    #[doc = " * the signed structure using the encryptionKey from the RA's certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct EeRaX509AuthenticatedCertRequestSpdu(pub Ieee1609Dot2DataEncrypted);
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for an end entity when it is"]
    #[doc = " * authorizing SecurityMgmtPsid messages. It has no parameters other than the"]
    #[doc = " * version number."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct EeSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl EeSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for an elector when it is authorizing"]
    #[doc = " * SecurityMgmtPsid messages. It has no parameters other than the version"]
    #[doc = " * number."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ElectorSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl ElectorSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for an intermediate CA when it is"]
    #[doc = " * authorizing SecurityMgmtPsid messages. It has no parameters other than the"]
    #[doc = " * version number."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct IcaSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl IcaSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure defines a parameterized type for creating an"]
    #[doc = " * encrypted data as a subtype of Ieee1609Dot2Data. An overview of this"]
    #[doc = " * structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param Tbe: is first encrypted per IEEE 1609.2. Per IEEE 1609.2, this"]
    #[doc = " * includes encapsulating Tbe in an Ieee1609Dot2Data of type unsecured if"]
    #[doc = " * Tbe is not already an Ieee1609Dot2Data. The ciphertext output from the"]
    #[doc = " * encryption of Tbe is used to set the encryptedData.ciphertext field. The"]
    #[doc = " * encryptedData.recipients field is set to reflect the recipients. This"]
    #[doc = " * parameterized type does not provide parameters to set the recipients; that"]
    #[doc = " * information is set directly by the entity that creates an instance of this"]
    #[doc = " * type."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, identifier = "Ieee1609Dot2Data-Encrypted")]
    pub struct Ieee1609Dot2DataEncrypted(pub Ieee1609Dot2Data);
    #[doc = "*"]
    #[doc = " * @brief This structure defines a parameterized type for creating an"]
    #[doc = " * encrypted then signed data as a subtype of Ieee1609Dot2Data."]
    #[doc = " *"]
    #[doc = " * @note This parameterized type inadvertently adds some overhead."]
    #[doc = " * The Ieee1609Dot2Data-EncryptedSigned {Tbes, Psid} structure, because it"]
    #[doc = " * puts Ieee1609Dot2Data-Encrypted inside Ieee1609Dot2Data-Signed {Tbs, Psid},"]
    #[doc = " * and because Ieee1609Dot2Data-Signed {Tbs, Psid} puts Tbs inside"]
    #[doc = " * unsecuredData, Tbes is \"Signed (Unsecured (Encrypted))\" instead of"]
    #[doc = " * \"Signed (Encrypted))\", which was the intent and also in the original CAMP"]
    #[doc = " * design. Other documents that use this document may be better off defining"]
    #[doc = " * this structure on their own, if they want avoid this overhead."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, identifier = "Ieee1609Dot2Data-EncryptedSigned")]
    pub struct Ieee1609Dot2DataEncryptedSigned(pub Ieee1609Dot2DataSigned);
    #[doc = "*"]
    #[doc = " * @brief This structure defines a parameterized type for creating a signed"]
    #[doc = " * data as a subtype of Ieee1609Dot2Data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, identifier = "Ieee1609Dot2Data-Signed")]
    pub struct Ieee1609Dot2DataSigned(pub Ieee1609Dot2Data);
    #[doc = "*"]
    #[doc = " * @brief This structure defines a parameterized type for creating a signed"]
    #[doc = " * certificate request as a subtype of Ieee1609Dot2Data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, identifier = "Ieee1609Dot2Data-SignedCertRequest")]
    pub struct Ieee1609Dot2DataSignedCertRequest(pub Ieee1609Dot2Data);
    #[doc = "*"]
    #[doc = " * @brief This structure defines a parameterized type for creating a signed"]
    #[doc = " * then encrypted data as a subtype of Ieee1609Dot2Data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, identifier = "Ieee1609Dot2Data-SignedEncrypted")]
    pub struct Ieee1609Dot2DataSignedEncrypted(pub Ieee1609Dot2DataEncrypted);
    #[doc = "*"]
    #[doc = " * @brief This structure defines a parameterized type for creating a signed"]
    #[doc = " * then encrypted certificate request as a subtype of Ieee1609Dot2Data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, identifier = "Ieee1609Dot2Data-SignedEncryptedCertRequest")]
    pub struct Ieee1609Dot2DataSignedEncryptedCertRequest(pub Ieee1609Dot2DataEncrypted);
    #[doc = "*"]
    #[doc = " * @brief This structure defines a parameterized type for creating a"]
    #[doc = " * certificate request, signed with an ITU-T X.509 certificate, as a subtype of"]
    #[doc = " * Ieee1609Dot2Data. It makes use of the extension of Ieee1609Dot2Content"]
    #[doc = " * defined in 11.2.3."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(
        delegate,
        identifier = "Ieee1609Dot2Data-SignedX509AuthenticatedCertRequest"
    )]
    pub struct Ieee1609Dot2DataSignedX509AuthenticatedCertRequest(pub Ieee1609Dot2Data);
    #[doc = "*"]
    #[doc = " * @brief This structure defines a parameterized type for creating an"]
    #[doc = " * encrypted data as a subtype of Ieee1609Dot2Data. An overview of this"]
    #[doc = " * structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @param Tbe: is first encrypted and the resulting ciphertext is used as"]
    #[doc = " * input to the encryptedData field."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, identifier = "Ieee1609Dot2Data-SymmEncryptedSingleRecipient")]
    pub struct Ieee1609Dot2DataSymmEncryptedSingleRecipient(pub Ieee1609Dot2Data);
    #[doc = "*"]
    #[doc = " * @brief This structure defines a parameterized type for creating an"]
    #[doc = " * unsecured data as a subtype of Ieee1609Dot2Data."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, identifier = "Ieee1609Dot2Data-Unsecured")]
    pub struct Ieee1609Dot2DataUnsecured(pub Ieee1609Dot2Data);
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for a linkage authority when it is"]
    #[doc = " * authorizing SecurityMgmtPsid messages. It has no parameters other than the"]
    #[doc = " * version number."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct LaSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "laId")]
        pub la_id: Uint16,
    }
    impl LaSsp {
        pub fn new(version: Uint8, la_id: Uint16) -> Self {
            Self { version, la_id }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for a location obscurer proxy (LOP)"]
    #[doc = " * when it is authorizing SecurityMgmtPsid messages. It has no parameters"]
    #[doc = " * other than the version number."]
    #[doc = " *"]
    #[doc = " * @note The LOP is in the SSP for backward compatibility reasons, and"]
    #[doc = " * in practice, in this design the LOP does not have a certificate."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct LopSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl LopSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for a misbehavior authority when it"]
    #[doc = " * is authorizing SecurityMgmtPsid messages. Its parameters"]
    #[doc = " * indicate the PSIDs associated with the misbehavior that is to be reported"]
    #[doc = " * to that MA (see 4.1.5 for further details). The certificate containing"]
    #[doc = " * this SSP is the MA Certificate to which an end entity should encrypt"]
    #[doc = " * misbehavior reports related to the indicated PSIDs."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct MaSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
        #[rasn(identifier = "relevantPsids")]
        pub relevant_psids: SequenceOfPsid,
    }
    impl MaSsp {
        pub fn new(version: Uint8, relevant_psids: SequenceOfPsid) -> Self {
            Self {
                version,
                relevant_psids,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send an unsecured MultiSignedCtl."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct MultiSignedCtlSpdu(pub Ieee1609Dot2DataUnsecured);
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for a policy generator when it is"]
    #[doc = " * authorizing SecurityMgmtPsid messages. It has no parameters other than the"]
    #[doc = " * version number."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct PgSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl PgSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = "***************************************************************************"]
    #[doc = "                             ACA - LA Interface                            "]
    #[doc = "***************************************************************************"]
    #[doc = "***************************************************************************"]
    #[doc = "                             ACA - MA Interface                            "]
    #[doc = "***************************************************************************"]
    #[doc = "***************************************************************************"]
    #[doc = "                             ACA - RA Interface                            "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed RaAcaCertRequest."]
    #[doc = " * For the signature to be valid the signing certificate shall conform to the"]
    #[doc = " * RA certificate profile given in 7.7.3.9, contain a PSID equal to"]
    #[doc = " * SecurityMgmtPsid and a corresponding SSP containing the C-OER encoding of a"]
    #[doc = " * SecurityMgmtSsp indicating RaSsp. The toBeSigned.certRequestPermissions"]
    #[doc = " * field of the RA certificate shall permit the requested permissions in the"]
    #[doc = " * raAcaCertRequest.tbsCert.appPermissions field."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct RaAcaCertRequestSpdu(pub Ieee1609Dot2DataSignedCertRequest);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed RaEeCertAck to"]
    #[doc = " * acknowledge the receipt of an EeRaCertRequestSpdu. For the signature to be"]
    #[doc = " * valid the signing certificate shall conform to the RA certificate profile"]
    #[doc = " * given in 7.7.3.9."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct RaEeCertAckSpdu(pub Ieee1609Dot2DataSigned);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to create a signed .info file to"]
    #[doc = " * be included in a certificate batch zip file as specified in 8.2. This"]
    #[doc = " * SPDU is used if the RaEeCertInfo contains an acpcTreeId field. For the"]
    #[doc = " * signature to be valid the signing certificate shall conform to the RA"]
    #[doc = " * certificate profile given in 7.7.3.9."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct RaEeCertAndAcpcInfoSpdu(pub Ieee1609Dot2DataSigned);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to create an unsigned .info file"]
    #[doc = " * to be included in a certificate batch zip file as specified in 8.2. This"]
    #[doc = " * SPDU is used if the RaEeCertInfo does not contain an acpcTreeId field."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct RaEeCertInfoSpdu(pub Ieee1609Dot2DataUnsecured);
    #[doc = "*"]
    #[doc = " * @brief This structure is the SPDU used to send a signed RaEeCertInfo. For"]
    #[doc = " * the signature to be valid the signing certificate shall conform to the RA"]
    #[doc = " * certificate profile given in 7.7.3.9."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct RaEeEnrollmentCertAckSpdu(pub Ieee1609Dot2DataSigned);
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for an RA when it is authorizing"]
    #[doc = " * SecurityMgmtPsid messages. It has no parameters other than the version"]
    #[doc = " * number."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct RaSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl RaSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure defines the SSP for a root CA when it is authorizing"]
    #[doc = " * SecurityMgmtPsid messages. It has no parameters other than the version"]
    #[doc = " * number."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct RootCaSsp {
        #[rasn(value("2"))]
        pub version: Uint8,
    }
    impl RootCaSsp {
        pub fn new(version: Uint8) -> Self {
            Self { version }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum ScmsPduContent {
        #[rasn(identifier = "aca-ee")]
        aca_ee(AcaEeInterfacePdu),
        #[rasn(identifier = "aca-la")]
        aca_la(AcaLaInterfacePdu),
        #[rasn(identifier = "aca-ma")]
        aca_ma(AcaMaInterfacePdu),
        #[rasn(identifier = "aca-ra")]
        aca_ra(AcaRaInterfacePdu),
        cert(CertManagementPdu),
        #[rasn(identifier = "eca-ee")]
        eca_ee(EcaEeInterfacePdu),
        #[rasn(identifier = "ee-ma")]
        ee_ma(EeMaInterfacePdu),
        #[rasn(identifier = "ee-ra")]
        ee_ra(EeRaInterfacePdu),
        #[rasn(identifier = "la-ma")]
        la_ma(LaMaInterfacePdu),
        #[rasn(identifier = "la-ra")]
        la_ra(LaRaInterfacePdu),
        #[rasn(identifier = "ma-ra")]
        ma_ra(MaRaInterfacePdu),
    }
    #[doc = "*"]
    #[doc = " * @brief This is the parent structure that encompasses all parent structures"]
    #[doc = " * of interfaces defined in the SCMS. An overview of this structure is as"]
    #[doc = " * follows:"]
    #[doc = " *   - aca-ee contains the interface structures defined for interaction"]
    #[doc = " * between the ACA and the EE."]
    #[doc = " *   - aca-la contains the interface structures defined for interaction"]
    #[doc = " * between the ACA and the LA."]
    #[doc = " *   - aca-ma contains the interface structures defined for interaction"]
    #[doc = " * between the ACA and the MA."]
    #[doc = " *   - aca-ra contains the interface structures defined for interaction"]
    #[doc = " * between the ACA and the RA."]
    #[doc = " *   - cert contains the interface structures defined for certificate"]
    #[doc = " * management."]
    #[doc = " *   - eca-ee contains the interface structures defined for interaction"]
    #[doc = " * between the ECA and the EE."]
    #[doc = " *   - ee-ma contains the interface structures defined for interaction"]
    #[doc = " * between the EE and the MA."]
    #[doc = " *   - ee-ra contains the interface structures defined for interaction"]
    #[doc = " * between the EE and the RA."]
    #[doc = " *   - la-ma contains the interface structures defined for interaction"]
    #[doc = " * between the LA and the MA."]
    #[doc = " *   - la-ra contains the interface structures defined for interaction"]
    #[doc = " * between the LA and the RA."]
    #[doc = " *   - ma-ra contains the interface structures defined for interactions"]
    #[doc = " * between the MA and the RA."]
    #[doc = " *"]
    #[doc = " * @param version: contains the current version of the structure."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct ScmsPdu {
        #[rasn(value("2"))]
        pub version: Uint8,
        pub content: ScmsPduContent,
    }
    impl ScmsPdu {
        pub fn new(version: Uint8, content: ScmsPduContent) -> Self {
            Self { version, content }
        }
    }
    #[doc = "***************************************************************************"]
    #[doc = "                            Parameterized Types                            "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure defines a parameterized type for creating a scoped"]
    #[doc = " * data as a subtype of ScmsPdu."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, identifier = "ScmsPdu-Scoped")]
    pub struct ScmsPduScoped(pub ScmsPdu);
    #[doc = "***************************************************************************"]
    #[doc = "                            Certificate Requests                           "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure defines the all certificate request structures as a"]
    #[doc = " * scoped version of the ScmsPdu."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct ScopedCertificateRequest(pub ScmsPdu);
    #[doc = "*"]
    #[doc = " * @brief This PSID, 0x23, identifies security management activities as"]
    #[doc = " * defined in this document."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, value("35"))]
    pub struct SecurityMgmtPsid(pub Psid);
    #[doc = "***************************************************************************"]
    #[doc = "                              LA - MA Interface                            "]
    #[doc = "***************************************************************************"]
    #[doc = "***************************************************************************"]
    #[doc = "                              LA - RA Interface                            "]
    #[doc = "***************************************************************************"]
    #[doc = "***************************************************************************"]
    #[doc = "                              MA - RA Interface                            "]
    #[doc = "***************************************************************************"]
    #[doc = "***************************************************************************"]
    #[doc = "                        Service Specific Permissions                       "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This parent structure defines the SSP for SecurityMgmtPsid and"]
    #[doc = " * encompasses all SSP structures defined in this document. An overview of"]
    #[doc = " * this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * @note The LOP is in the SSP for backward compatibility reasons,"]
    #[doc = " * and in practice, in this design the LOP does not have a certificate."]
    #[doc = " *"]
    #[doc = " * @param elector: contains the SSP defined for an elector."]
    #[doc = " *"]
    #[doc = " * @param root: contains the SSP defined for a root CA."]
    #[doc = " *"]
    #[doc = " * @param pg: contains the SSP defined for a policy generator."]
    #[doc = " *"]
    #[doc = " * @param ica: contains the SSP defined for an intermediate CA."]
    #[doc = " *"]
    #[doc = " * @param eca: contains the SSP defined for an enrollment CA."]
    #[doc = " *"]
    #[doc = " * @param aca: contains the SSP defined for an authorization CA."]
    #[doc = " *"]
    #[doc = " * @param crl: contains the SSP defined for a CRL signer."]
    #[doc = " *"]
    #[doc = " * @param dcm: contains the SSP defined for a device configuration manager."]
    #[doc = " *"]
    #[doc = " * @param la: contains the SSP defined for a linkage authority."]
    #[doc = " *"]
    #[doc = " * @param lop: contains the SSP defined for a location obscurer proxy."]
    #[doc = " *"]
    #[doc = " * @param ma: contains the SSP defined for a misbehavior authority."]
    #[doc = " *"]
    #[doc = " * @param ra: contains the SSP defined for a registration authority."]
    #[doc = " *"]
    #[doc = " * @param ee: contains the SSP defined for an end entity."]
    #[doc = " *"]
    #[doc = " * @param dc: contains the SSP defined for a distribution center."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum SecurityMgmtSsp {
        elector(ElectorSsp),
        root(RootCaSsp),
        pg(PgSsp),
        ica(IcaSsp),
        eca(EcaSsp),
        aca(AcaSsp),
        crl(CrlSignerSsp),
        dcm(DcmSsp),
        la(LaSsp),
        lop(LopSsp),
        ma(MaSsp),
        ra(RaSsp),
        ee(EeSsp),
        #[rasn(extension_addition)]
        dc(DcSsp),
    }
    #[doc = "*"]
    #[doc = " * @brief This type is used for clarity of definitions."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate, size("1.."))]
    pub struct SequenceOfX509Certificate(pub SequenceOf<X509Certificate>);
    #[doc = "*"]
    #[doc = " * @brief This structure defines the format of a signed certificate request."]
    #[doc = " * An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * The signature is generated on the hash of this structure, obtained"]
    #[doc = " * per the rules specified for hashing data objects in 5.3.1 of IEEE Std"]
    #[doc = " * 1609.2a-2017, where the parameter Data Input shall be the C-OER"]
    #[doc = " * encoding of tbsRequest, and the parameter Signer Identifier Input"]
    #[doc = " * depending on whether the request is self-signed or signed using an"]
    #[doc = " * enrollment certificate:"]
    #[doc = " *   - If the request is self-signed, the parameter Signer Identifier"]
    #[doc = " * Input shall be the empty string, i.e., a string of length 0."]
    #[doc = " *   - If the request is signed using an enrollment certificate, the"]
    #[doc = " * parameter Signer Identifier Input shall be the signer's enrollment"]
    #[doc = " * certificate."]
    #[doc = " *"]
    #[doc = " * @param hashAlgorithmId: contains the identifier of the hash algorithm used"]
    #[doc = " * to calculate the hash of tbsRequest."]
    #[doc = " *"]
    #[doc = " * @param tbsRequest: contains the certificate request information that is"]
    #[doc = " * signed by the recipient."]
    #[doc = " *"]
    #[doc = " * @param signer: denotes the signing entity's identifier."]
    #[doc = " *"]
    #[doc = " * @param signature: contains the request sender's signature."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct SignedCertificateRequest {
        #[rasn(identifier = "hashAlgorithmId")]
        pub hash_algorithm_id: HashAlgorithm,
        #[rasn(identifier = "tbsRequest")]
        pub tbs_request: ScopedCertificateRequest,
        pub signer: SignerIdentifier,
        pub signature: Signature,
    }
    impl SignedCertificateRequest {
        pub fn new(
            hash_algorithm_id: HashAlgorithm,
            tbs_request: ScopedCertificateRequest,
            signer: SignerIdentifier,
            signature: Signature,
        ) -> Self {
            Self {
                hash_algorithm_id,
                tbs_request,
                signer,
                signature,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure contains a certificate request signed with an ITU-T"]
    #[doc = " * X.509 certificate. The only type of certificate request signed with an"]
    #[doc = " * ITU-T X.509 certificate supported in this document is an authorization"]
    #[doc = " * certificate request. An overview of this structure is as follows:"]
    #[doc = " *"]
    #[doc = " * The signature is generated on the hash of this structure, obtained"]
    #[doc = " * per the rules specified for hashing data objects in 5.3.1 of IEEE Std"]
    #[doc = " * 1609.2a-2017, where the parameter Data Input shall be  the C-OER"]
    #[doc = " * encoding of tbsRequest, and the parameter Signer Identifier Input"]
    #[doc = " * shall be  the signer's certificate, that is, the ITU-T X.509 certificate"]
    #[doc = " * contained in the OCTET STRING indicated by the first X509Certificate in"]
    #[doc = " * signer. For example, if the signer is as below, the first 6 bytes are the"]
    #[doc = " * ASN.1 encoding overhead, where 80 01 01 is the overhead for signer, and"]
    #[doc = " * then 82 01 AC is the overhead introduced by the OCTET STRING encoding for"]
    #[doc = " * the first (in this case, the only) X509Certificate; and the first"]
    #[doc = " * X509Certificate is contained in the next 428 bytes (30 82 01 ... 00 00 00),"]
    #[doc = " * so the parameter Signer Identifier Input shall be '30 82 01 ... 00 00 00'."]
    #[doc = " *"]
    #[doc = " * An example X509SignerIdentifier with one X509Certificate:"]
    #[doc = " *"]
    #[doc = " * 80 01 01 82 01 AC 30 82 01 A8 30 82 01 4D A0 03 02 01 02 02 04 90"]
    #[doc = " * C5 9D 21 30 0A 06 08 2A 86 48 CE 3D 04 03 02 30 24 31 0A 30 08 06 03 55 04"]
    #[doc = " * 06 13 01 00 31 0A 30 08 06 03 55 04 0A 13 01 00 31 0A 30 08 06 03 55 04 03"]
    #[doc = " * 13 01 00 30 1E 17 0D 30 30 30 31 30 31 30 30 30 30 30 30 5A 17 0D 30 30 30"]
    #[doc = " * 31 30 31 30 30 30 30 30 30 5A 30 24 31 0A 30 08 06 03 55 04 06 13 01 00 31"]
    #[doc = " * 0A 30 08 06 03 55 04 0A 13 01 00 31 0A 30 08 06 03 55 04 03 13 01 00 30 59"]
    #[doc = " * 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07 03 42 00 00"]
    #[doc = " * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"]
    #[doc = " * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"]
    #[doc = " * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A3 6D 30 6B 30 0A 06 03 55 1D 0E"]
    #[doc = " * 04 03 04 01 00 30 0A 06 03 55 1D 23 04 03 04 01 00 30 0C 06 03 55 1D 13 01"]
    #[doc = " * 01 FF 04 02 30 00 30 0E 06 03 55 1D 0F 01 01 FF 04 04 03 02 03 C8 30 0A 06"]
    #[doc = " * 03 55 1D 25 04 03 04 01 00 30 0A 06 03 55 1D 1F 04 03 04 01 00 30 0F 06 08"]
    #[doc = " * 2B 06 01 05 05 07 01 01 04 03 04 01 00 30 0A 06 03 55 1D 20 04 03 04 01 00"]
    #[doc = " * 30 0A 06 08 2A 86 48 CE 3D 04 03 02 03 49 00 00 00 00 00 00 00 00 00 00 00"]
    #[doc = " * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"]
    #[doc = " * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"]
    #[doc = " * 00 00 00 00 00 00 00 00 00 00 00 00"]
    #[doc = " *"]
    #[doc = " * @param hashAlgorithmId: contains the identifier of the hash algorithm used"]
    #[doc = " * inside the binary tree."]
    #[doc = " *"]
    #[doc = " * @param tbsRequest: contains the certificate request information that is"]
    #[doc = " * signed by the recipient."]
    #[doc = " *"]
    #[doc = " * @param signer: denotes the signing entity's identifier."]
    #[doc = " *"]
    #[doc = " * @param signature: contains the request sender's signature."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(automatic_tags)]
    pub struct SignedX509CertificateRequest {
        #[rasn(identifier = "hashAlgorithmId")]
        pub hash_algorithm_id: HashAlgorithm,
        #[rasn(identifier = "tbsRequest")]
        pub tbs_request: ScopedCertificateRequest,
        pub signer: X509SignerIdentifier,
        pub signature: Signature,
    }
    impl SignedX509CertificateRequest {
        pub fn new(
            hash_algorithm_id: HashAlgorithm,
            tbs_request: ScopedCertificateRequest,
            signer: X509SignerIdentifier,
            signature: Signature,
        ) -> Self {
            Self {
                hash_algorithm_id,
                tbs_request,
                signer,
                signature,
            }
        }
    }
    #[doc = "*"]
    #[doc = " * @brief This structure is used to indicate a SignerIdentifier of type self."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SignerSelf(pub SignerIdentifier);
    #[doc = "***************************************************************************"]
    #[doc = "                                Signer Types                               "]
    #[doc = "***************************************************************************"]
    #[doc = "*"]
    #[doc = " * @brief This structure is used to indicate a SignerIdentifier with a"]
    #[doc = " * certificate chain of size 1."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SignerSingleCert(pub SignerIdentifier);
    #[doc = "*"]
    #[doc = " * @brief This structure is used to indicate an X509SignerIdentifier with a"]
    #[doc = " * certificate chain of size 1."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct SignerSingleX509Cert(pub X509SignerIdentifier);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct TestSecurityMgmtSsp(pub SecurityMgmtSsp);
    #[doc = "*"]
    #[doc = " * @brief This structure is a wrapper for an ITU-T X.509 certificate."]
    #[doc = " *"]
    #[doc = " * @note ITU-T X.509 certificates are encoded with the ASN.1 DER"]
    #[doc = " * rather than the OER used in this document and so cannot be \"directly\""]
    #[doc = " * imported into these structures."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(delegate)]
    pub struct X509Certificate(pub OctetString);
    #[doc = "*"]
    #[doc = " * @brief This structure identifies an ITU-T X.509 certificate used to sign a"]
    #[doc = " * signed data structure. The only data structure currently defined that can"]
    #[doc = " * be signed by an ITU-T X.509 certificate is SignedX509CertificateRequest."]
    #[doc = " "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum X509SignerIdentifier {
        certificate(SequenceOfX509Certificate),
    }
}
