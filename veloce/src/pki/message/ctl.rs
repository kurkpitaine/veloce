use core::fmt;

use veloce_asn1::{
    defs::etsi_102941_v221::{
        etsi_ts102941_messages_ca::{EtsiTs102941Data, EtsiTs102941DataContent},
        etsi_ts102941_trust_lists::{
            AaEntry as EtsiAaEntry, CtlCommand as EtsiCtlCommand, CtlDelete as EtsiCtlDelete,
            CtlEntry as EtsiCtlEntry, CtlFormat as EtsiCtlFormat, DcDelete as EtsiDcDelete,
            DcEntry as EtsiDcEntry, EaEntry as EtsiEaEntry, RootCaEntry as EtsiRootCaEntry,
            TlmEntry as EtsiTlmEntry, ToBeSignedRcaCtl, ToBeSignedTlmCtl, Url as EtsiUrl,
        },
        ieee1609_dot2_base_types::{Time32, Uint32},
    },
    defs::etsi_103097_v211::{
        etsi_ts103097_module::EtsiTs103097Certificate,
        ieee1609_dot2::Certificate as EtsiCertificate,
    },
    prelude::rasn::{
        error::strings::PermittedAlphabetError,
        types::{Ia5String, Integer, SequenceOf},
    },
};

use crate::{
    pki::{
        asn1_wrapper::{Asn1Wrapper, Asn1WrapperError, Asn1WrapperResult},
        signed_data::{SignedData, SignedDataError},
    },
    security::HashedId8,
    time::TAI2004,
};

use super::VerifierError;

/// Marker struct for a TLM CTL type.
#[derive(Debug, Clone, Copy)]
pub struct TLM;

/// Marker struct for an RCA CTL type.
#[derive(Debug, Clone, Copy)]
pub struct RCA;

/// TLM Certificate Trust List message type.
pub type TlmCertificateTrustListMessage = SignedData<TLM>;
/// RCA Certificate Trust List message type.
pub type RcaCertificateTrustListMessage = SignedData<RCA>;

/// URL error.
#[derive(Debug)]
pub struct CtlURLError(PermittedAlphabetError);

impl fmt::Display for CtlURLError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "URL: {}", self.0)
    }
}

/// CTL Root CA entry.
#[derive(Debug, Clone, PartialEq)]
pub struct RootCaEntry {
    /// Root certificate (self-signed).
    pub certificate: EtsiCertificate,
    /// Optional previous Root certificate which is succeeded by
    /// the new one in [RootCaEntry::certificate].
    pub successor_to: Option<EtsiCertificate>,
}

impl From<EtsiRootCaEntry> for RootCaEntry {
    fn from(value: EtsiRootCaEntry) -> Self {
        Self {
            certificate: value.selfsigned_root_ca.0,
            successor_to: value.successor_to.map(|st| st.0),
        }
    }
}

impl From<RootCaEntry> for EtsiRootCaEntry {
    fn from(value: RootCaEntry) -> Self {
        Self {
            selfsigned_root_ca: EtsiTs103097Certificate(value.certificate),
            successor_to: value.successor_to.map(EtsiTs103097Certificate),
        }
    }
}

/// CTL Enrollment Authority entry.
#[derive(Debug, Clone, PartialEq)]
pub struct EnrollmentAuthorityEntry {
    /// Enrollment Authority certificate.
    pub certificate: EtsiCertificate,
    /// URL of the Authorization Authority server, for the
    /// Enrollment Authority server.
    pub aa_access_point: String,
    /// URL of the Enrollment Authority server, for the ITS Stations.
    pub its_access_point: Option<String>,
}

impl TryFrom<EtsiEaEntry> for EnrollmentAuthorityEntry {
    type Error = CtlURLError;

    fn try_from(value: EtsiEaEntry) -> Result<Self, Self::Error> {
        let res = Self {
            certificate: value.ea_certificate.0,
            aa_access_point: value.aa_access_point.0.into(),
            its_access_point: value.its_access_point.map(|ap| ap.0.into()),
        };

        Ok(res)
    }
}

impl TryInto<EtsiEaEntry> for EnrollmentAuthorityEntry {
    type Error = CtlURLError;

    fn try_into(self) -> Result<EtsiEaEntry, Self::Error> {
        let ia5_aa_ap = EtsiUrl(
            Ia5String::from_iso646_bytes(self.aa_access_point.as_bytes()).map_err(CtlURLError)?,
        );

        let maybe_ia5_its_ap = self
            .its_access_point
            .map(|its_ap| Ia5String::from_iso646_bytes(its_ap.as_bytes()).map_err(CtlURLError))
            .transpose()?
            .map(EtsiUrl);

        let ea_entry = EtsiEaEntry::new(
            EtsiTs103097Certificate(self.certificate),
            ia5_aa_ap,
            maybe_ia5_its_ap,
        );
        Ok(ea_entry)
    }
}

/// CTL Authorization Authority entry.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationAuthorityEntry {
    /// Certificate of the Authorization Authority server.
    pub certificate: EtsiCertificate,
    /// URL of the Authorization Authority server.
    pub access_point: String,
}

impl TryFrom<EtsiAaEntry> for AuthorizationAuthorityEntry {
    type Error = CtlURLError;

    fn try_from(value: EtsiAaEntry) -> Result<Self, Self::Error> {
        let res = Self {
            certificate: value.aa_certificate.0,
            access_point: value.access_point.0.into(),
        };

        Ok(res)
    }
}

impl TryInto<EtsiAaEntry> for AuthorizationAuthorityEntry {
    type Error = CtlURLError;

    fn try_into(self) -> Result<EtsiAaEntry, Self::Error> {
        let ia5_ap = EtsiUrl(
            Ia5String::from_iso646_bytes(self.access_point.as_bytes()).map_err(CtlURLError)?,
        );

        let aa_entry = EtsiAaEntry::new(EtsiTs103097Certificate(self.certificate), ia5_ap);
        Ok(aa_entry)
    }
}

/// CTL Distribution Center entry.
/// The Distribution Center is a server that provides the CTL and the CRL
/// of a PKI.
#[derive(Debug, Clone, PartialEq)]
pub struct DistributionCenterEntry {
    /// Distribution Center certificates.
    pub certificates: Vec<HashedId8>,
    /// URL of the Distribution Center server.
    pub url: String,
}

impl TryFrom<EtsiDcEntry> for DistributionCenterEntry {
    type Error = CtlURLError;

    fn try_from(value: EtsiDcEntry) -> Result<Self, Self::Error> {
        let res = Self {
            certificates: value.cert.iter().map(|c| c.into()).collect(),
            url: value.url.0.into(),
        };

        Ok(res)
    }
}

impl TryInto<EtsiDcEntry> for DistributionCenterEntry {
    type Error = CtlURLError;

    fn try_into(self) -> Result<EtsiDcEntry, Self::Error> {
        let ia5_url =
            EtsiUrl(Ia5String::from_iso646_bytes(self.url.as_bytes()).map_err(CtlURLError)?);

        let dc_entry = EtsiDcEntry::new(
            ia5_url,
            self.certificates.into_iter().map(Into::into).collect(),
        );
        Ok(dc_entry)
    }
}

/// CTL Trust List Manager entry.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustListManagerEntry {
    /// Trust List Manager certificate (self-signed).
    pub certificate: EtsiCertificate,
    /// Optional previous Trust List Manager certificate which is succeeded by
    /// the new one in [TrustListManagerEntry::certificate].
    pub successor_to: Option<EtsiCertificate>,
    /// URL of the Trust List Manager server.
    pub access_point: String,
}

impl TryFrom<EtsiTlmEntry> for TrustListManagerEntry {
    type Error = CtlURLError;

    fn try_from(value: EtsiTlmEntry) -> Result<Self, Self::Error> {
        let res = Self {
            certificate: value.self_signed_tlmcertificate.0,
            successor_to: value.successor_to.map(|st| st.0),
            access_point: value.access_point.0.into(),
        };

        Ok(res)
    }
}

impl TryInto<EtsiTlmEntry> for TrustListManagerEntry {
    type Error = CtlURLError;

    fn try_into(self) -> Result<EtsiTlmEntry, Self::Error> {
        let ia5_ap = EtsiUrl(
            Ia5String::from_iso646_bytes(self.access_point.as_bytes()).map_err(CtlURLError)?,
        );

        let tlm_entry = EtsiTlmEntry::new(
            EtsiTs103097Certificate(self.certificate),
            self.successor_to.map(EtsiTs103097Certificate),
            ia5_ap,
        );
        Ok(tlm_entry)
    }
}

/// Add Command error.
#[derive(Debug)]
pub enum AddCommandError {
    /// Unsupported add command.
    UnsupportedCommand,
    /// URL error.
    URL(CtlURLError),
}

impl fmt::Display for AddCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddCommandError::UnsupportedCommand => write!(f, "unsupported command"),
            AddCommandError::URL(e) => write!(f, "URL: {}", e),
        }
    }
}

/// CTL Add commands. Each command entry type is grouped in a vector.
#[allow(clippy::len_without_is_empty)]
#[derive(Debug, Default, Clone, PartialEq)]
pub struct AddCommands {
    /// Root certificate entries.
    pub root: Vec<RootCaEntry>,
    /// Enrollment Authority entries.
    pub ea: Vec<EnrollmentAuthorityEntry>,
    /// Authorization Authority entries.
    pub aa: Vec<AuthorizationAuthorityEntry>,
    /// Distribution Center entries.
    pub dc: Vec<DistributionCenterEntry>,
    /// TLM certificate entries.
    pub tlm: Vec<TrustListManagerEntry>,
}

impl AddCommands {
    /// Returns the number of entries in the [AddCommands].
    pub fn len(&self) -> usize {
        self.root.len() + self.ea.len() + self.aa.len() + self.dc.len() + self.tlm.len()
    }
}

/* /// CTL Add command type.
#[derive(Debug, Clone, PartialEq)]
pub enum AddCommand {
    /// Root certificate variant.
    Root {
        /// Root certificate (self-signed).
        certificate: EtsiCertificate,
        /// Optional previous Root certificate which is succeeded by
        /// the new one in [AddCommand::Root::certificate].
        successor_to: Option<EtsiCertificate>,
    },
    /// Enrollment Authority variant.
    EnrollmentAuthority {
        /// Enrollment Authority certificate.
        certificate: EtsiCertificate,
        /// URL of the Authorization Authority server.
        aa_access_point: String,
        /// Optional URL of the Enrollment Authority server.
        its_access_point: Option<String>,
    },
    /// Authorization Authority variant.
    AuthorizationAuthority {
        /// Certificate of the Authorization Authority server.
        certificate: EtsiCertificate,
        /// URL of the Authorization Authority server.
        access_point: String,
    },
    /// Distribution Center variant.
    /// The Distribution Center is a server that provides the CTL and the CRL
    /// of a PKI.
    DistributionCenter {
        /// Distribution Center certificates.
        certificates: Vec<HashedId8>,
        /// URL of the Distribution Center server.
        url: String,
    },
    /// Trust List Manager variant.
    TrustListManager {
        /// Trust List Manager certificate (self-signed).
        certificate: EtsiCertificate,
        /// Optional previous Trust List Manager certificate which is succeeded by
        /// the new one in [AddCommand::TrustListManager::certificate].
        successor_to: Option<EtsiCertificate>,
        /// URL of the Trust List Manager server.
        access_point: String,
    },
}

impl TryFrom<&EtsiCtlEntry> for AddCommand {
    type Error = AddCommandError;

    fn try_from(value: &EtsiCtlEntry) -> Result<Self, Self::Error> {
        let res = match value {
            EtsiCtlEntry::rca(e) => AddCommand::Root {
                certificate: e.selfsigned_root_ca.to_owned(),
                successor_to: e.successor_to.to_owned(),
            },
            EtsiCtlEntry::ea(e) => AddCommand::EnrollmentAuthority {
                certificate: e.ea_certificate.to_owned(),
                aa_access_point: e.aa_access_point.0.to_owned().into(),
                its_access_point: e.its_access_point.as_ref().map(|ap| ap.0.to_owned().into()),
            },
            EtsiCtlEntry::aa(e) => AddCommand::AuthorizationAuthority {
                certificate: e.aa_certificate.to_owned(),
                access_point: e.access_point.0.to_owned().into(),
            },
            EtsiCtlEntry::dc(e) => AddCommand::DistributionCenter {
                certificates: e.cert.iter().map(|c| c.into()).collect(),
                url: e.url.0.to_owned().into(),
            },
            EtsiCtlEntry::tlm(e) => AddCommand::TrustListManager {
                certificate: e.self_signed_tlmcertificate.to_owned(),
                successor_to: e.successor_to.to_owned(),
                access_point: e.access_point.0.to_owned().into(),
            },
            _ => return Err(AddCommandError::UnsupportedCommand),
        };

        Ok(res)
    }
}

impl TryInto<EtsiCtlEntry> for AddCommand {
    type Error = AddCommandError;

    fn try_into(self) -> Result<EtsiCtlEntry, Self::Error> {
        let res = match self {
            AddCommand::Root {
                certificate,
                successor_to,
            } => {
                let rca_entry = RootCaEntry::new(certificate, successor_to);
                EtsiCtlEntry::rca(rca_entry)
            }
            AddCommand::EnrollmentAuthority {
                certificate,
                aa_access_point,
                its_access_point,
            } => {
                let ia5_aa_ap = EtsiUrl(
                    Ia5String::from_iso646_bytes(aa_access_point.as_bytes())
                        .map_err(AddCommandError::URL)?,
                );

                let maybe_ia5_its_ap = its_access_point
                    .map(|its_ap| {
                        Ia5String::from_iso646_bytes(its_ap.as_bytes())
                            .map_err(AddCommandError::URL)
                    })
                    .transpose()?
                    .map(EtsiUrl);

                let ea_entry = EaEntry::new(certificate, ia5_aa_ap, maybe_ia5_its_ap);
                EtsiCtlEntry::ea(ea_entry)
            }
            AddCommand::AuthorizationAuthority {
                certificate,
                access_point,
            } => {
                let ia5_ap = EtsiUrl(
                    Ia5String::from_iso646_bytes(access_point.as_bytes())
                        .map_err(AddCommandError::URL)?,
                );

                let aa_entry = AaEntry::new(certificate, ia5_ap);
                EtsiCtlEntry::aa(aa_entry)
            }
            AddCommand::DistributionCenter { certificates, url } => {
                let ia5_url = EtsiUrl(
                    Ia5String::from_iso646_bytes(url.as_bytes()).map_err(AddCommandError::URL)?,
                );

                let dc_entry =
                    DcEntry::new(ia5_url, certificates.into_iter().map(Into::into).collect());
                EtsiCtlEntry::dc(dc_entry)
            }
            AddCommand::TrustListManager {
                certificate,
                successor_to,
                access_point,
            } => {
                let ia5_ap = EtsiUrl(
                    Ia5String::from_iso646_bytes(access_point.as_bytes())
                        .map_err(AddCommandError::URL)?,
                );

                let tlm_entry = TlmEntry::new(certificate, successor_to, ia5_ap);
                EtsiCtlEntry::tlm(tlm_entry)
            }
        };

        Ok(res)
    }
} */

/// Delete Command error.
#[derive(Debug)]
pub enum DeleteCommandError {
    /// Unsupported delete command.
    UnsupportedCommand,
    /// URL error.
    URL(PermittedAlphabetError),
}

impl fmt::Display for DeleteCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeleteCommandError::UnsupportedCommand => {
                write!(f, "unsupported delete command")
            }
            DeleteCommandError::URL(e) => write!(f, "URL: {}", e),
        }
    }
}

/// CTL Delete command type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteCommand {
    /// A certificate which should be deleted from the trust store,
    /// identified by its [HashedId8].
    Certificate(HashedId8),
    /// A Distribution Center URL which should be deleted.
    Dc(String),
}

impl TryFrom<&EtsiCtlDelete> for DeleteCommand {
    type Error = DeleteCommandError;

    fn try_from(value: &EtsiCtlDelete) -> Result<Self, Self::Error> {
        let res = match value {
            EtsiCtlDelete::cert(c) => DeleteCommand::Certificate(c.into()),
            EtsiCtlDelete::dc(d) => DeleteCommand::Dc(d.0 .0.to_owned().into()),
            _ => return Err(DeleteCommandError::UnsupportedCommand),
        };

        Ok(res)
    }
}

impl TryInto<EtsiCtlDelete> for DeleteCommand {
    type Error = DeleteCommandError;

    fn try_into(self) -> Result<EtsiCtlDelete, Self::Error> {
        let res = match self {
            DeleteCommand::Certificate(c) => EtsiCtlDelete::cert(c.into()),
            DeleteCommand::Dc(d) => {
                let ia5_str =
                    Ia5String::from_iso646_bytes(d.as_bytes()).map_err(DeleteCommandError::URL)?;
                EtsiCtlDelete::dc(EtsiDcDelete(EtsiUrl(ia5_str)))
            }
        };

        Ok(res)
    }
}

/// CTL Commands error.
#[derive(Debug)]
pub enum CtlCommandsError {
    /// Add Command error.
    Add(AddCommandError),
    /// Delete Command error.
    Delete(DeleteCommandError),
    /// Unsupported command.
    UnsupportedCommand,
}

impl fmt::Display for CtlCommandsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CtlCommandsError::Add(e) => write!(f, "add command: {}", e),
            CtlCommandsError::Delete(e) => write!(f, "delete command: {}", e),
            CtlCommandsError::UnsupportedCommand => write!(f, "unsupported command"),
        }
    }
}

/// CTL commands type.
#[derive(Debug, Clone, PartialEq)]
pub struct CtlCommands {
    /// Contains the trusted entries, the ones considered as trusted by the CTL we should add to
    /// our trust store.
    pub add: AddCommands,
    /// Contains entries which become untrusted in the CTL, the ones we should remove from
    /// our trust store.
    pub delete: Vec<DeleteCommand>,
}

impl TryFrom<&SequenceOf<EtsiCtlCommand>> for CtlCommands {
    type Error = CtlCommandsError;

    fn try_from(value: &SequenceOf<EtsiCtlCommand>) -> Result<Self, Self::Error> {
        let mut add = AddCommands::default();
        let mut delete = Vec::with_capacity(value.len());

        for v in value {
            match v {
                EtsiCtlCommand::add(c) => match c {
                    EtsiCtlEntry::rca(e) => add.root.push(e.to_owned().into()),
                    EtsiCtlEntry::ea(e) => add.ea.push(
                        e.to_owned()
                            .try_into()
                            .map_err(|err| Self::Error::Add(AddCommandError::URL(err)))?,
                    ),
                    EtsiCtlEntry::aa(e) => add.aa.push(
                        e.to_owned()
                            .try_into()
                            .map_err(|err| Self::Error::Add(AddCommandError::URL(err)))?,
                    ),
                    EtsiCtlEntry::dc(e) => add.dc.push(
                        e.to_owned()
                            .try_into()
                            .map_err(|err| Self::Error::Add(AddCommandError::URL(err)))?,
                    ),
                    EtsiCtlEntry::tlm(e) => add.tlm.push(
                        e.to_owned()
                            .try_into()
                            .map_err(|err| Self::Error::Add(AddCommandError::URL(err)))?,
                    ),
                    _ => return Err(CtlCommandsError::Add(AddCommandError::UnsupportedCommand)),
                },
                EtsiCtlCommand::delete(c) => {
                    delete.push(c.try_into().map_err(Self::Error::Delete)?)
                }
                _ => return Err(CtlCommandsError::UnsupportedCommand),
            }
        }

        Ok(Self { add, delete })
    }
}

impl TryInto<SequenceOf<EtsiCtlCommand>> for CtlCommands {
    type Error = CtlCommandsError;

    fn try_into(self) -> Result<SequenceOf<EtsiCtlCommand>, Self::Error> {
        let mut res = SequenceOf::with_capacity(self.add.len() + self.delete.len());

        for a in self.add.root {
            res.push(EtsiCtlCommand::add(EtsiCtlEntry::rca(a.into())));
        }

        for a in self.add.ea {
            res.push(EtsiCtlCommand::add(EtsiCtlEntry::ea(
                a.try_into()
                    .map_err(|e| Self::Error::Add(AddCommandError::URL(e)))?,
            )));
        }

        for a in self.add.aa {
            res.push(EtsiCtlCommand::add(EtsiCtlEntry::aa(
                a.try_into()
                    .map_err(|e| Self::Error::Add(AddCommandError::URL(e)))?,
            )));
        }

        for a in self.add.dc {
            res.push(EtsiCtlCommand::add(EtsiCtlEntry::dc(
                a.try_into()
                    .map_err(|e| Self::Error::Add(AddCommandError::URL(e)))?,
            )));
        }

        for a in self.add.tlm {
            res.push(EtsiCtlCommand::add(EtsiCtlEntry::tlm(
                a.try_into()
                    .map_err(|e| Self::Error::Add(AddCommandError::URL(e)))?,
            )));
        }

        for d in self.delete {
            res.push(EtsiCtlCommand::delete(
                d.try_into().map_err(Self::Error::Delete)?,
            ));
        }

        Ok(res)
    }
}

/// CTL format, specifying if the CTL content is full or delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtlFormat {
    /// Full CTL.
    Full,
    /// Delta CTL.
    Delta,
}

pub type CertificateTrustListResult<T> = core::result::Result<T, CertificateTrustListError>;

/// Certificate Trust List error.
#[derive(Debug)]
pub enum CertificateTrustListError {
    /// Asn.1 wrapper error.
    Asn1Wrapper(Asn1WrapperError),
    /// CTL version is not supported.
    UnsupportedVersion,
    /// Unexpected Etsi TS 102941 data content.
    UnexpectedDataContent,
    /// CTL Commands error.
    Commands(CtlCommandsError),
    /// Outer wrapper.
    Outer(SignedDataError),
    /// Something went wrong while verifying the Outer wrapper.
    OuterVerifier(VerifierError),
    /// False Outer wrapper signature.
    FalseOuterSignature,
    /// No signer certificate to check the CTL signature against.
    NoSignerCertificate,
}

impl fmt::Display for CertificateTrustListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertificateTrustListError::Asn1Wrapper(e) => write!(f, "asn1 wrapper error: {}", e),
            CertificateTrustListError::UnsupportedVersion => write!(f, "unsupported version"),
            CertificateTrustListError::UnexpectedDataContent => {
                write!(f, "unexpected Etsi TS 102941 data content")
            }
            CertificateTrustListError::Commands(e) => write!(f, "commands: {}", e),
            CertificateTrustListError::Outer(e) => write!(f, "outer: {}", e),
            CertificateTrustListError::OuterVerifier(e) => write!(f, "outer verifier: {}", e),
            CertificateTrustListError::FalseOuterSignature => write!(f, "false outer signature"),
            CertificateTrustListError::NoSignerCertificate => write!(f, "no signer certificate"),
        }
    }
}

/// CTL data types enclosing trust lists.
/// Used to work in conjunction with the [Asn1Wrapper].
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq)]
enum InnerCertificateTrustListType {
    /// TLM CTL type, aka ECTL.
    TLM(Asn1Wrapper<ToBeSignedTlmCtl>),
    /// RCA CTL type, aka CTL.
    RCA(Asn1Wrapper<ToBeSignedRcaCtl>),
}

impl InnerCertificateTrustListType {
    /// Get a reference on the inner EtsiCtlFormat.
    pub fn inner_data(&self) -> &EtsiCtlFormat {
        match self {
            InnerCertificateTrustListType::TLM(w) => &w.inner().0,
            InnerCertificateTrustListType::RCA(w) => &w.inner().0,
        }
    }

    /// Get a mutable reference on the inner EtsiCtlFormat.
    pub fn inner_data_mut(&mut self) -> &mut EtsiCtlFormat {
        match self {
            InnerCertificateTrustListType::TLM(w) => &mut w.inner_mut().0,
            InnerCertificateTrustListType::RCA(w) => &mut w.inner_mut().0,
        }
    }

    /// Get the inner data as bytes, encoded as Asn.1 COER.
    #[allow(unused)]
    pub fn as_bytes(&self) -> Asn1WrapperResult<Vec<u8>> {
        match self {
            InnerCertificateTrustListType::TLM(w) => w.as_bytes(),
            InnerCertificateTrustListType::RCA(w) => w.as_bytes(),
        }
    }
}

/// Certificate Trust List type.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateTrustList {
    /// Inner certificate trust list structure.
    inner: InnerCertificateTrustListType,
}

impl CertificateTrustList {
    /// Constructs an [CertificateTrustList] from bytes, for a TLM emitted CTL type.
    /// The EtsiTs102941Data wrapper is expected.
    pub fn from_bytes_tlm(bytes: &[u8]) -> CertificateTrustListResult<Self> {
        let etsi_data = Asn1Wrapper::<EtsiTs102941Data>::decode_coer(bytes)
            .map_err(CertificateTrustListError::Asn1Wrapper)?;

        let tbs_tlm_ctl = match etsi_data.content {
            EtsiTs102941DataContent::certificateTrustListTlm(tlm) => tlm,
            _ => return Err(CertificateTrustListError::UnexpectedDataContent),
        };

        if tbs_tlm_ctl.0.version.0 != Integer::from(1) {
            return Err(CertificateTrustListError::UnsupportedVersion);
        }

        let inner_data =
            Asn1Wrapper::from_raw(tbs_tlm_ctl).map_err(CertificateTrustListError::Asn1Wrapper)?;
        let inner = InnerCertificateTrustListType::TLM(inner_data);

        Ok(Self { inner })
    }

    /// Constructs an [CertificateTrustList] from bytes, for an RCA emitted CTL type.
    /// The EtsiTs102941Data wrapper is expected.
    pub fn from_bytes_rca(bytes: &[u8]) -> CertificateTrustListResult<Self> {
        let etsi_data = Asn1Wrapper::<EtsiTs102941Data>::decode_coer(bytes)
            .map_err(CertificateTrustListError::Asn1Wrapper)?;

        let tbs_rca_ctl = match etsi_data.content {
            EtsiTs102941DataContent::certificateTrustListRca(rca) => rca,
            _ => return Err(CertificateTrustListError::UnexpectedDataContent),
        };

        if tbs_rca_ctl.0.version.0 != Integer::from(1) {
            return Err(CertificateTrustListError::UnsupportedVersion);
        }

        let inner_data =
            Asn1Wrapper::from_raw(tbs_rca_ctl).map_err(CertificateTrustListError::Asn1Wrapper)?;
        let inner = InnerCertificateTrustListType::RCA(inner_data);

        Ok(Self { inner })
    }

    /// Return the CTL next update moment as [TAI2004] time.
    pub fn next_update(&self) -> TAI2004 {
        let inner = self.inner.inner_data();
        TAI2004::from_secs(inner.next_update.0 .0)
    }

    /// Set the CTL `next_update` moment.
    pub fn set_next_update(&mut self, next_update: TAI2004) {
        let inner = self.inner.inner_data_mut();

        let value = next_update.secs() as u32;
        inner.next_update = Time32(Uint32(value));
    }

    /// Return the CTL format, ie: if the CTL is full or delta.
    pub fn format(&self) -> CtlFormat {
        let inner = self.inner.inner_data();

        if inner.is_full_ctl {
            CtlFormat::Full
        } else {
            CtlFormat::Delta
        }
    }

    /// Set the CTL format.
    pub fn set_format(&mut self, format: CtlFormat) {
        let inner = self.inner.inner_data_mut();
        inner.is_full_ctl = format == CtlFormat::Full;
    }

    /// Return the CTL sequence number.
    pub fn sequence_number(&self) -> u8 {
        let inner = self.inner.inner_data();
        inner.ctl_sequence
    }

    /// Set the CTL sequence number.
    pub fn set_sequence_number(&mut self, seq_num: u8) {
        let inner = self.inner.inner_data_mut();
        inner.ctl_sequence = seq_num;
    }

    /// Returns the CTL commands.
    pub fn commands(&self) -> CertificateTrustListResult<CtlCommands> {
        let inner = self.inner.inner_data();
        CtlCommands::try_from(&inner.ctl_commands).map_err(CertificateTrustListError::Commands)
    }

    /// Set the CTL commands.
    pub fn set_commands(&mut self, commands: CtlCommands) -> CertificateTrustListResult<()> {
        let inner = self.inner.inner_data_mut();
        inner.ctl_commands = commands
            .try_into()
            .map_err(CertificateTrustListError::Commands)?;

        Ok(())
    }
}
