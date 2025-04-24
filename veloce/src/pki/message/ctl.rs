use veloce_asn1::defs::etsi_102941_v221::etsi_ts102941_trust_lists::CtlFormat as InnerCtlFormat;

/// Certificate Trust List type.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateTrustList {
    /// Inner certificate trust list structure.
    inner: InnerCtlFormat,
}

impl CertificateTrustList {

}
