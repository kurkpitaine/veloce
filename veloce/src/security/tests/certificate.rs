use veloce_asn1::{defs::etsi_103097_v211::etsi_ts103097Module, prelude::rasn};

use crate::security::certificate::{
    AuthorizationAuthorityCertificate, EnrollmentAuthorityCertificate, RootCertificate,
    TrustListManagerCertificate,
};

fn load_root_cert() -> etsi_ts103097Module::EtsiTs103097Certificate {
    let input_root = include_bytes!("assets/RCA.cert");
    rasn::coer::decode::<etsi_ts103097Module::EtsiTs103097Certificate>(input_root).unwrap()
}

fn load_ea_cert() -> etsi_ts103097Module::EtsiTs103097Certificate {
    let input_ea = include_bytes!("assets/EA.cert");
    rasn::coer::decode::<etsi_ts103097Module::EtsiTs103097Certificate>(input_ea).unwrap()
}

fn load_aa_cert() -> etsi_ts103097Module::EtsiTs103097Certificate {
    let input_aa = include_bytes!("assets/AA.cert");
    rasn::coer::decode::<etsi_ts103097Module::EtsiTs103097Certificate>(input_aa).unwrap()
}

fn load_tlm_cert() -> etsi_ts103097Module::EtsiTs103097Certificate {
    let input_tlm = include_bytes!("assets/TLM.cert");
    rasn::coer::decode::<etsi_ts103097Module::EtsiTs103097Certificate>(input_tlm).unwrap()
}

#[test]
fn root_cert_valid() {
    let cert = load_root_cert();
    let _ = RootCertificate::from_etsi_certificate(cert.0).unwrap();
}

#[test]
fn tlm_cert_valid() {
    let cert = load_tlm_cert();
    let _ = TrustListManagerCertificate::from_etsi_certificate(cert.0).unwrap();
}

#[test]
fn tlm_ea_valid() {
    let cert = load_ea_cert();
    let _ = EnrollmentAuthorityCertificate::from_etsi_certificate(cert.0).unwrap();
}

#[test]
fn tlm_aa_valid() {
    let cert = load_aa_cert();
    let _ = AuthorizationAuthorityCertificate::from_etsi_certificate(cert.0).unwrap();
}
