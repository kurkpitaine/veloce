use std::{path::PathBuf, rc::Rc};

use veloce_asn1::{defs::etsi_103097_v211::etsi_ts103097_module, prelude::rasn};

use crate::{
    security::{
        backend::openssl::OpensslBackend,
        certificate::{
            AuthorizationAuthorityCertificate, AuthorizationTicketCertificate,
            EnrollmentAuthorityCertificate, ExplicitCertificate, RootCertificate,
            TrustListManagerCertificate,
        },
        DirectoryStorage, DirectoryStorageConfig, OpensslBackendConfig,
    },
    time::Instant,
};

pub fn openssl_backend() -> OpensslBackend {
    let mut key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    key_path.pop();
    key_path.push(file!());
    key_path.pop();
    let key_path = std::fs::canonicalize(key_path).unwrap();

    let storage_config =
        DirectoryStorageConfig::new(Some(key_path.into_os_string().into_string().unwrap()));
    let storage = Rc::new(DirectoryStorage::new(storage_config).unwrap());

    let config = OpensslBackendConfig::new("test1234".to_string().into());
    OpensslBackend::new(config, storage.clone()).unwrap()
}

pub fn load_root_cert() -> etsi_ts103097_module::EtsiTs103097Certificate {
    let input_root = include_bytes!("assets/RCA.cert");
    rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(input_root).unwrap()
}

pub fn load_ea_cert() -> etsi_ts103097_module::EtsiTs103097Certificate {
    let input_ea = include_bytes!("assets/EA.cert");
    rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(input_ea).unwrap()
}

pub fn load_aa_cert() -> etsi_ts103097_module::EtsiTs103097Certificate {
    let input_aa = include_bytes!("assets/AA.cert");
    rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(input_aa).unwrap()
}

pub fn load_at_cert() -> etsi_ts103097_module::EtsiTs103097Certificate {
    let input_at = include_bytes!("assets/AT_0.cert");
    rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(input_at).unwrap()
}

pub fn load_tlm_cert() -> etsi_ts103097_module::EtsiTs103097Certificate {
    let input_tlm = include_bytes!("assets/TLM.cert");
    rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(input_tlm).unwrap()
}

pub fn valid_timestamp() -> Instant {
    // 2024-05-26 - 00h00m00s
    Instant::from_secs(1716674400)
}

#[test]
fn root_cert_valid() {
    let backend = openssl_backend();
    let raw_cert = load_root_cert();
    let root_cert = RootCertificate::from_etsi_cert(raw_cert.0, &backend).unwrap();

    assert!(root_cert
        .check(valid_timestamp(), &backend, |_| { None::<RootCertificate> })
        .unwrap());
}

#[test]
fn tlm_cert_valid() {
    let backend = openssl_backend();
    let cert = load_tlm_cert();
    let _ = TrustListManagerCertificate::from_etsi_cert(cert.0, &backend).unwrap();
}

#[test]
fn ea_cert_valid() {
    let backend = openssl_backend();
    let raw_cert = load_ea_cert();
    let root_cert = RootCertificate::from_etsi_cert(load_root_cert().0, &backend).unwrap();
    let ea_cert = EnrollmentAuthorityCertificate::from_etsi_cert(raw_cert.0, &backend).unwrap();

    assert!(ea_cert
        .check(valid_timestamp(), &backend, |_| Some(root_cert))
        .unwrap());
}

#[test]
fn aa_cert_valid() {
    let backend = openssl_backend();
    let raw_cert = load_aa_cert();
    let root_cert = RootCertificate::from_etsi_cert(load_root_cert().0, &backend).unwrap();
    let aa_cert = AuthorizationAuthorityCertificate::from_etsi_cert(raw_cert.0, &backend).unwrap();

    assert!(aa_cert
        .check(valid_timestamp(), &backend, |_| Some(root_cert))
        .unwrap());
}

#[test]
fn at_cert_valid() {
    let backend = openssl_backend();
    let raw_cert = load_at_cert();
    let aa_cert = load_aa_cert();
    let aa_cert = AuthorizationAuthorityCertificate::from_etsi_cert(aa_cert.0, &backend).unwrap();
    let at_cert = AuthorizationTicketCertificate::from_etsi_cert(raw_cert.0, &backend).unwrap();

    assert!(at_cert
        .check(valid_timestamp(), &backend, |_| Some(aa_cert))
        .unwrap());
}
