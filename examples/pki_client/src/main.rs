use std::{path::PathBuf, time::Duration};
use ureq::Agent;

use veloce::{
    security::{
        backend::PkiBackendTrait,
        certificate::{EnrollmentAuthorityCertificate, ExplicitCertificate},
        pki::service::PkiClientService,
        EcKeyType, OpensslBackend, OpensslBackendConfig,
    },
    time::Instant,
};
use veloce_asn1::{defs::etsi_103097_v211::etsi_ts103097_module, prelude::rasn};

pub fn main() -> Result<(), ureq::Error> {
    // let ea_uri = "http://0.fr-ea-roads.l0.c-its-pki.eu";
    let ea_uri = "http://1.ctag-2-ea.L0.siscoga4cad.com/av";
    let its_id = "FR01DIRO7A07DACD";

    // Create crypto backend.
    let mut backend = openssl_backend();
    let raw_ea_cert = load_ea_cert();
    let ea_certificate = EnrollmentAuthorityCertificate::from_etsi_cert(raw_ea_cert.0, &backend)
        .unwrap()
        .into_with_hash_container(&backend)
        .unwrap();

    // Station canonical key.
    match backend.canonical_pubkey().unwrap() {
        Some(pk) => pk,
        None => backend
            .generate_canonical_keypair(EcKeyType::NistP256r1)
            .unwrap(),
    };

    let service = PkiClientService::new(its_id.to_string());

    let http_config = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build();

    let http_agent: Agent = http_config.into();

    let (enrollment_req, enrollment_ctx) = service
        .emit_enrollment_request(&ea_certificate, Instant::now(), &mut backend)
        .unwrap();

    let response = http_agent
        .post(ea_uri)
        .content_type("application/x-its-request")
        .send(enrollment_req)?
        .body_mut()
        .read_to_vec()?;

    let enrollment_resp = service.parse_enrollment_response(
        &response,
        enrollment_ctx,
        &ea_certificate,
        Instant::now(),
        &backend,
    );

    println!("{:?}", enrollment_resp);

    Ok(())
}

pub fn openssl_backend() -> OpensslBackend {
    #[cfg(debug_assertions)]
    let veloce_dir = {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/.veloce/");
        std::fs::canonicalize(path)
            .unwrap()
            .into_os_string()
            .into_string()
            .unwrap()
    };

    #[cfg(not(debug_assertions))]
    let veloce_dir = ".veloce".to_string();

    let config = OpensslBackendConfig {
        veloce_dir: Some(veloce_dir),
        keys_password: "test1234".to_string().into(),
        ..Default::default()
    };

    OpensslBackend::new(config).unwrap()
}

pub fn load_ea_cert() -> etsi_ts103097_module::EtsiTs103097Certificate {
    #[cfg(debug_assertions)]
    let input_ea = include_bytes!(".veloce/assets/EA.cert");
    #[cfg(not(debug_assertions))]
    let input_ea = &fs::read(".veloce/assets/EA.cert").unwrap();

    rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(input_ea).unwrap()
}
