use std::path::PathBuf;

use approx::assert_relative_eq;
use uom::si::angle::degree;

use crate::{
    common::PotiPosition,
    security::{
        backend::openssl::{OpensslBackend, OpensslBackendConfig},
        certificate::{
            AuthorizationAuthorityCertificate, AuthorizationTicketCertificate, ExplicitCertificate,
            RootCertificate,
        },
        permission::Permission,
        secured_message::{SecuredMessage, SignerIdentifier},
        service::SecurityService,
        ssp::{cam::CamSsp, denm::DenmSsp},
        trust_chain::TrustChain,
        SecurityBackend,
    },
    time::Duration,
    types::{tenth_of_microdegree, Latitude, Longitude},
};

use super::certificate::{self, valid_timestamp};

const SECURITY_ENVELOPE: [u8; 313] = [
    0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x42, 0x20, 0x50, 0x02, 0x00, 0x00, 0x1e, 0x01, 0x00, 0x3c,
    0x00, 0xae, 0x17, 0x15, 0xb4, 0x56, 0x03, 0xd7, 0x73, 0x4e, 0x6b, 0x1c, 0xa8, 0xac, 0xff, 0xff,
    0x04, 0x1e, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd1, 0x00, 0x00, 0x02,
    0x02, 0xc7, 0x92, 0xbf, 0xbc, 0x63, 0xa4, 0x00, 0xfa, 0x49, 0xb2, 0xbf, 0xed, 0x49, 0xbe, 0x16,
    0x06, 0x30, 0xa1, 0x40, 0x00, 0x33, 0x1a, 0x96, 0x80, 0x40, 0x01, 0x24, 0x00, 0x02, 0x49, 0x51,
    0x9a, 0xbd, 0x41, 0xf6, 0x81, 0x01, 0x01, 0x80, 0x03, 0x00, 0x80, 0x0e, 0xa1, 0xdf, 0x3d, 0x94,
    0xfa, 0x8f, 0x68, 0x10, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x5b, 0xaa, 0xb1, 0x85, 0x00,
    0x18, 0x01, 0x03, 0x80, 0x01, 0x8b, 0x81, 0x07, 0x06, 0x01, 0xb2, 0xa7, 0x33, 0x7e, 0xe0, 0x80,
    0x01, 0x25, 0x81, 0x05, 0x04, 0x01, 0xff, 0xb6, 0x20, 0x80, 0x01, 0x24, 0x81, 0x04, 0x03, 0x01,
    0x80, 0x00, 0x80, 0x80, 0x82, 0x6f, 0x63, 0xf4, 0x2a, 0xa1, 0xe0, 0x97, 0xcc, 0x40, 0xa0, 0x2c,
    0xfe, 0x91, 0xa8, 0x07, 0xe5, 0x68, 0xd1, 0xac, 0x7b, 0x65, 0x0e, 0x8b, 0xd6, 0x54, 0x5b, 0x92,
    0x4e, 0x43, 0x4f, 0xb1, 0x80, 0x80, 0x80, 0x8e, 0xe2, 0x77, 0xee, 0xf1, 0xed, 0x2a, 0xa5, 0xbf,
    0x9c, 0xcc, 0x23, 0xa2, 0xf5, 0x54, 0xdc, 0x46, 0x19, 0xec, 0x85, 0x5c, 0x2b, 0x4d, 0x15, 0x7c,
    0x01, 0x65, 0x44, 0xcb, 0xba, 0x62, 0x20, 0xc7, 0x5e, 0x45, 0xad, 0xd5, 0x66, 0xe8, 0x11, 0xa3,
    0x62, 0xb7, 0x82, 0x48, 0x19, 0x52, 0x53, 0x38, 0x95, 0xb9, 0x91, 0xe5, 0x6f, 0xab, 0x94, 0x45,
    0x14, 0x85, 0xd6, 0x99, 0x64, 0x42, 0x1a, 0x80, 0x80, 0x78, 0xb8, 0xa3, 0x2e, 0xdd, 0xdd, 0x59,
    0xe1, 0x46, 0xf9, 0xd0, 0xfa, 0x96, 0x05, 0x15, 0x6f, 0x7f, 0xf8, 0x4e, 0xd2, 0xb6, 0x8b, 0xa8,
    0x84, 0x7a, 0x2d, 0x67, 0x17, 0x99, 0x32, 0x93, 0x07, 0x22, 0xb7, 0xb4, 0x44, 0xc5, 0x2e, 0x54,
    0x46, 0x03, 0x45, 0xa5, 0xca, 0x73, 0xb8, 0xa7, 0x4c, 0x01, 0xe9, 0x41, 0x50, 0x43, 0x63, 0x69,
    0x75, 0xf8, 0x72, 0x86, 0xb9, 0xc6, 0xbc, 0x7d, 0xec,
];

const GN_CAM: [u8; 66] = [
    0x20, 0x50, 0x02, 0x00, 0x00, 0x1e, 0x01, 0x00, 0x3c, 0x00, 0xae, 0x17, 0x15, 0xb4, 0x56, 0x03,
    0xd7, 0x73, 0x4e, 0x6b, 0x1c, 0xa8, 0xac, 0xff, 0xff, 0x04, 0x1e, 0xb0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x07, 0xd1, 0x00, 0x00, 0x02, 0x02, 0xc7, 0x92, 0xbf, 0xbc, 0x63, 0xa4,
    0x00, 0xfa, 0x49, 0xb2, 0xbf, 0xed, 0x49, 0xbe, 0x16, 0x06, 0x30, 0xa1, 0x40, 0x00, 0x33, 0x1a,
    0x96, 0x80,
];

fn setup_security_service() -> SecurityService {
    let mut key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    key_path.pop();
    key_path.push(file!());
    key_path.pop();
    key_path.push("assets/AT.pem");
    let key_path = std::fs::canonicalize(key_path).unwrap();

    let config = OpensslBackendConfig {
        canonical_key_path: "".to_string(),
        canonical_key_passwd: "".to_string().into(),
        signing_cert_secret_key_path: Some(key_path.into_os_string().into_string().unwrap()),
        signing_cert_secret_key_passwd: Some("test1234".to_string().into()),
    };

    let backend = OpensslBackend::new(config).unwrap();
    let raw_root_cert = certificate::load_root_cert();
    let raw_aa_cert = certificate::load_aa_cert();
    let raw_at_cert = certificate::load_at_cert();

    let root_cert = RootCertificate::from_etsi_cert(raw_root_cert.0, &backend).unwrap();
    let aa_cert =
        AuthorizationAuthorityCertificate::from_etsi_cert(raw_aa_cert.0, &backend).unwrap();
    let at_cert = AuthorizationTicketCertificate::from_etsi_cert(raw_at_cert.0, &backend).unwrap();

    let mut own_chain = TrustChain::new(root_cert.into_with_hash_container(&backend).unwrap());
    own_chain.set_aa_cert(aa_cert.into_with_hash_container(&backend).unwrap());
    own_chain.set_at_cert(at_cert.into_with_hash_container(&backend).unwrap());

    SecurityService::new(own_chain, SecurityBackend::Openssl(backend))
}

#[test]
fn verify_secured_message() {
    let mut service = setup_security_service();

    let msg = SecuredMessage::from_bytes(&SECURITY_ENVELOPE).unwrap();

    service
        .verify_secured_message(&msg, valid_timestamp())
        .unwrap();
}

#[test]
fn test_sign_message() {
    let mut service = setup_security_service();

    let permissions = Permission::CAM(CamSsp::new().into());

    let position = PotiPosition {
        latitude: Some(Latitude::new::<degree>(48.2764384)),
        longitude: Some(Longitude::new::<degree>(-3.5519532)),
        altitude: None,
    };

    let res = service
        .encap_packet(&GN_CAM, permissions, valid_timestamp(), position)
        .unwrap();

    assert!(res.len() > 0);

    service
        .decap_packet(&res, valid_timestamp() + Duration::from_millis(50))
        .unwrap();
}

#[test]
fn test_signer_digest_or_certificate_cam() {
    let mut service = setup_security_service();

    let permissions = Permission::CAM(CamSsp::new().into());

    let position = PotiPosition {
        latitude: Some(Latitude::new::<degree>(48.2764384)),
        longitude: Some(Longitude::new::<degree>(-3.5519532)),
        altitude: None,
    };

    let timestamp_start = valid_timestamp();
    let mut message = SecuredMessage::new(&GN_CAM);

    service
        .sign_secured_message(&mut message, permissions.clone(), timestamp_start, position)
        .unwrap();

    // First secured message should contain the full certificate.
    let signer = message.signer_identifier().unwrap();
    assert!(matches!(signer, SignerIdentifier::Certificate(_)));

    let mut message = SecuredMessage::new(&GN_CAM);

    service
        .sign_secured_message(
            &mut message,
            permissions.clone(),
            timestamp_start + Duration::from_millis(500),
            position,
        )
        .unwrap();

    // 500 milliseconds after the inclusion of the full certificate, second secured message should contain the digest certificate.
    let signer = message.signer_identifier().unwrap();
    assert!(matches!(signer, SignerIdentifier::Digest(_)));

    let mut message = SecuredMessage::new(&GN_CAM);

    service
        .sign_secured_message(
            &mut message,
            permissions,
            timestamp_start + Duration::from_millis(1000),
            position,
        )
        .unwrap();

    // 1 second after the inclusion of the full certificate, secured message should contain the full certificate.
    let signer = message.signer_identifier().unwrap();
    assert!(matches!(signer, SignerIdentifier::Certificate(_)));

    // The previous behavior should only be valid for CAM messages.
    let mut message = SecuredMessage::new(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let permissions = Permission::DENM(DenmSsp::new_v1().into());

    service
        .sign_secured_message(
            &mut message,
            permissions,
            timestamp_start + Duration::from_millis(1100),
            position,
        )
        .unwrap();

    // 1 second after the inclusion of the full certificate, secured message should contain the full certificate.
    let signer = message.signer_identifier().unwrap();
    assert!(matches!(signer, SignerIdentifier::Certificate(_)));
}

#[test]
fn test_position_inclusion() {
    let mut service = setup_security_service();
    let permissions = Permission::DENM(DenmSsp::new_v1().into());

    let position = PotiPosition {
        latitude: Some(Latitude::new::<degree>(48.2764384)),
        longitude: Some(Longitude::new::<degree>(-3.5519532)),
        altitude: None,
    };

    // Position should be included only for DENM messages.
    let timestamp = valid_timestamp();
    let mut message = SecuredMessage::new(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    service
        .sign_secured_message(&mut message, permissions, timestamp, position)
        .unwrap();

    let location = message.generation_location().unwrap().unwrap();
    assert_relative_eq!(
        location.latitude.0 .0 as f64,
        position.latitude.unwrap().get::<tenth_of_microdegree>()
    );
    assert_relative_eq!(
        location.longitude.0 .0 as f64,
        position.longitude.unwrap().get::<tenth_of_microdegree>()
    );

    // Position should not be included for CAM messages.
    let permissions = Permission::CAM(CamSsp::new().into());
    let mut message = SecuredMessage::new(&GN_CAM);

    service
        .sign_secured_message(
            &mut message,
            permissions.clone(),
            timestamp + Duration::from_millis(500),
            position,
        )
        .unwrap();

    assert!(message.generation_location().unwrap().is_none());
}
