// build.rs build script
use rasn_compiler::prelude::*;
use std::{env, fs, path::PathBuf};

fn main() {
    let compile = env::var("COMPILE_ASN1").map_or(false, |c| c == "1");
    if !compile {
        return;
    }

    let gen_ts = env::var("GEN_TS").map_or(false, |c| c == "1");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from("./out");

    if !out_path.exists() {
        fs::create_dir(&out_path).unwrap();
    }

    // Compiler for CDD/CAM/DENM files.
    #[cfg(any(
        feature = "etsi-cdd-r2",
        feature = "etsi-cam-r2",
        feature = "etsi-denm-r2"
    ))]
    match Compiler::<RasnBackend, _>::new()
        .add_asn_sources_by_path(
            vec![
                #[cfg(feature = "etsi-cdd-r2")]
                PathBuf::from("asn/messages/etsi_102894-2_v2.2.1/ETSI-ITS-CDD.asn"),
                #[cfg(feature = "etsi-cam-r2")]
                PathBuf::from("asn/messages/etsi_103900_v2.1.1/CAM-PDU-Descriptions.asn"),
                #[cfg(feature = "etsi-denm-r2")]
                PathBuf::from("asn/messages/etsi_103831_v2.2.1/DENM-PDU-Descriptions.asn"),
            ]
            .iter(),
        )
        .compile_to_string()
    {
        Ok(res) => {
            println!("ASN1 compiler warnings: {:?}", res.warnings);
            let contents = res
                .generated
                .replace("DEFAULT_VALIDITY\n", "DeltaTimeSecond(600)\n");
            fs::write(out_path.join("etsi_messages_r2.rs"), contents).unwrap();
        }
        Err(error) => {
            panic!(
                "Cannot compile ETSI CDD/CAM/DENM ASN1 descriptions: {:?}",
                error
            );
        }
    }

    if gen_ts {
        match Compiler::<TypescriptBackend, _>::new()
            .add_asn_sources_by_path(
                vec![
                    #[cfg(feature = "etsi-cdd-r2")]
                    PathBuf::from("asn/messages/etsi_102894-2_v2.2.1/ETSI-ITS-CDD.asn"),
                    #[cfg(feature = "etsi-cam-r2")]
                    PathBuf::from("asn/messages/etsi_103900_v2.1.1/CAM-PDU-Descriptions.asn"),
                    #[cfg(feature = "etsi-denm-r2")]
                    PathBuf::from("asn/messages/etsi_103831_v2.2.1/DENM-PDU-Descriptions.asn"),
                ]
                .iter(),
            )
            .set_output_path(out_path.join("etsi_messages_r2.ts"))
            .compile()
        {
            Ok(o) => println!("TS compiler warnings: {:?}", o),
            Err(error) => {
                panic!(
                    "Cannot compile ETSI CDD/CAM/DENM ASN1 descriptions ot Typescript: {:?}",
                    error
                );
            }
        }
    }

    // Compiler for ETSI Security files.
    #[cfg(feature = "etsi-security-r2")]
    match Compiler::<RasnBackend, _>::new()
        .add_asn_sources_by_path(
            vec![
                PathBuf::from("asn/security/etsi_103097_v2.1.1/Ieee1609Dot2.asn"),
                PathBuf::from("asn/security/etsi_103097_v2.1.1/Ieee1609Dot2BaseTypes.asn"),
                PathBuf::from("asn/security/etsi_103097_v2.1.1/EtsiTs103097ExtensionModule.asn"),
                PathBuf::from("asn/security/etsi_103097_v2.1.1/EtsiTs103097Module.asn"),
            ]
            .iter(),
        )
        .compile_to_string()
    {
        Ok(res) => {
            println!("ASN1 compiler warnings: {:?}", res.warnings);
            let contents = res
                .generated
                .replace(
                    "data: Option<Ieee1609Dot2Data>",
                    "data: Option<alloc::boxed::Box<Ieee1609Dot2Data>>",
                )
                .replace(
                    "EtsiTs103097HeaderInfoExtensionId(ExtId(Integer::from(1)));\n",
                    "EtsiTs103097HeaderInfoExtensionId(ExtId(1));\n",
                )
                .replace(
                    "EtsiTs103097HeaderInfoExtensionId (ExtId (Integer :: from (2))) ;",
                    "EtsiTs103097HeaderInfoExtensionId (ExtId (2)) ;",
                )
                .replace(
                    "EndEntityType(Oid::const_new(&[]).to_owned())\n",
                    "EndEntityType(BitString::from_slice(&[1u8]))\n",
                );
            fs::write(out_path.join("etsi_103097_v211.rs"), contents).unwrap();
        }
        Err(error) => {
            panic!(
                "Cannot compile ETSI security ASN1 descriptions: {:?}",
                error
            );
        }
    }

    // Compiler for ETSI PKI files.
    #[cfg(feature = "etsi-pki-r2")]
    match Compiler::<RasnBackend, _>::new()
        .add_asn_sources_by_path(
            vec![
                PathBuf::from("asn/security/etsi_102941_v2.2.1/EtsiTs102941BaseTypes.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/EtsiTs102941MessagesCa.asn"),
                PathBuf::from(
                    "asn/security/etsi_102941_v2.2.1/EtsiTs102941MessagesItss-OptionalPrivacy.asn",
                ),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/EtsiTs102941MessagesItss.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/EtsiTs102941TrustLists.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/EtsiTs102941TypesAuthorization.asn"),
                PathBuf::from(
                    "asn/security/etsi_102941_v2.2.1/EtsiTs102941TypesAuthorizationValidation.asn",
                ),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/EtsiTs102941TypesCaManagement.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/EtsiTs102941TypesEnrolment.asn"),
                PathBuf::from(
                    "asn/security/etsi_102941_v2.2.1/EtsiTs102941TypesLinkCertificate.asn",
                ),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2BaseTypes.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Crl.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2CrlBaseTypes.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1AcaEeInterface.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1AcaLaInterface.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1AcaMaInterface.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1AcaRaInterface.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1Acpc.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1CamRaInterface.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1CertManagement.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1EcaEeInterface.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1EeMaInterface.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1EeRaInterface.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1LaMaInterface.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1LaRaInterface.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1MaRaInterface.asn"),
                PathBuf::from("asn/security/etsi_102941_v2.2.1/Ieee1609Dot2Dot1Protocol.asn"),
            ]
            .iter(),
        )
        .compile_to_string()
    {
        Ok(res) => {
            println!("ASN1 compiler warnings: {:?}", res.warnings);
            let contents = res
                .generated
                .replace(
                    "super::etsi_ts103097_module",
                    "crate::etsi_103097_v211::etsi_ts103097_module",
                )
                .replace(
                    "data: Option<Ieee1609Dot2Data>",
                    "data: Option<alloc::boxed::Box<Ieee1609Dot2Data>>",
                )
                .replace(
                    "super::etsi_ts103097_extension_module",
                    "crate::etsi_103097_v211::etsi_ts103097Extension_module",
                )
                .replace(
                    "EndEntityType(Oid::const_new(&[]).to_owned())\n",
                    "EndEntityType(BitString::from_slice(&[1u8]))\n",
                );
            fs::write(out_path.join("etsi_102941_v221.rs"), contents).unwrap();
        }
        Err(error) => {
            panic!(
                "Cannot compile ETSI security ASN1 descriptions: {:?}",
                error
            );
        }
    }

    // Compiler for IEEE1609.2-2023 files.
    #[cfg(feature = "ieee1609dot2-2023-wip-do-not-use")]
    match Compiler::<RasnBackend, _>::new()
        .add_asn_sources_by_path(
            vec![
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2BaseTypes.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Crl.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2CrlBaseTypes.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2CrlSsp.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1AcaEeInterface.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1AcaLaInterface.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1AcaMaInterface.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1AcaRaInterface.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1Acpc.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1CamRaInterface.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1CertManagement.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1EcaEeInterface.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1EeMaInterface.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1EeRaInterface.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1LaMaInterface.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1LaRaInterface.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1MaRaInterface.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Dot1Protocol.asn"),
                PathBuf::from("asn/security/ieee1609_2023/Ieee1609Dot2Peer2Peer.asn"),
                PathBuf::from("asn/security/ieee1609_2023/EtsiTs103097ExtensionModule.asn"),
                PathBuf::from("asn/security/ieee1609_2023/EtsiTs103097Module.asn"),
            ]
            .iter(),
        )
        .compile_to_string()
    {
        Ok(res) => {
            println!("ASN1 compiler warnings: {:?}", res.warnings);
            let contents = res
                .generated
                .replace(
                    "EtsiTs103097HeaderInfoExtensionId (ExtId (Integer :: from (2))) ;",
                    "EtsiTs103097HeaderInfoExtensionId (ExtId (2)) ;",
                )
                .replace(
                    "EtsiTs103097HeaderInfoExtensionId(ExtId(Integer::from(1)));\n",
                    "EtsiTs103097HeaderInfoExtensionId(ExtId(1));\n",
                )
                .replace(
                    "Ieee1609HeaderInfoExtensionId(ExtId(Integer::from(1)));\n",
                    "Ieee1609HeaderInfoExtensionId(ExtId(1));\n",
                )
                .replace(
                    "data: Option<Ieee1609Dot2Data>,\n",
                    "data: alloc::boxed::Box<Option<Ieee1609Dot2Data>>,\n",
                )
                .replace(
                    "EndEntityType(Oid::const_new(&[]).to_owned())\n",
                    "EndEntityType(BitString::from_slice(&[1u8]))\n",
                );
            fs::write(out_path.join("ieee1609dot2_2023.rs"), contents).unwrap();
        }
        Err(error) => {
            panic!(
                "Cannot compile IEEE1609.2-2023 ASN1 descriptions: {:?}",
                error
            );
        }
    }
}
