// build.rs build script
use rasn_compiler::prelude::*;
use std::{env, fs, path::PathBuf};

fn main() {
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Compiler for CDD/CAM/DENM files.
    match Compiler::<RasnBackend, _>::new()
        // add several ASN1 source files
        .add_asn_sources_by_path(
            vec![
                PathBuf::from("asn/ETSI-ITS-CDD.asn"),
                PathBuf::from("asn/CAM-PDU-Descriptions.asn"),
                PathBuf::from("asn/DENM-PDU-Descriptions.asn"),
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
            fs::write(out_path.join("bindings.rs"), contents).unwrap();
        }
        Err(error) => {
            panic!("Cannot compile ASN1 descriptions: {:?}", error);
        }
    }

    // Compiler for ETSI TS 103097 v2.1.1 files.
    /* match Compiler::new()
        // add several ASN1 source files
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
            fs::write(out_path.join("bindings_etsi_103097_v211.rs"), contents).unwrap();
        }
        Err(error) => {
            panic!("Cannot compile ASN1 descriptions: {:?}", error);
        }
    } */

    // Compiler for IEEE1609.2 files.
    /* match Compiler::new()
        // add several ASN1 source files
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
            fs::write(out_path.join("bindings_ieee1609dot2_2023.rs"), contents).unwrap();
        }
        Err(error) => {
            panic!("Cannot compile ASN1 descriptions: {:?}", error);
        }
    } */
}
