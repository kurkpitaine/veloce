// build.rs build script
use rasn_compiler::prelude::*;
use std::{env, fs, path::PathBuf};

fn main() {
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Initialize the compiler
    match Compiler::new()
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
}
