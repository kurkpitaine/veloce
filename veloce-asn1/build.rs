// build.rs build script
use rasn_compiler::prelude::*;
use std::{env, path::PathBuf};

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
            ]
            .iter(),
        )
        // set an output path for the generated rust code
        .set_output_path(out_path.join("bindings.rs"))
        // optionally choose to support `no_std`
        .compile()
    {
        Ok(warnings) => {
            println!("ASN1 compiler warnings: {:?}", warnings);
        }
        Err(error) => {
            panic!("Cannot compile ASN1 descriptions: {:?}", error);
        }
    }
}
