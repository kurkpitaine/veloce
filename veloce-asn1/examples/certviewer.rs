use veloce_asn1::defs::etsi_103097_v211::etsi_ts103097_module;
use veloce_asn1::prelude::*;

fn main() {
    let ea_cert = include_bytes!("assets/EA.cert");
    let at_cert = include_bytes!("assets/AT.cert");
    let aa_cert = include_bytes!("assets/AA.cert");
    let rca_cert = include_bytes!("assets/RCA.cert");

    match rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(ea_cert) {
        Ok(d) => {
            let json = rasn::jer::encode(&d).unwrap();
            println!("EA Certificate:");
            println!("{}", json);
            println!("--------------------------------------------");
        }
        Err(e) => println!("Cannot decode EA: {}", e),
    }

    match rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(at_cert) {
        Ok(d) => {
            let json = rasn::jer::encode(&d).unwrap();
            println!("AT Certificate:");
            println!("{}", json);
            println!("--------------------------------------------");
        }
        Err(e) => println!("Cannot decode AT: {}", e),
    }

    match rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(aa_cert) {
        Ok(d) => {
            let json = rasn::jer::encode(&d).unwrap();
            println!("AA Certificate:");
            println!("{}", json);
            println!("--------------------------------------------");
        }
        Err(e) => println!("Cannot decode AA: {}", e),
    }

    match rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(rca_cert) {
        Ok(d) => {
            let json = rasn::jer::encode(&d).unwrap();
            println!("RCA Certificate:");
            println!("{}", json);
            println!("--------------------------------------------");
        }
        Err(e) => println!("Cannot decode RCA: {}", e),
    }
}
