use log::error;
use veloce::utils;
use veloce_gnss::Gpsd;

pub fn main() {
    utils::setup_logging("trace");
    match Gpsd::connect("127.0.0.1:2947".to_string()) {
        Ok(handle) => loop {
            handle.recv();
        },
        Err(e) => {
            error!("{}", e);
        }
    }
}
