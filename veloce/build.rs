pub fn main() {
    #[cfg(feature = "proto-security")]
    {
        #[cfg(not(any(feature = "security-openssl")))]
        panic!("When proto-security feature is selected, at least one security-backend feature should be enabled, ie: security-openssl");
    }

    #[cfg(feature = "socket")]
    {
        #[cfg(not(any(
            feature = "socket-geonet",
            feature = "socket-btp-a",
            feature = "socket-btp-b",
            feature = "socket-cam",
            feature = "socket-denm"
        )))]
        panic!("At least one socket feature should be enabled, ie: socket-geonet, socket-btp-a, socket-btp-b, socket-cam, socket-denm");
    }

    #[cfg(not(any(feature = "proto-geonet")))]
    panic!("At least one low level protocol feature should be enabled, ie: proto-geonet");
}
