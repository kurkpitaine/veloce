use std::net::UdpSocket;
use std::thread;

fn main() {
    let udp_server = thread::Builder::new()
        .name("Uppertester UDP server".to_string())
        .spawn(move || {
            let socket = UdpSocket::bind("0.0.0.0:29000").expect("Failed to bind to address");
            println!("Server listening on 127.0.0.1:29000");

            let mut buffer = [0; 4096];
            loop {
                let (size, source) = socket
                    .recv_from(&mut buffer)
                    .expect("Failed to receive data");
                let request = String::from_utf8_lossy(&buffer[..size]);
                println!("Received request: {} from {}", request, source);

                let response = "Hello, client!";
                socket
                    .send_to(response.as_bytes(), source)
                    .expect("Failed to send response");
            }
        })
        .unwrap();

    let _tt = udp_server.join().unwrap();
}
