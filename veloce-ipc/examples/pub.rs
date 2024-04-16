use std::{
    thread,
    time::{Duration, Instant, SystemTime},
};

use rkyv::ser::{serializers::AllocSerializer, Serializer};
use veloce_ipc::{IpcSerializer, IpcEvent, IpcEventType, ZmqPublisher};

fn main() {
    let publisher =
        ZmqPublisher::new("127.0.0.1:45556".to_string()).expect("Cannot create publisher");
    println!("Published created");

    let start_time = Instant::now();

    loop {
        let evt = IpcEvent {
            timestamp: start_time.elapsed().as_micros() as u64,
            time: SystemTime::now(),
            r#type: IpcEventType::CamRx([0, 1, 2, 3, 4, 5].to_vec()),
        };

        let mut serializer = IpcSerializer::<AllocSerializer<2048>>::default();
        serializer.serialize_value(&evt).unwrap();

        let bytes = serializer.into_inner().into_serializer().into_inner();
        publisher.send(&bytes).unwrap();
        println!("Published send");

        thread::sleep(Duration::from_secs(1));
    }
}
