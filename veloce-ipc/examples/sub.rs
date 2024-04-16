use rkyv::Deserialize;
use veloce_ipc::{IpcEvent, ZmqSubscriber};

fn main() {
    let sub = ZmqSubscriber::new("127.0.0.1:45556".to_string()).expect("Cannot create subscriber");

    println!("Subscriber created");

    loop {
        sub.poll(None).unwrap();
        println!("poll");

        let data = sub.recv().unwrap();

        // You can use the safe API for fast zero-copy deserialization
        let archived = rkyv::check_archived_root::<IpcEvent>(&data[..]).unwrap();

        // And you can always deserialize back to the original type
        let deserialized: IpcEvent = archived.deserialize(&mut rkyv::Infallible).unwrap();

        println!("Data: {:?}", deserialized);
    }
}
