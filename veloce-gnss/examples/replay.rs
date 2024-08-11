use std::{path::PathBuf, thread::sleep};

use veloce::time::{Duration, Instant};
use veloce_gnss::Replay;

pub fn main() {
    let path = load_nmea_log();
    let mut player = Replay::new(&path, Duration::from_secs(1)).unwrap();

    loop {
        let now = Instant::now();
        let poll_at = player.poll_at();

        if now >= poll_at {
            if player.poll(now) {
                println!("Position: {:?}", player.fetch_position());
            }
        } else {
            let sleep_duration = poll_at - now;
            sleep(sleep_duration.into());
        }
    }
}

fn load_nmea_log() -> PathBuf {
    #[cfg(debug_assertions)]
    {
        let mut log_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        log_path.pop();
        log_path.push(file!());
        log_path.pop();
        log_path.push("assets/road.nmea");

        std::fs::canonicalize(log_path).unwrap()
    }

    #[cfg(not(debug_assertions))]
    std::fs::canonicalize("assets/road.nmea").unwrap()
}
