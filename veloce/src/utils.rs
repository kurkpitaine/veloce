#![allow(dead_code)]

#[cfg(feature = "log")]
use env_logger::Builder;
#[cfg(feature = "log")]
use log::{Level, LevelFilter};
use std::io::Write;
use std::str::{self};

use crate::time::Instant;

#[cfg(feature = "log")]
pub fn setup_logging_with_clock<F>(filter: &str, since_startup: F)
where
    F: Fn() -> Instant + Send + Sync + 'static,
{
    Builder::new()
        .format(move |buf, record| {
            let elapsed = since_startup();
            let timestamp = format!("[{elapsed}]");
            if record.target().starts_with("veloce::") {
                writeln!(
                    buf,
                    "\x1b[0m{} ({}): {}\x1b[0m",
                    timestamp,
                    record.target().replace("veloce::", ""),
                    record.args()
                )
            } else if record.level() == Level::Trace {
                let message = format!("{}", record.args());
                writeln!(
                    buf,
                    "\x1b[37m{} {}\x1b[0m",
                    timestamp,
                    message.replace('\n', "\n             ")
                )
            } else {
                writeln!(
                    buf,
                    "\x1b[32m{} ({}): {}\x1b[0m",
                    timestamp,
                    record.target(),
                    record.args()
                )
            }
        })
        .filter(None, LevelFilter::Trace)
        .parse_filters(filter)
        .parse_env("RUST_LOG")
        .init();
}

#[cfg(feature = "log")]
pub fn setup_logging(filter: &str) {
    setup_logging_with_clock(filter, Instant::now)
}
