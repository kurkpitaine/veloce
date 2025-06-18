use std::env;

fn main() {
    // Export defaults as compile time environment variables.
    // These variables are to be set by package managers in their build script.
    // `export VELOCE_CFG_PATH=<default configuration file> && cargo build`.
    let variables = vec!["VELOCE_CFG_PATH", "VELOCE_PID_FILE_PATH"];
    for variable in variables {
        if let Ok(val) = env::var(variable) {
            println!("cargo:rustc-env={variable}={val}");
        }
    }
}
