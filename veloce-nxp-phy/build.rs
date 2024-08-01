use std::env;
use std::path::PathBuf;

fn main() {
    // TODO: improve this.
    let target = std::env::var("TARGET").unwrap();
    let sdk_path = if target == "armv7-unknown-linux-gnueabihf" {
        Some("/opt/homebrew/Cellar/arm-unknown-linux-gnueabihf/13.2.0/toolchain/arm-unknown-linux-gnueabihf/sysroot")
    } else {
        None
    };

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    let wrapper_path = if cfg!(feature = "llc-r17_1") {
        println!("cargo:rerun-if-changed=sys/r17.1/wrapper.h");

        "sys/r17.1/wrapper.h"
    } else if cfg!(feature = "llc-r16") {
        println!("cargo:rerun-if-changed=sys/r16/wrapper.h");

        "sys/r16/wrapper.h"
    } else {
        panic!("No LLC version selected");
    };

    let mut builder = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(wrapper_path)
        // Use core libs instead of std.
        .use_core()
        // Disable generation of layout tests since they are
        // architecture specific.
        .layout_tests(false)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    if let Some(path) = sdk_path {
        builder = builder.clang_args(&["-isysroot", path]);
        builder = builder.clang_args(&["-isystem", &format!("{}{}", path, "/usr/include")]);
    }

    // Finish the builder and generate the bindings.
    let bindings = builder
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
