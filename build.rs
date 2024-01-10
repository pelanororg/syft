use std::{env, path::Path, process::Command};

fn main() -> Result<(), std::io::Error> {
    let status = Command::new("go")
        .args(["build", "-buildmode=c-shared", "-o", "libsyft.so"])
        .current_dir("cmd/syft")
        .status()
        .expect("Failed to execute go build");
    assert!(status.success(), "Failed to build the project");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR environment variable not set");

    let source_path = Path::new("cmd/syft/libsyft.so");
    let destination_path = Path::new(&out_dir).join("../../../deps/libsyft.so");

    std::fs::copy(source_path, destination_path).expect("Failed to copy libsyft.so");

    // Tell cargo to link the library
    println!("cargo:rustc-link-lib=dylib=syft");

    Ok(())
}
