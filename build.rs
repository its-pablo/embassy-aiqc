//! This build script copies the `memory.x` file from the crate root into
//! a directory where the linker can always find it at build time.
//! For many projects this is optional, as the linker always searches the
//! project root directory -- wherever `Cargo.toml` is. However, if you
//! are using a workspace or have a more complicated build setup, this
//! build script becomes required. Additionally, by requesting that
//! Cargo re-run the build script whenever `memory.x` is changed,
//! updating `memory.x` ensures a rebuild of the application with the
//! new memory settings.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use micropb_gen::{Config, Generator};

// Generate Rust module from .proto files
fn proto_generate() {
    let mut generator = Generator::new();
    generator
        .use_container_heapless()
        .configure(
            ".pitchfork.Credentials.domain",
            Config::new().max_bytes(1024),
        )
        .configure(".pitchfork.Credentials.ipv4", Config::new().max_bytes(4))
        .configure(
            ".pitchfork.Credentials.client_id",
            Config::new().max_bytes(1024),
        )
        .configure(
            ".pitchfork.Credentials.ca",
            Config::new().max_bytes(8 * 1024),
        )
        .configure(
            ".pitchfork.Credentials.cert",
            Config::new().max_bytes(8 * 1024),
        )
        .configure(
            ".pitchfork.Credentials.key",
            Config::new().max_bytes(8 * 1024),
        )
        .add_protoc_arg("-Iproto");
    generator
        .compile_protos(
            &[
                "google/protobuf/timestamp.proto",
                "google/protobuf/empty.proto",
                "storage.proto",
                "comms.proto",
            ],
            std::env::var("OUT_DIR").unwrap() + "/aiqc-proto.rs",
        )
        .unwrap();
    println!("cargo:rerun-if-changed=proto");
}

fn main() {
    // Put `memory.x` in our output directory and ensure it's
    // on the linker search path.
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());

    // By default, Cargo will re-run a build script whenever
    // any file in the project changes. By specifying `memory.x`
    // here, we ensure the build script is only re-run when
    // `memory.x` is changed.
    println!("cargo:rerun-if-changed=memory.x");

    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");

    proto_generate();
}
