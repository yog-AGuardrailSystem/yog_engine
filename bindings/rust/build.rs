use std::env;
use std::path::PathBuf;

fn main() {
    let dir = env::var("YOG_LIB_DIR").unwrap_or_else(|_| {
        let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
        manifest
            .join("..")
            .join("..")
            .join("yog")
            .join("build-release")
            .to_string_lossy()
            .into_owned()
    });
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=dylib=yog");
    println!("cargo:rerun-if-env-changed=YOG_LIB_DIR");
    println!("cargo:rerun-if-changed=build.rs");
}
