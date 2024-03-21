// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cmake::Config;
use std::path::Path;
use std::env;

fn main() {
    let path_extra = "lib";
    let mut logging_enabled = "off";
    if cfg!(windows) {
        logging_enabled = "on";
    }

    let target = env::var("TARGET").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);

    // Builds the native MsQuic and installs it into $OUT_DIR.
    let mut config = Config::new(".");
    config
        .define("QUIC_ENABLE_LOGGING", logging_enabled)
        .define("QUIC_TLS", "openssl")
        .define("QUIC_BUILD_SHARED", "off")
        .define("QUIC_OUTPUT_DIR", out_dir.join("lib").to_str().unwrap());

    match target.as_str() {
        "x86_64-apple-darwin" => config
            .define("CMAKE_OSX_ARCHITECTURES", "x86_64")
            .define("CMAKE_OSX_DEPLOYMENT_TARGET", "10.15"),
        "aarch64-apple-darwin" => config
            .define("CMAKE_OSX_ARCHITECTURES", "arm64")
            .define("CMAKE_OSX_DEPLOYMENT_TARGET", "11.0"),
        _ => &mut config
    };

    let dst = config.build();
    let lib_path = Path::join(Path::new(&dst), Path::new(path_extra));
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=static=msquic");
}
