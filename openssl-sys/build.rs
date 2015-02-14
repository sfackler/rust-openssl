#![feature(env, path, core)]

extern crate "pkg-config" as pkg_config;
extern crate gcc;

use std::env;

fn main() {
    if let Ok(info) = pkg_config::find_library("openssl") {
        build_old_openssl_shim(info.include_paths);
        return;
    }

    let (libcrypto, libssl) = if env::var("TARGET").unwrap().contains("windows") {
    	("eay32", "ssl32")
    } else {
    	("crypto", "ssl")
    };

    let mode = if env::var_os("OPENSSL_STATIC").is_some() {
    	"static"
    } else {
    	"dylib"
    };

    if let Ok(lib_dir) = env::var("OPENSSL_LIB_DIR") {
    	println!("cargo:rustc-flags=-L native={}", lib_dir);
    }

    println!("cargo:rustc-flags=-l {0}={1} -l {0}={2}", mode, libcrypto, libssl);

    let mut include_dirs = vec![];

    if let Ok(include_dir) = env::var("OPENSSL_INCLUDE_DIR") {
    	include_dirs.push(Path::new(include_dir));
    }

    build_old_openssl_shim(include_dirs);
}

fn build_old_openssl_shim(include_paths: Vec<Path>) {
    let mut config = gcc::Config::new();

    for path in include_paths {
        config.include(path);
    }

    config.file("src/old_openssl_shim.c")
        .compile("libold_openssl_shim.a");
}
