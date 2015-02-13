#![feature(env, path)]

extern crate "pkg-config" as pkg_config;
extern crate gcc;

use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();

    if target.contains("android") {
        let path = env::var("OPENSSL_PATH").ok()
            .expect("Android does not provide openssl libraries, please build them yourself \
                     (instructions in the README) and provide their location through \
                     $OPENSSL_PATH.");
        println!("cargo:rustc-flags=-L native={} -l crypto:static -l ssl:static", path);
        return;
    }

    if target.contains("win32") || target.contains("win64") || target.contains("windows") {
        println!("cargo:rustc-flags=-l crypto -l ssl -l gdi32 -l wsock32");
        // going to assume the user has a new version of openssl
        build_old_openssl_shim(false, vec![]);
        return;
    }

    if let Ok(info) =  pkg_config::Config::new().atleast_version("1.0.0").find("openssl") {
        build_old_openssl_shim(false, info.include_paths);
        return;
    }

    let err = match pkg_config::find_library("openssl") {
        Ok(info) => {
            build_old_openssl_shim(true, info.include_paths);
            return;
        }
        Err(err) => err,
    };

    // pkg-config doesn't know of OpenSSL on FreeBSD 10.1 and OpenBSD uses LibreSSL
    if target.contains("bsd") {
        println!("cargo:rustc-flags=-l crypto -l ssl");
        // going to assume the base system includes a new version of openssl
        build_old_openssl_shim(false, vec![]);
        return;
    }

    panic!("unable to find openssl: {}", err);
}

fn build_old_openssl_shim(is_old: bool, include_paths: Vec<Path>) {
    let mut config = gcc::Config::new();

    for path in include_paths {
        config.include(path);
    }
    if is_old {
        config.define("OLD_OPENSSL", None);
    }

    config.file("src/old_openssl_shim.c")
        .compile("libold_openssl_shim.a");
}
