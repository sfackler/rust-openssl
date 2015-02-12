#![feature(env)]

extern crate "pkg-config" as pkg_config;
extern crate gcc;

use std::env;
use std::default::Default;

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

    if target.contains("win32") || target.contains("win64") || target.contains("i386-pc-windows-gnu") || target.contains("x86_64-pc-windows-gnu") {
        println!("cargo:rustc-flags=-l crypto -l ssl -l gdi32 -l wsock32");
        // going to assume the user has a new version of openssl
        build_old_openssl_shim(false);
        return;
    }

    if pkg_config::Config::new().atleast_version("1.0.0").find("openssl").is_ok() {
        build_old_openssl_shim(false);
        return;
    }

    let err = match pkg_config::find_library("openssl") {
        Ok(..) => {
            build_old_openssl_shim(true);
            return;
        }
        Err(err) => err,
    };

    // pkg-config doesn't know of OpenSSL on FreeBSD 10.1 and OpenBSD uses LibreSSL
    if target.contains("bsd") {
        println!("cargo:rustc-flags=-l crypto -l ssl");
        // going to assume the base system includes a new version of openssl
        build_old_openssl_shim(false);
        return;
    }

    panic!("unable to find openssl: {}", err);
}

fn build_old_openssl_shim(is_old: bool) {
    let mut config: gcc::Config = Default::default();
    if is_old {
        config.definitions.push(("OLD_OPENSSL".to_string(), None));
    }

    gcc::compile_library("libold_openssl_shim.a",
            &config,
            &["src/old_openssl_shim.c"]);

    let out_dir = env::var("OUT_DIR").unwrap();
    println!("cargo:rustc-flags=-L native={} -l old_openssl_shim:static", out_dir);
}
