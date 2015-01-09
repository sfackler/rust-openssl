#![allow(unstable)]

extern crate "pkg-config" as pkg_config;

use std::os;

fn main() {
    // Without hackory, pkg-config will only look for host libraries.
    // So, abandon ship if we're cross compiling.
    if !pkg_config::target_supported() { return; }


    if pkg_config::find_library("openssl").is_err() {
        let target = os::getenv("TARGET").unwrap();
        let is_android = target.find_str("android").is_some();

        let mut flags = if is_android {
            " -l crypto:static -l ssl:static"
        } else {
            " -l crypto -l ssl"
        }.to_string();

        let win_pos = target.find_str("windows")
                            .or(target.find_str("win32"))
                            .or(target.find_str("win64"));

        // It's fun, but it looks like win32 and win64 both
        // have all the libs with 32 sufix
        if win_pos.is_some() {
           flags.push_str(" -l gdi32 -l wsock32");
        }

        if is_android {
            let path = os::getenv("OPENSSL_PATH").expect("Android does not provide openssl libraries, please \
                                                          build them yourselves (instructions in the README) \
                                                          and provide their location through $OPENSSL_PATH.");
            flags.push_str(format!(" -L {}", path).as_slice());
        }

        println!("cargo:rustc-flags={}", flags);
    }
}
