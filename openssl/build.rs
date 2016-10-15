use std::env;

fn main() {
    if env::var("DEP_OPENSSL_IS_110").is_ok() {
        println!("cargo:rustc-cfg=ossl110");
        return;
    } else if cfg!(feature = "openssl-110") {
        panic!("the openssl-110 feature is enabled but OpenSSL 1.1.0+ is not being linked against");
    }
    if env::var("DEP_OPENSSL_IS_102").is_ok() {
        println!("cargo:rustc-cfg=ossl102");
        println!("cargo:rustc-cfg=ossl10x");
        return;
    } else if cfg!(feature = "openssl-102") {
        panic!("the openssl-102 feature is enabled but OpenSSL 1.0.2+")
    }
    if env::var("DEP_OPENSSL_IS_101").is_ok() {
        println!("cargo:rustc-cfg=ossl101");
        println!("cargo:rustc-cfg=ossl10x");
    }
    if let Ok(vars) = env::var("DEP_OPENSSL_OSSLCONF") {
        for var in vars.split(",") {
            println!("cargo:rustc-cfg=osslconf=\"{}\"", var);
        }
    }
}
