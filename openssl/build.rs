use std::env;

fn main() {
    if env::var("DEP_OPENSSL_IS_110").is_ok() {
        println!("cargo:rustc-cfg=ossl110");
        return;
    } else if env::var("DEP_OPENSSL_IS_102").is_ok() {
        println!("cargo:rustc-cfg=ossl102");
        println!("cargo:rustc-cfg=ossl10x");
        return;
    } else if env::var("DEP_OPENSSL_IS_101").is_ok() {
        println!("cargo:rustc-cfg=ossl101");
        println!("cargo:rustc-cfg=ossl10x");
    } else {
        panic!("Unable to detect OpenSSL version");
    }

    if let Ok(vars) = env::var("DEP_OPENSSL_OSSLCONF") {
        for var in vars.split(",") {
            println!("cargo:rustc-cfg=osslconf=\"{}\"", var);
        }
    }
}
