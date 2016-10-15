use std::env;

fn main() {
    if env::var("DEP_OPENSSL_IS_101").is_ok() {
        println!("cargo:rustc-cfg=ossl101");
        println!("cargo:rustc-cfg=ossl10x");
    }
    if env::var("DEP_OPENSSL_IS_102").is_ok() {
        println!("cargo:rustc-cfg=ossl102");
        println!("cargo:rustc-cfg=ossl10x");
    }
    if env::var("DEP_OPENSSL_IS_110").is_ok() {
        println!("cargo:rustc-cfg=ossl110");
    }
    if let Ok(vars) = env::var("DEP_OPENSSL_OSSLCONF") {
        for var in vars.split(",") {
            println!("cargo:rustc-cfg=osslconf=\"{}\"", var);
        }
    }
}
