extern crate gcc;

use std::env;
use std::path::PathBuf;

fn main() {
    let mut config = gcc::Config::new();

    if let Some(paths) = env::var_os("DEP_OPENSSL_INCLUDE") {
        for path in env::split_paths(&paths) {
            config.include(PathBuf::from(path));
        }
    }

    config.file("src/c_helpers.c").compile("libc_helpers.a");
}
