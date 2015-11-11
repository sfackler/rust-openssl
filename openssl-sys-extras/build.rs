extern crate gcc;

use std::env;
use std::path::PathBuf;
use std::fs::File;
use std::io::Write as IoWrite;
use std::fmt::Write;

fn main() {
    let options_shim_file = generate_options_shim();
    let mut config = gcc::Config::new();

    if let Some(paths) = env::var_os("DEP_OPENSSL_INCLUDE") {
        for path in env::split_paths(&paths) {
            config.include(PathBuf::from(path));
        }
    }

    config.file("src/openssl_shim.c")
        .file(options_shim_file)
        .compile("libopenssl_shim.a");
}

macro_rules! import_options {
    ( $( $name:ident $val:expr  )* ) => {
       &[ $( (stringify!($name),$val), )* ]
    };
}

fn generate_options_shim() -> PathBuf {
    let options: &[(&'static str,u64)]=include!("src/ssl_options.rs");
    let mut shim = String::new();
    writeln!(shim,"#include <stdint.h>").unwrap();
    writeln!(shim,"#include <openssl/ssl.h>").unwrap();

    for &(name,value) in options {
        writeln!(shim,"#define RUST_{} UINT64_C({})",name,value).unwrap();
        writeln!(shim,"#ifndef {}",name).unwrap();
        writeln!(shim,"# define {} 0",name).unwrap();
        writeln!(shim,"#endif").unwrap();
    }

    writeln!(shim,"#define COPY_MASK ( \\").unwrap();

    let mut it=options.iter().peekable();
    while let Some(&(name,_))=it.next()  {
        let eol=match it.peek() {
            Some(_) => " | \\",
            None    => " )"
        };
        writeln!(shim,"    ((RUST_{0}==(uint64_t)(uint32_t){0})?RUST_{0}:UINT64_C(0)){1}",name,eol).unwrap();
    }

    writeln!(shim,"long rust_openssl_ssl_ctx_options_rust_to_c(uint64_t rustval) {{").unwrap();
    writeln!(shim,"    long cval=rustval&COPY_MASK;").unwrap();
    for &(name,_) in options {
        writeln!(shim,"    if (rustval&RUST_{0}) cval|={0};",name).unwrap();
    }
    writeln!(shim,"    return cval;").unwrap();
    writeln!(shim,"}}").unwrap();

    writeln!(shim,"uint64_t rust_openssl_ssl_ctx_options_c_to_rust(long cval) {{").unwrap();
    writeln!(shim,"    uint64_t rustval=cval&COPY_MASK;").unwrap();
    for &(name,_) in options {
        writeln!(shim,"    if (cval&{0}) rustval|=RUST_{0};",name).unwrap();
    }
    writeln!(shim,"    return rustval;").unwrap();
    writeln!(shim,"}}").unwrap();

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_file = PathBuf::from(&out_dir).join("ssl_ctx_options_shim.c");
    let mut f = File::create(&dest_file).unwrap();

    f.write_all(shim.as_bytes()).unwrap();

    dest_file
}
