extern crate pkg_config;
extern crate gcc;

use std::env;
use std::fmt::Write as FmtWrite;
use std::path::PathBuf;
use std::fs::File;
use std::io::Write;

fn main() {
    let target = env::var("TARGET").unwrap();

    // libressl_pnacl_sys links the libs needed.
    if target.ends_with("nacl") { return; }

    let lib_dir = env::var("OPENSSL_LIB_DIR").ok();
    let include_dir = env::var("OPENSSL_INCLUDE_DIR").ok();

    if lib_dir.is_none() && include_dir.is_none() {
        // rustc doesn't seem to work with pkg-config's output in mingw64
        if !target.contains("windows") {
            if let Ok(info) = pkg_config::find_library("openssl") {
                build_openssl_shim(&info.include_paths);
                return;
            }
        }
        if let Some(mingw_paths) = get_mingw_in_path() {
            for path in mingw_paths {
                println!("cargo:rustc-link-search=native={}", path);
            }
        }
    }

    let libs_env = env::var("OPENSSL_LIBS").ok();
    let libs = match libs_env {
        Some(ref v) => v.split(":").collect(),
        None => if target.contains("windows") {
            if get_mingw_in_path().is_some() && lib_dir.is_none() && include_dir.is_none() {
                vec!["ssleay32", "eay32"]
            } else {
                vec!["ssl32", "eay32"]
            }
        } else {
            vec!["ssl", "crypto"]
        }
    };

    let mode = if env::var_os("OPENSSL_STATIC").is_some() {
    	"static"
    } else {
    	"dylib"
    };

    if let Some(lib_dir) = lib_dir {
    	println!("cargo:rustc-link-search=native={}", lib_dir);
    }

    for lib in libs {
        println!("cargo:rustc-link-lib={}={}", mode, lib);
    }

    let mut include_dirs = vec![];

    if let Some(include_dir) = include_dir {
        println!("cargo:include={}", include_dir);
        include_dirs.push(PathBuf::from(&include_dir));
    }

    build_openssl_shim(&include_dirs);
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

fn build_openssl_shim(include_paths: &[PathBuf]) {
    let options_shim_file = generate_options_shim();
    let mut config = gcc::Config::new();

    for path in include_paths {
        config.include(path);
    }

    config.file("src/openssl_shim.c")
        .file(options_shim_file)
        .compile("libopenssl_shim.a");
}

fn get_mingw_in_path() -> Option<Vec<String>> {
    match env::var_os("PATH") {
        Some(env_path) => {
            let paths: Vec<String> = env::split_paths(&env_path).filter_map(|path| {
                use std::ascii::AsciiExt;

                match path.to_str() {
                    Some(path_str) => {
                        if path_str.to_ascii_lowercase().contains("mingw") {
                            Some(path_str.to_string())
                        } else { None }
                    },
                    None => None
                }
            }).collect();

            if paths.len() > 0 { Some(paths) } else { None }
        },
        None => None
    }
}
