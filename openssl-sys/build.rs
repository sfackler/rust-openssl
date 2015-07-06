extern crate pkg_config;
extern crate gcc;

use std::env;
use std::path::PathBuf;

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
                vec!("eay32", "ssleay32")
            } else {
                vec!("eay32", "ssl32")
            }
        } else {
            vec!("crypto", "ssl")
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
        include_dirs.push(PathBuf::from(&include_dir));
    }

    build_openssl_shim(&include_dirs);
}

fn build_openssl_shim(include_paths: &[PathBuf]) {
    let mut config = gcc::Config::new();

    for path in include_paths {
        config.include(path);
    }

    config.file("src/openssl_shim.c")
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
