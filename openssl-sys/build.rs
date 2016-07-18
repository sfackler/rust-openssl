extern crate pkg_config;

use std::env;

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
                // if we did not find any include paths try to find some other
                // ones we might want to emit.
                if info.include_paths.len() > 0 {
                    let paths = env::join_paths(info.include_paths).unwrap();
                    println!("cargo:include={}", paths.to_str().unwrap());
                } else {
                    find_fallback_headers();
                }
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

    if let Some(include_dir) = include_dir {
        println!("cargo:include={}", include_dir);
    } else {
        find_fallback_headers();
    }
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

fn find_fallback_headers() {
    let target = env::var("TARGET").unwrap();

    // if we are building on OS X we use our own shipped openssl headers.
    // The reason for this is that OS X no longer ships headers for openssl
    // 0.9.8 which it ships however.  System SSL is pretty terrible but there
    // is a reason to use it: it funnels cert checks through the osx security
    // library.
    //
    // This all here should only be found if no other library is provided
    // for other reasons.
    if target.contains("darwin") {
        let src = env::current_dir().unwrap();
        println!("cargo:include={}", src.join("vendor/osx-openssl").display());
    }
}
