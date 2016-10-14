extern crate pkg_config;

use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

fn main() {
    let target = env::var("TARGET").unwrap();

    let openssl_dir = env::var_os("OPENSSL_DIR").unwrap_or_else(|| {
        find_openssl_dir(&target)
    });

    let lib_dir = Path::new(&openssl_dir).join("lib");
    let include_dir = Path::new(&openssl_dir).join("include");
    if !Path::new(&lib_dir).exists() {
        panic!("OpenSSL library directory does not exist: {}",
               lib_dir.to_string_lossy());
    }

    if !Path::new(&include_dir).exists() {
        panic!("OpenSSL include directory does not exist: {}",
               include_dir.to_string_lossy());
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.to_string_lossy());
    println!("cargo:include={}", include_dir.to_string_lossy());

    let version = validate_headers(&[include_dir.clone().into()],
                                   &[lib_dir.clone().into()]);

    let libs = if (version.contains("0x10001") ||
                   version.contains("0x10002")) &&
                  target.contains("windows") {
        ["ssleay32", "libeay32"]
    } else if target.contains("windows") {
        ["libssl", "libcrypto"]
    } else {
        ["ssl", "crypto"]
    };

    let kind = determine_mode(Path::new(&lib_dir), &libs);
    for lib in libs.iter() {
        println!("cargo:rustc-link-lib={}={}", kind, lib);
    }
}

fn find_openssl_dir(target: &str) -> OsString {
    let host = env::var("HOST").unwrap();

    if host.contains("apple-darwin") && target.contains("apple-darwin") {
        let homebrew = Path::new("/usr/local/opt/openssl");
        if homebrew.exists() {
            return homebrew.to_path_buf().into()
        }
        let homebrew = Path::new("/usr/local/opt/openssl@1.1");
        if homebrew.exists() {
            return homebrew.to_path_buf().into()
        }
    }

    try_pkg_config();

    let mut msg = format!("

Could not find directory of OpenSSL installation, and this `-sys` crate cannot
proceed without this knowledge. If OpenSSL is installed and this crate had
trouble finding it,  you can set the `OPENSSL_DIR` environment variable for the
compilation process.

If you're in a situation where you think the directory *should* be found
automatically, please open a bug at https://github.com/sfackler/rust-openssl
and include information about your system as well as this message.

    $HOST = {}
    $TARGET = {}
    openssl-sys = {}

",
    host, target, env!("CARGO_PKG_VERSION"));

    if host.contains("apple-darwin") && target.contains("apple-darwin") {
        let system = Path::new("/usr/lib/libssl.0.9.8.dylib");
        if system.exists() {
            msg.push_str(&format!("

It looks like you're compiling on macOS, where the system contains a version of
OpenSSL 0.9.8. This crate no longer supports OpenSSL 0.9.8.

As a consumer of this crate, you can fix this error by using Homebrew to
install the `openssl` package, or as a maintainer you can use the openssl-sys
0.7 crate for support with OpenSSL 0.9.8.

Unfortunately though the compile cannot continue, so aborting.

"));
        }
    }

    if host.contains("windows") && target.contains("windows-gnu") {
        msg.push_str(&format!("
It looks like you're compiling for MinGW but you may not have either OpenSSL or
pkg-config installed. You can install these two dependencies with:

    pacman -S openssl pkg-config

and try building this crate again.

"
));
    }

    if host.contains("windows") && target.contains("windows-msvc") {
        msg.push_str(&format!("
It looks like you're compiling for MSVC but we couldn't detect an OpenSSL
installation. If there isn't one installed then you can try the rust-openssl
README for more information about how to download precompiled binaries of
OpenSSL:

    https://github.com/sfackler/rust-openssl#windows

"
));
    }

    panic!(msg);
}

/// Attempt to find OpenSSL through pkg-config.
///
/// Note that if this succeeds then the function does not return as pkg-config
/// typically tells us all the information that we need.
fn try_pkg_config() {
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();

    // If we're going to windows-gnu we can use pkg-config, but only so long as
    // we're coming from a windows host.
    //
    // Otherwise if we're going to windows we probably can't use pkg-config.
    if target.contains("windows-gnu") && host.contains("windows") {
        env::set_var("PKG_CONFIG_ALLOW_CROSS", "1");
    } else if target.contains("windows") {
        return
    }

    // We're going to be looking at header files, so show us all the system
    // cflags dirs for showing us lots of `-I`.
    env::set_var("PKG_CONFIG_ALLOW_SYSTEM_CFLAGS", "1");

    let lib = match pkg_config::find_library("openssl") {
        Ok(lib) => lib,
        Err(_) => return,
    };

    if lib.include_paths.len() == 0 {
        panic!("

Used pkg-config to discover the OpenSSL installation, but pkg-config did not
return any include paths for the installation. This crate needs to take a peek
at the header files so it cannot proceed unless they're found.

You can try fixing this by setting the `OPENSSL_DIR` environment variable
pointing to your OpenSSL installation.

");
    }

    validate_headers(&lib.include_paths, &lib.link_paths);

    for include in lib.include_paths.iter() {
        println!("cargo:include={}", include.display());
    }

    std::process::exit(0);
}

/// Validates the header files found in `include_dir` and then returns the
/// version string of OpenSSL.
fn validate_headers(include_dirs: &[PathBuf],
                    libdirs: &[PathBuf]) -> String {
    // This `*-sys` crate only works with OpenSSL 1.0.1, 1.0.2, and 1.1.0. To
    // correctly expose the right API from this crate, take a look at
    // `opensslv.h` to see what version OpenSSL claims to be.
    let mut version_header = String::new();
    let mut include = include_dirs.iter()
                                  .map(|p| p.join("openssl/opensslv.h"))
                                  .filter(|p| p.exists());
    let mut f = match include.next() {
        Some(f) => File::open(f).unwrap(),
        None => {
            panic!("failed to open header file at `openssl/opensslv.h` to learn
                    about OpenSSL's version number, looked inside:\n\n{:#?}\n\n",
                   include_dirs);
        }
    };
    f.read_to_string(&mut version_header).unwrap();

    // Do a bit of string parsing to find `#define OPENSSL_VERSION_NUMBER ...`
    let version_line = version_header.lines().find(|l| {
        l.contains("define ") && l.contains("OPENSSL_VERSION_NUMBER")
    }).and_then(|line| {
        let start = match line.find("0x") {
            Some(start) => start,
            None => return None,
        };
        Some(line[start..].trim())
    });
    let version_text = match version_line {
        Some(text) => text,
        None => {
            panic!("header file at `{}` did not include `OPENSSL_VERSION_NUMBER` \
                    that this crate recognized, failed to learn about the \
                    OpenSSL version number");
        }
    };
    if version_text.contains("0x10001") {
        println!("cargo:rustc-cfg=ossl101");
        println!("cargo:is_101=1");
    } else if version_text.contains("0x10002") {
        println!("cargo:rustc-cfg=ossl102");
        println!("cargo:is_102=1");
    } else if version_text.contains("0x10100") {
        println!("cargo:rustc-cfg=ossl110");
        println!("cargo:is_110=1");
    } else {
        panic!("

This crate is only compatible with OpenSSL 1.0.1, 1.0.2, and 1.1.0, but a
different version of OpenSSL was found:

    {}

The build is now aborting due to this version mismatch.

", version_text);
    }

    // OpenSSL has a number of build-time configuration options which affect
    // various structs and such. Since OpenSSL 1.1.0 this isn't really a problem
    // as the library is much more FFI-friendly, but 1.0.{1,2} suffer this problem.
    //
    // To handle all this conditional compilation we slurp up the configuration
    // file of OpenSSL, `opensslconf.h`, and then dump out everything it defines
    // as our own #[cfg] directives. That way the `ossl10x.rs` bindings can
    // account for compile differences and such.
    if version_text.contains("0x1000") {
        let mut conf_header = String::new();
        let mut include = include_dirs.iter()
                                      .map(|p| p.join("openssl/opensslconf.h"))
                                      .filter(|p| p.exists());
        let mut f = match include.next() {
            Some(f) => File::open(f).unwrap(),
            None => {
                // It's been seen that on linux the include dir printed out by
                // `pkg-config` doesn't actually have opensslconf.h. Instead
                // it's in an architecture-specific include directory.
                //
                // Try to detect that case to see if it exists.
                let mut libdirs = libdirs.iter().map(|p| {
                    p.iter()
                     .map(|p| if p == "lib" {"include".as_ref()} else {p})
                     .collect::<PathBuf>()
                }).map(|p| {
                    p.join("openssl/opensslconf.h")
                }).filter(|p| p.exists());
                match libdirs.next() {
                    Some(f) => File::open(f).unwrap(),
                    None => {
                        panic!("failed to open header file at
                                `openssl/opensslconf.h` to learn about \
                                OpenSSL's version number, looked \
                                inside:\n\n{:#?}\n\n",
                               include_dirs);
                    }
                }
            }
        };
        f.read_to_string(&mut conf_header).unwrap();

        // Look for `#define OPENSSL_FOO`, print out everything as our own
        // #[cfg] flag.
        for line in conf_header.lines() {
            let i = match line.find("define ") {
                Some(i) => i,
                None => continue,
            };
            let var = line[i + "define ".len()..].trim();
            if var.starts_with("OPENSSL") && !var.contains(" ") {
                println!("cargo:rustc-cfg=osslconf=\"{}\"", var);
            }
        }
    }

    return version_text.to_string()
}

/// Given a libdir for OpenSSL (where artifacts are located) as well as the name
/// of the libraries we're linking to, figure out whether we should link them
/// statically or dynamically.
fn determine_mode(libdir: &Path, libs: &[&str]) -> &'static str {
    // First see if a mode was explicitly requested
    let kind = env::var("OPENSSL_STATIC").ok();
    match kind.as_ref().map(|s| &s[..]) {
        Some("0") => return "dylib",
        Some(_) => return "static",
        None => {}
    }

    // Next, see what files we actually have to link against, and see what our
    // possibilities even are.
    let files = libdir.read_dir().unwrap()
                      .map(|e| e.unwrap())
                      .map(|e| e.file_name())
                      .filter_map(|e| e.into_string().ok())
                      .collect::<HashSet<_>>();
    let can_static = libs.iter().all(|l| {
        files.contains(&format!("lib{}.a", l)) ||
            files.contains(&format!("{}.lib", l))
    });
    let can_dylib = libs.iter().all(|l| {
        files.contains(&format!("lib{}.so", l)) ||
            files.contains(&format!("{}.dll", l)) ||
            files.contains(&format!("lib{}.dylib", l))
    });
    match (can_static, can_dylib) {
        (true, false) => return "static",
        (false, true) => return "dylib",
        (false, false) => {
            panic!("OpenSSL libdir at `{}` does not contain the required files \
                    to either statically or dynamically link OpenSSL",
                   libdir.display());
        }
        (true, true) => {}
    }

    // Ok, we've got not explicit preference and can *either* link statically or
    // link dynamically. In the interest of "security upgrades" and/or "best
    // practices with security libs", let's link dynamically.
    "dylib"
}
