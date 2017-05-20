extern crate pkg_config;
extern crate gcc;

use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::panic::{self, AssertUnwindSafe};
use std::process::Command;

// The set of `OPENSSL_NO_<FOO>`s that we care about.
const DEFINES: &'static [&'static str] = &["OPENSSL_NO_BUF_FREELISTS",
                                           "OPENSSL_NO_COMP",
                                           "OPENSSL_NO_EC",
                                           "OPENSSL_NO_EC2M",
                                           "OPENSSL_NO_ENGINE",
                                           "OPENSSL_NO_KRB5",
                                           "OPENSSL_NO_NEXTPROTONEG",
                                           "OPENSSL_NO_PSK",
                                           "OPENSSL_NO_RFC3779",
                                           "OPENSSL_NO_SHA",
                                           "OPENSSL_NO_SRP",
                                           "OPENSSL_NO_SSL3_METHOD",
                                           "OPENSSL_NO_TLSEXT"];

enum Version {
    Openssl110,
    Openssl102,
    Openssl101,
    Libressl,
}

fn main() {
    let target = env::var("TARGET").unwrap();

    let lib_dir = env::var_os("OPENSSL_LIB_DIR").map(PathBuf::from);
    let include_dir = env::var_os("OPENSSL_INCLUDE_DIR").map(PathBuf::from);

    let (lib_dir, include_dir) = if lib_dir.is_none() || include_dir.is_none() {
        let openssl_dir = env::var_os("OPENSSL_DIR").unwrap_or_else(|| find_openssl_dir(&target));
        let openssl_dir = Path::new(&openssl_dir);
        let lib_dir = lib_dir.unwrap_or_else(|| openssl_dir.join("lib"));
        let include_dir = include_dir.unwrap_or_else(|| openssl_dir.join("include"));
        (lib_dir, include_dir)
    } else {
        (lib_dir.unwrap(), include_dir.unwrap())
    };

    if !Path::new(&lib_dir).exists() {
        panic!("OpenSSL library directory does not exist: {}",
               lib_dir.to_string_lossy());
    }
    if !Path::new(&include_dir).exists() {
        panic!("OpenSSL include directory does not exist: {}",
               include_dir.to_string_lossy());
    }

    println!("cargo:rustc-link-search=native={}",
             lib_dir.to_string_lossy());
    println!("cargo:include={}", include_dir.to_string_lossy());

    let version = validate_headers(&[include_dir.clone().into()]);

    let libs_env = env::var("OPENSSL_LIBS").ok();
    let libs = match libs_env {
        Some(ref v) => v.split(":").collect(),
        None => {
            match version {
                Version::Openssl101 |
                Version::Openssl102 if target.contains("windows") => vec!["ssleay32", "libeay32"],
                Version::Openssl110 if target.contains("windows") => vec!["libssl", "libcrypto"],
                _ => vec!["ssl", "crypto"],
            }
        }
    };


    let kind = determine_mode(Path::new(&lib_dir), &libs);
    for lib in libs.into_iter() {
        println!("cargo:rustc-link-lib={}={}", kind, lib);
    }
}

fn find_openssl_dir(target: &str) -> OsString {
    let host = env::var("HOST").unwrap();

    if host.contains("apple-darwin") && target.contains("apple-darwin") {
        let homebrew = Path::new("/usr/local/opt/openssl@1.1");
        if homebrew.exists() {
            return homebrew.to_path_buf().into();
        }
        let homebrew = Path::new("/usr/local/opt/openssl");
        if homebrew.exists() {
            return homebrew.to_path_buf().into();
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
                          host,
                          target,
                          env!("CARGO_PKG_VERSION"));

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

    if host.contains("unknown-linux") && target.contains("unknown-linux-gnu") {
        if Command::new("pkg-config").output().is_err() {
            msg.push_str(&format!("
It looks like you're compiling on Linux and also targeting Linux. Currently this
requires the `pkg-config` utility to find OpenSSL but unfortunately `pkg-config`
could not be found. If you have OpenSSL installed you can likely fix this by
installing `pkg-config`.

"));
        }
    }

    if host.contains("windows") && target.contains("windows-gnu") {
        msg.push_str(&format!("
It looks like you're compiling for MinGW but you may not have either OpenSSL or
pkg-config installed. You can install these two dependencies with:

    pacman -S openssl pkg-config

and try building this crate again.

"));
    }

    if host.contains("windows") && target.contains("windows-msvc") {
        msg.push_str(&format!("
It looks like you're compiling for MSVC but we couldn't detect an OpenSSL
installation. If there isn't one installed then you can try the rust-openssl
README for more information about how to download precompiled binaries of
OpenSSL:

    https://github.com/sfackler/rust-openssl#windows

"));
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
        return;
    }

    let lib = match pkg_config::Config::new()
              .print_system_libs(false)
              .find("openssl") {
        Ok(lib) => lib,
        Err(e) => {
            println!("run pkg_config fail: {:?}", e);
            return;
        }
    };

    validate_headers(&lib.include_paths);

    for include in lib.include_paths.iter() {
        println!("cargo:include={}", include.display());
    }

    std::process::exit(0);
}

/// Validates the header files found in `include_dir` and then returns the
/// version string of OpenSSL.
fn validate_headers(include_dirs: &[PathBuf]) -> Version {
    // This `*-sys` crate only works with OpenSSL 1.0.1, 1.0.2, and 1.1.0. To
    // correctly expose the right API from this crate, take a look at
    // `opensslv.h` to see what version OpenSSL claims to be.
    //
    // OpenSSL has a number of build-time configuration options which affect
    // various structs and such. Since OpenSSL 1.1.0 this isn't really a problem
    // as the library is much more FFI-friendly, but 1.0.{1,2} suffer this problem.
    //
    // To handle all this conditional compilation we slurp up the configuration
    // file of OpenSSL, `opensslconf.h`, and then dump out everything it defines
    // as our own #[cfg] directives. That way the `ossl10x.rs` bindings can
    // account for compile differences and such.
    let mut path = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    path.push("expando.c");
    let mut file = BufWriter::new(File::create(&path).unwrap());

    write!(file,
           "\
#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>

#if LIBRESSL_VERSION_NUMBER >= 0x20505000
RUST_LIBRESSL_NEW
#elif LIBRESSL_VERSION_NUMBER >= 0x20504000
RUST_LIBRESSL_254
#elif LIBRESSL_VERSION_NUMBER >= 0x20503000
RUST_LIBRESSL_253
#elif LIBRESSL_VERSION_NUMBER >= 0x20502000
RUST_LIBRESSL_252
#elif LIBRESSL_VERSION_NUMBER >= 0x20501000
RUST_LIBRESSL_251
#elif LIBRESSL_VERSION_NUMBER >= 0x20500000
RUST_LIBRESSL_250
#elif defined (LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20500000
RUST_LIBRESSL_OLD
#elif OPENSSL_VERSION_NUMBER >= 0x10101000
RUST_OPENSSL_NEW
#elif OPENSSL_VERSION_NUMBER >= 0x10100000
RUST_OPENSSL_110
#elif OPENSSL_VERSION_NUMBER >= 0x10002000
RUST_OPENSSL_102
#elif OPENSSL_VERSION_NUMBER >= 0x10001000
RUST_OPENSSL_101
#else
RUST_OPENSSL_OLD
#endif
")
            .unwrap();

    for define in DEFINES {
        write!(file,
               "\
#ifdef {define}
RUST_{define}
#endif
",
               define = define)
                .unwrap();
    }

    file.flush().unwrap();
    drop(file);

    let mut gcc = gcc::Config::new();
    for include_dir in include_dirs {
        gcc.include(include_dir);
    }
    // https://github.com/alexcrichton/gcc-rs/issues/133
    let expanded = match panic::catch_unwind(AssertUnwindSafe(|| gcc.file(&path).expand())) {
        Ok(expanded) => expanded,
        Err(_) => {
            panic!("
Failed to find OpenSSL development headers.

You can try fixing this setting the `OPENSSL_DIR` environment variable
pointing to your OpenSSL installation or installing OpenSSL headers package
specific to your distribution:

    # On Ubuntu
    sudo apt-get install libssl-dev
    # On Arch Linux
    sudo pacman -S openssl
    # On Fedora
    sudo dnf install openssl-devel

See rust-openssl README for more information:

    https://github.com/sfackler/rust-openssl#linux
");
        }
    };
    let expanded = String::from_utf8(expanded).unwrap();

    let mut enabled = vec![];
    for &define in DEFINES {
        if expanded.contains(&format!("RUST_{}", define)) {
            println!("cargo:rustc-cfg=osslconf=\"{}\"", define);
            enabled.push(define);
        }
    }
    println!("cargo:conf={}", enabled.join(","));

    if expanded.contains("RUST_LIBRESSL_250") {
        println!("cargo:rustc-cfg=libressl");
        println!("cargo:rustc-cfg=libressl250");
        println!("cargo:libressl=true");
        println!("cargo:version=101");
        Version::Libressl
    } else if expanded.contains("RUST_LIBRESSL_251") {
        println!("cargo:rustc-cfg=libressl");
        println!("cargo:rustc-cfg=libressl251");
        println!("cargo:libressl=true");
        println!("cargo:version=101");
        Version::Libressl
    } else if expanded.contains("RUST_LIBRESSL_252") {
        println!("cargo:rustc-cfg=libressl");
        println!("cargo:rustc-cfg=libressl252");
        println!("cargo:libressl=true");
        println!("cargo:version=101");
        Version::Libressl
    } else if expanded.contains("RUST_LIBRESSL_253") {
        println!("cargo:rustc-cfg=libressl");
        println!("cargo:rustc-cfg=libressl253");
        println!("cargo:libressl=true");
        println!("cargo:version=101");
        Version::Libressl
    } else if expanded.contains("RUST_LIBRESSL_254") {
        println!("cargo:rustc-cfg=libressl");
        println!("cargo:rustc-cfg=libressl254");
        println!("cargo:libressl=true");
        println!("cargo:version=101");
        Version::Libressl
    } else if expanded.contains("RUST_OPENSSL_110") {
        println!("cargo:rustc-cfg=ossl110");
        println!("cargo:version=110");
        Version::Openssl110
    } else if expanded.contains("RUST_OPENSSL_102") {
        println!("cargo:rustc-cfg=ossl102");
        println!("cargo:version=102");
        Version::Openssl102
    } else if expanded.contains("RUST_OPENSSL_101") {
        println!("cargo:rustc-cfg=ossl101");
        println!("cargo:version=101");
        Version::Openssl101
    } else {
        panic!("

This crate is only compatible with OpenSSL 1.0.1, 1.0.2, and 1.1.0, or LibreSSL
2.5.0, 2.5.1, 2.5.2, 2.5.3, and 2.5.4, but a different version of OpenSSL was
found. The build is now aborting due to this version mismatch.

");
    }
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
    let files = libdir
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap())
        .map(|e| e.file_name())
        .filter_map(|e| e.into_string().ok())
        .collect::<HashSet<_>>();
    let can_static =
        libs.iter()
            .all(|l| {
                     files.contains(&format!("lib{}.a", l)) || files.contains(&format!("{}.lib", l))
                 });
    let can_dylib = libs.iter()
        .all(|l| {
                 files.contains(&format!("lib{}.so", l)) || files.contains(&format!("{}.dll", l)) ||
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
