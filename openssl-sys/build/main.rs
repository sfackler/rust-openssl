extern crate cc;
#[cfg(feature = "vendored")]
extern crate openssl_src;
extern crate pkg_config;
#[cfg(target_env = "msvc")]
extern crate vcpkg;

use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

mod cfgs;

// The set of `OPENSSL_NO_<FOO>`s that we care about.
const DEFINES: &'static [&'static str] = &[
    "OPENSSL_NO_BUF_FREELISTS",
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
    "OPENSSL_NO_TLSEXT",
    "OPENSSL_NO_STDIO",
];

enum Version {
    Openssl11x,
    Openssl10x,
    Libressl,
}

fn env(name: &str) -> Option<OsString> {
    let prefix = env::var("TARGET").unwrap().to_uppercase().replace("-", "_");
    let prefixed = format!("{}_{}", prefix, name);
    println!("cargo:rerun-if-env-changed={}", prefixed);

    if let Some(var) = env::var_os(&prefixed) {
        return Some(var);
    }

    println!("cargo:rerun-if-env-changed={}", name);
    env::var_os(name)
}

fn main() {
    let target = env::var("TARGET").unwrap();

    let (lib_dir, include_dir) = imp::get_openssl(&target);

    if !Path::new(&lib_dir).exists() {
        panic!(
            "OpenSSL library directory does not exist: {}",
            lib_dir.to_string_lossy()
        );
    }
    if !Path::new(&include_dir).exists() {
        panic!(
            "OpenSSL include directory does not exist: {}",
            include_dir.to_string_lossy()
        );
    }

    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir.to_string_lossy()
    );
    println!("cargo:include={}", include_dir.to_string_lossy());

    let version = validate_headers(&[include_dir.clone().into()]);

    let libs_env = env("OPENSSL_LIBS");
    let libs = match libs_env.as_ref().and_then(|s| s.to_str()) {
        Some(ref v) => v.split(":").collect(),
        None => match version {
            Version::Openssl10x if target.contains("windows") => vec!["ssleay32", "libeay32"],
            Version::Openssl11x if target.contains("windows") => vec!["libssl", "libcrypto"],
            _ => vec!["ssl", "crypto"],
        },
    };

    let kind = determine_mode(Path::new(&lib_dir), &libs);
    for lib in libs.into_iter() {
        println!("cargo:rustc-link-lib={}={}", kind, lib);
    }

    if kind == "static" && target.contains("windows") {
        println!("cargo:rustc-link-lib=dylib=gdi32");
        println!("cargo:rustc-link-lib=dylib=user32");
        println!("cargo:rustc-link-lib=dylib=crypt32");
        println!("cargo:rustc-link-lib=dylib=ws2_32");
        println!("cargo:rustc-link-lib=dylib=advapi32");
    }
}

#[cfg(feature = "vendored")]
mod imp {
    use openssl_src;
    use std::path::PathBuf;

    pub fn get_openssl(_target: &str) -> (PathBuf, PathBuf) {
        let artifacts = openssl_src::Build::new().build();
        (
            artifacts.lib_dir().to_path_buf(),
            artifacts.include_dir().to_path_buf(),
        )
    }
}

#[cfg(not(feature = "vendored"))]
mod imp {
    use pkg_config;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::process::{self, Command};

    use super::env;

    pub fn get_openssl(target: &str) -> (PathBuf, PathBuf) {
        let lib_dir = env("OPENSSL_LIB_DIR").map(PathBuf::from);
        let include_dir = env("OPENSSL_INCLUDE_DIR").map(PathBuf::from);

        if lib_dir.is_none() || include_dir.is_none() {
            let openssl_dir = env("OPENSSL_DIR").unwrap_or_else(|| find_openssl_dir(&target));
            let openssl_dir = Path::new(&openssl_dir);
            let lib_dir = lib_dir.unwrap_or_else(|| openssl_dir.join("lib"));
            let include_dir = include_dir.unwrap_or_else(|| openssl_dir.join("include"));
            (lib_dir, include_dir)
        } else {
            (lib_dir.unwrap(), include_dir.unwrap())
        }
    }

    fn find_openssl_dir(target: &str) -> OsString {
        let host = env::var("HOST").unwrap();

        if host == target && target.contains("apple-darwin") {
            // Check up default Homebrew installation location first
            // for quick resolution if possible.
            let homebrew = Path::new("/usr/local/opt/openssl@1.1");
            if homebrew.exists() {
                return homebrew.to_path_buf().into();
            }
            let homebrew = Path::new("/usr/local/opt/openssl");
            if homebrew.exists() {
                return homebrew.to_path_buf().into();
            }
            // Calling `brew --prefix <package>` command usually slow and
            // takes seconds, and will be used only as a last resort.
            let output = execute_command_and_get_output("brew", &["--prefix", "openssl@1.1"]);
            if let Some(ref output) = output {
                let homebrew = Path::new(&output);
                if homebrew.exists() {
                    return homebrew.to_path_buf().into();
                }
            }
            let output = execute_command_and_get_output("brew", &["--prefix", "openssl"]);
            if let Some(ref output) = output {
                let homebrew = Path::new(&output);
                if homebrew.exists() {
                    return homebrew.to_path_buf().into();
                }
            }
        }

        try_pkg_config();
        try_vcpkg();

        // FreeBSD ships with OpenSSL but doesn't include a pkg-config file :(
        if host == target && target.contains("freebsd") {
            return OsString::from("/usr");
        }

        let mut msg = format!(
            "

Could not find directory of OpenSSL installation, and this `-sys` crate cannot
proceed without this knowledge. If OpenSSL is installed and this crate had
trouble finding it,  you can set the `OPENSSL_DIR` environment variable for the
compilation process.

Make sure you also have the development packages of openssl installed.
For example, `libssl-dev` on Ubuntu or `openssl-devel` on Fedora.

If you're in a situation where you think the directory *should* be found
automatically, please open a bug at https://github.com/sfackler/rust-openssl
and include information about your system as well as this message.

    $HOST = {}
    $TARGET = {}
    openssl-sys = {}

",
            host,
            target,
            env!("CARGO_PKG_VERSION")
        );

        if host.contains("apple-darwin") && target.contains("apple-darwin") {
            let system = Path::new("/usr/lib/libssl.0.9.8.dylib");
            if system.exists() {
                msg.push_str(&format!(
                    "

It looks like you're compiling on macOS, where the system contains a version of
OpenSSL 0.9.8. This crate no longer supports OpenSSL 0.9.8.

As a consumer of this crate, you can fix this error by using Homebrew to
install the `openssl` package, or as a maintainer you can use the openssl-sys
0.7 crate for support with OpenSSL 0.9.8.

Unfortunately though the compile cannot continue, so aborting.

"
                ));
            }
        }

        if host.contains("unknown-linux") && target.contains("unknown-linux-gnu") {
            if Command::new("pkg-config").output().is_err() {
                msg.push_str(&format!(
                    "
It looks like you're compiling on Linux and also targeting Linux. Currently this
requires the `pkg-config` utility to find OpenSSL but unfortunately `pkg-config`
could not be found. If you have OpenSSL installed you can likely fix this by
installing `pkg-config`.

"
                ));
            }
        }

        if host.contains("windows") && target.contains("windows-gnu") {
            msg.push_str(&format!(
                "
It looks like you're compiling for MinGW but you may not have either OpenSSL or
pkg-config installed. You can install these two dependencies with:

    pacman -S openssl-devel pkg-config

and try building this crate again.

"
            ));
        }

        if host.contains("windows") && target.contains("windows-msvc") {
            msg.push_str(&format!(
                "
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
            return;
        }

        let lib = match pkg_config::Config::new()
            .print_system_libs(false)
            .find("openssl")
        {
            Ok(lib) => lib,
            Err(e) => {
                println!("run pkg_config fail: {:?}", e);
                return;
            }
        };

        super::validate_headers(&lib.include_paths);

        for include in lib.include_paths.iter() {
            println!("cargo:include={}", include.display());
        }

        process::exit(0);
    }

    /// Attempt to find OpenSSL through vcpkg.
    ///
    /// Note that if this succeeds then the function does not return as vcpkg
    /// should emit all of the cargo metadata that we need.
    #[cfg(target_env = "msvc")]
    fn try_vcpkg() {
        use vcpkg;

        // vcpkg will not emit any metadata if it can not find libraries
        // appropriate for the target triple with the desired linkage.

        let mut lib = vcpkg::Config::new()
            .emit_includes(true)
            .lib_name("libcrypto")
            .lib_name("libssl")
            .probe("openssl");

        if let Err(e) = lib {
            println!(
                "note: vcpkg did not find openssl as libcrypto and libssl : {:?}",
                e
            );
            lib = vcpkg::Config::new()
                .emit_includes(true)
                .lib_name("libeay32")
                .lib_name("ssleay32")
                .probe("openssl");
        }
        if let Err(e) = lib {
            println!(
                "note: vcpkg did not find openssl as ssleay32 and libeay32: {:?}",
                e
            );
            return;
        }

        let lib = lib.unwrap();
        super::validate_headers(&lib.include_paths);

        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=gdi32");
        println!("cargo:rustc-link-lib=crypt32");

        process::exit(0);
    }

    #[cfg(not(target_env = "msvc"))]
    fn try_vcpkg() {}

    fn execute_command_and_get_output(cmd: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(cmd).args(args).output();
        if let Ok(ref r1) = out {
            if r1.status.success() {
                let r2 = String::from_utf8(r1.stdout.clone());
                if let Ok(r3) = r2 {
                    return Some(r3.trim().to_string());
                }
            }
        }
        return None;
    }
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

    write!(
        file,
        "\
#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>

#define VERSION2(n, v) RUST_VERSION_ ## n ## _ ## v
#define VERSION(n, v) VERSION2(n, v)

VERSION(OPENSSL, OPENSSL_VERSION_NUMBER)

#ifdef LIBRESSL_VERSION_NUMBER
VERSION(LIBRESSL, LIBRESSL_VERSION_NUMBER)
#endif
"
    ).unwrap();

    for define in DEFINES {
        write!(
            file,
            "\
#ifdef {define}
RUST_CONF_{define}
#endif
",
            define = define
        ).unwrap();
    }

    file.flush().unwrap();
    drop(file);

    let mut gcc = cc::Build::new();
    for include_dir in include_dirs {
        gcc.include(include_dir);
    }
    // https://github.com/alexcrichton/gcc-rs/issues/133
    let expanded = match gcc.file(&path).try_expand() {
        Ok(expanded) => expanded,
        Err(e) => {
            panic!(
                "
Header expansion error:
{:?}

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
",
                e
            );
        }
    };
    let expanded = String::from_utf8(expanded).unwrap();

    let mut enabled = vec![];
    let mut openssl_version = None;
    let mut libressl_version = None;
    for line in expanded.lines() {
        let line = line.trim();

        let openssl_prefix = "RUST_VERSION_OPENSSL_";
        let libressl_prefix = "RUST_VERSION_LIBRESSL_";
        let conf_prefix = "RUST_CONF_";
        if line.starts_with(openssl_prefix) {
            let version = &line[openssl_prefix.len()..];
            openssl_version = Some(parse_version(version));
        } else if line.starts_with(libressl_prefix) {
            let version = &line[libressl_prefix.len()..];
            libressl_version = Some(parse_version(version));
        } else if line.starts_with(conf_prefix) {
            enabled.push(&line[conf_prefix.len()..]);
        }
    }

    for enabled in &enabled {
        println!("cargo:rustc-cfg=osslconf=\"{}\"", enabled);
    }
    println!("cargo:conf={}", enabled.join(","));

    for cfg in cfgs::get(openssl_version, libressl_version) {
        println!("cargo:rustc-cfg={}", cfg);
    }

    if let Some(libressl_version) = libressl_version {
        println!("cargo:libressl_version_number={:x}", libressl_version);

        let minor = (libressl_version >> 20) as u8;
        let fix = (libressl_version >> 12) as u8;
        let (minor, fix) = match (minor, fix) {
            (5, 0) => ('5', '0'),
            (5, 1) => ('5', '1'),
            (5, 2) => ('5', '2'),
            (5, _) => ('5', 'x'),
            (6, 0) => ('6', '0'),
            (6, 1) => ('6', '1'),
            (6, 2) => ('6', '2'),
            (6, _) => ('6', 'x'),
            (7, _) => ('7', 'x'),
            (8, 0) => ('8', '0'),
            (8, 1) => ('8', '1'),
            (8, _) => ('8', 'x'),
            (9, 0) => ('9', '0'),
            _ => version_error(),
        };

        println!("cargo:libressl=true");
        println!("cargo:libressl_version=2{}{}", minor, fix);
        println!("cargo:version=101");
        Version::Libressl
    } else {
        let openssl_version = openssl_version.unwrap();
        println!("cargo:version_number={:x}", openssl_version);

        if openssl_version >= 0x1_01_02_00_0 {
            version_error()
        } else if openssl_version >= 0x1_01_01_00_0 {
            println!("cargo:version=111");
            Version::Openssl11x
        } else if openssl_version >= 0x1_01_00_06_0 {
            println!("cargo:version=110");
            println!("cargo:patch=f");
            Version::Openssl11x
        } else if openssl_version >= 0x1_01_00_00_0 {
            println!("cargo:version=110");
            Version::Openssl11x
        } else if openssl_version >= 0x1_00_02_00_0 {
            println!("cargo:version=102");
            Version::Openssl10x
        } else if openssl_version >= 0x1_00_01_00_0 {
            println!("cargo:version=101");
            Version::Openssl10x
        } else {
            version_error()
        }
    }
}

fn version_error() -> ! {
    panic!(
        "

This crate is only compatible with OpenSSL 1.0.1 through 1.1.1, or LibreSSL 2.5
through 2.9.0, but a different version of OpenSSL was found. The build is now aborting
due to this version mismatch.

"
    );
}

// parses a string that looks like "0x100020cfL"
fn parse_version(version: &str) -> u64 {
    // cut off the 0x prefix
    assert!(version.starts_with("0x"));
    let version = &version[2..];

    // and the type specifier suffix
    let version = version.trim_right_matches(|c: char| match c {
        '0'...'9' | 'a'...'f' | 'A'...'F' => false,
        _ => true,
    });

    u64::from_str_radix(version, 16).unwrap()
}

/// Given a libdir for OpenSSL (where artifacts are located) as well as the name
/// of the libraries we're linking to, figure out whether we should link them
/// statically or dynamically.
fn determine_mode(libdir: &Path, libs: &[&str]) -> &'static str {
    // First see if a mode was explicitly requested
    let kind = env("OPENSSL_STATIC");
    match kind.as_ref().and_then(|s| s.to_str()).map(|s| &s[..]) {
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
    let can_static = libs
        .iter()
        .all(|l| files.contains(&format!("lib{}.a", l)) || files.contains(&format!("{}.lib", l)));
    let can_dylib = libs.iter().all(|l| {
        files.contains(&format!("lib{}.so", l))
            || files.contains(&format!("{}.dll", l))
            || files.contains(&format!("lib{}.dylib", l))
    });
    match (can_static, can_dylib) {
        (true, false) => return "static",
        (false, true) => return "dylib",
        (false, false) => {
            panic!(
                "OpenSSL libdir at `{}` does not contain the required files \
                 to either statically or dynamically link OpenSSL",
                libdir.display()
            );
        }
        (true, true) => {}
    }

    // Ok, we've got not explicit preference and can *either* link statically or
    // link dynamically. In the interest of "security upgrades" and/or "best
    // practices with security libs", let's link dynamically.
    "dylib"
}
