extern crate pkg_config;
extern crate gcc;
extern crate tar;
extern crate flate2;

use flate2::FlateReadExt;
use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::panic::{self, AssertUnwindSafe};
use std::process::Command;
use tar::Archive;

// The set of `OPENSSL_NO_<FOO>`s that we care about.
const DEFINES: &'static [&'static str] = &[
    "OPENSSL_NO_BUF_FREELISTS",
    "OPENSSL_NO_COMP",
    "OPENSSL_NO_EC",
    "OPENSSL_NO_ENGINE",
    "OPENSSL_NO_KRB5",
    "OPENSSL_NO_NEXTPROTONEG",
    "OPENSSL_NO_PSK",
    "OPENSSL_NO_RFC3779",
    "OPENSSL_NO_SHA",
    "OPENSSL_NO_SRP",
    "OPENSSL_NO_SSL3_METHOD",
    "OPENSSL_NO_TLSEXT",
];

enum Version {
    Openssl110,
    Openssl102,
    Openssl101,
    Libressl,
}

fn main() {
    let target = env::var("TARGET").unwrap();

    let (lib_dir, include_dir) = if let Some(tarball) = env::var_os("OPENSSL_SRC") {
        build_openssl(&target, Path::new(&tarball))
    } else {
        find_openssl(&target)
    };

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

    let version = validate_headers(&[include_dir.clone().into()]);

    let libs = match version {
        Version::Openssl101 | Version::Openssl102 if target.contains("windows") => {
            ["ssleay32", "libeay32"]
        }
        Version::Openssl110 if target.contains("windows") => ["libssl", "libcrypto"],
        _ => ["ssl", "crypto"],
    };

    let kind = determine_mode(Path::new(&lib_dir), &libs);
    for lib in libs.iter() {
        println!("cargo:rustc-link-lib={}={}", kind, lib);
    }
}

fn build_openssl(target: &str, tarball_path: &Path) -> (PathBuf, PathBuf) {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let build_dir = out_dir.join("build");
    let install_dir = out_dir.join("install");
    let lib_dir = install_dir.join("lib");
    let include_dir = install_dir.join("include");

    let stamp = build_dir.join("stamp");
    let mut contents = String::new();
    let _ = File::open(&stamp).and_then(|mut f| f.read_to_string(&mut contents));
    if tarball_path == Path::new(&contents) {
        return (lib_dir, include_dir);
    }

    if stamp.exists() {
        fs::remove_file(&stamp).unwrap();
    }
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).unwrap();
    }
    if install_dir.exists() {
        fs::remove_dir_all(&install_dir).unwrap();
    }

    let tarball = File::open(tarball_path).unwrap().gz_decode().unwrap();
    let mut tarball = Archive::new(tarball);
    tarball.unpack(&build_dir).unwrap();

    let inner_dir = fs::read_dir(&build_dir).unwrap().next().unwrap().unwrap().path();

    let mut configure = if target == "i686-unknown-linux-gnu" {
        let mut cmd = Command::new("setarch");
        cmd.arg("i386").arg("./Configure");
        cmd
    } else {
        Command::new("./Configure")
    };

    let os = match target {
        "aarch64-unknown-linux-gnu" => "linux-aarch64",
        "arm-unknown-linux-gnueabi" => "linux-armv4",
        "arm-unknown-linux-gnueabihf" => "linux-armv4",
        "armv7-unknown-linux-gnueabihf" => "linux-armv4",
        "i686-apple-darwin" => "darwin-i386-cc",
        "i686-unknown-freebsd" => "BSD-x86-elf",
        "i686-unknown-linux-gnu" => "linux-elf",
        "i686-unknown-linux-musl" => "linux-elf",
        "mips-unknown-linux-gnu" => "linux-mips32",
        "mips64-unknown-linux-gnuabi64" => "linux64-mips64",
        "mips64el-unknown-linux-gnuabi64" => "linux64-mips64",
        "mipsel-unknown-linux-gnu" => "linux-mips32",
        "powerpc-unknown-linux-gnu" => "linux-ppc",
        "powerpc64-unknown-linux-gnu" => "linux-ppc64",
        "powerpc64le-unknown-linux-gnu" => "linux-ppc64le",
        "s390x-unknown-linux-gnu" => "linux64-s390x",
        "x86_64-apple-darwin" => "darwin64-x86_64-cc",
        "x86_64-unknown-freebsd" => "BSD-x86_64",
        "x86_64-unknown-linux-gnu" => "linux-x86_64",
        "x86_64-unknown-linux-musl" => "linux-x86_64",
        "x86_64-unknown-netbsd" => "BSD-x86_64",
        _ => panic!("don't know how to configure OpenSSL for {}", target),
    };

    configure.arg(format!("--prefix={}", install_dir.display()))
        .arg("no-dso")
        .arg("no-ssl2")
        .arg("no-ssl3")
        .arg("no-comp")
        .arg(os)
        .arg("-fPIC");
    if target.contains("i686") {
        configure.arg("-m32");
    }

    configure.current_dir(&inner_dir);
    run_command(configure, "configuring OpenSSL build");

    let mut depend = Command::new("make");
    depend.arg("depend").current_dir(&inner_dir);
    run_command(depend, "building OpenSSL dependencies");

    let mut build = Command::new("make");
    build.current_dir(&inner_dir);
    run_command(build, "building OpenSSL");

    let mut install = Command::new("make");
    install.arg("install").current_dir(&inner_dir);
    run_command(install, "installing OpenSSL");

    File::create(&stamp).unwrap()
        .write_all(&tarball_path.display().to_string().as_bytes())
        .unwrap();

    (lib_dir, include_dir)
}

fn run_command(mut command: Command, desc: &str) {
    let output = command.output().unwrap();
    if !output.status.success() {
        panic!("
Error {}

    Exit status: {}

    Stdout:
{}

    Stderr:
{}
",
            desc,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr));
    }
}

fn find_openssl(target: &str) -> (PathBuf, PathBuf) {
    let lib_dir = env::var_os("OPENSSL_LIB_DIR").map(PathBuf::from);
    let include_dir = env::var_os("OPENSSL_INCLUDE_DIR").map(PathBuf::from);

    if lib_dir.is_none() || include_dir.is_none() {
        let openssl_dir = env::var_os("OPENSSL_DIR").unwrap_or_else(|| {
            find_openssl_dir(&target)
        });
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

    if host.contains("apple-darwin") && target.contains("apple-darwin") {
        let homebrew = Path::new("/usr/local/opt/openssl@1.1");
        if homebrew.exists() {
            return homebrew.to_path_buf().into()
        }
        let homebrew = Path::new("/usr/local/opt/openssl");
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

    let lib = pkg_config::Config::new()
        .print_system_libs(false)
        .find("openssl")
        .unwrap();

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

    write!(file, "\
#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>

#ifdef LIBRESSL_VERSION_NUMBER
RUST_LIBRESSL
#elif OPENSSL_VERSION_NUMBER >= 0x10200000
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
").unwrap();

    for define in DEFINES {
        write!(file, "\
#ifdef {define}
RUST_{define}
#endif
", define = define).unwrap();
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

    if expanded.contains("RUST_LIBRESSL") {
        println!("cargo:rustc-cfg=libressl");
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

This crate is only compatible with OpenSSL 1.0.1, 1.0.2, and 1.1.0, or LibreSSL,
but a different version of OpenSSL was found. The build is now aborting due to
this version mismatch.

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
