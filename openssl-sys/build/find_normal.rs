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

        let port_path_opt = get_macport_openssl();
        if let Some(port_path) = port_path_opt {
            return OsString::from(port_path);
        }
    }

    try_pkg_config();
    try_vcpkg();

    // FreeBSD ships with OpenSSL but doesn't include a pkg-config file :(
    if host == target && target.contains("freebsd") {
        return OsString::from("/usr");
    }

    // DragonFly has libressl (or openssl) in ports, but this doesn't include a pkg-config file
    if host == target && target.contains("dragonfly") {
        return OsString::from("/usr/local");
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
    // vcpkg will not emit any metadata if it can not find libraries
    // appropriate for the target triple with the desired linkage.

    let lib = vcpkg::Config::new()
        .emit_includes(true)
        .find_package("openssl");

    if let Err(e) = lib {
        println!("note: vcpkg did not find openssl: {}", e);
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

/// find openssl path on macport
fn get_macport_openssl() -> Option<std::string::String> {
    let out = Command::new("port")
        .arg("-q")
        .arg("installed")
        .arg("openssl")
        .output();
    if let Ok(res) = out {
        let outputs = std::str::from_utf8(&res.stdout).unwrap();
        let version_opt = get_macport_openssl_version(outputs);
        if let Some(version) = version_opt {
            if version >= (MacportVersion { major: 1, minor: 1 }) {
                Some(std::string::String::from("/opt/local"))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

/// get openssl version from the string printed out by port command
fn get_macport_openssl_version(port_outputs: &str) -> Option<MacportVersion> {
    for elem in port_outputs.split('\n') {
        let active_opt = elem.find("(active)");
        if let Some(active_pos) = active_opt {
            let ver_start = elem.find('@');
            if let Some(ver_start_pos) = ver_start {
                let ver_str = elem.get(ver_start_pos + 1..active_pos).unwrap();
                return parse_macport_version(ver_str);
            }
        }
    }
    None
}

/// parse macport version 
fn parse_macport_version(ver_str: &str)-> Option<MacportVersion> {
    let ver_elems: Vec<&str> = ver_str.split('.').collect();

    if ver_elems.len() > 1 {
        let major_res = ver_elems[0].parse::<u64>();
        let minor_res = ver_elems[1].parse::<u64>();
        if let Ok(major) = major_res {
            if let Ok(minor) = minor_res {
                Some(MacportVersion {
                    major,
                    minor,
                })
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

#[derive(Eq, Debug)]
struct MacportVersion {
    major: u64,
    minor: u64,
}

impl Ord for MacportVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let res = self.major.cmp(&other.major);
        if res == std::cmp::Ordering::Equal {
            self.minor.cmp(&other.minor)
        } else {
            res
        }
    }
}
impl PartialOrd for MacportVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for MacportVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}
