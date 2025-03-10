use std::path::{Path, PathBuf};
use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

#[cfg(unix)]
fn cstr_to_path(p: &CStr) -> Option<&Path> {
    Some(Path::new(OsStr::from_bytes(p.to_bytes())))
}

#[cfg(not(unix))]
fn cstr_to_path(p: &CStr) -> Option<&Path> {
    p.to_str().ok().map(Path::new)
}

fn system_cert_file() -> Option<&'static Path> {
    let c_path: &'static CStr = unsafe {
        let p = crate::X509_get_default_cert_file();
        CStr::from_ptr(p)
    };
    cstr_to_path(c_path)
}

fn system_cert_dir() -> Option<&'static Path> {
    let c_path: &'static CStr = unsafe {
        let p = crate::X509_get_default_cert_dir();
        CStr::from_ptr(p)
    };
    cstr_to_path(c_path)
}

/// Return the directories in which CA certificates should likely be found.
pub fn default_certs_dirs() -> Vec<PathBuf> {
    let Some(p) = system_cert_dir() else {
        return vec![];
    };
    vec![p.to_path_buf()]
}

/// Return the path to the file containing the default system CA certificates.
/// Any configuration provided via environment variables is ignored.
pub fn default_cert_file() -> Option<PathBuf> {
    Some(system_cert_file()?.to_path_buf())
}

/// Return the path to the directory containing the default system CA certificates.
/// Any configuration provided via environment variables is ignored.
pub fn default_cert_dir() -> Option<PathBuf> {
    Some(system_cert_file()?.join("certs"))
}
