use std::env;
use std::fs;
use std::path::PathBuf;

pub struct ProbeResult {
    pub cert_file: Option<PathBuf>,
    pub cert_dir: Option<PathBuf>,
}

/// Probe the system for the directory in which CA certificates should likely be
/// found.
///
/// This will only search known system locations.
pub fn find_certs_dirs() -> Vec<PathBuf> {
    // see http://gagravarr.org/writing/openssl-certs/others.shtml
    [
        "/var/ssl",
        "/usr/share/ssl",
        "/usr/local/ssl",
        "/usr/local/openssl",
        "/usr/local/share",
        "/usr/lib/ssl",
        "/usr/ssl",
        "/etc/openssl",
        "/etc/pki/tls",
        "/etc/ssl",
    ].iter().map(|s| PathBuf::from(*s)).filter(|p| {
        fs::metadata(p).is_ok()
    }).collect()
}

pub fn init_ssl_cert_env_vars() {
    let ProbeResult { cert_file, cert_dir } = probe();
    match cert_file {
        Some(path) => put("SSL_CERT_FILE", path),
        None => {}
    }
    match cert_dir {
        Some(path) => put("SSL_CERT_DIR", path),
        None => {}
    }

    fn put(var: &str, path: PathBuf) {
        // Don't stomp over what anyone else has set
        match env::var(var) {
            Ok(..) => {}
            Err(..) => env::set_var(var, &path),
        }
    }
}

pub fn probe() -> ProbeResult {
    let mut result = ProbeResult {
        cert_file: env::var_os("SSL_CERT_FILE").map(PathBuf::from),
        cert_dir: env::var_os("SSL_CERT_DIR").map(PathBuf::from),
    };
    for certs_dir in find_certs_dirs().iter() {
        // cert.pem looks to be an openssl 1.0.1 thing, while
        // certs/ca-certificates.crt appears to be a 0.9.8 thing
        try(&mut result.cert_file, certs_dir.join("cert.pem"));
        try(&mut result.cert_file, certs_dir.join("certs/ca-certificates.crt"));
        try(&mut result.cert_file, certs_dir.join("certs/ca-root-nss.crt"));

        try(&mut result.cert_dir, certs_dir.join("certs"));
    }
    result
}

fn try(dst: &mut Option<PathBuf>, val: PathBuf) {
    if dst.is_none() && fs::metadata(&val).is_ok() {
        *dst = Some(val);
    }
}
