use std::os;
use std::io::fs::PathExtensions;

pub struct ProbeResult {
    pub cert_file: Option<Path>,
    pub cert_dir: Option<Path>,
}

/// Probe the system for the directory in which CA certificates should likely be
/// found.
///
/// This will only search known system locations.
pub fn find_certs_dirs() -> Vec<Path> {
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
    ].iter().map(|s| Path::new(*s)).filter(|p| {
        p.exists()
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

    fn put(var: &str, path: Path) {
        // Don't stomp over what anyone else has set
        match os::getenv(var) {
            Some(..) => {}
            None => os::setenv(var, path),
        }
    }
}

pub fn probe() -> ProbeResult {
    let mut result = ProbeResult {
        cert_file: os::getenv("SSL_CERT_FILE").map(Path::new),
        cert_dir: os::getenv("SSL_CERT_DIR").map(Path::new),
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

fn try(dst: &mut Option<Path>, val: Path) {
    if dst.is_none() && val.exists() {
        *dst = Some(val);
    }
}
