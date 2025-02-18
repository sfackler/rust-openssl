use std::path::{Path, PathBuf};

// see http://gagravarr.org/writing/openssl-certs/others.shtml
static CERT_DIRS: &[&str] = &[
    "/var/ssl",
    "/usr/share/ssl",
    "/usr/local/ssl",
    "/usr/local/openssl",
    "/usr/local/etc/openssl",
    "/usr/local/share",
    "/usr/lib/ssl",
    "/usr/ssl",
    "/etc/openssl",
    "/etc/pki/ca-trust/extracted/pem",
    "/etc/pki/tls",
    "/etc/ssl",
    "/etc/certs",
    "/opt/etc/ssl", // Entware
    "/data/data/com.termux/files/usr/etc/tls",
    "/boot/system/data/ssl",
];

/// Return the directories in which CA certificates should likely be found.
pub fn default_certs_dirs() -> Vec<PathBuf> {
    CERT_DIRS.iter().filter_map(|p| {
        let p: &Path = p.as_ref();
        if p.exists() {
            Some(p.to_path_buf())
        } else {
            None
        }
    }).collect()
}

/// Return the path to the file containing the default system CA certificates.
/// Any configuration provided via environment variables is ignored.
pub fn default_cert_file() -> Option<PathBuf> {
    for certs_dir in CERT_DIRS.iter() {
        // cert.pem looks to be an openssl 1.0.1 thing, while
        // certs/ca-certificates.crt appears to be a 0.9.8 thing
        let certs_dir: &'static Path = certs_dir.as_ref();
        for cert_filename in [
            "cert.pem",
            "certs.pem",
            "ca-bundle.pem",
            "cacert.pem",
            "ca-certificates.crt",
            "certs/ca-certificates.crt",
            "certs/ca-root-nss.crt",
            "certs/ca-bundle.crt",
            "CARootCertificates.pem",
            "tls-ca-bundle.pem",
        ].iter() {
            let cert_file = certs_dir.join(cert_filename);
            if cert_file.exists() {
                return Some(cert_file);
            }
        }
    }
    None
}

/// Return the path to the directory containing the default system CA certificates.
/// Any configuration provided via environment variables is ignored.
pub fn default_cert_dir() -> Option<PathBuf> {
    for certs_dir in CERT_DIRS.iter() {
        let certs_dir: &'static Path = certs_dir.as_ref();
        let cert_dir = certs_dir.join("certs");
        if cert_dir.exists() {
            return Some(cert_dir);
        }
    }
    None
}
