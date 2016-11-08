use std::io::{Read, Write};

use dh::Dh;
use error::ErrorStack;
use ssl::{self, SslMethod, SslContextBuilder, SslContext, Ssl, SSL_VERIFY_PEER, SslStream,
          HandshakeError};
use pkey::PKeyRef;
use x509::X509Ref;

// Serialized form of DH_get_2048_256
#[cfg(any(ossl101, all(test, any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))))]
const DHPARAM_PEM: &'static str = r#"
-----BEGIN DH PARAMETERS-----
MIICCQKCAQEAh6jmHbS2Zjz/u9GcZRlZmYzu9ghmDdDyXSzu1ENeOwDgDfjx1hlX
1Pr330VhsqowFsPZETQJb6o79Cltgw6afCCeDGSXUXq9WoqdMGvPZ+2R+eZyW0dY
wCLgse9Cdb97bFv8EdRfkIi5QfVOseWbuLw5oL8SMH9cT9twxYGyP3a2Osrhyqa3
kC1SUmc1SIoO8TxtmlG/pKs62DR3llJNjvahZ7WkGCXZZ+FE5RQFZCUcysuD5rSG
9rPKP3lxUGAmwLhX9omWKFbe1AEKvQvmIcOjlgpU5xDDdfJjddcBQQOktUMwwZiv
EmEW0iduEXFfaTh3+tfvCcrbCUrpHhoVlwKCAQA/syybcxNNCy53UGZg7b1ITKex
jyHvIFQH9Hk6GguhJRDbwVB3vkY//0/tSqwLtVW+OmwbDGtHsbw3c79+jG9ikBIo
+MKMuxilWuMTQQAKZQGW+THHelfy3fRj5ensFEt3feYqqrioYorDdtKC1u04ZOZ5
gkKOvIMdFDSPby+Rk7UEWvJ2cWTh38lnwfs/LlWkvRv/6DucgNBSuYXRguoK2yo7
cxPT/hTISEseBSWIubfSu9LfAWGZ7NBuFVfNCRWzNTu7ZODsN3/QKDcN+StSx4kU
KM3GfrYYS1I9HbJGwy9jB4SQ8A741kfRSNR5VFFeIyfP75jFgmZLTA9sxBZZ
-----END DH PARAMETERS-----
"#;

fn ctx(method: SslMethod) -> Result<SslContextBuilder, ErrorStack> {
    let mut ctx = try!(SslContextBuilder::new(method));

    let mut opts = ssl::SSL_OP_ALL;
    opts |= ssl::SSL_OP_NO_TICKET;
    opts |= ssl::SSL_OP_NO_COMPRESSION;
    opts &= !ssl::SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
    opts &= !ssl::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
    opts |= ssl::SSL_OP_NO_SSLV2;
    opts |= ssl::SSL_OP_NO_SSLV3;
    opts |= ssl::SSL_OP_SINGLE_DH_USE;
    opts |= ssl::SSL_OP_SINGLE_ECDH_USE;
    opts |= ssl::SSL_OP_CIPHER_SERVER_PREFERENCE;
    ctx.set_options(opts);

    let mode = ssl::SSL_MODE_AUTO_RETRY | ssl::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
               ssl::SSL_MODE_ENABLE_PARTIAL_WRITE;
    ctx.set_mode(mode);

    Ok(ctx)
}

/// A builder for `SslConnector`s.
pub struct SslConnectorBuilder(SslContextBuilder);

impl SslConnectorBuilder {
    /// Creates a new builder for TLS connections.
    ///
    /// The default configuration is subject to change, and is currently derived from Python.
    pub fn new(method: SslMethod) -> Result<SslConnectorBuilder, ErrorStack> {
        let mut ctx = try!(ctx(method));
        try!(ctx.set_default_verify_paths());
        // From https://github.com/python/cpython/blob/c30098c8c6014f3340a369a31df9c74bdbacc269/Lib/ssl.py#L191
        try!(ctx.set_cipher_list("ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:ECDH+AES256:\
                                  DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:\
                                  RSA+AES:RSA+HIGH:!aNULL:!eNULL:!MD5:!3DES"));

        Ok(SslConnectorBuilder(ctx))
    }

    /// Returns a shared reference to the inner `SslContextBuilder`.
    pub fn builder(&self) -> &SslContextBuilder {
        &self.0
    }

    /// Returns a mutable reference to the inner `SslContextBuilder`.
    pub fn builder_mut(&mut self) -> &mut SslContextBuilder {
        &mut self.0
    }

    /// Consumes the builder, returning a `SslConnector`.
    pub fn build(self) -> SslConnector {
        SslConnector(self.0.build())
    }
}

/// A type which wraps client-side streams in a TLS session.
///
/// OpenSSL's default configuration is highly insecure. This connector manages the OpenSSL
/// structures, configuring cipher suites, session options, hostname verification, and more.
///
/// OpenSSL's built in hostname verification is used when linking against OpenSSL 1.0.2 or 1.1.0,
/// and a custom implementation is used when linking against OpenSSL 1.0.1.
pub struct SslConnector(SslContext);

impl SslConnector {
    /// Initiates a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI and hostname verification.
    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
        where S: Read + Write
    {
        let mut ssl = try!(Ssl::new(&self.0));
        try!(ssl.set_hostname(domain));
        try!(setup_verify(&mut ssl, domain));

        ssl.connect(stream)
    }
}

/// A builder for `SslAcceptor`s.
pub struct SslAcceptorBuilder(SslContextBuilder);

impl SslAcceptorBuilder {
    /// Creates a new builder configured to connect to non-legacy clients. This should generally be
    /// considered a reasonable default choice.
    ///
    /// This corresponds to the intermediate configuration of Mozilla's server side TLS
    /// recommendations. See its [documentation][docs] for more details on specifics.
    ///
    /// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
    pub fn mozilla_intermediate<I>(method: SslMethod,
                                   private_key: &PKeyRef,
                                   certificate: &X509Ref,
                                   chain: I)
                                   -> Result<SslAcceptorBuilder, ErrorStack>
        where I: IntoIterator,
              I::Item: AsRef<X509Ref>
    {
        let mut ctx = try!(ctx(method));
        let dh = try!(get_dh());
        try!(ctx.set_tmp_dh(&dh));
        try!(setup_curves(&mut ctx));
        try!(ctx.set_cipher_list("ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
                                  ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                                  ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                                  DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:\
                                  ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
                                  ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:\
                                  ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:\
                                  ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:\
                                  DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:\
                                  DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:\
                                  ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:\
                                  EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:\
                                  AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:\
                                  DES-CBC3-SHA:!DSS"));
        SslAcceptorBuilder::finish_setup(ctx, private_key, certificate, chain)
    }

    /// Creates a new builder configured to connect to modern clients.
    ///
    /// This corresponds to the modern configuration of Mozilla's server side TLS recommendations.
    /// See its [documentation][docs] for more details on specifics.
    ///
    /// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
    pub fn mozilla_modern<I>(method: SslMethod,
                             private_key: &PKeyRef,
                             certificate: &X509Ref,
                             chain: I)
                             -> Result<SslAcceptorBuilder, ErrorStack>
        where I: IntoIterator,
              I::Item: AsRef<X509Ref>
    {
        let mut ctx = try!(ctx(method));
        try!(setup_curves(&mut ctx));
        try!(ctx.set_cipher_list("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                                  ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
                                  ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                                  ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:\
                                  ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"));
        SslAcceptorBuilder::finish_setup(ctx, private_key, certificate, chain)
    }

    fn finish_setup<I>(mut ctx: SslContextBuilder,
                       private_key: &PKeyRef,
                       certificate: &X509Ref,
                       chain: I)
                       -> Result<SslAcceptorBuilder, ErrorStack>
        where I: IntoIterator,
              I::Item: AsRef<X509Ref>
    {
        try!(ctx.set_private_key(private_key));
        try!(ctx.set_certificate(certificate));
        try!(ctx.check_private_key());
        for cert in chain {
            try!(ctx.add_extra_chain_cert(cert.as_ref().to_owned()));
        }
        Ok(SslAcceptorBuilder(ctx))
    }

    /// Returns a shared reference to the inner `SslContextBuilder`.
    pub fn builder(&self) -> &SslContextBuilder {
        &self.0
    }

    /// Returns a mutable reference to the inner `SslContextBuilder`.
    pub fn builder_mut(&mut self) -> &mut SslContextBuilder {
        &mut self.0
    }

    /// Consumes the builder, returning a `SslAcceptor`.
    pub fn build(self) -> SslAcceptor {
        SslAcceptor(self.0.build())
    }
}

#[cfg(ossl101)]
fn get_dh() -> Result<Dh, ErrorStack> {
    Dh::from_pem(DHPARAM_PEM.as_bytes())
}

#[cfg(not(ossl101))]
fn get_dh() -> Result<Dh, ErrorStack> {
    use ffi;

    use cvt_p;
    use types::OpenSslType;

    // manually call into ffi to avoid forcing the features
    unsafe { cvt_p(ffi::DH_get_2048_256()).map(|p| Dh::from_ptr(p)) }
}

#[cfg(ossl101)]
fn setup_curves(ctx: &mut SslContextBuilder) -> Result<(), ErrorStack> {
    use ec_key::EcKey;
    use nid;

    let curve = try!(EcKey::new_by_curve_name(nid::X9_62_PRIME256V1));
    ctx.set_tmp_ecdh(&curve)
}

#[cfg(ossl102)]
fn setup_curves(ctx: &mut SslContextBuilder) -> Result<(), ErrorStack> {
    ctx._set_ecdh_auto(true)
}

#[cfg(ossl110)]
fn setup_curves(_: &mut SslContextBuilder) -> Result<(), ErrorStack> {
    Ok(())
}

/// A type which wraps server-side streams in a TLS session.
///
/// OpenSSL's default configuration is highly insecure. This connector manages the OpenSSL
/// structures, configuring cipher suites, session options, and more.
pub struct SslAcceptor(SslContext);

impl SslAcceptor {
    /// Initiates a server-side TLS session on a stream.
    pub fn accept<S>(&self, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
        where S: Read + Write
    {
        let ssl = try!(Ssl::new(&self.0));
        ssl.accept(stream)
    }
}

#[cfg(any(ossl102, ossl110))]
fn setup_verify(ssl: &mut Ssl, domain: &str) -> Result<(), ErrorStack> {
    // pass a noop closure in here to ensure that we consistently override any callback on the
    // context
    ssl.set_verify_callback(SSL_VERIFY_PEER, |p, _| p);
    let param = ssl._param_mut();
    param.set_hostflags(::verify::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    param.set_host(domain)
}

#[cfg(ossl101)]
fn setup_verify(ssl: &mut Ssl, domain: &str) -> Result<(), ErrorStack> {
    let domain = domain.to_owned();
    ssl.set_verify_callback(SSL_VERIFY_PEER,
                            move |p, x| verify::verify_callback(&domain, p, x));
    Ok(())
}

#[cfg(ossl101)]
mod verify {
    use std::net::IpAddr;
    use std::str;

    use nid;
    use x509::{X509StoreContextRef, X509Ref, X509NameRef, GeneralName};
    use stack::Stack;

    pub fn verify_callback(domain: &str,
                           preverify_ok: bool,
                           x509_ctx: &X509StoreContextRef)
                           -> bool {
        if !preverify_ok || x509_ctx.error_depth() != 0 {
            return preverify_ok;
        }

        match x509_ctx.current_cert() {
            Some(x509) => verify_hostname(domain, &x509),
            None => true,
        }
    }

    fn verify_hostname(domain: &str, cert: &X509Ref) -> bool {
        match cert.subject_alt_names() {
            Some(names) => verify_subject_alt_names(domain, names),
            None => verify_subject_name(domain, &cert.subject_name()),
        }
    }

    fn verify_subject_alt_names(domain: &str, names: Stack<GeneralName>) -> bool {
        let ip = domain.parse();

        for name in &names {
            match ip {
                Ok(ip) => {
                    if let Some(actual) = name.ipaddress() {
                        if matches_ip(&ip, actual) {
                            return true;
                        }
                    }
                }
                Err(_) => {
                    if let Some(pattern) = name.dnsname() {
                        if matches_dns(pattern, domain, false) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn verify_subject_name(domain: &str, subject_name: &X509NameRef) -> bool {
        if let Some(pattern) = subject_name.entries_by_nid(nid::COMMONNAME).next() {
            let pattern = match str::from_utf8(pattern.data().as_slice()) {
                Ok(pattern) => pattern,
                Err(_) => return false,
            };

            // Unlike with SANs, IP addresses in the subject name don't have a
            // different encoding. We need to pass this down to matches_dns to
            // disallow wildcard matches with bogus patterns like *.0.0.1
            let is_ip = domain.parse::<IpAddr>().is_ok();

            if matches_dns(&pattern, domain, is_ip) {
                return true;
            }
        }

        false
    }

    fn matches_dns(mut pattern: &str, mut hostname: &str, is_ip: bool) -> bool {
        // first strip trailing . off of pattern and hostname to normalize
        if pattern.ends_with('.') {
            pattern = &pattern[..pattern.len() - 1];
        }
        if hostname.ends_with('.') {
            hostname = &hostname[..hostname.len() - 1];
        }

        matches_wildcard(pattern, hostname, is_ip).unwrap_or_else(|| pattern == hostname)
    }

    fn matches_wildcard(pattern: &str, hostname: &str, is_ip: bool) -> Option<bool> {
        // IP addresses and internationalized domains can't involved in wildcards
        if is_ip || pattern.starts_with("xn--") {
            return None;
        }

        let wildcard_location = match pattern.find('*') {
            Some(l) => l,
            None => return None,
        };

        let mut dot_idxs = pattern.match_indices('.').map(|(l, _)| l);
        let wildcard_end = match dot_idxs.next() {
            Some(l) => l,
            None => return None,
        };

        // Never match wildcards if the pattern has less than 2 '.'s (no *.com)
        //
        // This is a bit dubious, as it doesn't disallow other TLDs like *.co.uk.
        // Chrome has a black- and white-list for this, but Firefox (via NSS) does
        // the same thing we do here.
        //
        // The Public Suffix (https://www.publicsuffix.org/) list could
        // potentically be used here, but it's both huge and updated frequently
        // enough that management would be a PITA.
        if dot_idxs.next().is_none() {
            return None;
        }

        // Wildcards can only be in the first component
        if wildcard_location > wildcard_end {
            return None;
        }

        let hostname_label_end = match hostname.find('.') {
            Some(l) => l,
            None => return None,
        };

        // check that the non-wildcard parts are identical
        if pattern[wildcard_end..] != hostname[hostname_label_end..] {
            return Some(false);
        }

        let wildcard_prefix = &pattern[..wildcard_location];
        let wildcard_suffix = &pattern[wildcard_location + 1..wildcard_end];

        let hostname_label = &hostname[..hostname_label_end];

        // check the prefix of the first label
        if !hostname_label.starts_with(wildcard_prefix) {
            return Some(false);
        }

        // and the suffix
        if !hostname_label[wildcard_prefix.len()..].ends_with(wildcard_suffix) {
            return Some(false);
        }

        Some(true)
    }

    fn matches_ip(expected: &IpAddr, actual: &[u8]) -> bool {
        match (expected, actual.len()) {
            (&IpAddr::V4(ref addr), 4) => actual == addr.octets(),
            (&IpAddr::V6(ref addr), 16) => {
                let segments = [((actual[0] as u16) << 8) | actual[1] as u16,
                                ((actual[2] as u16) << 8) | actual[3] as u16,
                                ((actual[4] as u16) << 8) | actual[5] as u16,
                                ((actual[6] as u16) << 8) | actual[7] as u16,
                                ((actual[8] as u16) << 8) | actual[9] as u16,
                                ((actual[10] as u16) << 8) | actual[11] as u16,
                                ((actual[12] as u16) << 8) | actual[13] as u16,
                                ((actual[14] as u16) << 8) | actual[15] as u16];
                segments == addr.segments()
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod test {
    #[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
    #[test]
    fn check_dhparam() {
        use dh::Dh;

        let expected = String::from_utf8(Dh::get_2048_256().unwrap().to_pem().unwrap()).unwrap();
        assert_eq!(expected.trim(), super::DHPARAM_PEM.trim());
    }
}
