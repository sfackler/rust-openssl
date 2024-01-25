//! Add extensions to an `X509` certificate or certificate request.
//!
//! The extensions defined for X.509 v3 certificates provide methods for
//! associating additional attributes with users or public keys and for
//! managing relationships between CAs. The extensions created using this
//! module can be used with `X509v3Context` objects.
//!
//! # Example
//!
//! ```rust
//! use openssl::x509::extension::BasicConstraints;
//! use openssl::x509::X509Extension;
//!
//! let mut bc = BasicConstraints::new();
//! let bc = bc.critical().ca().pathlen(1);
//!
//! let extension: X509Extension = bc.build().unwrap();
//! ```
use std::fmt::Write;

use crate::asn1::Asn1Object;
use crate::error::ErrorStack;
use crate::nid::Nid;
use crate::x509::{GeneralName, Stack, X509Extension, X509v3Context};

use foreign_types::ForeignType;

#[cfg(ossl110)]
#[cfg(not(OPENSSL_NO_RFC3779))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An extension which indicates whether a certificate is a CA certificate.
pub struct BasicConstraints {
    critical: bool,
    ca: bool,
    pathlen: Option<u32>,
}

impl Default for BasicConstraints {
    fn default() -> BasicConstraints {
        BasicConstraints::new()
    }
}

impl BasicConstraints {
    /// Construct a new `BasicConstraints` extension.
    pub fn new() -> BasicConstraints {
        BasicConstraints {
            critical: false,
            ca: false,
            pathlen: None,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut BasicConstraints {
        self.critical = true;
        self
    }

    /// Sets the `ca` flag to `true`.
    pub fn ca(&mut self) -> &mut BasicConstraints {
        self.ca = true;
        self
    }

    /// Sets the `pathlen` to an optional non-negative value. The `pathlen` is the
    /// maximum number of CAs that can appear below this one in a chain.
    pub fn pathlen(&mut self, pathlen: u32) -> &mut BasicConstraints {
        self.pathlen = Some(pathlen);
        self
    }

    /// Return the `BasicConstraints` extension as an `X509Extension`.
    // Temporarily silence the deprecation warning - this should be ported to
    // `X509Extension::new_internal`.
    #[allow(deprecated)]
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        if self.critical {
            value.push_str("critical,");
        }
        value.push_str("CA:");
        if self.ca {
            value.push_str("TRUE");
        } else {
            value.push_str("FALSE");
        }
        if let Some(pathlen) = self.pathlen {
            write!(value, ",pathlen:{}", pathlen).unwrap();
        }
        X509Extension::new_nid(None, None, Nid::BASIC_CONSTRAINTS, &value)
    }
}

/// An extension consisting of a list of names of the permitted key usages.
pub struct KeyUsage {
    critical: bool,
    digital_signature: bool,
    non_repudiation: bool,
    key_encipherment: bool,
    data_encipherment: bool,
    key_agreement: bool,
    key_cert_sign: bool,
    crl_sign: bool,
    encipher_only: bool,
    decipher_only: bool,
}

impl Default for KeyUsage {
    fn default() -> KeyUsage {
        KeyUsage::new()
    }
}

impl KeyUsage {
    /// Construct a new `KeyUsage` extension.
    pub fn new() -> KeyUsage {
        KeyUsage {
            critical: false,
            digital_signature: false,
            non_repudiation: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut KeyUsage {
        self.critical = true;
        self
    }

    /// Sets the `digitalSignature` flag to `true`.
    pub fn digital_signature(&mut self) -> &mut KeyUsage {
        self.digital_signature = true;
        self
    }

    /// Sets the `nonRepudiation` flag to `true`.
    pub fn non_repudiation(&mut self) -> &mut KeyUsage {
        self.non_repudiation = true;
        self
    }

    /// Sets the `keyEncipherment` flag to `true`.
    pub fn key_encipherment(&mut self) -> &mut KeyUsage {
        self.key_encipherment = true;
        self
    }

    /// Sets the `dataEncipherment` flag to `true`.
    pub fn data_encipherment(&mut self) -> &mut KeyUsage {
        self.data_encipherment = true;
        self
    }

    /// Sets the `keyAgreement` flag to `true`.
    pub fn key_agreement(&mut self) -> &mut KeyUsage {
        self.key_agreement = true;
        self
    }

    /// Sets the `keyCertSign` flag to `true`.
    pub fn key_cert_sign(&mut self) -> &mut KeyUsage {
        self.key_cert_sign = true;
        self
    }

    /// Sets the `cRLSign` flag to `true`.
    pub fn crl_sign(&mut self) -> &mut KeyUsage {
        self.crl_sign = true;
        self
    }

    /// Sets the `encipherOnly` flag to `true`.
    pub fn encipher_only(&mut self) -> &mut KeyUsage {
        self.encipher_only = true;
        self
    }

    /// Sets the `decipherOnly` flag to `true`.
    pub fn decipher_only(&mut self) -> &mut KeyUsage {
        self.decipher_only = true;
        self
    }

    /// Return the `KeyUsage` extension as an `X509Extension`.
    // Temporarily silence the deprecation warning - this should be ported to
    // `X509Extension::new_internal`.
    #[allow(deprecated)]
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(
            &mut value,
            &mut first,
            self.digital_signature,
            "digitalSignature",
        );
        append(
            &mut value,
            &mut first,
            self.non_repudiation,
            "nonRepudiation",
        );
        append(
            &mut value,
            &mut first,
            self.key_encipherment,
            "keyEncipherment",
        );
        append(
            &mut value,
            &mut first,
            self.data_encipherment,
            "dataEncipherment",
        );
        append(&mut value, &mut first, self.key_agreement, "keyAgreement");
        append(&mut value, &mut first, self.key_cert_sign, "keyCertSign");
        append(&mut value, &mut first, self.crl_sign, "cRLSign");
        append(&mut value, &mut first, self.encipher_only, "encipherOnly");
        append(&mut value, &mut first, self.decipher_only, "decipherOnly");
        X509Extension::new_nid(None, None, Nid::KEY_USAGE, &value)
    }
}

/// An extension consisting of a list of usages indicating purposes
/// for which the certificate public key can be used for.
pub struct ExtendedKeyUsage {
    critical: bool,
    items: Vec<String>,
}

impl Default for ExtendedKeyUsage {
    fn default() -> ExtendedKeyUsage {
        ExtendedKeyUsage::new()
    }
}

impl ExtendedKeyUsage {
    /// Construct a new `ExtendedKeyUsage` extension.
    pub fn new() -> ExtendedKeyUsage {
        ExtendedKeyUsage {
            critical: false,
            items: vec![],
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut ExtendedKeyUsage {
        self.critical = true;
        self
    }

    /// Sets the `serverAuth` flag to `true`.
    pub fn server_auth(&mut self) -> &mut ExtendedKeyUsage {
        self.other("serverAuth")
    }

    /// Sets the `clientAuth` flag to `true`.
    pub fn client_auth(&mut self) -> &mut ExtendedKeyUsage {
        self.other("clientAuth")
    }

    /// Sets the `codeSigning` flag to `true`.
    pub fn code_signing(&mut self) -> &mut ExtendedKeyUsage {
        self.other("codeSigning")
    }

    /// Sets the `emailProtection` flag to `true`.
    pub fn email_protection(&mut self) -> &mut ExtendedKeyUsage {
        self.other("emailProtection")
    }

    /// Sets the `timeStamping` flag to `true`.
    pub fn time_stamping(&mut self) -> &mut ExtendedKeyUsage {
        self.other("timeStamping")
    }

    /// Sets the `msCodeInd` flag to `true`.
    pub fn ms_code_ind(&mut self) -> &mut ExtendedKeyUsage {
        self.other("msCodeInd")
    }

    /// Sets the `msCodeCom` flag to `true`.
    pub fn ms_code_com(&mut self) -> &mut ExtendedKeyUsage {
        self.other("msCodeCom")
    }

    /// Sets the `msCTLSign` flag to `true`.
    pub fn ms_ctl_sign(&mut self) -> &mut ExtendedKeyUsage {
        self.other("msCTLSign")
    }

    /// Sets the `msSGC` flag to `true`.
    pub fn ms_sgc(&mut self) -> &mut ExtendedKeyUsage {
        self.other("msSGC")
    }

    /// Sets the `msEFS` flag to `true`.
    pub fn ms_efs(&mut self) -> &mut ExtendedKeyUsage {
        self.other("msEFS")
    }

    /// Sets the `nsSGC` flag to `true`.
    pub fn ns_sgc(&mut self) -> &mut ExtendedKeyUsage {
        self.other("nsSGC")
    }

    /// Sets a flag not already defined.
    pub fn other(&mut self, other: &str) -> &mut ExtendedKeyUsage {
        self.items.push(other.to_string());
        self
    }

    /// Return the `ExtendedKeyUsage` extension as an `X509Extension`.
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut stack = Stack::new()?;
        for item in &self.items {
            stack.push(Asn1Object::from_str(item)?)?;
        }
        unsafe {
            X509Extension::new_internal(Nid::EXT_KEY_USAGE, self.critical, stack.as_ptr().cast())
        }
    }
}

/// An extension that provides a means of identifying certificates that contain a
/// particular public key.
pub struct SubjectKeyIdentifier {
    critical: bool,
}

impl Default for SubjectKeyIdentifier {
    fn default() -> SubjectKeyIdentifier {
        SubjectKeyIdentifier::new()
    }
}

impl SubjectKeyIdentifier {
    /// Construct a new `SubjectKeyIdentifier` extension.
    pub fn new() -> SubjectKeyIdentifier {
        SubjectKeyIdentifier { critical: false }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut SubjectKeyIdentifier {
        self.critical = true;
        self
    }

    /// Return a `SubjectKeyIdentifier` extension as an `X509Extension`.
    // Temporarily silence the deprecation warning - this should be ported to
    // `X509Extension::new_internal`.
    #[allow(deprecated)]
    pub fn build(&self, ctx: &X509v3Context<'_>) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(&mut value, &mut first, true, "hash");
        X509Extension::new_nid(None, Some(ctx), Nid::SUBJECT_KEY_IDENTIFIER, &value)
    }
}

/// An extension that provides a means of identifying the public key corresponding
/// to the private key used to sign a CRL.
pub struct AuthorityKeyIdentifier {
    critical: bool,
    keyid: Option<bool>,
    issuer: Option<bool>,
}

impl Default for AuthorityKeyIdentifier {
    fn default() -> AuthorityKeyIdentifier {
        AuthorityKeyIdentifier::new()
    }
}

impl AuthorityKeyIdentifier {
    /// Construct a new `AuthorityKeyIdentifier` extension.
    pub fn new() -> AuthorityKeyIdentifier {
        AuthorityKeyIdentifier {
            critical: false,
            keyid: None,
            issuer: None,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut AuthorityKeyIdentifier {
        self.critical = true;
        self
    }

    /// Sets the `keyid` flag.
    pub fn keyid(&mut self, always: bool) -> &mut AuthorityKeyIdentifier {
        self.keyid = Some(always);
        self
    }

    /// Sets the `issuer` flag.
    pub fn issuer(&mut self, always: bool) -> &mut AuthorityKeyIdentifier {
        self.issuer = Some(always);
        self
    }

    /// Return a `AuthorityKeyIdentifier` extension as an `X509Extension`.
    // Temporarily silence the deprecation warning - this should be ported to
    // `X509Extension::new_internal`.
    #[allow(deprecated)]
    pub fn build(&self, ctx: &X509v3Context<'_>) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        match self.keyid {
            Some(true) => append(&mut value, &mut first, true, "keyid:always"),
            Some(false) => append(&mut value, &mut first, true, "keyid"),
            None => {}
        }
        match self.issuer {
            Some(true) => append(&mut value, &mut first, true, "issuer:always"),
            Some(false) => append(&mut value, &mut first, true, "issuer"),
            None => {}
        }
        X509Extension::new_nid(None, Some(ctx), Nid::AUTHORITY_KEY_IDENTIFIER, &value)
    }
}

/// A constructor for the `X509` AS number extension.
#[cfg(ossl110)]
#[cfg(not(OPENSSL_NO_RFC3779))]
pub struct SbgpAsIdentifier(SbgpAsIdentifierOrInherit);

#[cfg(ossl110)]
#[cfg(not(OPENSSL_NO_RFC3779))]
enum SbgpAsIdentifierOrInherit {
    Inherit,
    List(Vec<(u32, u32)>),
}

#[cfg(ossl110)]
#[cfg(not(OPENSSL_NO_RFC3779))]
impl Default for SbgpAsIdentifier {
    fn default() -> SbgpAsIdentifier {
        SbgpAsIdentifier::new()
    }
}

#[cfg(ossl110)]
#[cfg(not(OPENSSL_NO_RFC3779))]
impl SbgpAsIdentifier {
    /// Construct a new `SbgpAsIdentifier` extension.
    pub fn new() -> SbgpAsIdentifier {
        Self(SbgpAsIdentifierOrInherit::List(Vec::new()))
    }

    /// Sets the `inherit` flag to `true`.
    pub fn add_inherit(&mut self) -> &mut SbgpAsIdentifier {
        if let SbgpAsIdentifierOrInherit::List(ref l) = self.0 {
            if !l.is_empty() {
                panic!("cannot set extension to inherit, list allready contains elements");
            }
        }

        self.0 = SbgpAsIdentifierOrInherit::Inherit;
        self
    }

    /// Adds an AS number to the AS number extension.
    pub fn add_asn(&mut self, asn: u32) -> &mut SbgpAsIdentifier {
        if let SbgpAsIdentifierOrInherit::List(ref mut asns) = self.0 {
            asns.push((asn, asn))
        } else {
            panic!("cannot add AS number to extension, extension is set to inherit");
        }
        self
    }

    /// Adds a range of AS numbers to the AS number extension.
    pub fn add_asn_range(&mut self, asn_min: u32, asn_max: u32) -> &mut SbgpAsIdentifier {
        if let SbgpAsIdentifierOrInherit::List(ref mut asns) = self.0 {
            asns.push((asn_min, asn_max))
        } else {
            panic!("cannot add AS range to extension, extension is set to inherit");
        }
        self
    }

    /// Return a `SbgpAsIdentifier` extension as an `X509Extension`.
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        unsafe {
            let asid = super::sbgp::ASIdentifiers::from_ptr(ffi::ASIdentifiers_new());
            match self.0 {
                SbgpAsIdentifierOrInherit::Inherit => {
                    crate::cvt(ffi::X509v3_asid_add_inherit(
                        asid.as_ptr(),
                        ffi::V3_ASID_ASNUM,
                    ))?;
                }
                SbgpAsIdentifierOrInherit::List(ref asns) => {
                    assert!(!asns.is_empty(), "cannot create empty extension");

                    for (min, max) in asns {
                        let asn_min = crate::bn::BigNum::from_u32(*min)?.to_asn1_integer()?;
                        if min == max {
                            crate::cvt(ffi::X509v3_asid_add_id_or_range(
                                asid.as_ptr(),
                                0,
                                asn_min.as_ptr(),
                                std::ptr::null_mut(),
                            ))?;
                        } else {
                            let asn_max = crate::bn::BigNum::from_u32(*max)?.to_asn1_integer()?;
                            crate::cvt(ffi::X509v3_asid_add_id_or_range(
                                asid.as_ptr(),
                                0,
                                asn_min.as_ptr(),
                                asn_max.as_ptr(),
                            ))?;
                            std::mem::forget(asn_max);
                        };
                        // On success ownership of min and max was moved, so forget
                        // On failure the fn early returned, thus the Rust types will free min and max
                        std::mem::forget(asn_min);
                    }

                    // canonize must only be performed on this branch, since an inherit
                    // ext is automatically canoical
                    if ffi::X509v3_asid_is_canonical(asid.as_ptr()) != 1 {
                        crate::cvt(ffi::X509v3_asid_canonize(asid.as_ptr()))?;
                    }
                }
            }
            X509Extension::new_internal(Nid::SBGP_AUTONOMOUSSYSNUM, true, asid.as_ptr().cast())
        }
    }
}

/// The contstructor for a `X509` IP address extension.
#[cfg(ossl110)]
#[cfg(not(OPENSSL_NO_RFC3779))]
pub struct SbgpIpAddressIdentifier {
    v4: SbgpIpAddressIdentifierOrInherit<Ipv4Addr>,
    v6: SbgpIpAddressIdentifierOrInherit<Ipv6Addr>,
}

#[cfg(ossl110)]
#[cfg(not(OPENSSL_NO_RFC3779))]
enum SbgpIpAddressIdentifierOrInherit<Addr> {
    Inherit,
    List(Vec<(Addr, Addr)>),
}

#[cfg(ossl110)]
#[cfg(not(OPENSSL_NO_RFC3779))]
impl Default for SbgpIpAddressIdentifier {
    fn default() -> SbgpIpAddressIdentifier {
        SbgpIpAddressIdentifier::new()
    }
}

#[cfg(ossl110)]
#[cfg(not(OPENSSL_NO_RFC3779))]
impl SbgpIpAddressIdentifier {
    /// Construct a new `SbgpIpAddressIdentifier` extension.
    pub fn new() -> SbgpIpAddressIdentifier {
        SbgpIpAddressIdentifier {
            v4: SbgpIpAddressIdentifierOrInherit::List(Vec::new()),
            v6: SbgpIpAddressIdentifierOrInherit::List(Vec::new()),
        }
    }

    fn len_of(&self, afi: super::sbgp::IpVersion) -> usize {
        match (afi, &self.v4, &self.v6) {
            (super::sbgp::IpVersion::V4, SbgpIpAddressIdentifierOrInherit::List(l), _) => l.len(),
            (super::sbgp::IpVersion::V6, _, SbgpIpAddressIdentifierOrInherit::List(l)) => l.len(),
            _ => 0,
        }
    }

    /// Sets the `inherit` flag in the list corresponding to the ip version.
    pub fn add_inherit(&mut self, afi: super::sbgp::IpVersion) -> &mut SbgpIpAddressIdentifier {
        match afi {
            super::sbgp::IpVersion::V4 if self.len_of(afi) == 0 => {
                self.v4 = SbgpIpAddressIdentifierOrInherit::Inherit
            }
            super::sbgp::IpVersion::V4 => {
                panic!("cannot set ipv4 to inherit, list allready contains values")
            }
            super::sbgp::IpVersion::V6 if self.len_of(afi) == 0 => {
                self.v6 = SbgpIpAddressIdentifierOrInherit::Inherit
            }
            super::sbgp::IpVersion::V6 => {
                panic!("cannot set ipv6 to inherit, list allready contains values")
            }
        }
        self
    }

    /// Adds an IP address to the IP address extension.
    pub fn add_ip_addr(&mut self, ip_addr: IpAddr) -> &mut SbgpIpAddressIdentifier {
        match ip_addr {
            IpAddr::V4(addr) => self.add_ipv4_addr_range(addr, addr),
            IpAddr::V6(addr) => self.add_ipv6_addr_range(addr, addr),
        }
    }

    /// Adds a range of IPv4 adresses to the IP address extension.
    pub fn add_ipv4_addr_range(
        &mut self,
        ip_addr_min: Ipv4Addr,
        ip_addr_max: Ipv4Addr,
    ) -> &mut SbgpIpAddressIdentifier {
        if let SbgpIpAddressIdentifierOrInherit::List(ref mut ips) = self.v4 {
            ips.push((ip_addr_min, ip_addr_max));
        } else {
            panic!("cannot add ipv4 address to extension, ipv4 is set to inherit");
        }
        self
    }

    /// Adds a range of IPv6 adresses of the IP adress extension.
    pub fn add_ipv6_addr_range(
        &mut self,
        ip_addr_min: Ipv6Addr,
        ip_addr_max: Ipv6Addr,
    ) -> &mut SbgpIpAddressIdentifier {
        if let SbgpIpAddressIdentifierOrInherit::List(ref mut ips) = self.v6 {
            ips.push((ip_addr_min, ip_addr_max));
        } else {
            panic!("cannot add ipv6 address to extension, ipv6 is set to inherit");
        }
        self
    }

    /// Adds a IP prefix to the IP address extension.
    pub fn add_ip_prefix(
        &mut self,
        prefix: IpAddr,
        prefixlen: usize,
    ) -> &mut SbgpIpAddressIdentifier {
        match prefix {
            IpAddr::V4(prefix) => {
                let mask = !(u32::MAX >> prefixlen);
                let min = mask & u32::from(prefix);
                let max = min | !mask;
                self.add_ipv4_addr_range(min.into(), max.into());
            }
            IpAddr::V6(prefix) => {
                let mask = !(u128::MAX >> prefixlen);
                let min = mask & u128::from(prefix);
                let max = min | !mask;
                self.add_ipv6_addr_range(min.into(), max.into());
            }
        }
        self
    }

    /// Return a `SbgpIpAddressIdentifier` extension as an `X509Extension`.
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        unsafe {
            let mut stack = Stack::<super::sbgp::IPAddressFamily>::new()?;

            match self.v4 {
                SbgpIpAddressIdentifierOrInherit::Inherit => {
                    crate::cvt(ffi::X509v3_addr_add_inherit(
                        stack.as_ptr(),
                        ffi::IANA_AFI_IPV4 as u32,
                        std::ptr::null(),
                    ))?;
                }
                SbgpIpAddressIdentifierOrInherit::List(ref ips) => {
                    for (min, max) in ips {
                        stack.sbgp_add_addr_range(*min, *max, ffi::IANA_AFI_IPV4 as u32)?;
                    }
                }
            }
            match self.v6 {
                SbgpIpAddressIdentifierOrInherit::Inherit => {
                    crate::cvt(ffi::X509v3_addr_add_inherit(
                        stack.as_ptr(),
                        ffi::IANA_AFI_IPV6 as u32,
                        std::ptr::null(),
                    ))?;
                }
                SbgpIpAddressIdentifierOrInherit::List(ref ips) => {
                    for (min, max) in ips {
                        stack.sbgp_add_addr_range(*min, *max, ffi::IANA_AFI_IPV6 as u32)?;
                    }
                }
            }

            if ffi::X509v3_addr_is_canonical(stack.as_ptr()) != 1 {
                crate::cvt(ffi::X509v3_addr_canonize(stack.as_ptr()))?;
            }

            X509Extension::new_internal(Nid::SBGP_IPADDRBLOCK, true, stack.as_ptr().cast())
        }
    }
}

#[cfg(ossl110)]
#[cfg(not(OPENSSL_NO_RFC3779))]
impl Stack<super::sbgp::IPAddressFamily> {
    // No pub, since messing with existing stacks outside build()
    // seems like an unnessecary risk.
    fn sbgp_add_addr_range<Addr>(
        &mut self,
        mut min: Addr,
        mut max: Addr,
        afi: u32,
    ) -> Result<(), ErrorStack> {
        unsafe {
            let min = &mut min as *mut _ as *mut u8;
            let max = &mut max as *mut _ as *mut u8;

            crate::cvt(ffi::X509v3_addr_add_range(
                self.as_ptr().cast(),
                afi,
                std::ptr::null_mut(),
                min,
                max,
            ))
            .map(|_| ())
        }
    }
}

enum RustGeneralName {
    Dns(String),
    Email(String),
    Uri(String),
    Ip(String),
    Rid(String),
    OtherName(Asn1Object, Vec<u8>),
}

/// An extension that allows additional identities to be bound to the subject
/// of the certificate.
pub struct SubjectAlternativeName {
    critical: bool,
    items: Vec<RustGeneralName>,
}

impl Default for SubjectAlternativeName {
    fn default() -> SubjectAlternativeName {
        SubjectAlternativeName::new()
    }
}

impl SubjectAlternativeName {
    /// Construct a new `SubjectAlternativeName` extension.
    pub fn new() -> SubjectAlternativeName {
        SubjectAlternativeName {
            critical: false,
            items: vec![],
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut SubjectAlternativeName {
        self.critical = true;
        self
    }

    /// Sets the `email` flag.
    pub fn email(&mut self, email: &str) -> &mut SubjectAlternativeName {
        self.items.push(RustGeneralName::Email(email.to_string()));
        self
    }

    /// Sets the `uri` flag.
    pub fn uri(&mut self, uri: &str) -> &mut SubjectAlternativeName {
        self.items.push(RustGeneralName::Uri(uri.to_string()));
        self
    }

    /// Sets the `dns` flag.
    pub fn dns(&mut self, dns: &str) -> &mut SubjectAlternativeName {
        self.items.push(RustGeneralName::Dns(dns.to_string()));
        self
    }

    /// Sets the `rid` flag.
    pub fn rid(&mut self, rid: &str) -> &mut SubjectAlternativeName {
        self.items.push(RustGeneralName::Rid(rid.to_string()));
        self
    }

    /// Sets the `ip` flag.
    pub fn ip(&mut self, ip: &str) -> &mut SubjectAlternativeName {
        self.items.push(RustGeneralName::Ip(ip.to_string()));
        self
    }

    /// Sets the `dirName` flag.
    ///
    /// Not currently actually supported, always panics.
    #[deprecated = "dir_name is deprecated and always panics. Please file a bug if you have a use case for this."]
    pub fn dir_name(&mut self, _dir_name: &str) -> &mut SubjectAlternativeName {
        unimplemented!(
            "This has not yet been adapted for the new internals. File a bug if you need this."
        );
    }

    /// Sets the `otherName` flag.
    ///
    /// Not currently actually supported, always panics. Please use other_name2
    #[deprecated = "other_name is deprecated and always panics. Please use other_name2."]
    pub fn other_name(&mut self, _other_name: &str) -> &mut SubjectAlternativeName {
        unimplemented!("This has not yet been adapted for the new internals. Use other_name2.");
    }

    /// Sets the `otherName` flag.
    ///
    /// `content` must be a valid der encoded ASN1_TYPE
    ///
    /// If you want to add just a ia5string use `other_name_ia5string`
    pub fn other_name2(&mut self, oid: Asn1Object, content: &[u8]) -> &mut SubjectAlternativeName {
        self.items
            .push(RustGeneralName::OtherName(oid, content.into()));
        self
    }

    /// Return a `SubjectAlternativeName` extension as an `X509Extension`.
    pub fn build(&self, _ctx: &X509v3Context<'_>) -> Result<X509Extension, ErrorStack> {
        let mut stack = Stack::new()?;
        for item in &self.items {
            let gn = match item {
                RustGeneralName::Dns(s) => GeneralName::new_dns(s.as_bytes())?,
                RustGeneralName::Email(s) => GeneralName::new_email(s.as_bytes())?,
                RustGeneralName::Uri(s) => GeneralName::new_uri(s.as_bytes())?,
                RustGeneralName::Ip(s) => {
                    GeneralName::new_ip(s.parse().map_err(|_| ErrorStack::get())?)?
                }
                RustGeneralName::Rid(s) => GeneralName::new_rid(Asn1Object::from_str(s)?)?,
                RustGeneralName::OtherName(oid, content) => {
                    GeneralName::new_other_name(oid.clone(), content)?
                }
            };
            stack.push(gn)?;
        }

        unsafe {
            X509Extension::new_internal(Nid::SUBJECT_ALT_NAME, self.critical, stack.as_ptr().cast())
        }
    }
}

fn append(value: &mut String, first: &mut bool, should: bool, element: &str) {
    if !should {
        return;
    }

    if !*first {
        value.push(',');
    }
    *first = false;
    value.push_str(element);
}
