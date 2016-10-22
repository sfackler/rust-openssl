use std::fmt;

use nid::{self, Nid};

/// Type-only version of the `Extension` enum.
///
/// See the `Extension` documentation for more information on the different
/// variants.
#[derive(Clone,Hash,PartialEq,Eq)]
pub enum ExtensionType {
    KeyUsage,
    ExtKeyUsage,
    SubjectAltName,
    IssuerAltName,
    OtherNid(Nid),
    OtherStr(String),
}

/// A X.509 v3 certificate extension.
///
/// Only one extension of each type is allow in a certificate.
/// See RFC 3280 for more information about extensions.
#[derive(Clone)]
pub enum Extension {
    /// The purposes of the key contained in the certificate
    KeyUsage(Vec<KeyUsageOption>),
    /// The extended purposes of the key contained in the certificate
    ExtKeyUsage(Vec<ExtKeyUsageOption>),
    /// Subject Alternative Names
    SubjectAltName(Vec<(AltNameOption, String)>),
    /// Issuer Alternative Names
    IssuerAltName(Vec<(AltNameOption, String)>),
    /// Arbitrary extensions by NID. See `man x509v3_config` for value syntax.
    ///
    /// You must not use this to add extensions which this enum can express directly.
    ///
    /// ```
    /// use openssl::x509::extension::Extension::*;
    /// use openssl::nid;
    ///
    /// # let generator = openssl::x509::X509Generator::new();
    /// generator.add_extension(OtherNid(nid::BASIC_CONSTRAINTS,"critical,CA:TRUE".to_owned()));
    /// ```
    OtherNid(Nid, String),
    /// Arbitrary extensions by OID string. See `man ASN1_generate_nconf` for value syntax.
    ///
    /// You must not use this to add extensions which this enum can express directly.
    ///
    /// ```
    /// use openssl::x509::extension::Extension::*;
    ///
    /// # let generator = openssl::x509::X509Generator::new();
    /// generator.add_extension(OtherStr("2.999.2".to_owned(),"ASN1:UTF8:example value".to_owned()));
    /// ```
    OtherStr(String, String),
}

impl Extension {
    pub fn get_type(&self) -> ExtensionType {
        match self {
            &Extension::KeyUsage(_) => ExtensionType::KeyUsage,
            &Extension::ExtKeyUsage(_) => ExtensionType::ExtKeyUsage,
            &Extension::SubjectAltName(_) => ExtensionType::SubjectAltName,
            &Extension::IssuerAltName(_) => ExtensionType::IssuerAltName,
            &Extension::OtherNid(nid, _) => ExtensionType::OtherNid(nid),
            &Extension::OtherStr(ref s, _) => ExtensionType::OtherStr(s.clone()),
        }
    }
}

impl ExtensionType {
    pub fn get_nid(&self) -> Option<Nid> {
        match self {
            &ExtensionType::KeyUsage => Some(nid::KEY_USAGE),
            &ExtensionType::ExtKeyUsage => Some(nid::EXT_KEY_USAGE),
            &ExtensionType::SubjectAltName => Some(nid::SUBJECT_ALT_NAME),
            &ExtensionType::IssuerAltName => Some(nid::ISSUER_ALT_NAME),
            &ExtensionType::OtherNid(nid) => Some(nid),
            &ExtensionType::OtherStr(_) => None,
        }
    }

    pub fn get_name(&self) -> Option<&str> {
        match self {
            &ExtensionType::OtherStr(ref s) => Some(s),
            _ => None,
        }
    }
}

// FIXME: This would be nicer as a method on Iterator<Item=ToString>. This can
// eventually be replaced by the successor to std::slice::SliceConcatExt.connect
fn join<I: Iterator<Item = T>, T: ToString>(iter: I, sep: &str) -> String {
    iter.enumerate().fold(String::new(), |mut acc, (idx, v)| {
        if idx > 0 {
            acc.push_str(sep)
        };
        acc.push_str(&v.to_string());
        acc
    })
}

impl ToString for Extension {
    fn to_string(&self) -> String {
        match self {
            &Extension::KeyUsage(ref purposes) => join(purposes.iter(), ","),
            &Extension::ExtKeyUsage(ref purposes) => join(purposes.iter(), ","),
            &Extension::SubjectAltName(ref names) => {
                join(names.iter().map(|&(ref opt, ref val)| opt.to_string() + ":" + &val),
                     ",")
            }
            &Extension::IssuerAltName(ref names) => {
                join(names.iter().map(|&(ref opt, ref val)| opt.to_string() + ":" + &val),
                     ",")
            }
            &Extension::OtherNid(_, ref value) => value.clone(),
            &Extension::OtherStr(_, ref value) => value.clone(),
        }
    }
}

#[derive(Clone,Copy)]
pub enum KeyUsageOption {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CRLSign,
    EncipherOnly,
    DecipherOnly,
}

impl fmt::Display for KeyUsageOption {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.pad(match self {
            &KeyUsageOption::DigitalSignature => "digitalSignature",
            &KeyUsageOption::NonRepudiation => "nonRepudiation",
            &KeyUsageOption::KeyEncipherment => "keyEncipherment",
            &KeyUsageOption::DataEncipherment => "dataEncipherment",
            &KeyUsageOption::KeyAgreement => "keyAgreement",
            &KeyUsageOption::KeyCertSign => "keyCertSign",
            &KeyUsageOption::CRLSign => "cRLSign",
            &KeyUsageOption::EncipherOnly => "encipherOnly",
            &KeyUsageOption::DecipherOnly => "decipherOnly",
        })
    }
}

#[derive(Clone)]
pub enum ExtKeyUsageOption {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    MsCodeInd,
    MsCodeCom,
    MsCtlSign,
    MsSgc,
    MsEfs,
    NsSgc,
    /// An arbitrary key usage by OID.
    Other(String),
}

impl fmt::Display for ExtKeyUsageOption {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.pad(match self {
            &ExtKeyUsageOption::ServerAuth => "serverAuth",
            &ExtKeyUsageOption::ClientAuth => "clientAuth",
            &ExtKeyUsageOption::CodeSigning => "codeSigning",
            &ExtKeyUsageOption::EmailProtection => "emailProtection",
            &ExtKeyUsageOption::TimeStamping => "timeStamping",
            &ExtKeyUsageOption::MsCodeInd => "msCodeInd",
            &ExtKeyUsageOption::MsCodeCom => "msCodeCom",
            &ExtKeyUsageOption::MsCtlSign => "msCTLSign",
            &ExtKeyUsageOption::MsSgc => "msSGC",
            &ExtKeyUsageOption::MsEfs => "msEFS",
            &ExtKeyUsageOption::NsSgc => "nsSGC",
            &ExtKeyUsageOption::Other(ref s) => &s[..],
        })
    }
}

#[derive(Clone, Copy)]
pub enum AltNameOption {
    /// The value is specified as OID;content. See `man ASN1_generate_nconf` for more information on the content syntax.
    ///
    /// ```
    /// use openssl::x509::extension::Extension::*;
    /// use openssl::x509::extension::AltNameOption::Other as OtherName;
    ///
    /// # let generator = openssl::x509::X509Generator::new();
    /// generator.add_extension(SubjectAltName(vec![(OtherName,"2.999.3;ASN1:UTF8:some other name".to_owned())]));
    /// ```
    Other,
    Email,
    DNS,
    // X400, // Not supported by OpenSSL
    Directory,
    // EDIParty, // Not supported by OpenSSL
    URI,
    IPAddress,
    RegisteredID,
}

impl fmt::Display for AltNameOption {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.pad(match self {
            &AltNameOption::Other => "otherName",
            &AltNameOption::Email => "email",
            &AltNameOption::DNS => "DNS",
            &AltNameOption::Directory => "dirName",
            &AltNameOption::URI => "URI",
            &AltNameOption::IPAddress => "IP",
            &AltNameOption::RegisteredID => "RID",
        })
    }
}
