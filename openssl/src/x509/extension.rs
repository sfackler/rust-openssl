use std::fmt::{self, Write};

use error::ErrorStack;
use nid::{self, Nid};
use x509::{X509v3Context, X509Extension};

/// Type-only version of the `Extension` enum.
///
/// See the `Extension` documentation for more information on the different
/// variants.
#[derive(Clone,Hash,PartialEq,Eq)]
#[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
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
#[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
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
    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
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
    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
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

    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
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
#[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
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
#[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
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
#[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
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

pub struct BasicConstraints {
    critical: bool,
    ca: bool,
    pathlen: Option<u32>,
}

impl BasicConstraints {
    pub fn new() -> BasicConstraints {
        BasicConstraints {
            critical: false,
            ca: false,
            pathlen: None,
        }
    }

    pub fn critical(&mut self) -> &mut BasicConstraints {
        self.critical = true;
        self
    }

    pub fn ca(&mut self) -> &mut BasicConstraints {
        self.ca = true;
        self
    }

    pub fn pathlen(&mut self, pathlen: u32) -> &mut BasicConstraints {
        self.pathlen = Some(pathlen);
        self
    }

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
        X509Extension::new_nid(None, None, nid::BASIC_CONSTRAINTS, &value)
    }
}

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

impl KeyUsage {
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

    pub fn critical(&mut self) -> &mut KeyUsage {
        self.critical = true;
        self
    }

    pub fn digital_signature(&mut self) -> &mut KeyUsage {
        self.digital_signature = true;
        self
    }

    pub fn non_repudiation(&mut self) -> &mut KeyUsage {
        self.non_repudiation = true;
        self
    }

    pub fn key_encipherment(&mut self) -> &mut KeyUsage {
        self.key_encipherment = true;
        self
    }

    pub fn data_encipherment(&mut self) -> &mut KeyUsage {
        self.data_encipherment = true;
        self
    }

    pub fn key_agreement(&mut self) -> &mut KeyUsage {
        self.key_agreement = true;
        self
    }

    pub fn key_cert_sign(&mut self) -> &mut KeyUsage {
        self.key_cert_sign = true;
        self
    }

    pub fn crl_sign(&mut self) -> &mut KeyUsage {
        self.crl_sign = true;
        self
    }

    pub fn encipher_only(&mut self) -> &mut KeyUsage {
        self.encipher_only = true;
        self
    }

    pub fn decipher_only(&mut self) -> &mut KeyUsage {
        self.decipher_only = true;
        self
    }

    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(&mut value, &mut first, self.digital_signature, "digitalSignature");
        append(&mut value, &mut first, self.non_repudiation, "nonRepudiation");
        append(&mut value, &mut first, self.key_encipherment, "keyEncipherment");
        append(&mut value, &mut first, self.data_encipherment, "dataEncipherment");
        append(&mut value, &mut first, self.key_agreement, "keyAgreement");
        append(&mut value, &mut first, self.key_cert_sign, "keyCertSign");
        append(&mut value, &mut first, self.crl_sign, "cRLSign");
        append(&mut value, &mut first, self.encipher_only, "encipherOnly");
        append(&mut value, &mut first, self.decipher_only, "decipherOnly");
        X509Extension::new_nid(None, None, nid::KEY_USAGE, &value)
    }
}

pub struct ExtendedKeyUsage {
    critical: bool,
    server_auth: bool,
    client_auth: bool,
    code_signing: bool,
    email_protection: bool,
    time_stamping: bool,
    ms_code_ind: bool,
    ms_code_com: bool,
    ms_ctl_sign: bool,
    ms_sgc: bool,
    ms_efs: bool,
    ns_sgc: bool,
    other: Vec<String>,
}

impl ExtendedKeyUsage {
    pub fn new() -> ExtendedKeyUsage {
        ExtendedKeyUsage {
            critical: false,
            server_auth: false,
            client_auth: false,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ms_code_ind: false,
            ms_code_com: false,
            ms_ctl_sign: false,
            ms_sgc: false,
            ms_efs: false,
            ns_sgc: false,
            other: vec![],
        }
    }

    pub fn critical(&mut self) -> &mut ExtendedKeyUsage {
        self.critical = true;
        self
    }

    pub fn server_auth(&mut self) -> &mut ExtendedKeyUsage {
        self.server_auth = true;
        self
    }

    pub fn client_auth(&mut self) -> &mut ExtendedKeyUsage {
        self.client_auth = true;
        self
    }

    pub fn code_signing(&mut self) -> &mut ExtendedKeyUsage {
        self.code_signing = true;
        self
    }

    pub fn time_stamping(&mut self) -> &mut ExtendedKeyUsage {
        self.time_stamping = true;
        self
    }

    pub fn ms_code_ind(&mut self) -> &mut ExtendedKeyUsage {
        self.ms_code_ind = true;
        self
    }

    pub fn ms_code_com(&mut self) -> &mut ExtendedKeyUsage {
        self.ms_code_com = true;
        self
    }

    pub fn ms_ctl_sign(&mut self) -> &mut ExtendedKeyUsage {
        self.ms_ctl_sign = true;
        self
    }

    pub fn ms_sgc(&mut self) -> &mut ExtendedKeyUsage {
        self.ms_sgc = true;
        self
    }

    pub fn ms_efs(&mut self) -> &mut ExtendedKeyUsage {
        self.ms_efs = true;
        self
    }

    pub fn ns_sgc(&mut self) -> &mut ExtendedKeyUsage {
        self.ns_sgc = true;
        self
    }

    pub fn other(&mut self, other: &str) -> &mut ExtendedKeyUsage {
        self.other.push(other.to_owned());
        self
    }

    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(&mut value, &mut first, self.server_auth, "serverAuth");
        append(&mut value, &mut first, self.client_auth, "clientAuth");
        append(&mut value, &mut first, self.code_signing, "codeSigning");
        append(&mut value, &mut first, self.email_protection, "emailProtection");
        append(&mut value, &mut first, self.time_stamping, "timeStamping");
        append(&mut value, &mut first, self.ms_code_ind, "msCodeInd");
        append(&mut value, &mut first, self.ms_code_com, "msCodeCom");
        append(&mut value, &mut first, self.ms_ctl_sign, "msCTLSign");
        append(&mut value, &mut first, self.ms_sgc, "msSGC");
        append(&mut value, &mut first, self.ms_efs, "msEFS");
        append(&mut value, &mut first, self.ns_sgc, "nsSGC");
        for other in &self.other {
            append(&mut value, &mut first, true, other);
        }
        X509Extension::new_nid(None, None, nid::EXT_KEY_USAGE, &value)
    }
}

pub struct SubjectKeyIdentifier {
    critical: bool,
}

impl SubjectKeyIdentifier {
    pub fn new() -> SubjectKeyIdentifier {
        SubjectKeyIdentifier {
            critical: false,
        }
    }

    pub fn critical(&mut self) -> &mut SubjectKeyIdentifier {
        self.critical = true;
        self
    }

    pub fn build(&self, ctx: &X509v3Context) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(&mut value, &mut first, true, "hash");
        X509Extension::new_nid(None, Some(ctx), nid::SUBJECT_KEY_IDENTIFIER, &value)
    }
}

pub struct AuthorityKeyIdentifier {
    critical: bool,
    keyid: Option<bool>,
    issuer: Option<bool>,
}

impl AuthorityKeyIdentifier {
    pub fn new() -> AuthorityKeyIdentifier {
        AuthorityKeyIdentifier {
            critical: false,
            keyid: None,
            issuer: None,
        }
    }

    pub fn critical(&mut self) -> &mut AuthorityKeyIdentifier {
        self.critical = true;
        self
    }

    pub fn keyid(&mut self, always: bool) -> &mut AuthorityKeyIdentifier {
        self.keyid = Some(always);
        self
    }

    pub fn issuer(&mut self, always: bool) -> &mut AuthorityKeyIdentifier {
        self.issuer = Some(always);
        self
    }

    pub fn build(&self, ctx: &X509v3Context) -> Result<X509Extension, ErrorStack> {
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
        X509Extension::new_nid(None, Some(ctx), nid::AUTHORITY_KEY_IDENTIFIER, &value)
    }
}

pub struct SubjectAlternativeName {
    critical: bool,
    names: Vec<String>,
}

impl SubjectAlternativeName {
    pub fn new() -> SubjectAlternativeName {
        SubjectAlternativeName {
            critical: false,
            names: vec![],
        }
    }

    pub fn critical(&mut self) -> &mut SubjectAlternativeName {
        self.critical = true;
        self
    }

    pub fn email(&mut self, email: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("email:{}", email));
        self
    }

    pub fn uri(&mut self, uri: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("URI:{}", uri));
        self
    }

    pub fn dns(&mut self, dns: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("DNS:{}", dns));
        self
    }

    pub fn rid(&mut self, rid: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("RID:{}", rid));
        self
    }

    pub fn ip(&mut self, ip: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("IP:{}", ip));
        self
    }

    pub fn dir_name(&mut self, dir_name: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("dirName:{}", dir_name));
        self
    }

    pub fn other_name(&mut self, other_name: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("otherName:{}", other_name));
        self
    }

    pub fn build(&self, ctx: &X509v3Context) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        for name in &self.names {
            append(&mut value, &mut first, true, name);
        }
        X509Extension::new_nid(None, Some(ctx), nid::SUBJECT_ALT_NAME, &value)
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
