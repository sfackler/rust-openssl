use std::fmt::Write;

use error::ErrorStack;
use nid::Nid;
use x509::{X509Extension, X509v3Context};

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
        X509Extension::new_nid(None, None, Nid::BASIC_CONSTRAINTS, &value)
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
        append(
            &mut value,
            &mut first,
            self.email_protection,
            "emailProtection",
        );
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
        X509Extension::new_nid(None, None, Nid::EXT_KEY_USAGE, &value)
    }
}

pub struct SubjectKeyIdentifier {
    critical: bool,
}

impl SubjectKeyIdentifier {
    pub fn new() -> SubjectKeyIdentifier {
        SubjectKeyIdentifier { critical: false }
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
        X509Extension::new_nid(None, Some(ctx), Nid::SUBJECT_KEY_IDENTIFIER, &value)
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
        X509Extension::new_nid(None, Some(ctx), Nid::AUTHORITY_KEY_IDENTIFIER, &value)
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
        X509Extension::new_nid(None, Some(ctx), Nid::SUBJECT_ALT_NAME, &value)
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
