use std::fmt;
use nid::Nid;

#[derive(Clone,Hash,PartialEq,Eq)]
pub enum ExtensionType {
	KeyUsage,
	ExtKeyUsage,
	OtherNid(Nid),
	OtherStr(String),
}

#[derive(Clone)]
pub enum Extension {
	KeyUsage(Vec<KeyUsageOption>),
	ExtKeyUsage(Vec<ExtKeyUsageOption>),
	OtherNid(Nid,String),
	OtherStr(String,String),
}

impl Extension {
	pub fn get_type(&self) -> ExtensionType {
		match self {
			&Extension::KeyUsage(_) => ExtensionType::KeyUsage,
			&Extension::ExtKeyUsage(_) => ExtensionType::ExtKeyUsage,
			&Extension::OtherNid(nid,_) => ExtensionType::OtherNid(nid),
			&Extension::OtherStr(ref s,_) => ExtensionType::OtherStr(s.clone()),
		}
	}
}

impl ExtensionType {
	pub fn get_nid(&self) -> Option<Nid> {
		match self {
			&ExtensionType::KeyUsage => Some(Nid::KeyUsage),
			&ExtensionType::ExtKeyUsage => Some(Nid::ExtendedKeyUsage),
			&ExtensionType::OtherNid(nid) => Some(nid),
			&ExtensionType::OtherStr(_) => None,
		}
	}

	pub fn get_name<'a>(&'a self) -> Option<&'a str> {
		match self {
			&ExtensionType::OtherStr(ref s) => Some(s),
			_ => None,
		}
	}
}

// FIXME: This would be nicer as a method on Iterator<Item=ToString>. This can
// eventually be replaced by the successor to std::slice::SliceConcatExt.connect
fn join<I: Iterator<Item=T>,T: ToString>(iter: I, sep: &str) -> String {
    iter.enumerate().fold(String::new(), |mut acc, (idx, v)| {
        if idx > 0 { acc.push_str(sep) };
        acc.push_str(&v.to_string());
        acc
    })
}

impl ToString for Extension {
    fn to_string(&self) -> String {
		match self {
			&Extension::KeyUsage(ref purposes) => join(purposes.iter(),","),
			&Extension::ExtKeyUsage(ref purposes) => join(purposes.iter(),","),
			&Extension::OtherNid(_,ref value) => value.clone(),
			&Extension::OtherStr(_,ref value) => value.clone(),
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
            &ExtKeyUsageOption::NsSgc =>"nsSGC",
            &ExtKeyUsageOption::Other(ref s) => &s[..],
        })
    }
}
