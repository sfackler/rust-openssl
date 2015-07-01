use std::fmt;
use nid::Nid;

#[derive(Clone,Copy,Hash,PartialEq,Eq)]
pub enum ExtensionType {
	KeyUsage,
	ExtKeyUsage,
}

#[derive(Clone)]
pub enum Extension {
	KeyUsage(Vec<KeyUsageOption>),
	ExtKeyUsage(Vec<ExtKeyUsageOption>),
}

impl Extension {
	pub fn get_type(&self) -> ExtensionType {
		match self {
			&Extension::KeyUsage(_) => ExtensionType::KeyUsage,
			&Extension::ExtKeyUsage(_) => ExtensionType::ExtKeyUsage,
		}
	}

	pub fn get_nid(&self) -> Nid {
		match self {
			&Extension::KeyUsage(_) => Nid::KeyUsage,
			&Extension::ExtKeyUsage(_) => Nid::ExtendedKeyUsage,
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

#[derive(Clone,Copy)]
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
        })
    }
}
