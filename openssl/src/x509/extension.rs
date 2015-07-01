use std::fmt;

#[derive(Clone)]
pub enum Extension {
	KeyUsage(Vec<KeyUsageOption>),
	ExtKeyUsage(Vec<ExtKeyUsageOption>),
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
