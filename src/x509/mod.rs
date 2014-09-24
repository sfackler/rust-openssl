use libc::{c_int, c_long, c_uint};
use std::mem;
use std::ptr;

use asn1;
use bio::{MemBio};
use crypto::hash::{HashType, evpmd, SHA1};
use crypto::pkey::{PKey};
use crypto::rand::rand_bytes;
use ssl::error::{SslError, StreamError};


#[repr(i32)]
pub enum X509FileType {
    PEM = ffi::X509_FILETYPE_PEM,
    ASN1 = ffi::X509_FILETYPE_ASN1,
    Default = ffi::X509_FILETYPE_DEFAULT
}
pub struct X509StoreContext {
    ctx: *mut ffi::X509_STORE_CTX
}

impl X509StoreContext {
    pub fn new(ctx: *mut ffi::X509_STORE_CTX) -> X509StoreContext {
        X509StoreContext {
            ctx: ctx
        }
    }

    pub fn get_error(&self) -> Option<X509ValidationError> {
        let err = unsafe { ffi::X509_STORE_CTX_get_error(self.ctx) };
        X509ValidationError::from_raw(err)
    }

    pub fn get_current_cert<'a>(&'a self) -> Option<X509<'a>> {
        let ptr = unsafe { ffi::X509_STORE_CTX_get_current_cert(self.ctx) };

        if ptr.is_null() {
            None
        } else {
            Some(X509 { ctx: Some(self), x509: ptr })
        }
    }
}

trait AsStr<'a> {
    fn as_str(&self) -> &'a str;
}

#[deriving(Clone)]
pub enum KeyUsage {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CRLSign,
    EncipherOnly,
    DecipherOnly
}

impl AsStr<'static> for KeyUsage {
    fn as_str(&self) -> &'static str {
        match self {
            &DigitalSignature => "digitalSignature",
            &NonRepudiation => "nonRepudiation",
            &KeyEncipherment => "keyEncipherment",
            &DataEncipherment => "dataEncipherment",
            &KeyAgreement => "keyAgreement",
            &KeyCertSign => "keyCertSign",
            &CRLSign => "cRLSign",
            &EncipherOnly => "encipherOnly",
            &DecipherOnly => "decipherOnly"
        }
    }
}


#[deriving(Clone)]
pub enum ExtKeyUsage {
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
    NsSgc
}

impl AsStr<'static> for ExtKeyUsage {
    fn as_str(&self) -> &'static str {
        match self {
            &ServerAuth => "serverAuth",
            &ClientAuth => "clientAuth",
            &CodeSigning => "codeSigning",
            &EmailProtection => "emailProtection",
            &TimeStamping => "timeStamping",
            &MsCodeInd => "msCodeInd",
            &MsCodeCom => "msCodeCom",
            &MsCtlSign => "msCTLSign",
            &MsSgc => "msSGC",
            &MsEfs => "msEFS",
            &NsSgc =>"nsSGC"
        }
    }
}


// FIXME: a dirty hack as there is no way to
// implement ToString for Vec as both are defined
// in another crate
trait ToStr {
    fn to_str(&self) -> String;
}

impl<'a, T: AsStr<'a>> ToStr for Vec<T> {
    fn to_str(&self) -> String {
        self.iter().enumerate().fold(String::new(), |mut acc, (idx, v)| {
            if idx > 0 { acc.push_char(',') };
            acc.push_str(v.as_str());
            acc
        })
    }
}

#[allow(non_snake_case)]
pub struct X509Generator {
    bits: uint,
    days: uint,
    CN: String,
    key_usage: Vec<KeyUsage>,
    ext_key_usage: Vec<ExtKeyUsage>,
    hash_type: HashType,
}

impl X509Generator {
    pub fn new() -> X509Generator {
        X509Generator {
            bits: 1024,
            days: 365,
            CN: "rust-openssl".to_string(),
            key_usage: Vec::new(),
            ext_key_usage: Vec::new(),
            hash_type: SHA1
        }
    }

    pub fn set_bitlength(mut self, bits: uint) -> X509Generator {
        self.bits = bits;
        self
    }

    pub fn set_valid_period(mut self, days: uint) -> X509Generator {
        self.days = days;
        self
    }

    #[allow(non_snake_case)]
    pub fn set_CN(mut self, CN: &str) -> X509Generator {
        self.CN = CN.to_string();
        self
    }

    pub fn set_usage(mut self, purposes: &[KeyUsage]) -> X509Generator {
        self.key_usage = purposes.to_vec();
        self
    }

    pub fn set_ext_usage(mut self, purposes: &[ExtKeyUsage]) -> X509Generator {
        self.ext_key_usage = purposes.to_vec();
        self
    }

    pub fn set_sign_hash(mut self, hash_type: HashType) -> X509Generator {
        self.hash_type = hash_type;
        self
    }

    fn add_extension(x509: *mut ffi::X509, extension: c_int, value: &str) -> Result<(), SslError> {
        unsafe {
            // FIXME: RAII
            let ctx: ffi::X509V3_CTX = mem::zeroed();
            ffi::X509V3_set_ctx(mem::transmute(&ctx), x509, x509,
                                ptr::null_mut(), ptr::null_mut(), 0);
            let ext = value.with_c_str(|value|
                                       ffi::X509V3_EXT_conf_nid(ptr::null_mut(), mem::transmute(&ctx), extension, mem::transmute(value)));
            try_ssl_null!(ext);
            try_ssl!(ffi::X509_add_ext(x509, ext, -1));
            ffi::X509_EXTENSION_free(ext);
            Ok(())
        }
    }

    fn add_name(name: *mut ffi::X509_NAME, key: &str, value: &str) -> Result<(), SslError> {
        let value_len = value.len() as c_int;
        lift_ssl!(key.with_c_str(|key| {
            value.with_c_str(|value| unsafe {
                    ffi::X509_NAME_add_entry_by_txt(name, key, asn1::ffi::MBSTRING_UTF8,
                                                    value, value_len, -1, 0)
            })
        }))
    }

    fn random_serial() -> c_long {
        let len = mem::size_of::<c_long>();
        let bytes = rand_bytes(len);
        let mut res = 0;
        for b in bytes.iter() {
            res = res << 8;
            res |= (*b as c_long) & 0xff;
        }
        res
    }

    pub fn generate<'a>(&self) -> Result<(X509<'a>, PKey), SslError> {
        let mut p_key = PKey::new();
        p_key.gen(self.bits);

        // FIXME: all allocated resources should be correctly
        // dropped in case of failure
        unsafe {
            let x509 = ffi::X509_new();
            try_ssl_null!(x509);
            try_ssl!(ffi::X509_set_version(x509, 2));
            try_ssl!(asn1::ffi::ASN1_INTEGER_set(ffi::X509_get_serialNumber(x509), X509Generator::random_serial()));

            let not_before = ffi::X509_gmtime_adj(ptr::null_mut(), 0);
            try_ssl_null!(not_before);

            let not_after = ffi::X509_gmtime_adj(ptr::null_mut(), 60*60*24*self.days as i64);
            try_ssl_null!(not_after);

            try_ssl!(ffi::X509_set_notBefore(x509, mem::transmute(not_before)));
            try_ssl!(ffi::X509_set_notAfter(x509, mem::transmute(not_after)));

            try_ssl!(ffi::X509_set_pubkey(x509, p_key.get_handle()));

            let name = ffi::X509_get_subject_name(x509);
            try_ssl_null!(name);

            try!(X509Generator::add_name(name, "CN", self.CN.as_slice()));
            ffi::X509_set_issuer_name(x509, name);

            if self.key_usage.len() > 0 {
                try!(X509Generator::add_extension(x509, ffi::NID_key_usage,
                                                  self.key_usage.to_str().as_slice()));
            }

            if self.ext_key_usage.len() > 0 {
                try!(X509Generator::add_extension(x509, ffi::NID_ext_key_usage,
                                                  self.ext_key_usage.to_str().as_slice()));
            }

            let (hash_fn, _) = evpmd(self.hash_type);
            try_ssl!(ffi::X509_sign(x509, p_key.get_handle(), hash_fn));
            Ok((X509 { x509: x509, ctx: None }, p_key))
        }
    }
}

#[allow(dead_code)]
/// A public key certificate
pub struct X509<'ctx> {
    ctx: Option<&'ctx X509StoreContext>,
    x509: *mut ffi::X509
}

impl<'ctx> X509<'ctx> {
    pub fn subject_name<'a>(&'a self) -> X509Name<'a> {
        let name = unsafe { ffi::X509_get_subject_name(self.x509) };
        X509Name { x509: self, name: name }
    }

    /// Returns certificate fingerprint calculated using provided hash
    pub fn fingerprint(&self, hash_type: HashType) -> Option<Vec<u8>> {
        let (evp, len) = evpmd(hash_type);
        let v: Vec<u8> = Vec::from_elem(len, 0);
        let act_len: c_uint = 0;
        let res = unsafe {
            ffi::X509_digest(self.x509, evp, mem::transmute(v.as_ptr()),
                             mem::transmute(&act_len))
        };

        match res {
            0 => None,
            _ => {
                let act_len = act_len as uint;
                match len.cmp(&act_len) {
                    Greater => None,
                    Equal => Some(v),
                    Less => fail!("Fingerprint buffer was corrupted!")
                }
            }
        }
    }

    /// Writes certificate as PEM
    pub fn write_pem(&self, writer: &mut Writer) -> Result<(), SslError> {
        let mut mem_bio = try!(MemBio::new());
        unsafe {
            try_ssl!(ffi::PEM_write_bio_X509(mem_bio.get_handle(),
                                         self.x509));
        }
        let buf = try!(mem_bio.read_to_end().map_err(StreamError));
        writer.write(buf.as_slice()).map_err(StreamError)
    }
}

#[allow(dead_code)]
pub struct X509Name<'x> {
    x509: &'x X509<'x>,
    name: *mut ffi::X509_NAME
}


pub mod ffi {
    #![allow(non_camel_case_types)]
    use libc::{c_void, c_int, c_char, c_ulong, c_long, c_uint};

    use asn1::ffi::{ASN1_INTEGER, ASN1_TIME};
    use bio::ffi::{BIO};
    use crypto::hash::{EVP_MD};
    use crypto::pkey::{EVP_PKEY};

    pub type X509_STORE_CTX = c_void;
    pub type X509 = c_void;
    pub type X509_NAME = c_void;
    pub type X509_CRL = c_void;
    pub type X509_REQ = c_void;
    pub type X509_EXTENSION = c_void;

    #[repr(C)]
    pub struct X509V3_CTX {
        flags: c_int,
        issuer_cert: *mut c_void,
        subject_cert: *mut c_void,
        subject_req: *mut c_void,
        crl: *mut c_void,
        db_meth: *mut c_void,
        db: *mut c_void,
        // I like the last comment line, it is copied from OpenSSL sources:
        // Maybe more here
    }

    pub static X509_V_OK: c_int = 0;
    pub static X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
    pub static X509_V_ERR_UNABLE_TO_GET_CRL: c_int = 3;
    pub static X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: c_int = 4;
    pub static X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: c_int = 5;
    pub static X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: c_int = 6;
    pub static X509_V_ERR_CERT_SIGNATURE_FAILURE: c_int = 7;
    pub static X509_V_ERR_CRL_SIGNATURE_FAILURE: c_int = 8;
    pub static X509_V_ERR_CERT_NOT_YET_VALID: c_int = 9;
    pub static X509_V_ERR_CERT_HAS_EXPIRED: c_int = 10;
    pub static X509_V_ERR_CRL_NOT_YET_VALID: c_int = 11;
    pub static X509_V_ERR_CRL_HAS_EXPIRED: c_int = 12;
    pub static X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: c_int = 13;
    pub static X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: c_int = 14;
    pub static X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: c_int = 15;
    pub static X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: c_int = 16;
    pub static X509_V_ERR_OUT_OF_MEM: c_int = 17;
    pub static X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
    pub static X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: c_int = 19;
    pub static X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_int = 20;
    pub static X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_int = 21;
    pub static X509_V_ERR_CERT_CHAIN_TOO_LONG: c_int = 22;
    pub static X509_V_ERR_CERT_REVOKED: c_int = 23;
    pub static X509_V_ERR_INVALID_CA: c_int = 24;
    pub static X509_V_ERR_PATH_LENGTH_EXCEEDED: c_int = 25;
    pub static X509_V_ERR_INVALID_PURPOSE: c_int = 26;
    pub static X509_V_ERR_CERT_UNTRUSTED: c_int = 27;
    pub static X509_V_ERR_CERT_REJECTED: c_int = 28;
    pub static X509_V_ERR_SUBJECT_ISSUER_MISMATCH: c_int = 29;
    pub static X509_V_ERR_AKID_SKID_MISMATCH: c_int = 30;
    pub static X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH: c_int = 31;
    pub static X509_V_ERR_KEYUSAGE_NO_CERTSIGN: c_int = 32;
    pub static X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: c_int = 33;
    pub static X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION: c_int = 34;
    pub static X509_V_ERR_KEYUSAGE_NO_CRL_SIGN: c_int = 35;
    pub static X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION: c_int = 36;
    pub static X509_V_ERR_INVALID_NON_CA: c_int = 37;
    pub static X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED: c_int = 38;
    pub static X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE: c_int = 39;
    pub static X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED: c_int = 40;
    pub static X509_V_ERR_INVALID_EXTENSION: c_int = 41;
    pub static X509_V_ERR_INVALID_POLICY_EXTENSION: c_int = 42;
    pub static X509_V_ERR_NO_EXPLICIT_POLICY: c_int = 43;
    pub static X509_V_ERR_DIFFERENT_CRL_SCOPE: c_int = 44;
    pub static X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE: c_int = 45;
    pub static X509_V_ERR_UNNESTED_RESOURCE: c_int = 46;
    pub static X509_V_ERR_PERMITTED_VIOLATION: c_int = 47;
    pub static X509_V_ERR_EXCLUDED_VIOLATION: c_int = 48;
    pub static X509_V_ERR_SUBTREE_MINMAX: c_int = 49;
    pub static X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE: c_int = 51;
    pub static X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX: c_int = 52;
    pub static X509_V_ERR_UNSUPPORTED_NAME_SYNTAX: c_int = 53;
    pub static X509_V_ERR_CRL_PATH_VALIDATION_ERROR: c_int = 54;
    pub static X509_V_ERR_APPLICATION_VERIFICATION: c_int = 50;

    pub static X509_FILETYPE_PEM: c_int = 1;
    pub static X509_FILETYPE_ASN1: c_int = 2;
    pub static X509_FILETYPE_DEFAULT: c_int = 3;

    pub static NID_key_usage:     c_int = 83;
    pub static NID_ext_key_usage: c_int = 126;



    extern "C" {
        pub fn X509_STORE_CTX_get_ex_data(ctx: *mut X509_STORE_CTX, idx: c_int) -> *mut c_void;
        pub fn X509_STORE_CTX_get_current_cert(ct: *mut X509_STORE_CTX) -> *mut X509;
        pub fn X509_STORE_CTX_get_error(ctx: *mut X509_STORE_CTX) -> c_int;

        pub fn X509_add_ext(x: *mut X509, ext: *mut X509_EXTENSION, loc: c_int) -> c_int;
        pub fn X509_digest(x: *mut X509, digest: *const EVP_MD, buf: *mut c_char, len: *mut c_uint) -> c_int;
        pub fn X509_get_serialNumber(x: *mut X509) -> *mut ASN1_INTEGER;
        pub fn X509_get_subject_name(x: *mut X509) -> *mut X509_NAME;
        pub fn X509_gmtime_adj(time: *mut ASN1_TIME, adj: c_long) -> *mut ASN1_TIME;
        pub fn X509_new() -> *mut X509;
        pub fn X509_set_issuer_name(x: *mut X509, name: *mut X509_NAME) -> c_int;
        pub fn X509_set_notAfter(x: *mut X509, tm: *const ASN1_TIME) -> c_int;
        pub fn X509_set_notBefore(x: *mut X509, tm: *const ASN1_TIME) -> c_int;
        pub fn X509_set_version(x: *mut X509, version: c_ulong) -> c_int;
        pub fn X509_set_pubkey(x: *mut X509, pkey: *mut EVP_PKEY) -> c_int;
        pub fn X509_sign(x: *mut X509, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int;

        pub fn X509_NAME_add_entry_by_txt(x: *mut X509, field: *const c_char, ty: c_int, bytes: *const c_char, len: c_int, loc: c_int, set: c_int) -> c_int;

        pub fn X509V3_EXT_conf_nid(conf: *mut c_void, ctx: *mut X509V3_CTX, ext_nid: c_int, value: *mut c_char) -> *mut X509_EXTENSION;
        pub fn X509V3_set_ctx(ctx: *mut X509V3_CTX, issuer: *mut X509, subject: *mut X509, req: *mut X509_REQ, crl: *mut X509_CRL, flags: c_int);

        pub fn X509_EXTENSION_free(ext: *mut X509_EXTENSION);

        pub fn PEM_write_bio_X509(bio: *mut BIO, x509: *mut X509) -> c_int;
    }
}

macro_rules! make_validation_error(
    ($ok_val:ident, $($name:ident = $val:ident,)+) => (
        pub enum X509ValidationError {
            $($name,)+
            X509UnknownError(c_int)
        }

        impl X509ValidationError {
            #[doc(hidden)]
            pub fn from_raw(err: c_int) -> Option<X509ValidationError> {
                match err {
                    self::ffi::$ok_val => None,
                    $(self::ffi::$val => Some($name),)+
                    err => Some(X509UnknownError(err))
                }
            }
        }
    )
)

make_validation_error!(X509_V_OK,
    X509UnableToGetIssuerCert = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
    X509UnableToGetCrl = X509_V_ERR_UNABLE_TO_GET_CRL,
    X509UnableToDecryptCertSignature = X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
    X509UnableToDecryptCrlSignature = X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
    X509UnableToDecodeIssuerPublicKey = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
    X509CertSignatureFailure = X509_V_ERR_CERT_SIGNATURE_FAILURE,
    X509CrlSignatureFailure = X509_V_ERR_CRL_SIGNATURE_FAILURE,
    X509CertNotYetValid = X509_V_ERR_CERT_NOT_YET_VALID,
    X509CertHasExpired = X509_V_ERR_CERT_HAS_EXPIRED,
    X509CrlNotYetValid = X509_V_ERR_CRL_NOT_YET_VALID,
    X509CrlHasExpired = X509_V_ERR_CRL_HAS_EXPIRED,
    X509ErrorInCertNotBeforeField = X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD,
    X509ErrorInCertNotAfterField = X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD,
    X509ErrorInCrlLastUpdateField = X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD,
    X509ErrorInCrlNextUpdateField = X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD,
    X509OutOfMem = X509_V_ERR_OUT_OF_MEM,
    X509DepthZeroSelfSignedCert = X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
    X509SelfSignedCertInChain = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
    X509UnableToGetIssuerCertLocally = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
    X509UnableToVerifyLeafSignature = X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
    X509CertChainTooLong = X509_V_ERR_CERT_CHAIN_TOO_LONG,
    X509CertRevoked = X509_V_ERR_CERT_REVOKED,
    X509InvalidCA = X509_V_ERR_INVALID_CA,
    X509PathLengthExceeded = X509_V_ERR_PATH_LENGTH_EXCEEDED,
    X509InvalidPurpose = X509_V_ERR_INVALID_PURPOSE,
    X509CertUntrusted = X509_V_ERR_CERT_UNTRUSTED,
    X509CertRejected = X509_V_ERR_CERT_REJECTED,
    X509SubjectIssuerMismatch = X509_V_ERR_SUBJECT_ISSUER_MISMATCH,
    X509AkidSkidMismatch = X509_V_ERR_AKID_SKID_MISMATCH,
    X509AkidIssuerSerialMismatch = X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH,
    X509KeyusageNoCertsign = X509_V_ERR_KEYUSAGE_NO_CERTSIGN,
    X509UnableToGetCrlIssuer = X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER,
    X509UnhandledCriticalExtension = X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION,
    X509KeyusageNoCrlSign = X509_V_ERR_KEYUSAGE_NO_CRL_SIGN,
    X509UnhandledCriticalCrlExtension = X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION,
    X509InvalidNonCA = X509_V_ERR_INVALID_NON_CA,
    X509ProxyPathLengthExceeded = X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED,
    X509KeyusageNoDigitalSignature = X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE,
    X509ProxyCertificatesNotAllowed = X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED,
    X509InvalidExtension = X509_V_ERR_INVALID_EXTENSION,
    X509InavlidPolicyExtension = X509_V_ERR_INVALID_POLICY_EXTENSION,
    X509NoExplicitPolicy = X509_V_ERR_NO_EXPLICIT_POLICY,
    X509DifferentCrlScope = X509_V_ERR_DIFFERENT_CRL_SCOPE,
    X509UnsupportedExtensionFeature = X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE,
    X509UnnestedResource = X509_V_ERR_UNNESTED_RESOURCE,
    X509PermittedVolation = X509_V_ERR_PERMITTED_VIOLATION,
    X509ExcludedViolation = X509_V_ERR_EXCLUDED_VIOLATION,
    X509SubtreeMinmax = X509_V_ERR_SUBTREE_MINMAX,
    X509UnsupportedConstraintType = X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE,
    X509UnsupportedConstraintSyntax = X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX,
    X509UnsupportedNameSyntax = X509_V_ERR_UNSUPPORTED_NAME_SYNTAX,
    X509CrlPathValidationError= X509_V_ERR_CRL_PATH_VALIDATION_ERROR,
    X509ApplicationVerification = X509_V_ERR_APPLICATION_VERIFICATION,
)
