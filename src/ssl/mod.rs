use libc::{c_int, c_uint, c_void, c_char};
use std::io::{IoResult, IoError, EndOfFile, Stream, Reader, Writer};
use std::mem;
use std::ptr;
use std::rt::mutex::NativeMutex;
use std::string;
use std::c_str::CString;
use sync::one::{Once, ONCE_INIT};

use crypto::hash::{HashType, evpmd};
use ssl::error::{SslError, SslSessionClosed, StreamError};
use std::collections::enum_set::CLike;

pub mod error;
mod ffi;
#[cfg(test)]
mod tests;

static mut VERIFY_IDX: c_int = -1;
static mut MUTEXES: *mut Vec<NativeMutex> = 0 as *mut Vec<NativeMutex>;

macro_rules! try_ssl(
    ($e:expr) => (
        match $e {
            Ok(ok) => ok,
            Err(err) => return Err(StreamError(err))
        }
    )
)

fn init() {
    static mut INIT: Once = ONCE_INIT;

    unsafe {
        INIT.doit(|| {
            ffi::SSL_library_init();
            let verify_idx = ffi::SSL_CTX_get_ex_new_index(0, ptr::null(), None,
                                                           None, None);
            assert!(verify_idx >= 0);
            VERIFY_IDX = verify_idx;

            let num_locks = ffi::CRYPTO_num_locks();
            let mutexes = box Vec::from_fn(num_locks as uint, |_| NativeMutex::new());
            MUTEXES = mem::transmute(mutexes);

            ffi::CRYPTO_set_locking_callback(locking_function);

            ffi::SSL_load_error_strings();
        });
    }
}

pub mod nid {
    use std::mem;
    use std::collections::enum_set::CLike;

    #[allow(dead_code)]
    #[allow(non_camel_case_types)]
    #[repr(uint)]
    pub enum Nid {
        Undefined,
        Rsadsi,
        Pkcs,
        MD2,
        MD4,
        MD5,
        RC4,
        RsaEncryption,
        RSA_MD2,
        RSA_MD5,
        PBE_MD2_DES,
        X500,
        x509,
        CN,
        C,
        L,
        ST,
        O,
        OU,
        RSA,
        Pkcs7,
        Pkcs7_data,
        Pkcs7_signedData,
        Pkcs7_envelopedData,
        Pkcs7_signedAndEnvelopedData,
        Pkcs7_digestData,
        Pkcs7_encryptedData,
        Pkcs3,
        DhKeyAgreement,
        DES_ECB,
        DES_CFB,
        DES_CBC,
        DES_EDE,
        DES_EDE3,
        IDEA_CBC,
        IDEA_ECB,
        RC2_CBC,
        RC2_ECB,
        RC2_CFB,
        RC2_OFB,
        SHA,
        RSA_SHA,
        DES_EDE_CBC,
        DES_EDE3_CBC,
        DES_OFB,
        IDEA_OFB,
        Pkcs9,
        Email,
        UnstructuredName,
        ContentType,
        MessageDigest,
        SigningTime,
        CounterSignature,
        UnstructuredAddress,
        ExtendedCertificateAttributes,
        Netscape,
        NetscapeCertExtention,
        NetscapeDatatype,
        DES_EDE_CFB64,
        DES_EDE3_CFB64,
        DES_EDE_OFB64,
        DES_EDE3_OFB64,
        SHA1,
        RSA_SHA1,
        DSA_SHA,
        DSA_OLD,
        PBE_SHA1_RC2_64,
        PBKDF2,
        DSA_SHA1_OLD,
        NetscapeCertType,
        NetscapeBaseUrl,
        NetscapeRevocationUrl,
        NetscapeCARevocationUrl,
        NetscapeRenewalUrl,
        NetscapeCAPolicyUrl,
        NetscapeSSLServerName,
        NetscapeComment,
        NetscapeCertSequence,
        DESX_CBC,
        ID_CE,
        SubjectKeyIdentifier,
        KeyUsage,
        PrivateKeyUsagePeriod,
        SubjectAltName,
        IssuerAltName,
        BasicConstraints,
        CrlNumber,
        CertificatePolicies,
        AuthorityKeyIdentifier,
        BF_CBC,
        BF_ECB,
        BF_OFB,
        MDC2,
        RSA_MDC2,
        RC4_40,
        RC2_40_CBC,
        G,
        S,
        I,
        UID,
        CrlDistributionPoints,
        RSA_NP_MD5,
        SN,
        T,
        D,
        CAST5_CBC,
        CAST5_ECB,
        CAST5_CFB,
        CAST5_OFB,
        PbeWithMD5AndCast5CBC,
        DSA_SHA1, // 113
        MD5_SHA1,
        RSA_SHA1_2,
        DSA,
        RIPEMD160,
        RSA_RIPEMD160,
        RC5_CBC,
        RC5_ECB,
        RC5_CFB,
        RC5_OFB,
        RLE,
        ZLIB,
        ExtendedKeyUsage,
        PKIX,
        ID_KP,
        ServerAuth,
        ClientAuth,
        CodeSigning,
        EmailProtection,
        TimeStamping,
        MsCodeInd,
        MsCodeCom,
        MsCtlSigh,
        MsSGC,
        MsEFS,
        NsSGC,
        DeltaCRL,
        CRLReason,
        InvalidityDate,
        SXNetID,
        Pkcs12,
        PBE_SHA1_RC4_128,
        PBE_SHA1_RC4_40,
        PBE_SHA1_3DES,
        PBE_SHA1_2DES,
        PBE_SHA1_RC2_128,
        PBE_SHA1_RC2_40,
        KeyBag,
        Pkcs8ShroudedKeyBag,
        CertBag,
        CrlBag,
        SecretBag,
        SafeContentsBag,
        FriendlyName,
        LocalKeyID,
        X509Certificate,
        SdsiCertificate,
        X509Crl,
        PBES2,
        PBMAC1,
        HmacWithSha1,
        ID_QT_CPS,
        ID_QT_UNOTICE,
        RC2_64_CBC,
        SMIMECaps,

    }

    impl CLike for Nid {
        fn to_uint(&self) -> uint {
            *self as uint
        }

        fn from_uint(v: uint) -> Nid {
            unsafe { mem::transmute(v) }
        }
    }
}

/// Determines the SSL method supported
#[deriving(Show, Hash, PartialEq, Eq)]
pub enum SslMethod {
    #[cfg(sslv2)]
    /// Only support the SSLv2 protocol
    Sslv2,
    /// Only support the SSLv3 protocol
    Sslv3,
    /// Only support the TLSv1 protocol
    Tlsv1,
    /// Support the SSLv2, SSLv3 and TLSv1 protocols
    Sslv23,

    #[cfg(sslv2)]
    /// Only support the SSLv2 protocol
    Sslv2Server,
    /// Only support the SSLv3 protocol
    Sslv3Server,
    /// Only support the TLSv1 protocol
    Tlsv1Server,
    /// Support the SSLv2, SSLv3 and TLSv1 protocols
    Sslv23Server,
}

impl SslMethod {
    unsafe fn to_raw(&self) -> *const ffi::SSL_METHOD {
        match *self {
            #[cfg(sslv2)]
            Sslv2 => ffi::SSLv2_method(),
            Sslv3 => ffi::SSLv3_method(),
            Tlsv1 => ffi::TLSv1_method(),
            Sslv23 => ffi::SSLv23_method(),

            #[cfg(sslv2)]
            Sslv2Server => ffi::SSLv2_server_method(),
            Sslv3Server => ffi::SSLv3_server_method(),
            Tlsv1Server => ffi::TLSv1_server_method(),
            Sslv23Server => ffi::SSLv23_server_method(),
        }
    }
}

/// Determines the type of certificate verification used
bitflags! {
    flags SslVerifyMode: c_uint {
        #[doc="Server mode: request a certificate from the client and verify.
        Client mode: verify that the server's certificate is trusted"]
        static SslVerifyPeer = ffi::SSL_VERIFY_PEER,
        #[doc="Server mode: Server will not requst a client certificate.
        Client mode: Do not verify the server's certificate."]
        static SslVerifyNone = ffi::SSL_VERIFY_NONE,
        #[doc="Server mode: require a client certificate. Must be used together with SslVerifyPeer.
        Client mode: ignored."]
        static SslVerifyFailIfNoPeerCert = ffi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        #[doc="Server mode: only request a client certificate durring initial handshake, note
        durring renegotiation.
        Client mode: ignored."]
        static SslVerifyClientOnce = ffi::SSL_VERIFY_CLIENT_ONCE,
    }
}

extern fn locking_function(mode: c_int, n: c_int, _file: *const c_char,
                               _line: c_int) {
    unsafe {
        let mutex = (*MUTEXES).get_mut(n as uint);

        if mode & ffi::CRYPTO_LOCK != 0 {
            mutex.lock_noguard();
        } else {
            mutex.unlock_noguard();
        }
    }
}

extern fn raw_verify(preverify_ok: c_int, x509_ctx: *mut ffi::X509_STORE_CTX)
        -> c_int {
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);
        let verify = ffi::SSL_CTX_get_ex_data(ssl_ctx, VERIFY_IDX);
        let verify: Option<VerifyCallback> = mem::transmute(verify);

        let ctx = X509StoreContext { ctx: x509_ctx };

        match verify {
            None => preverify_ok,
            Some(verify) => verify(preverify_ok != 0, &ctx) as c_int
        }
    }
}

/// The signature of functions that can be used to manually verify certificates
pub type VerifyCallback = fn(preverify_ok: bool,
                             x509_ctx: &X509StoreContext) -> bool;

#[repr(i32)]
pub enum X509FileType {
    PEM = ffi::X509_FILETYPE_PEM,
    ASN1 = ffi::X509_FILETYPE_ASN1,
    Default = ffi::X509_FILETYPE_DEFAULT
}

// FIXME: macro may be instead of inlining?
#[inline]
fn wrap_ssl_result(res: c_int) -> Option<SslError> {
    if res == 0 {
        Some(SslError::get())
    } else {
        None
    }
}

/// An SSL context object
pub struct SslContext {
    ctx: *mut ffi::SSL_CTX
}

impl Drop for SslContext {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(self.ctx) }
    }
}

impl SslContext {
    /// Creates a new SSL context.
    pub fn new(method: SslMethod) -> Result<SslContext, SslError> {
        init();

        let ctx = unsafe { ffi::SSL_CTX_new(method.to_raw()) };
        if ctx == ptr::null_mut() {
            return Err(SslError::get());
        }

        Ok(SslContext { ctx: ctx })
    }

    /// Configures the certificate verification method for new connections.
    pub fn set_verify(&mut self, mode: SslVerifyMode,
                      verify: Option<VerifyCallback>) {
        unsafe {
            ffi::SSL_CTX_set_ex_data(self.ctx, VERIFY_IDX,
                                     mem::transmute(verify));
            ffi::SSL_CTX_set_verify(self.ctx, mode.bits as c_int, Some(raw_verify));
        }
    }

    #[allow(non_snake_case)]
    /// Specifies the file that contains trusted CA certificates.
    pub fn set_CA_file(&mut self, file: &str) -> Option<SslError> {
        wrap_ssl_result(file.with_c_str(|file| {
            unsafe {
                ffi::SSL_CTX_load_verify_locations(self.ctx, file, ptr::null())
            }
        }))
    }

    /// Specifies the file that is client certificate
    pub fn set_certificate_file(&mut self, file: &str,
                                file_type: X509FileType) -> Option<SslError> {
        wrap_ssl_result(file.with_c_str(|file| {
            unsafe {
                ffi::SSL_CTX_use_certificate_file(self.ctx, file, file_type as c_int)
            }
        }))
    }

    /// Specifies the file that is client private key
    pub fn set_private_key_file(&mut self, file: &str,
                                file_type: X509FileType) -> Option<SslError> {
        wrap_ssl_result(file.with_c_str(|file| {
            unsafe {
                ffi::SSL_CTX_use_PrivateKey_file(self.ctx, file, file_type as c_int)
            }
        }))
    }

    pub fn set_cipher_list(&mut self, cipher_list: &str) -> Option<SslError> {
        wrap_ssl_result(cipher_list.with_c_str(|cipher_list| {
            unsafe {
                ffi::SSL_CTX_set_cipher_list(self.ctx, cipher_list)
            }
        }))
    }
}

pub struct X509StoreContext {
    ctx: *mut ffi::X509_STORE_CTX
}

impl X509StoreContext {
    pub fn get_error(&self) -> Option<X509ValidationError> {
        let err = unsafe { ffi::X509_STORE_CTX_get_error(self.ctx) };
        X509ValidationError::from_raw(err)
    }

    pub fn get_current_cert<'a>(&'a self) -> Option<X509<'a>> {
        let ptr = unsafe { ffi::X509_STORE_CTX_get_current_cert(self.ctx) };

        if ptr.is_null() {
            None
        } else {
            Some(X509 { ctx: self, x509: ptr })
        }
    }
}

#[allow(dead_code)]
/// A public key certificate
pub struct X509<'ctx> {
    ctx: &'ctx X509StoreContext,
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
}

#[allow(dead_code)]
pub struct X509Name<'x> {
    x509: &'x X509<'x>,
    name: *mut ffi::X509_NAME
}

#[allow(dead_code)]
pub struct X509NameEntry<'x> {
    x509_name: &'x X509Name<'x>,
    ne: *mut ffi::X509_NAME_ENTRY
}

#[allow(dead_code)]
pub struct Asn1String<'x> {
    x509_name_entry: &'x X509NameEntry<'x>,
    asn1_str: *mut ffi::ASN1_STRING
}

#[deriving(Show)]
pub struct SslCString {
    c_str : CString
}

impl Drop for SslCString {
    fn drop(&mut self) {
        unsafe { ffi::CRYPTO_free(self.c_str.as_mut_ptr() as *mut c_void); }
    }
}

impl SslCString {
    pub unsafe fn new(buf: *const i8) -> SslCString {
        SslCString {
            c_str : CString::new(buf, false)
        }
    }
}

impl <'x> X509Name<'x> {
    pub fn text_by_nid(&self, nid: nid::Nid) -> Option<SslCString> {
        unsafe {
            let loc = ffi::X509_NAME_get_index_by_NID(self.name, nid.to_uint() as c_int, -1);
            if loc == -1 {
                return None;
            }

            let ne = ffi::X509_NAME_get_entry(self.name, loc);
            if ne.is_null() {
                return None;
            }

            let asn1_str = ffi::X509_NAME_ENTRY_get_data(ne);
            if asn1_str.is_null() {
                return None;
            }

            let mut str_from_asn1 : *mut c_char = ptr::null_mut();
            let utf8_succ = ffi::ASN1_STRING_to_UTF8(&mut str_from_asn1, asn1_str);

            if utf8_succ < 0 {
                return None
            }

            assert!(!str_from_asn1.is_null());

            Some(SslCString::new(str_from_asn1 as *const i8))
        }
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

pub struct Ssl {
    ssl: *mut ffi::SSL
}

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe { ffi::SSL_free(self.ssl) }
    }
}

impl Ssl {
    pub fn new(ctx: &SslContext) -> Result<Ssl, SslError> {
        let ssl = unsafe { ffi::SSL_new(ctx.ctx) };
        if ssl == ptr::null_mut() {
            return Err(SslError::get());
        }
        let ssl = Ssl { ssl: ssl };

        let rbio = unsafe { ffi::BIO_new(ffi::BIO_s_mem()) };
        if rbio == ptr::null_mut() {
            return Err(SslError::get());
        }

        let wbio = unsafe { ffi::BIO_new(ffi::BIO_s_mem()) };
        if wbio == ptr::null_mut() {
            unsafe { ffi::BIO_free_all(rbio) }
            return Err(SslError::get());
        }

        unsafe { ffi::SSL_set_bio(ssl.ssl, rbio, wbio) }
        Ok(ssl)
    }

    fn get_rbio<'a>(&'a self) -> MemBioRef<'a> {
        unsafe { self.wrap_bio(ffi::SSL_get_rbio(self.ssl)) }
    }

    fn get_wbio<'a>(&'a self) -> MemBioRef<'a> {
        unsafe { self.wrap_bio(ffi::SSL_get_wbio(self.ssl)) }
    }

    fn wrap_bio<'a>(&'a self, bio: *mut ffi::BIO) -> MemBioRef<'a> {
        assert!(bio != ptr::null_mut());
        MemBioRef {
            ssl: self,
            bio: MemBio {
                bio: bio,
                owned: false
            }
        }
    }

    fn connect(&self) -> c_int {
        unsafe { ffi::SSL_connect(self.ssl) }
    }

    fn accept(&self) -> c_int {
        unsafe { ffi::SSL_accept(self.ssl) }
    }

    fn read(&self, buf: &mut [u8]) -> c_int {
        unsafe { ffi::SSL_read(self.ssl, buf.as_ptr() as *mut c_void,
                               buf.len() as c_int) }
    }

    fn write(&self, buf: &[u8]) -> c_int {
        unsafe { ffi::SSL_write(self.ssl, buf.as_ptr() as *const c_void,
                                buf.len() as c_int) }
    }

    fn get_error(&self, ret: c_int) -> LibSslError {
        let err = unsafe { ffi::SSL_get_error(self.ssl, ret) };
        match FromPrimitive::from_int(err as int) {
            Some(err) => err,
            None => unreachable!()
        }
    }

    /// Set the host name to be used with SNI (Server Name Indication).
    pub fn set_hostname(&self, hostname: &str) -> Result<(), SslError> {
        let ret = hostname.with_c_str(|hostname| {
            unsafe {
                // This is defined as a macro:
                //      #define SSL_set_tlsext_host_name(s,name) \
                //          SSL_ctrl(s,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name,(char *)name)

                ffi::SSL_ctrl(self.ssl, ffi::SSL_CTRL_SET_TLSEXT_HOSTNAME,
                              ffi::TLSEXT_NAMETYPE_host_name,
                              hostname as *const c_void as *mut c_void)
            }
        });

        // For this case, 0 indicates failure.
        if ret == 0 {
            Err(SslError::get())
        } else {
            Ok(())
        }
    }

}

#[deriving(FromPrimitive)]
#[repr(i32)]
enum LibSslError {
    ErrorNone = ffi::SSL_ERROR_NONE,
    ErrorSsl = ffi::SSL_ERROR_SSL,
    ErrorWantRead = ffi::SSL_ERROR_WANT_READ,
    ErrorWantWrite = ffi::SSL_ERROR_WANT_WRITE,
    ErrorWantX509Lookup = ffi::SSL_ERROR_WANT_X509_LOOKUP,
    ErrorSyscall = ffi::SSL_ERROR_SYSCALL,
    ErrorZeroReturn = ffi::SSL_ERROR_ZERO_RETURN,
    ErrorWantConnect = ffi::SSL_ERROR_WANT_CONNECT,
    ErrorWantAccept = ffi::SSL_ERROR_WANT_ACCEPT,
}

#[allow(dead_code)]
struct MemBioRef<'ssl> {
    ssl: &'ssl Ssl,
    bio: MemBio,
}

impl<'ssl> MemBioRef<'ssl> {
    fn read(&self, buf: &mut [u8]) -> Option<uint> {
        self.bio.read(buf)
    }

    fn write(&self, buf: &[u8]) {
        self.bio.write(buf)
    }
}

struct MemBio {
    bio: *mut ffi::BIO,
    owned: bool
}

impl Drop for MemBio {
    fn drop(&mut self) {
        if self.owned {
            unsafe {
                ffi::BIO_free_all(self.bio);
            }
        }
    }
}

impl MemBio {
    fn read(&self, buf: &mut [u8]) -> Option<uint> {
        let ret = unsafe {
            ffi::BIO_read(self.bio, buf.as_ptr() as *mut c_void,
                          buf.len() as c_int)
        };

        if ret < 0 {
            None
        } else {
            Some(ret as uint)
        }
    }

    fn write(&self, buf: &[u8]) {
        let ret = unsafe {
            ffi::BIO_write(self.bio, buf.as_ptr() as *const c_void,
                           buf.len() as c_int)
        };
        assert_eq!(buf.len(), ret as uint);
    }
}

/// A stream wrapper which handles SSL encryption for an underlying stream.
pub struct SslStream<S> {
    stream: S,
    ssl: Ssl,
    buf: Vec<u8>
}

impl<S: Stream> SslStream<S> {
    fn new_base(ssl:Ssl, stream: S) -> SslStream<S> {
        SslStream {
            stream: stream,
            ssl: ssl,
            // Maximum TLS record size is 16k
            buf: Vec::from_elem(16 * 1024, 0u8)
        }
    }

    pub fn new_server_from(ssl: Ssl, stream: S) -> Result<SslStream<S>, SslError> {
        let mut ssl = SslStream::new_base(ssl, stream);
        match ssl.in_retry_wrapper(|ssl| { ssl.accept() }) {
            Ok(_) => Ok(ssl),
            Err(err) => Err(err)
        }
    }

    /// Attempts to create a new SSL stream from a given `Ssl` instance.
    pub fn new_from(ssl: Ssl, stream: S) -> Result<SslStream<S>, SslError> {
        let mut ssl = SslStream::new_base(ssl, stream);
        match ssl.in_retry_wrapper(|ssl| { ssl.connect() }) {
            Ok(_) => Ok(ssl),
            Err(err) => Err(err)
        }
    }

    /// Creates a new SSL stream
    pub fn new(ctx: &SslContext, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = match Ssl::new(ctx) {
            Ok(ssl) => ssl,
            Err(err) => return Err(err)
        };

        SslStream::new_from(ssl, stream)
    }

    /// Creates a new SSL server stream
    pub fn new_server(ctx: &SslContext, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = match Ssl::new(ctx) {
            Ok(ssl) => ssl,
            Err(err) => return Err(err)
        };

        SslStream::new_server_from(ssl, stream)
    }

    fn in_retry_wrapper(&mut self, blk: |&Ssl| -> c_int)
            -> Result<c_int, SslError> {
        loop {
            let ret = blk(&self.ssl);
            if ret > 0 {
                return Ok(ret);
            }

            match self.ssl.get_error(ret) {
                ErrorWantRead => {
                    try_ssl!(self.flush());
                    let len = try_ssl!(self.stream.read(self.buf.as_mut_slice()));
                    self.ssl.get_rbio().write(self.buf.slice_to(len));
                }
                ErrorWantWrite => { try_ssl!(self.flush()) }
                ErrorZeroReturn => return Err(SslSessionClosed),
                ErrorSsl => return Err(SslError::get()),
                _ => unreachable!()
            }
        }
    }

    fn write_through(&mut self) -> IoResult<()> {
        loop {
            match self.ssl.get_wbio().read(self.buf.as_mut_slice()) {
                Some(len) => try!(self.stream.write(self.buf.slice_to(len))),
                None => break
            };
        }
        Ok(())
    }

    /// Get the compression currently in use.  The result will be
    /// either None, indicating no compression is in use, or a string
    /// with the compression name.
    pub fn get_compression(&self) -> Option<String> {
        let ptr = unsafe { ffi::SSL_get_current_compression(self.ssl.ssl) };
        if ptr == ptr::null() {
            return None;
        }

        let meth = unsafe { ffi::SSL_COMP_get_name(ptr) };
        let s = unsafe { string::raw::from_buf(meth as *const u8) };

        Some(s)
    }
}

impl<S: Stream> Reader for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        match self.in_retry_wrapper(|ssl| { ssl.read(buf) }) {
            Ok(len) => Ok(len as uint),
            Err(SslSessionClosed) =>
                Err(IoError {
                    kind: EndOfFile,
                    desc: "SSL session closed",
                    detail: None
                }),
            Err(StreamError(e)) => Err(e),
            _ => unreachable!()
        }
    }
}

impl<S: Stream> Writer for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> IoResult<()> {
        let mut start = 0;
        while start < buf.len() {
            let ret = self.in_retry_wrapper(|ssl| {
                ssl.write(buf.slice_from(start))
            });
            match ret {
                Ok(len) => start += len as uint,
                _ => unreachable!()
            }
            try!(self.write_through());
        }
        Ok(())
    }

    fn flush(&mut self) -> IoResult<()> {
        try!(self.write_through());
        self.stream.flush()
    }
}

