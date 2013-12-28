#[feature(struct_variant, macro_rules)];
#[crate_id="github.com/sfackler/rust-ssl"];
#[doc(html_root_url="http://sfackler.github.io/rust-ssl/doc/")];

use std::cast;
use std::libc::{c_int, c_void, c_char};
use std::ptr;
use std::task;
use std::sync::atomics::{AtomicBool, INIT_ATOMIC_BOOL, AtomicUint,
                         INIT_ATOMIC_UINT, Acquire, Release, SeqCst};
use std::unstable::mutex::Mutex;
use std::io::{Stream, Reader, Writer, Decorator};
use std::vec;

use self::error::{SslError, SslSessionClosed, StreamEof};

pub mod error;

mod ffi;

static mut STARTED_INIT: AtomicBool = INIT_ATOMIC_BOOL;
static mut FINISHED_INIT: AtomicBool = INIT_ATOMIC_BOOL;

static mut VERIFY_IDX: AtomicUint = INIT_ATOMIC_UINT;

// actually a *~[Mutex]
static mut MUTEXES: AtomicUint = INIT_ATOMIC_UINT;

fn init() {
    unsafe {
        if STARTED_INIT.swap(true, Acquire) {
            while !FINISHED_INIT.load(Release) {
                task::deschedule();
            }
            return;
        }

        ffi::SSL_library_init();
        let verify_idx = ffi::SSL_CTX_get_ex_new_index(0, ptr::null(), None,
                                                       None, None);
        assert!(verify_idx >= 0);
        VERIFY_IDX.store(verify_idx as uint, Release);

        let num_locks = ffi::CRYPTO_num_locks();
        let mutexes = ~vec::from_fn(num_locks as uint, |_| Mutex::new());
        MUTEXES.store(cast::transmute(mutexes), Release);

        ffi::CRYPTO_set_locking_callback(locking_function);

        FINISHED_INIT.store(true, Release);
    }
}

/// Determines the SSL method supported
pub enum SslMethod {
    /// Only support the SSLv3 protocol
    Sslv3,
    /// Only support the TLSv1 protocol
    Tlsv1,
    /// Support the SSLv2, SSLv3 and TLSv1 protocols
    Sslv23
}

impl SslMethod {
    unsafe fn to_raw(&self) -> *ffi::SSL_METHOD {
        match *self {
            Sslv3 => ffi::SSLv3_method(),
            Tlsv1 => ffi::TLSv1_method(),
            Sslv23 => ffi::SSLv23_method()
        }
    }
}

/// Determines the type of certificate verification used
pub enum SslVerifyMode {
    /// Verify that the server's certificate is trusted
    SslVerifyPeer = ffi::SSL_VERIFY_PEER,
    /// Do not verify the server's certificate
    SslVerifyNone = ffi::SSL_VERIFY_NONE
}

extern "C" fn locking_function(mode: c_int, n: c_int, _file: *c_char,
                               _line: c_int) {
    unsafe {
        let mutexes: *mut ~[Mutex] = cast::transmute(MUTEXES.load(Acquire));
        let mutex = &mut (*mutexes)[n as uint];

        if mode & ffi::CRYPTO_LOCK != 0 {
            mutex.lock();
        } else {
            mutex.unlock();
        }
    }
}

extern "C" fn raw_verify(preverify_ok: c_int, x509_ctx: *ffi::X509_STORE_CTX)
        -> c_int {
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);
        let idx = VERIFY_IDX.load(Acquire) as c_int;
        let verify = ffi::SSL_CTX_get_ex_data(ssl_ctx, idx);
        let verify: Option<VerifyCallback> = cast::transmute(verify);

        let ctx = X509StoreContext { ctx: x509_ctx };

        match verify {
            None => preverify_ok,
            Some(verify) => verify(preverify_ok != 0, &ctx) as c_int
        }
    }
}

/// The signature of functions that can be used to manually verify certificates
pub type VerifyCallback = extern "Rust" fn(preverify_ok: bool,
                                           x509_ctx: &X509StoreContext) -> bool;

/// An SSL context object
pub struct SslContext {
    priv ctx: *ffi::SSL_CTX
}

impl Drop for SslContext {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(self.ctx) }
    }
}

impl SslContext {
    /// Attempts to create a new SSL context.
    pub fn try_new(method: SslMethod) -> Result<SslContext, SslError> {
        init();

        let ctx = unsafe { ffi::SSL_CTX_new(method.to_raw()) };
        if ctx == ptr::null() {
            return Err(SslError::get());
        }

        Ok(SslContext { ctx: ctx })
    }

    /// A convenience wrapper around `try_new`.
    pub fn new(method: SslMethod) -> SslContext {
        match SslContext::try_new(method) {
            Ok(ctx) => ctx,
            Err(err) => fail!("Error creating SSL context: {:?}", err)
        }
    }

    /// Configures the certificate verification method for new connections.
    pub fn set_verify(&mut self, mode: SslVerifyMode,
                      verify: Option<VerifyCallback>) {
        unsafe {
            let idx = VERIFY_IDX.load(SeqCst) as c_int;
            ffi::SSL_CTX_set_ex_data(self.ctx, idx,
                                     cast::transmute(verify));
            ffi::SSL_CTX_set_verify(self.ctx, mode as c_int, Some(raw_verify));
        }
    }

    /// Specifies the file that contains trusted CA certificates.
    pub fn set_CA_file(&mut self, file: &str) -> Option<SslError> {
        let ret = file.with_c_str(|file| {
            unsafe {
                ffi::SSL_CTX_load_verify_locations(self.ctx, file, ptr::null())
            }
        });

        if ret == 0 {
            Some(SslError::get())
        } else {
            None
        }
    }
}

pub struct X509StoreContext {
    priv ctx: *ffi::X509_STORE_CTX
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

/// A public key certificate
pub struct X509<'ctx> {
    priv ctx: &'ctx X509StoreContext,
    priv x509: *ffi::X509
}

impl<'ctx> X509<'ctx> {
    pub fn subject_name<'a>(&'a self) -> X509Name<'a> {
        let name = unsafe { ffi::X509_get_subject_name(self.x509) };
        X509Name { x509: self, name: name }
    }
}

pub struct X509Name<'x> {
    priv x509: &'x X509<'x>,
    priv name: *ffi::X509_NAME
}

pub enum X509NameFormat {
    Rfc2253 = ffi::XN_FLAG_RFC2253,
    Oneline = ffi::XN_FLAG_ONELINE,
    Multiline = ffi::XN_FLAG_MULTILINE
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

struct Ssl {
    ssl: *ffi::SSL
}

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe { ffi::SSL_free(self.ssl) }
    }
}

impl Ssl {
    fn try_new(ctx: &SslContext) -> Result<Ssl, SslError> {
        let ssl = unsafe { ffi::SSL_new(ctx.ctx) };
        if ssl == ptr::null() {
            return Err(SslError::get());
        }
        let ssl = Ssl { ssl: ssl };

        let rbio = unsafe { ffi::BIO_new(ffi::BIO_s_mem()) };
        if rbio == ptr::null() {
            return Err(SslError::get());
        }

        let wbio = unsafe { ffi::BIO_new(ffi::BIO_s_mem()) };
        if wbio == ptr::null() {
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

    fn wrap_bio<'a>(&'a self, bio: *ffi::BIO) -> MemBioRef<'a> {
        assert!(bio != ptr::null());
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

    fn read(&self, buf: &mut [u8]) -> c_int {
        unsafe { ffi::SSL_read(self.ssl, buf.as_ptr() as *c_void,
                               buf.len() as c_int) }
    }

    fn write(&self, buf: &[u8]) -> c_int {
        unsafe { ffi::SSL_write(self.ssl, buf.as_ptr() as *c_void,
                                buf.len() as c_int) }
    }

    fn get_error(&self, ret: c_int) -> LibSslError {
        let err = unsafe { ffi::SSL_get_error(self.ssl, ret) };
        match FromPrimitive::from_int(err as int) {
            Some(err) => err,
            None => unreachable!()
        }
    }
}

#[deriving(FromPrimitive)]
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
    bio: *ffi::BIO,
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
            ffi::BIO_read(self.bio, buf.as_ptr() as *c_void,
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
            ffi::BIO_write(self.bio, buf.as_ptr() as *c_void,
                           buf.len() as c_int)
        };
        assert_eq!(buf.len(), ret as uint);
    }
}

/// A stream wrapper which handles SSL encryption for an underlying stream.
pub struct SslStream<S> {
    priv stream: S,
    priv ssl: Ssl,
    priv buf: ~[u8]
}

impl<S: Stream> SslStream<S> {
    /// Attempts to create a new SSL stream
    pub fn try_new(ctx: &SslContext, stream: S) -> Result<SslStream<S>,
                                                          SslError> {
        let ssl = match Ssl::try_new(ctx) {
            Ok(ssl) => ssl,
            Err(err) => return Err(err)
        };

        let mut ssl = SslStream {
            stream: stream,
            ssl: ssl,
            // Maximum TLS record size is 16k
            buf: vec::from_elem(16 * 1024, 0u8)
        };

        match ssl.in_retry_wrapper(|ssl| { ssl.connect() }) {
            Ok(_) => Ok(ssl),
            Err(err) => Err(err)
        }
    }

    /// A convenience wrapper around `try_new`.
    pub fn new(ctx: &SslContext, stream: S) -> SslStream<S> {
        match SslStream::try_new(ctx, stream) {
            Ok(stream) => stream,
            Err(err) => fail!("Error creating SSL stream: {:?}", err)
        }
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
                    self.flush();
                    match self.stream.read(self.buf) {
                        Some(len) =>
                            self.ssl.get_rbio().write(self.buf.slice_to(len)),
                        None => return Err(StreamEof)
                    }
                }
                ErrorWantWrite => self.flush(),
                ErrorZeroReturn => return Err(SslSessionClosed),
                ErrorSsl => return Err(SslError::get()),
                _ => unreachable!()
            }
        }
    }

    fn write_through(&mut self) {
        loop {
            match self.ssl.get_wbio().read(self.buf) {
                Some(len) => self.stream.write(self.buf.slice_to(len)),
                None => break
            }
        }
    }
}

impl<S: Stream> Reader for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> Option<uint> {
        match self.in_retry_wrapper(|ssl| { ssl.read(buf) }) {
            Ok(len) => Some(len as uint),
            Err(StreamEof) | Err(SslSessionClosed) => None,
            _ => unreachable!()
        }
    }

    fn eof(&mut self) -> bool {
        self.stream.eof()
    }
}

impl<S: Stream> Writer for SslStream<S> {
    fn write(&mut self, buf: &[u8]) {
        let mut start = 0;
        while start < buf.len() {
            let ret = self.in_retry_wrapper(|ssl| {
                ssl.write(buf.slice_from(start))
            });
            match ret {
                Ok(len) => start += len as uint,
                _ => unreachable!()
            }
            self.write_through();
        }
    }

    fn flush(&mut self) {
        self.write_through();
        self.stream.flush()
    }
}

impl<S> Decorator<S> for SslStream<S> {
    fn inner(self) -> S {
        self.stream
    }

    fn inner_ref<'a>(&'a self) -> &'a S {
        &self.stream
    }

    fn inner_mut_ref<'a>(&'a mut self) -> &'a mut S {
        &mut self.stream
    }
}
