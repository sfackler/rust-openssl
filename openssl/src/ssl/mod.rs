use libc::{c_int, c_void, c_long};
use std::any::TypeId;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::mem;
use std::str;
use std::net;
use std::path::Path;
use std::ptr;
use std::sync::{Once, ONCE_INIT, Arc, Mutex};
use std::ops::{Deref, DerefMut};
use std::cmp;
use std::any::Any;
#[cfg(any(feature = "npn", feature = "alpn"))]
use libc::{c_uchar, c_uint};
#[cfg(any(feature = "npn", feature = "alpn"))]
use std::slice;

use bio::{MemBio};
use ffi;
use ffi_extras;
use dh::DH;
use ssl::error::{NonblockingSslError, SslError, SslSessionClosed, StreamError, OpenSslErrors};
use x509::{X509StoreContext, X509FileType, X509};
use crypto::pkey::PKey;

pub mod error;
#[cfg(test)]
mod tests;

static mut VERIFY_IDX: c_int = -1;

/// Manually initialize SSL.
/// It is optional to call this function and safe to do so more than once.
pub fn init() {
    static mut INIT: Once = ONCE_INIT;

    unsafe {
        INIT.call_once(|| {
            ffi::init();

            let verify_idx = ffi::SSL_CTX_get_ex_new_index(0, ptr::null(), None,
                                                           None, None);
            assert!(verify_idx >= 0);
            VERIFY_IDX = verify_idx;
        });
    }
}

bitflags! {
    flags SslContextOptions: u64 {
        const SSL_OP_MICROSOFT_SESS_ID_BUG                    = ffi_extras::SSL_OP_MICROSOFT_SESS_ID_BUG,
        const SSL_OP_NETSCAPE_CHALLENGE_BUG                   = ffi_extras::SSL_OP_NETSCAPE_CHALLENGE_BUG,
        const SSL_OP_LEGACY_SERVER_CONNECT                    = ffi_extras::SSL_OP_LEGACY_SERVER_CONNECT,
        const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG         = ffi_extras::SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG,
        const SSL_OP_TLSEXT_PADDING                           = ffi_extras::SSL_OP_TLSEXT_PADDING,
        const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER               = ffi_extras::SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER,
        const SSL_OP_SAFARI_ECDHE_ECDSA_BUG                   = ffi_extras::SSL_OP_SAFARI_ECDHE_ECDSA_BUG,
        const SSL_OP_SSLEAY_080_CLIENT_DH_BUG                 = ffi_extras::SSL_OP_SSLEAY_080_CLIENT_DH_BUG,
        const SSL_OP_TLS_D5_BUG                               = ffi_extras::SSL_OP_TLS_D5_BUG,
        const SSL_OP_TLS_BLOCK_PADDING_BUG                    = ffi_extras::SSL_OP_TLS_BLOCK_PADDING_BUG,
        const SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS              = ffi_extras::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS,
        const SSL_OP_NO_QUERY_MTU                             = ffi_extras::SSL_OP_NO_QUERY_MTU,
        const SSL_OP_COOKIE_EXCHANGE                          = ffi_extras::SSL_OP_COOKIE_EXCHANGE,
        const SSL_OP_NO_TICKET                                = ffi_extras::SSL_OP_NO_TICKET,
        const SSL_OP_CISCO_ANYCONNECT                         = ffi_extras::SSL_OP_CISCO_ANYCONNECT,
        const SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   = ffi_extras::SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
        const SSL_OP_NO_COMPRESSION                           = ffi_extras::SSL_OP_NO_COMPRESSION,
        const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION        = ffi_extras::SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
        const SSL_OP_SINGLE_ECDH_USE                          = ffi_extras::SSL_OP_SINGLE_ECDH_USE,
        const SSL_OP_SINGLE_DH_USE                            = ffi_extras::SSL_OP_SINGLE_DH_USE,
        const SSL_OP_CIPHER_SERVER_PREFERENCE                 = ffi_extras::SSL_OP_CIPHER_SERVER_PREFERENCE,
        const SSL_OP_TLS_ROLLBACK_BUG                         = ffi_extras::SSL_OP_TLS_ROLLBACK_BUG,
        const SSL_OP_NO_SSLV2                                 = ffi_extras::SSL_OP_NO_SSLv2,
        const SSL_OP_NO_SSLV3                                 = ffi_extras::SSL_OP_NO_SSLv3,
        const SSL_OP_NO_DTLSV1                                = ffi_extras::SSL_OP_NO_DTLSv1,
        const SSL_OP_NO_TLSV1                                 = ffi_extras::SSL_OP_NO_TLSv1,
        const SSL_OP_NO_DTLSV1_2                              = ffi_extras::SSL_OP_NO_DTLSv1_2,
        const SSL_OP_NO_TLSV1_2                               = ffi_extras::SSL_OP_NO_TLSv1_2,
        const SSL_OP_NO_TLSV1_1                               = ffi_extras::SSL_OP_NO_TLSv1_1,
        const SSL_OP_NETSCAPE_CA_DN_BUG                       = ffi_extras::SSL_OP_NETSCAPE_CA_DN_BUG,
        const SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG          = ffi_extras::SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG,
        const SSL_OP_CRYPTOPRO_TLSEXT_BUG                     = ffi_extras::SSL_OP_CRYPTOPRO_TLSEXT_BUG,
        const SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG              = ffi_extras::SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG,
        const SSL_OP_MSIE_SSLV2_RSA_PADDING                   = ffi_extras::SSL_OP_MSIE_SSLV2_RSA_PADDING,
        const SSL_OP_PKCS1_CHECK_1                            = ffi_extras::SSL_OP_PKCS1_CHECK_1,
        const SSL_OP_PKCS1_CHECK_2                            = ffi_extras::SSL_OP_PKCS1_CHECK_2,
        const SSL_OP_EPHEMERAL_RSA                            = ffi_extras::SSL_OP_EPHEMERAL_RSA,
        const SSL_OP_ALL         = SSL_OP_MICROSOFT_SESS_ID_BUG.bits|SSL_OP_NETSCAPE_CHALLENGE_BUG.bits
                                  |SSL_OP_LEGACY_SERVER_CONNECT.bits|SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG.bits
                                  |SSL_OP_TLSEXT_PADDING.bits|SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER.bits
                                  |SSL_OP_SAFARI_ECDHE_ECDSA_BUG.bits|SSL_OP_SSLEAY_080_CLIENT_DH_BUG.bits
                                  |SSL_OP_TLS_D5_BUG.bits|SSL_OP_TLS_BLOCK_PADDING_BUG.bits
                                  |SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS.bits|SSL_OP_CRYPTOPRO_TLSEXT_BUG.bits,
        const SSL_OP_NO_SSL_MASK = SSL_OP_NO_SSLV2.bits|SSL_OP_NO_SSLV3.bits|SSL_OP_NO_TLSV1.bits
                                  |SSL_OP_NO_TLSV1_1.bits|SSL_OP_NO_TLSV1_2.bits,
    }
}

/// Determines the SSL method supported
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum SslMethod {
    #[cfg(feature = "sslv2")]
    /// Only support the SSLv2 protocol, requires the `sslv2` feature.
    Sslv2,
    /// Support the SSLv2, SSLv3, TLSv1, TLSv1.1, and TLSv1.2 protocols depending on what the
    /// linked OpenSSL library supports.
    Sslv23,
    #[cfg(feature = "sslv3")]
    /// Only support the SSLv3 protocol.
    Sslv3,
    /// Only support the TLSv1 protocol.
    Tlsv1,
    #[cfg(feature = "tlsv1_1")]
    /// Support TLSv1.1 protocol, requires the `tlsv1_1` feature.
    Tlsv1_1,
    #[cfg(feature = "tlsv1_2")]
    /// Support TLSv1.2 protocol, requires the `tlsv1_2` feature.
    Tlsv1_2,
    #[cfg(feature = "dtlsv1")]
    /// Support DTLSv1 protocol, requires the `dtlsv1` feature.
    Dtlsv1,
    #[cfg(feature = "dtlsv1_2")]
    /// Support DTLSv1.2 protocol, requires the `dtlsv1_2` feature.
    Dtlsv1_2,
}

impl SslMethod {
    unsafe fn to_raw(&self) -> *const ffi::SSL_METHOD {
        match *self {
            #[cfg(feature = "sslv2")]
            SslMethod::Sslv2 => ffi::SSLv2_method(),
            #[cfg(feature = "sslv3")]
            SslMethod::Sslv3 => ffi::SSLv3_method(),
            SslMethod::Tlsv1 => ffi::TLSv1_method(),
            SslMethod::Sslv23 => ffi::SSLv23_method(),
            #[cfg(feature = "tlsv1_1")]
            SslMethod::Tlsv1_1 => ffi::TLSv1_1_method(),
            #[cfg(feature = "tlsv1_2")]
            SslMethod::Tlsv1_2 => ffi::TLSv1_2_method(),
            #[cfg(feature = "dtlsv1")]
            SslMethod::Dtlsv1 => ffi::DTLSv1_method(),
            #[cfg(feature = "dtlsv1_2")]
            SslMethod::Dtlsv1_2 => ffi::DTLSv1_2_method(),
        }
    }

    unsafe fn from_raw(method: *const ffi::SSL_METHOD) -> Option<SslMethod> {
        match method {
            #[cfg(feature = "sslv2")]
            x if x == ffi::SSLv2_method() => Some(SslMethod::Sslv2),
            #[cfg(feature = "sslv3")]
            x if x == ffi::SSLv3_method() => Some(SslMethod::Sslv3),
            x if x == ffi::TLSv1_method() => Some(SslMethod::Tlsv1),
            x if x == ffi::SSLv23_method() => Some(SslMethod::Sslv23),
            #[cfg(feature = "tlsv1_1")]
            x if x == ffi::TLSv1_1_method() => Some(SslMethod::Tlsv1_1),
            #[cfg(feature = "tlsv1_2")]
            x if x == ffi::TLSv1_2_method() => Some(SslMethod::Tlsv1_2),
            #[cfg(feature = "dtlsv1")]
            x if x == ffi::DTLSv1_method() => Some(SslMethod::Dtlsv1),
            #[cfg(feature = "dtlsv1_2")]
            x if x == ffi::DTLSv1_2_method() => Some(SslMethod::Dtlsv1_2),
            _ => None,
        }
    }

    #[cfg(feature = "dtlsv1")]
    pub fn is_dtlsv1(&self) -> bool {
        *self == SslMethod::Dtlsv1
    }

    #[cfg(feature = "dtlsv1_2")]
    pub fn is_dtlsv1_2(&self) -> bool {
        *self == SslMethod::Dtlsv1_2
    }

    pub fn is_dtls(&self) -> bool {
        self.is_dtlsv1() || self.is_dtlsv1_2()
    }

    #[cfg(not(feature = "dtlsv1"))]
    pub fn is_dtlsv1(&self) -> bool {
        false
    }

    #[cfg(not(feature = "dtlsv1_2"))]
    pub fn is_dtlsv1_2(&self) -> bool {
        false
    }
}

/// Determines the type of certificate verification used
bitflags! {
    flags SslVerifyMode: i32 {
        /// Verify that the server's certificate is trusted
        const SSL_VERIFY_PEER = ffi::SSL_VERIFY_PEER,
        /// Do not verify the server's certificate
        const SSL_VERIFY_NONE = ffi::SSL_VERIFY_NONE,
        /// Terminate handshake if client did not return a certificate.
        /// Use together with SSL_VERIFY_PEER.
        const SSL_VERIFY_FAIL_IF_NO_PEER_CERT = ffi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
    }
}

lazy_static! {
    static ref INDEXES: Mutex<HashMap<TypeId, c_int>> = Mutex::new(HashMap::new());
}

// Creates a static index for user data of type T
// Registers a destructor for the data which will be called
// when context is freed
fn get_verify_data_idx<T: Any + 'static>() -> c_int {
    *INDEXES.lock().unwrap().entry(TypeId::of::<T>()).or_insert_with(|| {
        get_new_idx::<T>()
    })
}

#[cfg(feature = "npn")]
lazy_static! {
    static ref NPN_PROTOS_IDX: c_int = get_new_idx::<Vec<u8>>();
}
#[cfg(feature = "alpn")]
lazy_static! {
    static ref ALPN_PROTOS_IDX: c_int = get_new_idx::<Vec<u8>>();
}

/// Determine a new index to use for SSL CTX ex data.
/// Registers a destruct for the data which will be called by openssl when the context is freed.
fn get_new_idx<T>() -> c_int {
    extern fn free_data_box<T>(_parent: *mut c_void, ptr: *mut c_void,
                            _ad: *mut ffi::CRYPTO_EX_DATA, _idx: c_int,
                            _argl: c_long, _argp: *mut c_void) {
        if !ptr.is_null() {
            let _: Box<T> = unsafe { mem::transmute(ptr) };
        }
    }

    unsafe {
        let f: ffi::CRYPTO_EX_free = free_data_box::<T>;
        let idx = ffi::SSL_CTX_get_ex_new_index(0, ptr::null(), None,
                                                None, Some(f));
        assert!(idx >= 0);
        idx
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

        let ctx = X509StoreContext::new(x509_ctx);

        match verify {
            None => preverify_ok,
            Some(verify) => verify(preverify_ok != 0, &ctx) as c_int
        }
    }
}

extern fn raw_verify_with_data<T>(preverify_ok: c_int,
                                  x509_ctx: *mut ffi::X509_STORE_CTX) -> c_int
                                  where T: Any + 'static {
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);

        let verify = ffi::SSL_CTX_get_ex_data(ssl_ctx, VERIFY_IDX);
        let verify: Option<VerifyCallbackData<T>> = mem::transmute(verify);

        let data = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_verify_data_idx::<T>());
        let data: Box<T> = mem::transmute(data);

        let ctx = X509StoreContext::new(x509_ctx);

        let res = match verify {
            None => preverify_ok,
            Some(verify) => verify(preverify_ok != 0, &ctx, &*data) as c_int
        };

        // Since data might be required on the next verification
        // it is time to forget about it and avoid dropping
        // data will be freed once OpenSSL considers it is time
        // to free all context data
        mem::forget(data);
        res
    }
}

#[cfg(any(feature = "npn", feature = "alpn"))]
unsafe fn select_proto_using(ssl: *mut ffi::SSL,
                      out: *mut *mut c_uchar, outlen: *mut c_uchar,
                      inbuf: *const c_uchar, inlen: c_uint,
                      ex_data: c_int) -> c_int {

        // First, get the list of protocols (that the client should support) saved in the context
        // extra data.
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);
        let protocols = ffi::SSL_CTX_get_ex_data(ssl_ctx, ex_data);
        let protocols: &Vec<u8> = mem::transmute(protocols);
        // Prepare the client list parameters to be passed to the OpenSSL function...
        let client = protocols.as_ptr();
        let client_len = protocols.len() as c_uint;
        // Finally, let OpenSSL find a protocol to be used, by matching the given server and
        // client lists.
        if ffi::SSL_select_next_proto(out, outlen, inbuf, inlen, client, client_len) != ffi::OPENSSL_NPN_NEGOTIATED {
            ffi::SSL_TLSEXT_ERR_NOACK
        } else {
            ffi::SSL_TLSEXT_ERR_OK
        }
}

/// The function is given as the callback to `SSL_CTX_set_next_proto_select_cb`.
///
/// It chooses the protocol that the client wishes to use, out of the given list of protocols
/// supported by the server. It achieves this by delegating to the `SSL_select_next_proto`
/// function. The list of protocols supported by the client is found in the extra data of the
/// OpenSSL context.
#[cfg(feature = "npn")]
extern fn raw_next_proto_select_cb(ssl: *mut ffi::SSL,
                                   out: *mut *mut c_uchar, outlen: *mut c_uchar,
                                   inbuf: *const c_uchar, inlen: c_uint,
                                   _arg: *mut c_void) -> c_int {
    unsafe {
        select_proto_using(ssl, out, outlen, inbuf, inlen, *NPN_PROTOS_IDX)
    }
}

#[cfg(feature = "alpn")]
extern fn raw_alpn_select_cb(ssl: *mut ffi::SSL,
                                   out: *mut *mut c_uchar, outlen: *mut c_uchar,
                                   inbuf: *const c_uchar, inlen: c_uint,
                                   _arg: *mut c_void) -> c_int {
    unsafe {
        select_proto_using(ssl, out, outlen, inbuf, inlen, *ALPN_PROTOS_IDX)
    }
}

/// The function is given as the callback to `SSL_CTX_set_next_protos_advertised_cb`.
///
/// It causes the parameter `out` to point at a `*const c_uchar` instance that
/// represents the list of protocols that the server should advertise as those
/// that it supports.
/// The list of supported protocols is found in the extra data of the OpenSSL
/// context.
#[cfg(feature = "npn")]
extern fn raw_next_protos_advertise_cb(ssl: *mut ffi::SSL,
                                       out: *mut *const c_uchar, outlen: *mut c_uint,
                                       _arg: *mut c_void) -> c_int {
    unsafe {
        // First, get the list of (supported) protocols saved in the context extra data.
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);
        let protocols = ffi::SSL_CTX_get_ex_data(ssl_ctx, *NPN_PROTOS_IDX);
        if protocols.is_null() {
            *out = b"".as_ptr();
            *outlen = 0;
        } else {
            // If the pointer is valid, put the pointer to the actual byte array into the
            // output parameter `out`, as well as its length into `outlen`.
            let protocols: &Vec<u8> = mem::transmute(protocols);
            *out = protocols.as_ptr();
            *outlen = protocols.len() as c_uint;
        }
    }

    ffi::SSL_TLSEXT_ERR_OK
}

/// Convert a set of byte slices into a series of byte strings encoded for SSL. Encoding is a byte
/// containing the length followed by the string.
#[cfg(any(feature = "npn", feature = "alpn"))]
fn ssl_encode_byte_strings(strings: &[&[u8]]) -> Vec<u8>
{
    let mut enc = Vec::new();
    for string in strings {
        let len = string.len() as u8;
        if len as usize != string.len() {
            // If the item does not fit, discard it
            continue;
        }
        enc.push(len);
        enc.extend(string[..len as usize].to_vec());
    }
    enc
}

/// The signature of functions that can be used to manually verify certificates
pub type VerifyCallback = fn(preverify_ok: bool,
                             x509_ctx: &X509StoreContext) -> bool;

/// The signature of functions that can be used to manually verify certificates
/// when user-data should be carried for all verification process
pub type VerifyCallbackData<T> = fn(preverify_ok: bool,
                                    x509_ctx: &X509StoreContext,
                                    data: &T) -> bool;

// FIXME: macro may be instead of inlining?
#[inline]
fn wrap_ssl_result(res: c_int) -> Result<(),SslError> {
    if res == 0 {
        Err(SslError::get())
    } else {
        Ok(())
    }
}

/// An SSL context object
pub struct SslContext {
    ctx: *mut ffi::SSL_CTX
}

unsafe impl Send for SslContext {}
unsafe impl Sync for SslContext {}

// TODO: add useful info here
impl fmt::Debug for SslContext {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SslContext")
    }
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

        let ctx = try_ssl_null!(unsafe { ffi::SSL_CTX_new(method.to_raw()) });

        let ctx = SslContext { ctx: ctx };

        if method.is_dtls() {
            ctx.set_read_ahead(1);
        }

        Ok(ctx)
    }

    /// Configures the certificate verification method for new connections.
    pub fn set_verify(&mut self, mode: SslVerifyMode,
                      verify: Option<VerifyCallback>) {
        unsafe {
            ffi::SSL_CTX_set_ex_data(self.ctx, VERIFY_IDX,
                                     mem::transmute(verify));
            let f: extern fn(c_int, *mut ffi::X509_STORE_CTX) -> c_int =
                                raw_verify;

            ffi::SSL_CTX_set_verify(self.ctx, mode.bits as c_int, Some(f));
        }
    }

    /// Configures the certificate verification method for new connections also
    /// carrying supplied data.
    // Note: no option because there is no point to set data without providing
    // a function handling it
    pub fn set_verify_with_data<T>(&mut self, mode: SslVerifyMode,
                                   verify: VerifyCallbackData<T>,
                                   data: T)
                                   where T: Any + 'static {
        let data = Box::new(data);
        unsafe {
            ffi::SSL_CTX_set_ex_data(self.ctx, VERIFY_IDX,
                                     mem::transmute(Some(verify)));
            ffi::SSL_CTX_set_ex_data(self.ctx, get_verify_data_idx::<T>(),
                                     mem::transmute(data));
            let f: extern fn(c_int, *mut ffi::X509_STORE_CTX) -> c_int =
                                raw_verify_with_data::<T>;

            ffi::SSL_CTX_set_verify(self.ctx, mode.bits as c_int, Some(f));
        }
    }

    /// Sets verification depth
    pub fn set_verify_depth(&mut self, depth: u32) {
        unsafe {
            ffi::SSL_CTX_set_verify_depth(self.ctx, depth as c_int);
        }
    }

    pub fn set_read_ahead(&self, m: u32) {
        unsafe {
            ffi_extras::SSL_CTX_set_read_ahead(self.ctx, m as c_long);
        }
    }

    pub fn set_tmp_dh(&self, dh: DH) -> Result<(),SslError> {
        wrap_ssl_result(unsafe {
            ffi_extras::SSL_CTX_set_tmp_dh(self.ctx, dh.raw()) as i32
        })
    }

    #[allow(non_snake_case)]
    /// Specifies the file that contains trusted CA certificates.
    pub fn set_CA_file<P: AsRef<Path>>(&mut self, file: P) -> Result<(),SslError> {
        let file = CString::new(file.as_ref().as_os_str().to_str().expect("invalid utf8")).unwrap();
        wrap_ssl_result(
            unsafe {
                ffi::SSL_CTX_load_verify_locations(self.ctx, file.as_ptr(), ptr::null())
            })
    }

    /// Specifies the file that contains certificate
    pub fn set_certificate_file<P: AsRef<Path>>(&mut self, file: P, file_type: X509FileType)
                                                -> Result<(),SslError> {
        let file = CString::new(file.as_ref().as_os_str().to_str().expect("invalid utf8")).unwrap();
        wrap_ssl_result(
            unsafe {
                ffi::SSL_CTX_use_certificate_file(self.ctx, file.as_ptr(), file_type as c_int)
            })
    }

    /// Specifies the file that contains certificate chain
    pub fn set_certificate_chain_file<P: AsRef<Path>>(&mut self, file: P, file_type: X509FileType)
                                                -> Result<(),SslError> {
        let file = CString::new(file.as_ref().as_os_str().to_str().expect("invalid utf8")).unwrap();
        wrap_ssl_result(
            unsafe {
                ffi::SSL_CTX_use_certificate_chain_file(self.ctx, file.as_ptr(), file_type as c_int)
            })
    }

    /// Specifies the certificate
    pub fn set_certificate(&mut self, cert: &X509) -> Result<(),SslError> {
        wrap_ssl_result(
            unsafe {
                ffi::SSL_CTX_use_certificate(self.ctx, cert.get_handle())
            })
    }

    /// Adds a certificate to the certificate chain presented together with the
    /// certificate specified using set_certificate()
    pub fn add_extra_chain_cert(&mut self, cert: &X509) -> Result<(),SslError> {
        wrap_ssl_result(
            unsafe {
                ffi_extras::SSL_CTX_add_extra_chain_cert(self.ctx, cert.get_handle()) as c_int
            })
    }

    /// Specifies the file that contains private key
    pub fn set_private_key_file<P: AsRef<Path>>(&mut self, file: P,
                                file_type: X509FileType) -> Result<(),SslError> {
        let file = CString::new(file.as_ref().as_os_str().to_str().expect("invalid utf8")).unwrap();
        wrap_ssl_result(
            unsafe {
                ffi::SSL_CTX_use_PrivateKey_file(self.ctx, file.as_ptr(), file_type as c_int)
            })
    }

    /// Specifies the private key
    pub fn set_private_key(&mut self, key: &PKey) -> Result<(),SslError> {
        wrap_ssl_result(
            unsafe {
                ffi::SSL_CTX_use_PrivateKey(self.ctx, key.get_handle())
            })
    }

    /// Check consistency of private key and certificate
    pub fn check_private_key(&mut self) -> Result<(),SslError> {
        wrap_ssl_result(
            unsafe {
                ffi::SSL_CTX_check_private_key(self.ctx)
            })
    }

    pub fn set_cipher_list(&mut self, cipher_list: &str) -> Result<(),SslError> {
        wrap_ssl_result(
            unsafe {
                let cipher_list = CString::new(cipher_list).unwrap();
                ffi::SSL_CTX_set_cipher_list(self.ctx, cipher_list.as_ptr())
            })
    }

    /// If `onoff` is set to `true`, enable ECDHE for key exchange with compatible
    /// clients, and automatically select an appropriate elliptic curve.
    ///
    /// This method requires OpenSSL >= 1.2.0 or LibreSSL and the `ecdh_auto` feature.
    #[cfg(feature = "ecdh_auto")]
    pub fn set_ecdh_auto(&mut self, onoff: bool) -> Result<(),SslError> {
        wrap_ssl_result(
            unsafe {
                ffi_extras::SSL_CTX_set_ecdh_auto(self.ctx, onoff as c_int)
            })
    }

    pub fn set_options(&mut self, option: SslContextOptions) -> SslContextOptions {
        let raw_bits = option.bits();
        let ret = unsafe {
            ffi_extras::SSL_CTX_set_options(self.ctx, raw_bits)
        };
        SslContextOptions::from_bits(ret).unwrap()
    }

    pub fn get_options(&mut self) -> SslContextOptions {
        let ret = unsafe {
            ffi_extras::SSL_CTX_get_options(self.ctx)
        };
        SslContextOptions::from_bits(ret).unwrap()
    }

    pub fn clear_options(&mut self, option: SslContextOptions) -> SslContextOptions {
        let raw_bits = option.bits();
        let ret = unsafe {
            ffi_extras::SSL_CTX_clear_options(self.ctx, raw_bits)
        };
        SslContextOptions::from_bits(ret).unwrap()
    }

    /// Set the protocols to be used during Next Protocol Negotiation (the protocols
    /// supported by the application).
    ///
    /// This method needs the `npn` feature.
    #[cfg(feature = "npn")]
    pub fn set_npn_protocols(&mut self, protocols: &[&[u8]]) {
        // Firstly, convert the list of protocols to a byte-array that can be passed to OpenSSL
        // APIs -- a list of length-prefixed strings.
        let protocols: Box<Vec<u8>> = Box::new(ssl_encode_byte_strings(protocols));

        unsafe {
            // Attach the protocol list to the OpenSSL context structure,
            // so that we can refer to it within the callback.
            ffi::SSL_CTX_set_ex_data(self.ctx, *NPN_PROTOS_IDX,
                                     mem::transmute(protocols));
            // Now register the callback that performs the default protocol
            // matching based on the client-supported list of protocols that
            // has been saved.
            ffi::SSL_CTX_set_next_proto_select_cb(self.ctx, raw_next_proto_select_cb, ptr::null_mut());
            // Also register the callback to advertise these protocols, if a server socket is
            // created with the context.
            ffi::SSL_CTX_set_next_protos_advertised_cb(self.ctx, raw_next_protos_advertise_cb, ptr::null_mut());
        }
    }

    /// Set the protocols to be used during ALPN (application layer protocol negotiation).
    /// If this is a server, these are the protocols we report to the client.
    /// If this is a client, these are the protocols we try to match with those reported by the
    /// server.
    ///
    /// Note that ordering of the protocols controls the priority with which they are chosen.
    ///
    /// This method needs the `alpn` feature.
    #[cfg(feature = "alpn")]
    pub fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) {
        let protocols: Box<Vec<u8>> = Box::new(ssl_encode_byte_strings(protocols));
        unsafe {
            // Set the context's internal protocol list for use if we are a server
            ffi::SSL_CTX_set_alpn_protos(self.ctx, protocols.as_ptr(), protocols.len() as c_uint);

            // Rather than use the argument to the callback to contain our data, store it in the
            // ssl ctx's ex_data so that we can configure a function to free it later. In the
            // future, it might make sense to pull this into our internal struct Ssl instead of
            // leaning on openssl and using function pointers.
            ffi::SSL_CTX_set_ex_data(self.ctx, *ALPN_PROTOS_IDX,
                                     mem::transmute(protocols));

            // Now register the callback that performs the default protocol
            // matching based on the client-supported list of protocols that
            // has been saved.
            ffi::SSL_CTX_set_alpn_select_cb(self.ctx, raw_alpn_select_cb, ptr::null_mut());
        }
    }
}

#[allow(dead_code)]
struct MemBioRef<'ssl> {
    ssl: &'ssl Ssl,
    bio: MemBio,
}

impl<'ssl> Deref for MemBioRef<'ssl> {
    type Target = MemBio;

    fn deref(&self) -> &MemBio {
        &self.bio
    }
}

impl<'ssl> DerefMut for MemBioRef<'ssl> {
    fn deref_mut(&mut self) -> &mut MemBio {
        &mut self.bio
    }
}

pub struct Ssl {
    ssl: *mut ffi::SSL
}

unsafe impl Send for Ssl {}
unsafe impl Sync for Ssl {}

impl fmt::Debug for Ssl {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Ssl")
            .field("state", &self.state_string_long())
            .finish()
    }
}

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe { ffi::SSL_free(self.ssl) }
    }
}

impl Ssl {
    pub fn new(ctx: &SslContext) -> Result<Ssl, SslError> {
        let ssl = try_ssl_null!(unsafe { ffi::SSL_new(ctx.ctx) });
        let ssl = Ssl { ssl: ssl };
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
            bio: MemBio::borrowed(bio)
        }
    }

    fn connect(&self) -> c_int {
        unsafe { ffi::SSL_connect(self.ssl) }
    }

    fn accept(&self) -> c_int {
        unsafe { ffi::SSL_accept(self.ssl) }
    }

    fn read(&self, buf: &mut [u8]) -> c_int {
        let len = cmp::min(c_int::max_value() as usize, buf.len()) as c_int;
        unsafe { ffi::SSL_read(self.ssl, buf.as_ptr() as *mut c_void, len) }
    }

    fn write(&self, buf: &[u8]) -> c_int {
        let len = cmp::min(c_int::max_value() as usize, buf.len()) as c_int;
        unsafe { ffi::SSL_write(self.ssl, buf.as_ptr() as *const c_void, len) }
    }

    fn get_error(&self, ret: c_int) -> LibSslError {
        let err = unsafe { ffi::SSL_get_error(self.ssl, ret) };
        match LibSslError::from_i32(err as i32) {
            Some(err) => err,
            None => unreachable!()
        }
    }

    pub fn state_string(&self) -> &'static str {
        let state = unsafe {
            let ptr = ffi::SSL_state_string(self.ssl);
            CStr::from_ptr(ptr)
        };

        str::from_utf8(state.to_bytes()).unwrap()
    }

    pub fn state_string_long(&self) -> &'static str {
        let state = unsafe {
            let ptr = ffi::SSL_state_string_long(self.ssl);
            CStr::from_ptr(ptr)
        };

        str::from_utf8(state.to_bytes()).unwrap()
    }

    /// Sets the host name to be used with SNI (Server Name Indication).
    pub fn set_hostname(&self, hostname: &str) -> Result<(), SslError> {
        let cstr = CString::new(hostname).unwrap();
        let ret = unsafe { ffi_extras::SSL_set_tlsext_host_name(self.ssl, cstr.as_ptr()) };

        // For this case, 0 indicates failure.
        if ret == 0 {
            Err(SslError::get())
        } else {
            Ok(())
        }
    }

    /// Returns the certificate of the peer, if present.
    pub fn peer_certificate(&self) -> Option<X509> {
        unsafe {
            let ptr = ffi::SSL_get_peer_certificate(self.ssl);
            if ptr.is_null() {
                None
            } else {
                Some(X509::new(ptr, true))
            }
        }
    }

    /// Returns the protocol selected by performing Next Protocol Negotiation, if any.
    ///
    /// The protocol's name is returned is an opaque sequence of bytes. It is up to the client
    /// to interpret it.
    ///
    /// This method needs the `npn` feature.
    #[cfg(feature = "npn")]
    pub fn selected_npn_protocol(&self) -> Option<&[u8]> {
        unsafe {
            let mut data: *const c_uchar = ptr::null();
            let mut len: c_uint = 0;
            // Get the negotiated protocol from the SSL instance.
            // `data` will point at a `c_uchar` array; `len` will contain the length of this array.
            ffi::SSL_get0_next_proto_negotiated(self.ssl, &mut data, &mut len);

            if data.is_null() {
                None
            } else {
                Some(slice::from_raw_parts(data, len as usize))
            }
        }
    }

    /// Returns the protocol selected by performing ALPN, if any.
    ///
    /// The protocol's name is returned is an opaque sequence of bytes. It is up to the client
    /// to interpret it.
    ///
    /// This method needs the `alpn` feature.
    #[cfg(feature = "alpn")]
    pub fn selected_alpn_protocol(&self) -> Option<&[u8]> {
        unsafe {
            let mut data: *const c_uchar = ptr::null();
            let mut len: c_uint = 0;
            // Get the negotiated protocol from the SSL instance.
            // `data` will point at a `c_uchar` array; `len` will contain the length of this array.
            ffi::SSL_get0_alpn_selected(self.ssl, &mut data, &mut len);

            if data.is_null() {
                None
            } else {
                Some(slice::from_raw_parts(data, len as usize))
            }
        }
    }

    /// Returns the number of bytes remaining in the currently processed TLS
    /// record.
    pub fn pending(&self) -> usize {
        unsafe {
            ffi::SSL_pending(self.ssl) as usize
        }
    }

    /// Returns the compression currently in use.
    ///
    /// The result will be either None, indicating no compression is in use, or
    /// a string with the compression name.
    pub fn compression(&self) -> Option<String> {
        let ptr = unsafe { ffi::SSL_get_current_compression(self.ssl) };
        if ptr == ptr::null() {
            return None;
        }

        let meth = unsafe { ffi::SSL_COMP_get_name(ptr) };
        let s = unsafe {
            String::from_utf8(CStr::from_ptr(meth).to_bytes().to_vec()).unwrap()
        };

        Some(s)
    }

    pub fn get_ssl_method(&self) -> Option<SslMethod> {
        unsafe {
            let method = ffi::SSL_get_ssl_method(self.ssl);
            SslMethod::from_raw(method)
        }
    }
}

macro_rules! make_LibSslError {
    ($($variant:ident = $value:ident),+) => {
        #[derive(Debug)]
        #[repr(i32)]
        enum LibSslError {
            $($variant = ffi::$value),+
        }

        impl LibSslError {
            fn from_i32(val: i32) -> Option<LibSslError> {
                match val {
                    $(ffi::$value => Some(LibSslError::$variant),)+
                    _ => None
                }
            }
        }
    }
}

make_LibSslError! {
    ErrorNone = SSL_ERROR_NONE,
    ErrorSsl = SSL_ERROR_SSL,
    ErrorWantRead = SSL_ERROR_WANT_READ,
    ErrorWantWrite = SSL_ERROR_WANT_WRITE,
    ErrorWantX509Lookup = SSL_ERROR_WANT_X509_LOOKUP,
    ErrorSyscall = SSL_ERROR_SYSCALL,
    ErrorZeroReturn = SSL_ERROR_ZERO_RETURN,
    ErrorWantConnect = SSL_ERROR_WANT_CONNECT,
    ErrorWantAccept = SSL_ERROR_WANT_ACCEPT
}

struct IndirectStream<S> {
    stream: S,
    ssl: Arc<Ssl>,
    // Max TLS record size is 16k
    buf: Box<[u8; 16 * 1024]>,
}

impl<S: Clone> Clone for IndirectStream<S> {
    fn clone(&self) -> IndirectStream<S> {
        IndirectStream {
            stream: self.stream.clone(),
            ssl: self.ssl.clone(),
            buf: Box::new(*self.buf)
        }
    }
}

impl IndirectStream<net::TcpStream> {
    fn try_clone(&self) -> io::Result<IndirectStream<net::TcpStream>> {
        Ok(IndirectStream {
            stream: try!(self.stream.try_clone()),
            ssl: self.ssl.clone(),
            buf: Box::new(*self.buf)
        })
    }
}

impl<S: Read+Write> IndirectStream<S> {
    fn new_base<T: IntoSsl>(ssl: T, stream: S) -> Result<IndirectStream<S>, SslError> {
        let ssl = try!(ssl.into_ssl());

        let rbio = try!(MemBio::new());
        let wbio = try!(MemBio::new());

        unsafe { ffi::SSL_set_bio(ssl.ssl, rbio.unwrap(), wbio.unwrap()) }

        Ok(IndirectStream {
            stream: stream,
            ssl: Arc::new(ssl),
            buf: Box::new([0; 16 * 1024]),
        })
    }

    fn connect<T: IntoSsl>(ssl: T, stream: S) -> Result<IndirectStream<S>, SslError> {
        let mut ssl = try!(IndirectStream::new_base(ssl, stream));
        try!(ssl.in_retry_wrapper(|ssl| ssl.connect()));
        Ok(ssl)
    }

    fn accept<T: IntoSsl>(ssl: T, stream: S) -> Result<IndirectStream<S>, SslError> {
        let mut ssl = try!(IndirectStream::new_base(ssl, stream));
        try!(ssl.in_retry_wrapper(|ssl| ssl.accept()));
        Ok(ssl)
    }

    fn in_retry_wrapper<F>(&mut self, mut blk: F) -> Result<c_int, SslError>
            where F: FnMut(&Ssl) -> c_int {
        loop {
            let ret = blk(&self.ssl);
            if ret > 0 {
                return Ok(ret);
            }

            let e = self.ssl.get_error(ret);
            match e {
                LibSslError::ErrorWantRead => {
                    try_ssl_stream!(self.flush());
                    let len = try_ssl_stream!(self.stream.read(&mut self.buf[..]));


                    if len == 0 {
                        let method = self.ssl.get_ssl_method();

                        if method.map(|m| m.is_dtls()).unwrap_or(false) {
                            return Ok(0);
                        } else {
                            self.ssl.get_rbio().set_eof(true);
                        }
                    } else {
                        try_ssl_stream!(self.ssl.get_rbio().write_all(&self.buf[..len]));
                    }
                }
                LibSslError::ErrorWantWrite => { try_ssl_stream!(self.flush()) }
                LibSslError::ErrorZeroReturn => return Err(SslSessionClosed),
                LibSslError::ErrorSsl => return Err(SslError::get()),
                LibSslError::ErrorSyscall if ret == 0 => return Ok(0),
                err => panic!("unexpected error {:?} with ret {}", err, ret),
            }
        }
    }

    fn write_through(&mut self) -> io::Result<()> {
        io::copy(&mut *self.ssl.get_wbio(), &mut self.stream).map(|_| ())
    }
}

impl<S: Read+Write> Read for IndirectStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.in_retry_wrapper(|ssl| { ssl.read(buf) }) {
            Ok(len) => Ok(len as usize),
            Err(SslSessionClosed) => Ok(0),
            Err(StreamError(e)) => Err(e),
            Err(e @ OpenSslErrors(_)) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }
}

impl<S: Read+Write> Write for IndirectStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let count = match self.in_retry_wrapper(|ssl| ssl.write(buf)) {
            Ok(len) => len as usize,
            Err(SslSessionClosed) => 0,
            Err(StreamError(e)) => return Err(e),
            Err(e @ OpenSslErrors(_)) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        };
        try!(self.write_through());
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        try!(self.write_through());
        self.stream.flush()
    }
}

#[derive(Clone)]
struct DirectStream<S> {
    stream: S,
    ssl: Arc<Ssl>,
}

impl DirectStream<net::TcpStream> {
    fn try_clone(&self) -> io::Result<DirectStream<net::TcpStream>> {
        Ok(DirectStream {
            stream: try!(self.stream.try_clone()),
            ssl: self.ssl.clone(),
        })
    }
}

impl<S> DirectStream<S> {
    fn new_base(ssl: Ssl, stream: S, sock: c_int) -> Result<DirectStream<S>, SslError> {
        unsafe {
            let bio = try_ssl_null!(ffi::BIO_new_socket(sock, 0));
            ffi::SSL_set_bio(ssl.ssl, bio, bio);
        }

        Ok(DirectStream {
            stream: stream,
            ssl: Arc::new(ssl),
        })
    }

    fn connect(ssl: Ssl, stream: S, sock: c_int) -> Result<DirectStream<S>, SslError> {
        let ssl = try!(DirectStream::new_base(ssl, stream, sock));
        let ret = ssl.ssl.connect();
        if ret > 0 {
            Ok(ssl)
        } else {
            Err(ssl.make_error(ret))
        }
    }

    fn accept(ssl: Ssl, stream: S, sock: c_int) -> Result<DirectStream<S>, SslError> {
        let ssl = try!(DirectStream::new_base(ssl, stream, sock));
        let ret = ssl.ssl.accept();
        if ret > 0 {
            Ok(ssl)
        } else {
            Err(ssl.make_error(ret))
        }
    }

    fn make_error(&self, ret: c_int) -> SslError {
        match self.ssl.get_error(ret) {
            LibSslError::ErrorSsl => SslError::get(),
            LibSslError::ErrorSyscall => {
                let err = SslError::get();
                let count = match err {
                    SslError::OpenSslErrors(ref v) => v.len(),
                    _ => unreachable!(),
                };
                if count == 0 {
                    if ret == 0 {
                        SslError::StreamError(io::Error::new(io::ErrorKind::ConnectionAborted,
                                                             "unexpected EOF observed"))
                    } else {
                        SslError::StreamError(io::Error::last_os_error())
                    }
                } else {
                    err
                }
            }
            LibSslError::ErrorWantWrite | LibSslError::ErrorWantRead => {
                SslError::StreamError(io::Error::last_os_error())
            }
            err => panic!("unexpected error {:?} with ret {}", err, ret),
        }
    }
}

impl<S> Read for DirectStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = self.ssl.read(buf);
        if ret >= 0 {
            return Ok(ret as usize);
        }

        match self.make_error(ret) {
            SslError::StreamError(e) => Err(e),
            e => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

impl<S: Write> Write for DirectStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ret = self.ssl.write(buf);
        if ret > 0 {
            return Ok(ret as usize);
        }

        match self.make_error(ret) {
            SslError::StreamError(e) => Err(e),
            e => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[derive(Clone)]
enum StreamKind<S> {
    Indirect(IndirectStream<S>),
    Direct(DirectStream<S>),
}

impl<S> StreamKind<S> {
    fn stream(&self) -> &S {
        match *self {
            StreamKind::Indirect(ref s) => &s.stream,
            StreamKind::Direct(ref s) => &s.stream,
        }
    }

    fn mut_stream(&mut self) -> &mut S {
        match *self {
            StreamKind::Indirect(ref mut s) => &mut s.stream,
            StreamKind::Direct(ref mut s) => &mut s.stream,
        }
    }

    fn ssl(&self) -> &Ssl {
        match *self {
            StreamKind::Indirect(ref s) => &s.ssl,
            StreamKind::Direct(ref s) => &s.ssl,
        }
    }
}

/// A stream wrapper which handles SSL encryption for an underlying stream.
#[derive(Clone)]
pub struct SslStream<S> {
    kind: StreamKind<S>,
}

impl SslStream<net::TcpStream> {
    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> io::Result<SslStream<net::TcpStream>> {
        let kind = match self.kind {
            StreamKind::Indirect(ref s) => StreamKind::Indirect(try!(s.try_clone())),
            StreamKind::Direct(ref s) => StreamKind::Direct(try!(s.try_clone()))
        };
        Ok(SslStream {
            kind: kind
        })
    }
}

impl<S> fmt::Debug for SslStream<S> where S: fmt::Debug {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SslStream")
            .field("stream", &self.kind.stream())
            .field("ssl", &self.kind.ssl())
            .finish()
    }
}

#[cfg(unix)]
impl<S: Read+Write+::std::os::unix::io::AsRawFd> SslStream<S> {
    /// Creates an SSL/TLS client operating over the provided stream.
    ///
    /// Streams passed to this method must implement `AsRawFd` on Unixy
    /// platforms and `AsRawSocket` on Windows. Use `connect_generic` for
    /// streams that do not.
    pub fn connect<T: IntoSsl>(ssl: T, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = try!(ssl.into_ssl());
        let fd = stream.as_raw_fd() as c_int;
        let stream = try!(DirectStream::connect(ssl, stream, fd));
        Ok(SslStream {
            kind: StreamKind::Direct(stream)
        })
    }

    /// Creates an SSL/TLS server operating over the provided stream.
    ///
    /// Streams passed to this method must implement `AsRawFd` on Unixy
    /// platforms and `AsRawSocket` on Windows. Use `accept_generic` for
    /// streams that do not.
    pub fn accept<T: IntoSsl>(ssl: T, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = try!(ssl.into_ssl());
        let fd = stream.as_raw_fd() as c_int;
        let stream = try!(DirectStream::accept(ssl, stream, fd));
        Ok(SslStream {
            kind: StreamKind::Direct(stream)
        })
    }
}

#[cfg(windows)]
impl<S: Read+Write+::std::os::windows::io::AsRawSocket> SslStream<S> {
    /// Creates an SSL/TLS client operating over the provided stream.
    ///
    /// Streams passed to this method must implement `AsRawFd` on Unixy
    /// platforms and `AsRawSocket` on Windows. Use `connect_generic` for
    /// streams that do not.
    pub fn connect<T: IntoSsl>(ssl: T, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = try!(ssl.into_ssl());
        let fd = stream.as_raw_socket() as c_int;
        let stream = try!(DirectStream::connect(ssl, stream, fd));
        Ok(SslStream {
            kind: StreamKind::Direct(stream)
        })
    }

    /// Creates an SSL/TLS server operating over the provided stream.
    ///
    /// Streams passed to this method must implement `AsRawFd` on Unixy
    /// platforms and `AsRawSocket` on Windows. Use `accept_generic` for
    /// streams that do not.
    pub fn accept<T: IntoSsl>(ssl: T, stream: S) -> Result<SslStream<S>, SslError> {
        let ssl = try!(ssl.into_ssl());
        let fd = stream.as_raw_socket() as c_int;
        let stream = try!(DirectStream::accept(ssl, stream, fd));
        Ok(SslStream {
            kind: StreamKind::Direct(stream)
        })
    }
}

impl<S: Read+Write> SslStream<S> {
    /// Creates an SSL/TLS client operating over the provided stream.
    ///
    /// `SslStream`s returned by this method will be less efficient than ones
    /// returned by `connect`, so this method should only be used for streams
    /// that do not implement `AsRawFd` and `AsRawSocket`.
    pub fn connect_generic<T: IntoSsl>(ssl: T, stream: S) -> Result<SslStream<S>, SslError> {
        let stream = try!(IndirectStream::connect(ssl, stream));
        Ok(SslStream {
            kind: StreamKind::Indirect(stream)
        })
    }

    /// Creates an SSL/TLS server operating over the provided stream.
    ///
    /// `SslStream`s returned by this method will be less efficient than ones
    /// returned by `accept`, so this method should only be used for streams
    /// that do not implement `AsRawFd` and `AsRawSocket`.
    pub fn accept_generic<T: IntoSsl>(ssl: T, stream: S) -> Result<SslStream<S>, SslError> {
        let stream = try!(IndirectStream::accept(ssl, stream));
        Ok(SslStream {
            kind: StreamKind::Indirect(stream)
        })
    }

    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        self.kind.stream()
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// ## Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream as it
    /// will most likely corrupt the SSL session.
    pub fn get_mut(&mut self) -> &mut S {
        self.kind.mut_stream()
    }

    /// Returns the OpenSSL `Ssl` object associated with this stream.
    pub fn ssl(&self) -> &Ssl {
        self.kind.ssl()
    }
}

impl<S: Read+Write> Read for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.kind {
            StreamKind::Indirect(ref mut s) => s.read(buf),
            StreamKind::Direct(ref mut s) => s.read(buf),
        }
    }
}

impl<S: Read+Write> Write for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.kind {
            StreamKind::Indirect(ref mut s) => s.write(buf),
            StreamKind::Direct(ref mut s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.kind {
            StreamKind::Indirect(ref mut s) => s.flush(),
            StreamKind::Direct(ref mut s) => s.flush(),
        }
    }
}

pub trait IntoSsl {
    fn into_ssl(self) -> Result<Ssl, SslError>;
}

impl IntoSsl for Ssl {
    fn into_ssl(self) -> Result<Ssl, SslError> {
        Ok(self)
    }
}

impl<'a> IntoSsl for &'a SslContext {
    fn into_ssl(self) -> Result<Ssl, SslError> {
        Ssl::new(self)
    }
}

/// A utility type to help in cases where the use of SSL is decided at runtime.
#[derive(Debug)]
pub enum MaybeSslStream<S> where S: Read+Write {
    /// A connection using SSL
    Ssl(SslStream<S>),
    /// A connection not using SSL
    Normal(S),
}

impl<S> Read for MaybeSslStream<S> where S: Read+Write {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.read(buf),
            MaybeSslStream::Normal(ref mut s) => s.read(buf),
        }
    }
}

impl<S> Write for MaybeSslStream<S> where S: Read+Write {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.write(buf),
            MaybeSslStream::Normal(ref mut s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.flush(),
            MaybeSslStream::Normal(ref mut s) => s.flush(),
        }
    }
}

impl<S> MaybeSslStream<S> where S: Read+Write {
    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        match *self {
            MaybeSslStream::Ssl(ref s) => s.get_ref(),
            MaybeSslStream::Normal(ref s) => s,
        }
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// ## Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.get_mut(),
            MaybeSslStream::Normal(ref mut s) => s,
        }
    }
}

/// An SSL stream wrapping a nonblocking socket.
#[derive(Clone)]
pub struct NonblockingSslStream<S> {
    stream: S,
    ssl: Arc<Ssl>,
}

impl NonblockingSslStream<net::TcpStream> {
    pub fn try_clone(&self) -> io::Result<NonblockingSslStream<net::TcpStream>> {
        Ok(NonblockingSslStream {
            stream: try!(self.stream.try_clone()),
            ssl: self.ssl.clone(),
        })
    }
}

impl<S> NonblockingSslStream<S> {
    fn new_base(ssl: Ssl, stream: S, sock: c_int) -> Result<NonblockingSslStream<S>, SslError> {
        unsafe {
            let bio = try_ssl_null!(ffi::BIO_new_socket(sock, 0));
            ffi_extras::BIO_set_nbio(bio, 1);
            ffi::SSL_set_bio(ssl.ssl, bio, bio);
        }

        Ok(NonblockingSslStream {
            stream: stream,
            ssl: Arc::new(ssl),
        })
    }

    fn make_error(&self, ret: c_int) -> NonblockingSslError {
        match self.ssl.get_error(ret) {
            LibSslError::ErrorSsl => NonblockingSslError::SslError(SslError::get()),
            LibSslError::ErrorSyscall => {
                let err = SslError::get();
                let count = match err {
                    SslError::OpenSslErrors(ref v) => v.len(),
                    _ => unreachable!(),
                };
                let ssl_error = if count == 0 {
                    if ret == 0 {
                        SslError::StreamError(io::Error::new(io::ErrorKind::ConnectionAborted,
                                                             "unexpected EOF observed"))
                    } else {
                        SslError::StreamError(io::Error::last_os_error())
                    }
                } else {
                    err
                };
                ssl_error.into()
            },
            LibSslError::ErrorWantWrite => NonblockingSslError::WantWrite,
            LibSslError::ErrorWantRead => NonblockingSslError::WantRead,
            err => panic!("unexpected error {:?} with ret {}", err, ret),
        }
    }

    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// ## Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream as it
    /// will most likely corrupt the SSL session.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Returns a reference to the Ssl.
    pub fn ssl(&self) -> &Ssl {
        &self.ssl
    }
}

#[cfg(unix)]
impl<S: Read+Write+::std::os::unix::io::AsRawFd> NonblockingSslStream<S> {
    /// Create a new nonblocking client ssl connection on wrapped `stream`.
    ///
    /// Note that this method will most likely not actually complete the SSL
    /// handshake because doing so requires several round trips; the handshake will
    /// be completed in subsequent read/write calls managed by your event loop.
    pub fn connect<T: IntoSsl>(ssl: T, stream: S) -> Result<NonblockingSslStream<S>, SslError> {
        let ssl = try!(ssl.into_ssl());
        let fd = stream.as_raw_fd() as c_int;
        let ssl = try!(NonblockingSslStream::new_base(ssl, stream, fd));
        let ret = ssl.ssl.connect();
        if ret > 0 {
            Ok(ssl)
        } else {
            // WantRead/WantWrite is okay here; we'll finish the handshake in
            // subsequent send/recv calls.
            match ssl.make_error(ret) {
                NonblockingSslError::WantRead | NonblockingSslError::WantWrite => Ok(ssl),
                NonblockingSslError::SslError(other) => Err(other),
            }
        }
    }

    /// Create a new nonblocking server ssl connection on wrapped `stream`.
    ///
    /// Note that this method will most likely not actually complete the SSL
    /// handshake because doing so requires several round trips; the handshake will
    /// be completed in subsequent read/write calls managed by your event loop.
    pub fn accept<T: IntoSsl>(ssl: T, stream: S) -> Result<NonblockingSslStream<S>, SslError> {
        let ssl = try!(ssl.into_ssl());
        let fd = stream.as_raw_fd() as c_int;
        let ssl = try!(NonblockingSslStream::new_base(ssl, stream, fd));
        let ret = ssl.ssl.accept();
        if ret > 0 {
            Ok(ssl)
        } else {
            // WantRead/WantWrite is okay here; we'll finish the handshake in
            // subsequent send/recv calls.
            match ssl.make_error(ret) {
                NonblockingSslError::WantRead | NonblockingSslError::WantWrite => Ok(ssl),
                NonblockingSslError::SslError(other) => Err(other),
            }
        }
    }
}

#[cfg(unix)]
impl<S: ::std::os::unix::io::AsRawFd> ::std::os::unix::io::AsRawFd for NonblockingSslStream<S> {
    fn as_raw_fd(&self) -> ::std::os::unix::io::RawFd {
        self.stream.as_raw_fd()
    }
}

#[cfg(windows)]
impl<S: Read+Write+::std::os::windows::io::AsRawSocket> NonblockingSslStream<S> {
    /// Create a new nonblocking client ssl connection on wrapped `stream`.
    ///
    /// Note that this method will most likely not actually complete the SSL
    /// handshake because doing so requires several round trips; the handshake will
    /// be completed in subsequent read/write calls managed by your event loop.
    pub fn connect<T: IntoSsl>(ssl: T, stream: S) -> Result<NonblockingSslStream<S>, SslError> {
        let ssl = try!(ssl.into_ssl());
        let fd = stream.as_raw_socket() as c_int;
        let ssl = try!(NonblockingSslStream::new_base(ssl, stream, fd));
        let ret = ssl.ssl.connect();
        if ret > 0 {
            Ok(ssl)
        } else {
            // WantRead/WantWrite is okay here; we'll finish the handshake in
            // subsequent send/recv calls.
            match ssl.make_error(ret) {
                NonblockingSslError::WantRead | NonblockingSslError::WantWrite => Ok(ssl),
                NonblockingSslError::SslError(other) => Err(other),
            }
        }
    }

    /// Create a new nonblocking server ssl connection on wrapped `stream`.
    ///
    /// Note that this method will most likely not actually complete the SSL
    /// handshake because doing so requires several round trips; the handshake will
    /// be completed in subsequent read/write calls managed by your event loop.
    pub fn accept<T: IntoSsl>(ssl: T, stream: S) -> Result<NonblockingSslStream<S>, SslError> {
        let ssl = try!(ssl.into_ssl());
        let fd = stream.as_raw_socket() as c_int;
        let ssl = try!(NonblockingSslStream::new_base(ssl, stream, fd));
        let ret = ssl.ssl.accept();
        if ret > 0 {
            Ok(ssl)
        } else {
            // WantRead/WantWrite is okay here; we'll finish the handshake in
            // subsequent send/recv calls.
            match ssl.make_error(ret) {
                NonblockingSslError::WantRead | NonblockingSslError::WantWrite => Ok(ssl),
                NonblockingSslError::SslError(other) => Err(other),
            }
        }
    }
}

impl<S: Read+Write> NonblockingSslStream<S> {
    /// Read bytes from the SSL stream into `buf`.
    ///
    /// Given the SSL state machine, this method may return either `WantWrite`
    /// or `WantRead` to indicate that your event loop should respectively wait
    /// for write or read readiness on the underlying stream.  Upon readiness,
    /// repeat your `read()` call with the same arguments each time until you
    /// receive an `Ok(count)`.
    ///
    /// An `SslError` return value, is terminal; do not re-attempt your read.
    ///
    /// As expected of a nonblocking API, this method will never block your
    /// thread on I/O.
    ///
    /// On a return value of `Ok(count)`, count is the number of decrypted
    /// plaintext bytes copied into the `buf` slice.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, NonblockingSslError> {
        let ret = self.ssl.read(buf);
        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(self.make_error(ret))
        }
    }

    /// Write bytes from `buf` to the SSL stream.
    ///
    /// Given the SSL state machine, this method may return either `WantWrite`
    /// or `WantRead` to indicate that your event loop should respectively wait
    /// for write or read readiness on the underlying stream.  Upon readiness,
    /// repeat your `write()` call with the same arguments each time until you
    /// receive an `Ok(count)`.
    ///
    /// An `SslError` return value, is terminal; do not re-attempt your write.
    ///
    /// As expected of a nonblocking API, this method will never block your
    /// thread on I/O.
    ///
    /// Given a return value of `Ok(count)`, count is the number of plaintext bytes
    /// from the `buf` slice that were encrypted and written onto the stream.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, NonblockingSslError> {
        let ret = self.ssl.write(buf);
        if ret > 0 {
            Ok(ret as usize)
        } else {
            Err(self.make_error(ret))
        }
    }
}
