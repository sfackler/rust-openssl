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
use std::sync::{Once, ONCE_INIT, Mutex, Arc};
use std::cmp;
use std::any::Any;
#[cfg(any(feature = "npn", feature = "alpn"))]
use libc::{c_uchar, c_uint};
#[cfg(any(feature = "npn", feature = "alpn"))]
use std::slice;
use std::marker::PhantomData;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

use ffi;
use ffi_extras;
use dh::DH;
use ssl::error::{NonblockingSslError, SslError, OpenSslError, OpensslError};
use x509::{X509StoreContext, X509FileType, X509};
use crypto::pkey::PKey;

pub mod error;
mod bio;
#[cfg(test)]
mod tests;

use self::bio::BioMethod;

#[doc(inline)]
pub use ssl::error::Error;

extern "C" {
    fn rust_SSL_clone(ssl: *mut ffi::SSL);
    fn rust_SSL_CTX_clone(cxt: *mut ffi::SSL_CTX);
}

static mut VERIFY_IDX: c_int = -1;
static mut SNI_IDX: c_int = -1;

/// Manually initialize SSL.
/// It is optional to call this function and safe to do so more than once.
pub fn init() {
    static mut INIT: Once = ONCE_INIT;

    unsafe {
        INIT.call_once(|| {
            ffi::init();

            let verify_idx = ffi::SSL_CTX_get_ex_new_index(0, ptr::null(), None, None, None);
            assert!(verify_idx >= 0);
            VERIFY_IDX = verify_idx;

            let sni_idx = ffi::SSL_CTX_get_ex_new_index(0, ptr::null(), None, None, None);
            assert!(sni_idx >= 0);
            SNI_IDX = sni_idx;
        });
    }
}

bitflags! {
    pub flags SslContextOptions: u64 {
        const SSL_OP_MICROSOFT_SESS_ID_BUG                    = ::ffi_extras::SSL_OP_MICROSOFT_SESS_ID_BUG,
        const SSL_OP_NETSCAPE_CHALLENGE_BUG                   = ::ffi_extras::SSL_OP_NETSCAPE_CHALLENGE_BUG,
        const SSL_OP_LEGACY_SERVER_CONNECT                    = ::ffi_extras::SSL_OP_LEGACY_SERVER_CONNECT,
        const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG         = ::ffi_extras::SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG,
        const SSL_OP_TLSEXT_PADDING                           = ::ffi_extras::SSL_OP_TLSEXT_PADDING,
        const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER               = ::ffi_extras::SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER,
        const SSL_OP_SAFARI_ECDHE_ECDSA_BUG                   = ::ffi_extras::SSL_OP_SAFARI_ECDHE_ECDSA_BUG,
        const SSL_OP_SSLEAY_080_CLIENT_DH_BUG                 = ::ffi_extras::SSL_OP_SSLEAY_080_CLIENT_DH_BUG,
        const SSL_OP_TLS_D5_BUG                               = ::ffi_extras::SSL_OP_TLS_D5_BUG,
        const SSL_OP_TLS_BLOCK_PADDING_BUG                    = ::ffi_extras::SSL_OP_TLS_BLOCK_PADDING_BUG,
        const SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS              = ::ffi_extras::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS,
        const SSL_OP_NO_QUERY_MTU                             = ::ffi_extras::SSL_OP_NO_QUERY_MTU,
        const SSL_OP_COOKIE_EXCHANGE                          = ::ffi_extras::SSL_OP_COOKIE_EXCHANGE,
        const SSL_OP_NO_TICKET                                = ::ffi_extras::SSL_OP_NO_TICKET,
        const SSL_OP_CISCO_ANYCONNECT                         = ::ffi_extras::SSL_OP_CISCO_ANYCONNECT,
        const SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   = ::ffi_extras::SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
        const SSL_OP_NO_COMPRESSION                           = ::ffi_extras::SSL_OP_NO_COMPRESSION,
        const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION        = ::ffi_extras::SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
        const SSL_OP_SINGLE_ECDH_USE                          = ::ffi_extras::SSL_OP_SINGLE_ECDH_USE,
        const SSL_OP_SINGLE_DH_USE                            = ::ffi_extras::SSL_OP_SINGLE_DH_USE,
        const SSL_OP_CIPHER_SERVER_PREFERENCE                 = ::ffi_extras::SSL_OP_CIPHER_SERVER_PREFERENCE,
        const SSL_OP_TLS_ROLLBACK_BUG                         = ::ffi_extras::SSL_OP_TLS_ROLLBACK_BUG,
        const SSL_OP_NO_SSLV2                                 = ::ffi_extras::SSL_OP_NO_SSLv2,
        const SSL_OP_NO_SSLV3                                 = ::ffi_extras::SSL_OP_NO_SSLv3,
        const SSL_OP_NO_DTLSV1                                = ::ffi_extras::SSL_OP_NO_DTLSv1,
        const SSL_OP_NO_TLSV1                                 = ::ffi_extras::SSL_OP_NO_TLSv1,
        const SSL_OP_NO_DTLSV1_2                              = ::ffi_extras::SSL_OP_NO_DTLSv1_2,
        const SSL_OP_NO_TLSV1_2                               = ::ffi_extras::SSL_OP_NO_TLSv1_2,
        const SSL_OP_NO_TLSV1_1                               = ::ffi_extras::SSL_OP_NO_TLSv1_1,
        const SSL_OP_NETSCAPE_CA_DN_BUG                       = ::ffi_extras::SSL_OP_NETSCAPE_CA_DN_BUG,
        const SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG          = ::ffi_extras::SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG,
        const SSL_OP_CRYPTOPRO_TLSEXT_BUG                     = ::ffi_extras::SSL_OP_CRYPTOPRO_TLSEXT_BUG,
        const SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG              = ::ffi_extras::SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG,
        const SSL_OP_MSIE_SSLV2_RSA_PADDING                   = ::ffi_extras::SSL_OP_MSIE_SSLV2_RSA_PADDING,
        const SSL_OP_PKCS1_CHECK_1                            = ::ffi_extras::SSL_OP_PKCS1_CHECK_1,
        const SSL_OP_PKCS1_CHECK_2                            = ::ffi_extras::SSL_OP_PKCS1_CHECK_2,
        const SSL_OP_EPHEMERAL_RSA                            = ::ffi_extras::SSL_OP_EPHEMERAL_RSA,
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
    pub flags SslVerifyMode: i32 {
        /// Verify that the server's certificate is trusted
        const SSL_VERIFY_PEER = ::ffi::SSL_VERIFY_PEER,
        /// Do not verify the server's certificate
        const SSL_VERIFY_NONE = ::ffi::SSL_VERIFY_NONE,
        /// Terminate handshake if client did not return a certificate.
        /// Use together with SSL_VERIFY_PEER.
        const SSL_VERIFY_FAIL_IF_NO_PEER_CERT = ::ffi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
    }
}

lazy_static! {
    static ref INDEXES: Mutex<HashMap<TypeId, c_int>> = Mutex::new(HashMap::new());
    static ref SSL_INDEXES: Mutex<HashMap<TypeId, c_int>> = Mutex::new(HashMap::new());
}

// Creates a static index for user data of type T
// Registers a destructor for the data which will be called
// when context is freed
fn get_verify_data_idx<T: Any + 'static>() -> c_int {
    *INDEXES.lock().unwrap().entry(TypeId::of::<T>()).or_insert_with(|| get_new_idx::<T>())
}

fn get_ssl_verify_data_idx<T: Any + 'static>() -> c_int {
    *SSL_INDEXES.lock().unwrap().entry(TypeId::of::<T>()).or_insert_with(|| get_new_ssl_idx::<T>())
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
    extern "C" fn free_data_box<T>(_parent: *mut c_void,
                                   ptr: *mut c_void,
                                   _ad: *mut ffi::CRYPTO_EX_DATA,
                                   _idx: c_int,
                                   _argl: c_long,
                                   _argp: *mut c_void) {
        if !ptr.is_null() {
            let _: Box<T> = unsafe { mem::transmute(ptr) };
        }
    }

    unsafe {
        let f: ffi::CRYPTO_EX_free = free_data_box::<T>;
        let idx = ffi::SSL_CTX_get_ex_new_index(0, ptr::null(), None, None, Some(f));
        assert!(idx >= 0);
        idx
    }
}

fn get_new_ssl_idx<T>() -> c_int {
    extern "C" fn free_data_box<T>(_parent: *mut c_void,
                                   ptr: *mut c_void,
                                   _ad: *mut ffi::CRYPTO_EX_DATA,
                                   _idx: c_int,
                                   _argl: c_long,
                                   _argp: *mut c_void) {
        if !ptr.is_null() {
            let _: Box<T> = unsafe { mem::transmute(ptr) };
        }
    }

    unsafe {
        let f: ffi::CRYPTO_EX_free = free_data_box::<T>;
        let idx = ffi::SSL_get_ex_new_index(0, ptr::null(), None, None, Some(f));
        assert!(idx >= 0);
        idx
    }
}

extern "C" fn raw_verify(preverify_ok: c_int, x509_ctx: *mut ffi::X509_STORE_CTX) -> c_int {
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);
        let verify = ffi::SSL_CTX_get_ex_data(ssl_ctx, VERIFY_IDX);
        let verify: Option<VerifyCallback> = mem::transmute(verify);

        let ctx = X509StoreContext::new(x509_ctx);

        match verify {
            None => preverify_ok,
            Some(verify) => verify(preverify_ok != 0, &ctx) as c_int,
        }
    }
}

extern "C" fn raw_verify_with_data<T>(preverify_ok: c_int,
                                      x509_ctx: *mut ffi::X509_STORE_CTX)
                                      -> c_int
    where T: Any + 'static
{
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);

        let verify = ffi::SSL_CTX_get_ex_data(ssl_ctx, VERIFY_IDX);
        let verify: Option<VerifyCallbackData<T>> = mem::transmute(verify);

        let data = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_verify_data_idx::<T>());
        let data: &T = mem::transmute(data);

        let ctx = X509StoreContext::new(x509_ctx);

        let res = match verify {
            None => preverify_ok,
            Some(verify) => verify(preverify_ok != 0, &ctx, data) as c_int,
        };

        res
    }
}

extern "C" fn ssl_raw_verify<F>(preverify_ok: c_int, x509_ctx: *mut ffi::X509_STORE_CTX) -> c_int
    where F: Fn(bool, &X509StoreContext) -> bool + Any + 'static + Sync + Send
{
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let verify = ffi::SSL_get_ex_data(ssl, get_ssl_verify_data_idx::<F>());
        let verify: &F = mem::transmute(verify);

        let ctx = X509StoreContext::new(x509_ctx);

        verify(preverify_ok != 0, &ctx) as c_int
    }
}

extern "C" fn raw_sni(ssl: *mut ffi::SSL, ad: &mut c_int, _arg: *mut c_void) -> c_int {
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, SNI_IDX);
        let callback: Option<ServerNameCallback> = mem::transmute(callback);
        rust_SSL_clone(ssl);
        let mut s = Ssl { ssl: ssl };

        let res = match callback {
            None => ffi::SSL_TLSEXT_ERR_ALERT_FATAL,
            Some(callback) => callback(&mut s, ad),
        };

        res
    }
}

extern "C" fn raw_sni_with_data<T>(ssl: *mut ffi::SSL, ad: &mut c_int, arg: *mut c_void) -> c_int
    where T: Any + 'static
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);

        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, SNI_IDX);
        let callback: Option<ServerNameCallbackData<T>> = mem::transmute(callback);
        rust_SSL_clone(ssl);
        let mut s = Ssl { ssl: ssl };

        let data: &T = mem::transmute(arg);

        let res = match callback {
            None => ffi::SSL_TLSEXT_ERR_ALERT_FATAL,
            Some(callback) => callback(&mut s, ad, &*data),
        };

        // Since data might be required on the next verification
        // it is time to forget about it and avoid dropping
        // data will be freed once OpenSSL considers it is time
        // to free all context data
        res
    }
}


#[cfg(any(feature = "npn", feature = "alpn"))]
unsafe fn select_proto_using(ssl: *mut ffi::SSL,
                             out: *mut *mut c_uchar,
                             outlen: *mut c_uchar,
                             inbuf: *const c_uchar,
                             inlen: c_uint,
                             ex_data: c_int)
                             -> c_int {

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
    if ffi::SSL_select_next_proto(out, outlen, inbuf, inlen, client, client_len) !=
       ffi::OPENSSL_NPN_NEGOTIATED {
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
extern "C" fn raw_next_proto_select_cb(ssl: *mut ffi::SSL,
                                       out: *mut *mut c_uchar,
                                       outlen: *mut c_uchar,
                                       inbuf: *const c_uchar,
                                       inlen: c_uint,
                                       _arg: *mut c_void)
                                       -> c_int {
    unsafe { select_proto_using(ssl, out, outlen, inbuf, inlen, *NPN_PROTOS_IDX) }
}

#[cfg(feature = "alpn")]
extern "C" fn raw_alpn_select_cb(ssl: *mut ffi::SSL,
                                 out: *mut *mut c_uchar,
                                 outlen: *mut c_uchar,
                                 inbuf: *const c_uchar,
                                 inlen: c_uint,
                                 _arg: *mut c_void)
                                 -> c_int {
    unsafe { select_proto_using(ssl, out, outlen, inbuf, inlen, *ALPN_PROTOS_IDX) }
}

/// The function is given as the callback to `SSL_CTX_set_next_protos_advertised_cb`.
///
/// It causes the parameter `out` to point at a `*const c_uchar` instance that
/// represents the list of protocols that the server should advertise as those
/// that it supports.
/// The list of supported protocols is found in the extra data of the OpenSSL
/// context.
#[cfg(feature = "npn")]
extern "C" fn raw_next_protos_advertise_cb(ssl: *mut ffi::SSL,
                                           out: *mut *const c_uchar,
                                           outlen: *mut c_uint,
                                           _arg: *mut c_void)
                                           -> c_int {
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
fn ssl_encode_byte_strings(strings: &[&[u8]]) -> Vec<u8> {
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
pub type VerifyCallback = fn(preverify_ok: bool, x509_ctx: &X509StoreContext) -> bool;

/// The signature of functions that can be used to manually verify certificates
/// when user-data should be carried for all verification process
pub type VerifyCallbackData<T> = fn(preverify_ok: bool, x509_ctx: &X509StoreContext, data: &T)
                                    -> bool;

/// The signature of functions that can be used to choose the context depending on the server name
pub type ServerNameCallback = fn(ssl: &mut Ssl, ad: &mut i32) -> i32;

pub type ServerNameCallbackData<T> = fn(ssl: &mut Ssl, ad: &mut i32, data: &T) -> i32;

// FIXME: macro may be instead of inlining?
#[inline]
fn wrap_ssl_result(res: c_int) -> Result<(), SslError> {
    if res == 0 {
        Err(SslError::get())
    } else {
        Ok(())
    }
}

/// An SSL context object
///
/// Internally ref-counted, use `.clone()` in the same way as Rc and Arc.
pub struct SslContext {
    ctx: *mut ffi::SSL_CTX,
}

unsafe impl Send for SslContext {}
unsafe impl Sync for SslContext {}

impl Clone for SslContext {
    fn clone(&self) -> Self {
        unsafe { SslContext::new_ref(self.ctx) }
    }
}

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
    // Create a new SslContext given an existing ref, and incriment ref-count appropriately.
    unsafe fn new_ref(ctx: *mut ffi::SSL_CTX) -> SslContext {
        rust_SSL_CTX_clone(ctx);
        SslContext { ctx: ctx }
    }

    /// Creates a new SSL context.
    pub fn new(method: SslMethod) -> Result<SslContext, SslError> {
        init();

        let ctx = try_ssl_null!(unsafe { ffi::SSL_CTX_new(method.to_raw()) });

        let ctx = SslContext { ctx: ctx };

        // this is a bit dubious (?)
        try!(ctx.set_mode(ffi::SSL_MODE_AUTO_RETRY));

        if method.is_dtls() {
            ctx.set_read_ahead(1);
        }

        Ok(ctx)
    }

    /// Configures the certificate verification method for new connections.
    pub fn set_verify(&mut self, mode: SslVerifyMode, verify: Option<VerifyCallback>) {
        unsafe {
            ffi::SSL_CTX_set_ex_data(self.ctx, VERIFY_IDX, mem::transmute(verify));
            let f: extern "C" fn(c_int, *mut ffi::X509_STORE_CTX) -> c_int = raw_verify;

            ffi::SSL_CTX_set_verify(self.ctx, mode.bits as c_int, Some(f));
        }
    }

    /// Configures the certificate verification method for new connections also
    /// carrying supplied data.
    // Note: no option because there is no point to set data without providing
    // a function handling it
    pub fn set_verify_with_data<T>(&mut self,
                                   mode: SslVerifyMode,
                                   verify: VerifyCallbackData<T>,
                                   data: T)
        where T: Any + 'static
    {
        let data = Box::new(data);
        unsafe {
            ffi::SSL_CTX_set_ex_data(self.ctx, VERIFY_IDX, mem::transmute(Some(verify)));
            ffi::SSL_CTX_set_ex_data(self.ctx, get_verify_data_idx::<T>(), mem::transmute(data));
            let f: extern "C" fn(c_int, *mut ffi::X509_STORE_CTX) -> c_int =
                raw_verify_with_data::<T>;

            ffi::SSL_CTX_set_verify(self.ctx, mode.bits as c_int, Some(f));
        }
    }

    /// Configures the server name indication (SNI) callback for new connections
    ///
    /// obtain the server name with `get_servername` then set the corresponding context
    /// with `set_ssl_context`
    pub fn set_servername_callback(&mut self, callback: Option<ServerNameCallback>) {
        unsafe {
            ffi::SSL_CTX_set_ex_data(self.ctx, SNI_IDX, mem::transmute(callback));
            let f: extern "C" fn(_, _, _) -> _ = raw_sni;
            let f: extern "C" fn() = mem::transmute(f);
            ffi_extras::SSL_CTX_set_tlsext_servername_callback(self.ctx, Some(f));
        }
    }

    /// Configures the server name indication (SNI) callback for new connections
    /// carrying supplied data
    pub fn set_servername_callback_with_data<T>(&mut self,
                                                callback: ServerNameCallbackData<T>,
                                                data: T)
        where T: Any + 'static
    {
        let data = Box::new(data);
        unsafe {
            ffi::SSL_CTX_set_ex_data(self.ctx, SNI_IDX, mem::transmute(Some(callback)));

            ffi_extras::SSL_CTX_set_tlsext_servername_arg(self.ctx, mem::transmute(data));
            let f: extern "C" fn(_, _, _) -> _ = raw_sni_with_data::<T>;
            let f: extern "C" fn() = mem::transmute(f);
            ffi_extras::SSL_CTX_set_tlsext_servername_callback(self.ctx, Some(f));
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

    fn set_mode(&self, mode: c_long) -> Result<(), SslError> {
        wrap_ssl_result(unsafe { ffi_extras::SSL_CTX_set_mode(self.ctx, mode) as c_int })
    }

    pub fn set_tmp_dh(&self, dh: DH) -> Result<(), SslError> {
        wrap_ssl_result(unsafe { ffi_extras::SSL_CTX_set_tmp_dh(self.ctx, dh.raw()) as c_int })
    }

    /// Use the default locations of trusted certificates for verification.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// environment variables if present, or defaults specified at OpenSSL
    /// build time otherwise.
    pub fn set_default_verify_paths(&mut self) -> Result<(), SslError> {
        wrap_ssl_result(unsafe { ffi::SSL_CTX_set_default_verify_paths(self.ctx) })
    }

    #[allow(non_snake_case)]
    /// Specifies the file that contains trusted CA certificates.
    pub fn set_CA_file<P: AsRef<Path>>(&mut self, file: P) -> Result<(), SslError> {
        let file = CString::new(file.as_ref().as_os_str().to_str().expect("invalid utf8")).unwrap();
        wrap_ssl_result(unsafe {
            ffi::SSL_CTX_load_verify_locations(self.ctx, file.as_ptr() as *const _, ptr::null())
        })
    }

    /// Set the context identifier for sessions
    ///
    /// This value identifies the server's session cache to a clients, telling them when they're
    /// able to reuse sessions. Should be set to a unique value per server, unless multiple servers
    /// share a session cache.
    ///
    /// This value should be set when using client certificates, or each request will fail
    /// handshake and need to be restarted.
    pub fn set_session_id_context(&mut self, sid_ctx: &[u8]) -> Result<(), SslError> {
        wrap_ssl_result(unsafe {
            ffi::SSL_CTX_set_session_id_context(self.ctx, sid_ctx.as_ptr(), sid_ctx.len() as u32)
        })
    }

    /// Specifies the file that contains certificate
    pub fn set_certificate_file<P: AsRef<Path>>(&mut self,
                                                file: P,
                                                file_type: X509FileType)
                                                -> Result<(), SslError> {
        let file = CString::new(file.as_ref().as_os_str().to_str().expect("invalid utf8")).unwrap();
        wrap_ssl_result(unsafe {
            ffi::SSL_CTX_use_certificate_file(self.ctx,
                                              file.as_ptr() as *const _,
                                              file_type as c_int)
        })
    }

    /// Specifies the file that contains certificate chain
    pub fn set_certificate_chain_file<P: AsRef<Path>>(&mut self,
                                                      file: P,
                                                      file_type: X509FileType)
                                                      -> Result<(), SslError> {
        let file = CString::new(file.as_ref().as_os_str().to_str().expect("invalid utf8")).unwrap();
        wrap_ssl_result(unsafe {
            ffi::SSL_CTX_use_certificate_chain_file(self.ctx,
                                                    file.as_ptr() as *const _,
                                                    file_type as c_int)
        })
    }

    /// Specifies the certificate
    pub fn set_certificate(&mut self, cert: &X509) -> Result<(), SslError> {
        wrap_ssl_result(unsafe { ffi::SSL_CTX_use_certificate(self.ctx, cert.get_handle()) })
    }

    /// Adds a certificate to the certificate chain presented together with the
    /// certificate specified using set_certificate()
    pub fn add_extra_chain_cert(&mut self, cert: &X509) -> Result<(), SslError> {
        wrap_ssl_result(unsafe {
            ffi_extras::SSL_CTX_add_extra_chain_cert(self.ctx, cert.get_handle()) as c_int
        })
    }

    /// Specifies the file that contains private key
    pub fn set_private_key_file<P: AsRef<Path>>(&mut self,
                                                file: P,
                                                file_type: X509FileType)
                                                -> Result<(), SslError> {
        let file = CString::new(file.as_ref().as_os_str().to_str().expect("invalid utf8")).unwrap();
        wrap_ssl_result(unsafe {
            ffi::SSL_CTX_use_PrivateKey_file(self.ctx,
                                             file.as_ptr() as *const _,
                                             file_type as c_int)
        })
    }

    /// Specifies the private key
    pub fn set_private_key(&mut self, key: &PKey) -> Result<(), SslError> {
        wrap_ssl_result(unsafe { ffi::SSL_CTX_use_PrivateKey(self.ctx, key.get_handle()) })
    }

    /// Check consistency of private key and certificate
    pub fn check_private_key(&mut self) -> Result<(), SslError> {
        wrap_ssl_result(unsafe { ffi::SSL_CTX_check_private_key(self.ctx) })
    }

    pub fn set_cipher_list(&mut self, cipher_list: &str) -> Result<(), SslError> {
        wrap_ssl_result(unsafe {
            let cipher_list = CString::new(cipher_list).unwrap();
            ffi::SSL_CTX_set_cipher_list(self.ctx, cipher_list.as_ptr() as *const _)
        })
    }

    /// If `onoff` is set to `true`, enable ECDHE for key exchange with compatible
    /// clients, and automatically select an appropriate elliptic curve.
    ///
    /// This method requires OpenSSL >= 1.0.2 or LibreSSL and the `ecdh_auto` feature.
    #[cfg(feature = "ecdh_auto")]
    pub fn set_ecdh_auto(&mut self, onoff: bool) -> Result<(), SslError> {
        wrap_ssl_result(unsafe { ffi_extras::SSL_CTX_set_ecdh_auto(self.ctx, onoff as c_int) })
    }

    pub fn set_options(&mut self, option: SslContextOptions) -> SslContextOptions {
        let raw_bits = option.bits();
        let ret = unsafe { ffi_extras::SSL_CTX_set_options(self.ctx, raw_bits) };
        SslContextOptions::from_bits(ret).unwrap()
    }

    pub fn get_options(&mut self) -> SslContextOptions {
        let ret = unsafe { ffi_extras::SSL_CTX_get_options(self.ctx) };
        SslContextOptions::from_bits(ret).unwrap()
    }

    pub fn clear_options(&mut self, option: SslContextOptions) -> SslContextOptions {
        let raw_bits = option.bits();
        let ret = unsafe { ffi_extras::SSL_CTX_clear_options(self.ctx, raw_bits) };
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
            ffi::SSL_CTX_set_ex_data(self.ctx, *NPN_PROTOS_IDX, mem::transmute(protocols));
            // Now register the callback that performs the default protocol
            // matching based on the client-supported list of protocols that
            // has been saved.
            ffi::SSL_CTX_set_next_proto_select_cb(self.ctx,
                                                  raw_next_proto_select_cb,
                                                  ptr::null_mut());
            // Also register the callback to advertise these protocols, if a server socket is
            // created with the context.
            ffi::SSL_CTX_set_next_protos_advertised_cb(self.ctx,
                                                       raw_next_protos_advertise_cb,
                                                       ptr::null_mut());
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
            ffi::SSL_CTX_set_ex_data(self.ctx, *ALPN_PROTOS_IDX, mem::transmute(protocols));

            // Now register the callback that performs the default protocol
            // matching based on the client-supported list of protocols that
            // has been saved.
            ffi::SSL_CTX_set_alpn_select_cb(self.ctx, raw_alpn_select_cb, ptr::null_mut());
        }
    }
}


pub struct CipherBits {
    /// The number of secret bits used for the cipher.
    pub secret: i32,
    /// The number of bits processed by the chosen algorithm, if not None.
    pub algorithm: Option<i32>,
}


pub struct SslCipher<'a> {
    cipher: *const ffi::SSL_CIPHER,
    ph: PhantomData<&'a ()>,
}

impl<'a> SslCipher<'a> {
    /// Returns the name of cipher.
    pub fn name(&self) -> &'static str {
        let name = unsafe {
            let ptr = ffi::SSL_CIPHER_get_name(self.cipher);
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(name.to_bytes()).unwrap()
    }

    /// Returns the SSL/TLS protocol version that first defined the cipher.
    pub fn version(&self) -> &'static str {
        let version = unsafe {
            let ptr = ffi::SSL_CIPHER_get_version(self.cipher);
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(version.to_bytes()).unwrap()
    }

    /// Returns the number of bits used for the cipher.
    pub fn bits(&self) -> CipherBits {
        unsafe {
            let algo_bits: *mut c_int = ptr::null_mut();
            let secret_bits = ffi::SSL_CIPHER_get_bits(self.cipher, algo_bits);
            if !algo_bits.is_null() {
                CipherBits {
                    secret: secret_bits,
                    algorithm: Some(*algo_bits),
                }
            } else {
                CipherBits {
                    secret: secret_bits,
                    algorithm: None,
                }
            }
        }
    }

    /// Returns a textual description of the cipher used
    pub fn description(&self) -> Option<String> {
        unsafe {
            // SSL_CIPHER_description requires a buffer of at least 128 bytes.
            let mut buf = [0; 128];
            let desc_ptr = ffi::SSL_CIPHER_description(self.cipher, buf.as_mut_ptr(), 128);

            if !desc_ptr.is_null() {
                String::from_utf8(CStr::from_ptr(desc_ptr as *const _).to_bytes().to_vec()).ok()
            } else {
                None
            }
        }
    }
}


pub struct Ssl {
    ssl: *mut ffi::SSL,
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

impl Clone for Ssl {
    /// # Deprecated
    fn clone(&self) -> Ssl {
        unsafe { rust_SSL_clone(self.ssl) };
        Ssl { ssl: self.ssl }

    }
}

impl Ssl {
    pub fn new(ctx: &SslContext) -> Result<Ssl, SslError> {
        let ssl = try_ssl_null!(unsafe { ffi::SSL_new(ctx.ctx) });
        let ssl = Ssl { ssl: ssl };
        Ok(ssl)
    }

    fn get_raw_rbio(&self) -> *mut ffi::BIO {
        unsafe { ffi::SSL_get_rbio(self.ssl) }
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
            None => unreachable!(),
        }
    }

    /// Sets the verification mode to be used during the handshake process.
    ///
    /// Use `set_verify_callback` to additionally add a callback.
    pub fn set_verify(&mut self, mode: SslVerifyMode) {
        unsafe { ffi::SSL_set_verify(self.ssl, mode.bits as c_int, None) }
    }

    /// Sets the certificate verification callback to be used during the
    /// handshake process.
    ///
    /// The callback is provided with a boolean indicating if the
    /// preveification process was successful, and an object providing access
    /// to the certificate chain. It should return `true` if the certificate
    /// chain is valid and `false` otherwise.
    pub fn set_verify_callback<F>(&mut self, mode: SslVerifyMode, verify: F)
        where F: Fn(bool, &X509StoreContext) -> bool + Any + 'static + Sync + Send
    {
        unsafe {
            let verify = Box::new(verify);
            ffi::SSL_set_ex_data(self.ssl,
                                 get_ssl_verify_data_idx::<F>(),
                                 mem::transmute(verify));
            ffi::SSL_set_verify(self.ssl, mode.bits as c_int, Some(ssl_raw_verify::<F>));
        }
    }

    pub fn get_current_cipher<'a>(&'a self) -> Option<SslCipher<'a>> {
        unsafe {
            let ptr = ffi::SSL_get_current_cipher(self.ssl);

            if ptr.is_null() {
                None
            } else {
                Some(SslCipher {
                    cipher: ptr,
                    ph: PhantomData,
                })
            }
        }
    }

    pub fn state_string(&self) -> &'static str {
        let state = unsafe {
            let ptr = ffi::SSL_state_string(self.ssl);
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(state.to_bytes()).unwrap()
    }

    pub fn state_string_long(&self) -> &'static str {
        let state = unsafe {
            let ptr = ffi::SSL_state_string_long(self.ssl);
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(state.to_bytes()).unwrap()
    }

    /// Sets the host name to be used with SNI (Server Name Indication).
    pub fn set_hostname(&self, hostname: &str) -> Result<(), SslError> {
        let cstr = CString::new(hostname).unwrap();
        let ret = unsafe {
            ffi_extras::SSL_set_tlsext_host_name(self.ssl, cstr.as_ptr() as *const _)
        };

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

    /// Returns the name of the protocol used for the connection, e.g. "TLSv1.2", "SSLv3", etc.
    pub fn version(&self) -> &'static str {
        let version = unsafe {
            let ptr = ffi::SSL_get_version(self.ssl);
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(version.to_bytes()).unwrap()
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
        unsafe { ffi::SSL_pending(self.ssl) as usize }
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
            String::from_utf8(CStr::from_ptr(meth as *const _).to_bytes().to_vec()).unwrap()
        };

        Some(s)
    }

    pub fn get_ssl_method(&self) -> Option<SslMethod> {
        unsafe {
            let method = ffi::SSL_get_ssl_method(self.ssl);
            SslMethod::from_raw(method)
        }
    }

    /// Returns the server's name for the current connection
    pub fn get_servername(&self) -> Option<String> {
        let name = unsafe { ffi::SSL_get_servername(self.ssl, ffi::TLSEXT_NAMETYPE_host_name) };
        if name == ptr::null() {
            return None;
        }

        unsafe { String::from_utf8(CStr::from_ptr(name as *const _).to_bytes().to_vec()).ok() }
    }

    /// change the context corresponding to the current connection
    ///
    /// Returns a clone of the SslContext @ctx (ie: the new context). The old context is freed.
    pub fn set_ssl_context(&self, ctx: &SslContext) -> SslContext {
        // If duplication of @ctx's cert fails, this returns NULL. This _appears_ to only occur on
        // allocation failures (meaning panicing is probably appropriate), but it might be nice to
        // propogate the error.
        assert!(unsafe { ffi::SSL_set_SSL_CTX(self.ssl, ctx.ctx) } != ptr::null_mut());

        // FIXME: we return this reference here for compatibility, but it isn't actually required.
        // This should be removed when a api-incompatabile version is to be released.
        //
        // ffi:SSL_set_SSL_CTX() returns copy of the ctx pointer passed to it, so it's easier for
        // us to do the clone directly.
        ctx.clone()
    }

    /// obtain the context corresponding to the current connection
    pub fn get_ssl_context(&self) -> SslContext {
        unsafe {
            let ssl_ctx = ffi::SSL_get_SSL_CTX(self.ssl);
            SslContext::new_ref(ssl_ctx)
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

/// A stream wrapper which handles SSL encryption for an underlying stream.
pub struct SslStream<S> {
    ssl: Ssl,
    _method: Arc<BioMethod>, // NOTE: this *must* be after the Ssl field so things drop right
    _p: PhantomData<S>,
}

/// # Deprecated
///
/// This method does not behave as expected and will be removed in a future
/// release.
impl<S: Clone + Read + Write> Clone for SslStream<S> {
    fn clone(&self) -> SslStream<S> {
        SslStream {
            ssl: self.ssl.clone(),
            _method: self._method.clone(),
            _p: PhantomData,
        }
    }
}

impl<S> fmt::Debug for SslStream<S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SslStream")
           .field("stream", &self.get_ref())
           .field("ssl", &self.ssl())
           .finish()
    }
}

#[cfg(unix)]
impl<S: AsRawFd> AsRawFd for SslStream<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.get_ref().as_raw_fd()
    }
}

#[cfg(windows)]
impl<S: AsRawSocket> AsRawSocket for SslStream<S> {
    fn as_raw_socket(&self) -> RawSocket {
        self.get_ref().as_raw_socket()
    }
}

impl<S: Read + Write> SslStream<S> {
    fn new_base(ssl: Ssl, stream: S) -> Self {
        unsafe {
            let (bio, method) = bio::new(stream).unwrap();
            ffi::SSL_set_bio(ssl.ssl, bio, bio);

            SslStream {
                ssl: ssl,
                _method: method,
                _p: PhantomData,
            }
        }
    }

    /// Creates an SSL/TLS client operating over the provided stream.
    pub fn connect<T: IntoSsl>(ssl: T, stream: S) -> Result<Self, SslError> {
        let ssl = try!(ssl.into_ssl());
        let mut stream = Self::new_base(ssl, stream);
        let ret = stream.ssl.connect();
        if ret > 0 {
            Ok(stream)
        } else {
            match stream.make_old_error(ret) {
                Some(err) => Err(err),
                None => Ok(stream),
            }
        }
    }

    /// Creates an SSL/TLS server operating over the provided stream.
    pub fn accept<T: IntoSsl>(ssl: T, stream: S) -> Result<Self, SslError> {
        let ssl = try!(ssl.into_ssl());
        let mut stream = Self::new_base(ssl, stream);
        let ret = stream.ssl.accept();
        if ret > 0 {
            Ok(stream)
        } else {
            match stream.make_old_error(ret) {
                Some(err) => Err(err),
                None => Ok(stream),
            }
        }
    }

    /// ### Deprecated
    ///
    /// Use `connect`.
    pub fn connect_generic<T: IntoSsl>(ssl: T, stream: S) -> Result<SslStream<S>, SslError> {
        Self::connect(ssl, stream)
    }

    /// ### Deprecated
    ///
    /// Use `accept`.
    pub fn accept_generic<T: IntoSsl>(ssl: T, stream: S) -> Result<SslStream<S>, SslError> {
        Self::accept(ssl, stream)
    }

    /// Like `read`, but returns an `ssl::Error` rather than an `io::Error`.
    ///
    /// This is particularly useful with a nonblocking socket, where the error
    /// value will identify if OpenSSL is waiting on read or write readiness.
    pub fn ssl_read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let ret = self.ssl.read(buf);
        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(self.make_error(ret))
        }
    }

    /// Like `write`, but returns an `ssl::Error` rather than an `io::Error`.
    ///
    /// This is particularly useful with a nonblocking socket, where the error
    /// value will identify if OpenSSL is waiting on read or write readiness.
    pub fn ssl_write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let ret = self.ssl.write(buf);
        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(self.make_error(ret))
        }
    }
}

impl<S> SslStream<S> {
    fn make_error(&mut self, ret: c_int) -> Error {
        self.check_panic();

        match self.ssl.get_error(ret) {
            LibSslError::ErrorSsl => Error::Ssl(OpenSslError::get_stack()),
            LibSslError::ErrorSyscall => {
                let errs = OpenSslError::get_stack();
                if errs.is_empty() {
                    if ret == 0 {
                        Error::Stream(io::Error::new(io::ErrorKind::ConnectionAborted,
                                                     "unexpected EOF observed"))
                    } else {
                        Error::Stream(self.get_bio_error())
                    }
                } else {
                    Error::Ssl(errs)
                }
            }
            LibSslError::ErrorZeroReturn => Error::ZeroReturn,
            LibSslError::ErrorWantWrite => Error::WantWrite(self.get_bio_error()),
            LibSslError::ErrorWantRead => Error::WantRead(self.get_bio_error()),
            err => {
                Error::Stream(io::Error::new(io::ErrorKind::Other,
                                             format!("unexpected error {:?}", err)))
            }
        }
    }

    fn make_old_error(&mut self, ret: c_int) -> Option<SslError> {
        self.check_panic();

        match self.ssl.get_error(ret) {
            LibSslError::ErrorSsl => Some(SslError::get()),
            LibSslError::ErrorSyscall => {
                let err = SslError::get();
                let count = match err {
                    SslError::OpenSslErrors(ref v) => v.len(),
                    _ => unreachable!(),
                };
                if count == 0 {
                    if ret == 0 {
                        Some(SslError::StreamError(io::Error::new(io::ErrorKind::ConnectionAborted,
                                                                  "unexpected EOF observed")))
                    } else {
                        Some(SslError::StreamError(self.get_bio_error()))
                    }
                } else {
                    Some(err)
                }
            }
            LibSslError::ErrorZeroReturn => Some(SslError::SslSessionClosed),
            LibSslError::ErrorWantWrite |
            LibSslError::ErrorWantRead => None,
            err => {
                Some(SslError::StreamError(io::Error::new(io::ErrorKind::Other,
                                                          format!("unexpected error {:?}", err))))
            }
        }
    }

    #[cfg(feature = "nightly")]
    fn check_panic(&mut self) {
        if let Some(err) = unsafe { bio::take_panic::<S>(self.ssl.get_raw_rbio()) } {
            ::std::panic::resume_unwind(err)
        }
    }

    #[cfg(not(feature = "nightly"))]
    fn check_panic(&mut self) {}

    fn get_bio_error(&mut self) -> io::Error {
        let error = unsafe { bio::take_error::<S>(self.ssl.get_raw_rbio()) };
        match error {
            Some(error) => error,
            None => {
                io::Error::new(io::ErrorKind::Other,
                               "BUG: got an ErrorSyscall without an error in the BIO?")
            }
        }
    }

    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        unsafe {
            let bio = self.ssl.get_raw_rbio();
            bio::get_ref(bio)
        }
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// ## Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream as it
    /// will most likely corrupt the SSL session.
    pub fn get_mut(&mut self) -> &mut S {
        unsafe {
            let bio = self.ssl.get_raw_rbio();
            bio::get_mut(bio)
        }
    }

    /// Returns the OpenSSL `Ssl` object associated with this stream.
    pub fn ssl(&self) -> &Ssl {
        &self.ssl
    }
}

impl SslStream<::std::net::TcpStream> {
    /// # Deprecated
    ///
    /// This method does not behave as expected and will be removed in a future
    /// release.
    pub fn try_clone(&self) -> io::Result<SslStream<::std::net::TcpStream>> {
        Ok(SslStream {
            ssl: self.ssl.clone(),
            _method: self._method.clone(),
            _p: PhantomData,
        })
    }
}

impl<S: Read + Write> Read for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.ssl_read(buf) {
            Ok(n) => Ok(n),
            Err(Error::ZeroReturn) => Ok(0),
            Err(Error::Stream(e)) => Err(e),
            Err(Error::WantRead(e)) => Err(e),
            Err(Error::WantWrite(e)) => Err(e),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

impl<S: Read + Write> Write for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ssl_write(buf).map_err(|e| {
            match e {
                Error::Stream(e) => e,
                Error::WantRead(e) => e,
                Error::WantWrite(e) => e,
                e => io::Error::new(io::ErrorKind::Other, e),
            }
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.get_mut().flush()
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
pub enum MaybeSslStream<S>
    where S: Read + Write
{
    /// A connection using SSL
    Ssl(SslStream<S>),
    /// A connection not using SSL
    Normal(S),
}

impl<S> Read for MaybeSslStream<S>
    where S: Read + Write
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.read(buf),
            MaybeSslStream::Normal(ref mut s) => s.read(buf),
        }
    }
}

impl<S> Write for MaybeSslStream<S>
    where S: Read + Write
{
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

impl<S> MaybeSslStream<S>
    where S: Read + Write
{
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

impl MaybeSslStream<net::TcpStream> {
    /// Like `TcpStream::try_clone`.
    pub fn try_clone(&self) -> io::Result<MaybeSslStream<net::TcpStream>> {
        match *self {
            MaybeSslStream::Ssl(ref s) => s.try_clone().map(MaybeSslStream::Ssl),
            MaybeSslStream::Normal(ref s) => s.try_clone().map(MaybeSslStream::Normal),
        }
    }
}

/// # Deprecated
///
/// Use `SslStream` with `ssl_read` and `ssl_write`.
pub struct NonblockingSslStream<S>(SslStream<S>);

impl<S: Clone + Read + Write> Clone for NonblockingSslStream<S> {
    fn clone(&self) -> Self {
        NonblockingSslStream(self.0.clone())
    }
}

#[cfg(unix)]
impl<S: AsRawFd> AsRawFd for NonblockingSslStream<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(windows)]
impl<S: AsRawSocket> AsRawSocket for NonblockingSslStream<S> {
    fn as_raw_socket(&self) -> RawSocket {
        self.0.as_raw_socket()
    }
}

impl NonblockingSslStream<net::TcpStream> {
    pub fn try_clone(&self) -> io::Result<NonblockingSslStream<net::TcpStream>> {
        self.0.try_clone().map(NonblockingSslStream)
    }
}

impl<S> NonblockingSslStream<S> {
    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// ## Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream as it
    /// will most likely corrupt the SSL session.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    /// Returns a reference to the Ssl.
    pub fn ssl(&self) -> &Ssl {
        self.0.ssl()
    }
}

impl<S: Read + Write> NonblockingSslStream<S> {
    /// Create a new nonblocking client ssl connection on wrapped `stream`.
    ///
    /// Note that this method will most likely not actually complete the SSL
    /// handshake because doing so requires several round trips; the handshake will
    /// be completed in subsequent read/write calls managed by your event loop.
    pub fn connect<T: IntoSsl>(ssl: T, stream: S) -> Result<NonblockingSslStream<S>, SslError> {
        SslStream::connect(ssl, stream).map(NonblockingSslStream)
    }

    /// Create a new nonblocking server ssl connection on wrapped `stream`.
    ///
    /// Note that this method will most likely not actually complete the SSL
    /// handshake because doing so requires several round trips; the handshake will
    /// be completed in subsequent read/write calls managed by your event loop.
    pub fn accept<T: IntoSsl>(ssl: T, stream: S) -> Result<NonblockingSslStream<S>, SslError> {
        SslStream::accept(ssl, stream).map(NonblockingSslStream)
    }

    fn convert_err(&self, err: Error) -> NonblockingSslError {
        match err {
            Error::ZeroReturn => SslError::SslSessionClosed.into(),
            Error::WantRead(_) => NonblockingSslError::WantRead,
            Error::WantWrite(_) => NonblockingSslError::WantWrite,
            Error::WantX509Lookup => unreachable!(),
            Error::Stream(e) => SslError::StreamError(e).into(),
            Error::Ssl(e) => {
                SslError::OpenSslErrors(e.iter()
                                         .map(|e| OpensslError::from_error_code(e.error_code()))
                                         .collect())
                    .into()
            }
        }
    }

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
        match self.0.ssl_read(buf) {
            Ok(n) => Ok(n),
            Err(Error::ZeroReturn) => Ok(0),
            Err(e) => Err(self.convert_err(e)),
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
        self.0.ssl_write(buf).map_err(|e| self.convert_err(e))
    }
}
