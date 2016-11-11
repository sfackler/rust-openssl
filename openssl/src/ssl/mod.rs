//! SSL/TLS support.
//!
//! `SslConnector` and `SslAcceptor` should be used in most cases - they handle
//! configuration of the OpenSSL primitives for you.
//!
//! # Examples
//!
//! To connect as a client to a remote server:
//!
//! ```
//! use openssl::ssl::{SslMethod, SslConnectorBuilder};
//! use std::io::{Read, Write};
//! use std::net::TcpStream;
//!
//! let connector = SslConnectorBuilder::new(SslMethod::tls()).unwrap().build();
//!
//! let stream = TcpStream::connect("google.com:443").unwrap();
//! let mut stream = connector.connect("google.com", stream).unwrap();
//!
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! let mut res = vec![];
//! stream.read_to_end(&mut res).unwrap();
//! println!("{}", String::from_utf8_lossy(&res));
//! ```
//!
//! To accept connections as a server from remote clients:
//!
//! ```no_run
//! use openssl::pkcs12::Pkcs12;
//! use openssl::ssl::{SslMethod, SslAcceptorBuilder, SslStream};
//! use std::fs::File;
//! use std::io::{Read, Write};
//! use std::net::{TcpListener, TcpStream};
//! use std::sync::Arc;
//! use std::thread;
//!
//! // In this example we retrieve our keypair and certificate chain from a PKCS #12 archive,
//! // but but they can also be retrieved from, for example, individual PEM- or DER-formatted
//! // files. See the documentation for the `PKey` and `X509` types for more details.
//! let mut file = File::open("identity.pfx").unwrap();
//! let mut pkcs12 = vec![];
//! file.read_to_end(&mut pkcs12).unwrap();
//! let pkcs12 = Pkcs12::from_der(&pkcs12).unwrap();
//! let identity = pkcs12.parse("password123").unwrap();
//!
//! let acceptor = SslAcceptorBuilder::mozilla_intermediate(SslMethod::tls(),
//!                                                         &identity.pkey,
//!                                                         &identity.cert,
//!                                                         &identity.chain)
//!     .unwrap()
//!     .build();
//! let acceptor = Arc::new(acceptor);
//!
//! let listener = TcpListener::bind("0.0.0.0:8443").unwrap();
//!
//! fn handle_client(stream: SslStream<TcpStream>) {
//!     // ...
//! }
//!
//! for stream in listener.incoming() {
//!     match stream {
//!         Ok(stream) => {
//!             let acceptor = acceptor.clone();
//!             thread::spawn(move || {
//!                 let stream = acceptor.accept(stream).unwrap();
//!                 handle_client(stream);
//!             });
//!         }
//!         Err(e) => { /* connection failed */ }
//!     }
//! }
//! ```
use ffi;
use libc::{c_int, c_void, c_long, c_ulong};
use libc::{c_uchar, c_uint};
use std::any::Any;
use std::any::TypeId;
use std::cmp;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::ptr;
use std::slice;
use std::str;
use std::sync::Mutex;

use {init, cvt, cvt_p};
use dh::DhRef;
use ec_key::EcKeyRef;
use x509::{X509StoreContextRef, X509FileType, X509, X509Ref, X509VerifyError, X509Name};
#[cfg(any(ossl102, ossl110))]
use verify::X509VerifyParamRef;
use pkey::PKeyRef;
use error::ErrorStack;
use types::{OpenSslType, OpenSslTypeRef};
use util::Opaque;
use stack::Stack;

mod error;
mod connector;
mod bio;
#[cfg(test)]
mod tests;

use self::bio::BioMethod;

pub use ssl::connector::{SslConnectorBuilder, SslConnector, SslAcceptorBuilder, SslAcceptor};
pub use ssl::error::{Error, HandshakeError};

bitflags! {
    pub flags SslOption: c_ulong {
        const SSL_OP_MICROSOFT_SESS_ID_BUG = ffi::SSL_OP_MICROSOFT_SESS_ID_BUG,
        const SSL_OP_NETSCAPE_CHALLENGE_BUG = ffi::SSL_OP_NETSCAPE_CHALLENGE_BUG,
        const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG =
            ffi::SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG,
        const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = ffi::SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER,
        const SSL_OP_SSLEAY_080_CLIENT_DH_BUG = ffi::SSL_OP_SSLEAY_080_CLIENT_DH_BUG,
        const SSL_OP_TLS_D5_BUG = ffi::SSL_OP_TLS_D5_BUG,
        const SSL_OP_TLS_BLOCK_PADDING_BUG = ffi::SSL_OP_TLS_BLOCK_PADDING_BUG,
        const SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = ffi::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS,
        const SSL_OP_ALL = ffi::SSL_OP_ALL,
        const SSL_OP_NO_QUERY_MTU = ffi::SSL_OP_NO_QUERY_MTU,
        const SSL_OP_COOKIE_EXCHANGE = ffi::SSL_OP_COOKIE_EXCHANGE,
        const SSL_OP_NO_TICKET = ffi::SSL_OP_NO_TICKET,
        const SSL_OP_CISCO_ANYCONNECT = ffi::SSL_OP_CISCO_ANYCONNECT,
        const SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION =
            ffi::SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
        const SSL_OP_NO_COMPRESSION = ffi::SSL_OP_NO_COMPRESSION,
        const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION =
            ffi::SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
        const SSL_OP_SINGLE_ECDH_USE = ffi::SSL_OP_SINGLE_ECDH_USE,
        const SSL_OP_SINGLE_DH_USE = ffi::SSL_OP_SINGLE_DH_USE,
        const SSL_OP_CIPHER_SERVER_PREFERENCE = ffi::SSL_OP_CIPHER_SERVER_PREFERENCE,
        const SSL_OP_TLS_ROLLBACK_BUG = ffi::SSL_OP_TLS_ROLLBACK_BUG,
        const SSL_OP_NO_SSLV2 = ffi::SSL_OP_NO_SSLv2,
        const SSL_OP_NO_SSLV3 = ffi::SSL_OP_NO_SSLv3,
        const SSL_OP_NO_TLSV1 = ffi::SSL_OP_NO_TLSv1,
        const SSL_OP_NO_TLSV1_2 = ffi::SSL_OP_NO_TLSv1_2,
        const SSL_OP_NO_TLSV1_1 = ffi::SSL_OP_NO_TLSv1_1,
        /// Requires the `v102` or `v110` features and OpenSSL 1.0.2 or OpenSSL 1.1.0.
        #[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
        const SSL_OP_NO_DTLSV1 = ffi::SSL_OP_NO_DTLSv1,
        /// Requires the `v102` or `v110` features and OpenSSL 1.0.2 or OpenSSL 1.1.0.
        #[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
        const SSL_OP_NO_DTLSV1_2 = ffi::SSL_OP_NO_DTLSv1_2,
        /// Requires the `v102` or `v110` features and OpenSSL 1.0.2 or OpenSSL 1.1.0.
        #[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
        const SSL_OP_NO_SSL_MASK = ffi::SSL_OP_NO_SSL_MASK,
    }
}

bitflags! {
    pub flags SslMode: c_long {
        const SSL_MODE_ENABLE_PARTIAL_WRITE = ffi::SSL_MODE_ENABLE_PARTIAL_WRITE,
        const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = ffi::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER,
        const SSL_MODE_AUTO_RETRY = ffi::SSL_MODE_AUTO_RETRY,
        const SSL_MODE_NO_AUTO_CHAIN = ffi::SSL_MODE_NO_AUTO_CHAIN,
        const SSL_MODE_RELEASE_BUFFERS = ffi::SSL_MODE_RELEASE_BUFFERS,
        const SSL_MODE_SEND_CLIENTHELLO_TIME = ffi::SSL_MODE_SEND_CLIENTHELLO_TIME,
        const SSL_MODE_SEND_SERVERHELLO_TIME = ffi::SSL_MODE_SEND_SERVERHELLO_TIME,
        const SSL_MODE_SEND_FALLBACK_SCSV = ffi::SSL_MODE_SEND_FALLBACK_SCSV,
    }
}

#[derive(Copy, Clone)]
pub struct SslMethod(*const ffi::SSL_METHOD);

impl SslMethod {
    /// Support all versions of the TLS protocol.
    ///
    /// This corresponds to `TLS_method` on OpenSSL 1.1.0 and `SSLv23_method`
    /// on OpenSSL 1.0.x.
    pub fn tls() -> SslMethod {
        SslMethod(compat::tls_method())
    }

    /// Support all versions of the DTLS protocol.
    ///
    /// This corresponds to `DTLS_method` on OpenSSL 1.1.0 and `DTLSv1_method`
    /// on OpenSSL 1.0.x.
    pub fn dtls() -> SslMethod {
        SslMethod(compat::dtls_method())
    }

    pub unsafe fn from_ptr(ptr: *const ffi::SSL_METHOD) -> SslMethod {
        SslMethod(ptr)
    }

    pub fn as_ptr(&self) -> *const ffi::SSL_METHOD {
        self.0
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

lazy_static! {
    static ref NPN_PROTOS_IDX: c_int = get_new_idx::<Vec<u8>>();
}

#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
lazy_static! {
    static ref ALPN_PROTOS_IDX: c_int = get_new_idx::<Vec<u8>>();
}

unsafe extern "C" fn free_data_box<T>(_parent: *mut c_void,
                                      ptr: *mut c_void,
                                      _ad: *mut ffi::CRYPTO_EX_DATA,
                                      _idx: c_int,
                                      _argl: c_long,
                                      _argp: *mut c_void) {
    if !ptr.is_null() {
        Box::<T>::from_raw(ptr as *mut T);
    }
}

/// Determine a new index to use for SSL CTX ex data.
/// Registers a destruct for the data which will be called by openssl when the context is freed.
fn get_new_idx<T>() -> c_int {
    unsafe {
        let idx = compat::get_new_idx(free_data_box::<T>);
        assert!(idx >= 0);
        idx
    }
}

fn get_new_ssl_idx<T>() -> c_int {
    unsafe {
        let idx = compat::get_new_ssl_idx(free_data_box::<T>);
        assert!(idx >= 0);
        idx
    }
}

extern "C" fn raw_verify<F>(preverify_ok: c_int, x509_ctx: *mut ffi::X509_STORE_CTX) -> c_int
    where F: Fn(bool, &X509StoreContextRef) -> bool + Any + 'static + Sync + Send
{
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
        let verify = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_verify_data_idx::<F>());
        let verify: &F = &*(verify as *mut F);

        let ctx = X509StoreContextRef::from_ptr(x509_ctx);

        verify(preverify_ok != 0, ctx) as c_int
    }
}

extern "C" fn ssl_raw_verify<F>(preverify_ok: c_int, x509_ctx: *mut ffi::X509_STORE_CTX) -> c_int
    where F: Fn(bool, &X509StoreContextRef) -> bool + Any + 'static + Sync + Send
{
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let verify = ffi::SSL_get_ex_data(ssl as *const _, get_ssl_verify_data_idx::<F>());
        let verify: &F = &*(verify as *mut F);

        let ctx = X509StoreContextRef::from_ptr(x509_ctx);

        verify(preverify_ok != 0, ctx) as c_int
    }
}

extern "C" fn raw_sni<F>(ssl: *mut ffi::SSL, al: *mut c_int, _arg: *mut c_void) -> c_int
    where F: Fn(&mut SslRef) -> Result<(), SniError> + Any + 'static + Sync + Send
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_verify_data_idx::<F>());
        let callback: &F = &*(callback as *mut F);
        let ssl = SslRef::from_ptr_mut(ssl);

        match callback(ssl) {
            Ok(()) => ffi::SSL_TLSEXT_ERR_OK,
            Err(SniError::Fatal(e)) => {
                *al = e;
                ffi::SSL_TLSEXT_ERR_ALERT_FATAL
            }
            Err(SniError::Warning(e)) => {
                *al = e;
                ffi::SSL_TLSEXT_ERR_ALERT_WARNING
            }
            Err(SniError::NoAck) => ffi::SSL_TLSEXT_ERR_NOACK,
        }
    }
}

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
    let protocols: &Vec<u8> = &*(protocols as *mut Vec<u8>);
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
extern "C" fn raw_next_proto_select_cb(ssl: *mut ffi::SSL,
                                       out: *mut *mut c_uchar,
                                       outlen: *mut c_uchar,
                                       inbuf: *const c_uchar,
                                       inlen: c_uint,
                                       _arg: *mut c_void)
                                       -> c_int {
    unsafe { select_proto_using(ssl, out, outlen, inbuf, inlen, *NPN_PROTOS_IDX) }
}

#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
extern "C" fn raw_alpn_select_cb(ssl: *mut ffi::SSL,
                                 out: *mut *const c_uchar,
                                 outlen: *mut c_uchar,
                                 inbuf: *const c_uchar,
                                 inlen: c_uint,
                                 _arg: *mut c_void)
                                 -> c_int {
    unsafe { select_proto_using(ssl, out as *mut _, outlen, inbuf, inlen, *ALPN_PROTOS_IDX) }
}

/// The function is given as the callback to `SSL_CTX_set_next_protos_advertised_cb`.
///
/// It causes the parameter `out` to point at a `*const c_uchar` instance that
/// represents the list of protocols that the server should advertise as those
/// that it supports.
/// The list of supported protocols is found in the extra data of the OpenSSL
/// context.
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
            let protocols: &Vec<u8> = &*(protocols as *mut Vec<u8>);
            *out = protocols.as_ptr();
            *outlen = protocols.len() as c_uint;
        }
    }

    ffi::SSL_TLSEXT_ERR_OK
}

/// Convert a set of byte slices into a series of byte strings encoded for SSL. Encoding is a byte
/// containing the length followed by the string.
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

/// An error returned from an SNI callback.
pub enum SniError {
    Fatal(c_int),
    Warning(c_int),
    NoAck,
}

/// A builder for `SslContext`s.
pub struct SslContextBuilder(*mut ffi::SSL_CTX);

unsafe impl Sync for SslContextBuilder {}
unsafe impl Send for SslContextBuilder {}

impl Drop for SslContextBuilder {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(self.as_ptr()) }
    }
}

impl SslContextBuilder {
    pub fn new(method: SslMethod) -> Result<SslContextBuilder, ErrorStack> {
        unsafe {
            init();
            let ctx = try!(cvt_p(ffi::SSL_CTX_new(method.as_ptr())));

            Ok(SslContextBuilder::from_ptr(ctx))
        }
    }

    pub unsafe fn from_ptr(ctx: *mut ffi::SSL_CTX) -> SslContextBuilder {
        SslContextBuilder(ctx)
    }

    pub fn as_ptr(&self) -> *mut ffi::SSL_CTX {
        self.0
    }

    /// Configures the certificate verification method for new connections.
    pub fn set_verify(&mut self, mode: SslVerifyMode) {
        unsafe {
            ffi::SSL_CTX_set_verify(self.as_ptr(), mode.bits as c_int, None);
        }
    }

    /// Configures the certificate verification method for new connections and
    /// registers a verification callback.
    pub fn set_verify_callback<F>(&mut self, mode: SslVerifyMode, verify: F)
        where F: Fn(bool, &X509StoreContextRef) -> bool + Any + 'static + Sync + Send
    {
        unsafe {
            let verify = Box::new(verify);
            ffi::SSL_CTX_set_ex_data(self.as_ptr(),
                                     get_verify_data_idx::<F>(),
                                     mem::transmute(verify));
            ffi::SSL_CTX_set_verify(self.as_ptr(), mode.bits as c_int, Some(raw_verify::<F>));
        }
    }

    /// Configures the server name indication (SNI) callback for new connections
    ///
    /// Obtain the server name with `servername` then set the corresponding context
    /// with `set_ssl_context`
    pub fn set_servername_callback<F>(&mut self, callback: F)
        where F: Fn(&mut SslRef) -> Result<(), SniError> + Any + 'static + Sync + Send
    {
        unsafe {
            let callback = Box::new(callback);
            ffi::SSL_CTX_set_ex_data(self.as_ptr(),
                                     get_verify_data_idx::<F>(),
                                     mem::transmute(callback));
            let f: extern "C" fn(_, _, _) -> _ = raw_sni::<F>;
            let f: extern "C" fn() = mem::transmute(f);
            ffi::SSL_CTX_set_tlsext_servername_callback(self.as_ptr(), Some(f));
        }
    }

    /// Sets verification depth
    pub fn set_verify_depth(&mut self, depth: u32) {
        unsafe {
            ffi::SSL_CTX_set_verify_depth(self.as_ptr(), depth as c_int);
        }
    }

    pub fn set_read_ahead(&mut self, read_ahead: bool) {
        unsafe {
            ffi::SSL_CTX_set_read_ahead(self.as_ptr(), read_ahead as c_long);
        }
    }

    pub fn set_mode(&mut self, mode: SslMode) -> SslMode {
        unsafe {
            let mode = ffi::SSL_CTX_set_mode(self.as_ptr(), mode.bits());
            SslMode::from_bits(mode).unwrap()
        }
    }

    pub fn set_tmp_dh(&mut self, dh: &DhRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_set_tmp_dh(self.as_ptr(), dh.as_ptr()) as c_int).map(|_| ()) }
    }

    pub fn set_tmp_ecdh(&mut self, key: &EcKeyRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_set_tmp_ecdh(self.as_ptr(), key.as_ptr()) as c_int).map(|_| ()) }
    }

    /// Use the default locations of trusted certificates for verification.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// environment variables if present, or defaults specified at OpenSSL
    /// build time otherwise.
    pub fn set_default_verify_paths(&mut self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_set_default_verify_paths(self.as_ptr())).map(|_| ()) }
    }

    /// Specifies the file that contains trusted CA certificates.
    pub fn set_ca_file<P: AsRef<Path>>(&mut self, file: P) -> Result<(), ErrorStack> {
        let file = CString::new(file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            cvt(ffi::SSL_CTX_load_verify_locations(self.as_ptr(),
                                                   file.as_ptr() as *const _,
                                                   ptr::null()))
                .map(|_| ())
        }
    }

    /// Sets the list of CAs sent to the client.
    ///
    /// The CA certificates must still be added to the trust root.
    pub fn set_client_ca_list(&mut self, list: Stack<X509Name>) {
        unsafe {
            ffi::SSL_CTX_set_client_CA_list(self.as_ptr(), list.as_ptr());
            mem::forget(list);
        }
    }

    /// Set the context identifier for sessions
    ///
    /// This value identifies the server's session cache to a clients, telling them when they're
    /// able to reuse sessions. Should be set to a unique value per server, unless multiple servers
    /// share a session cache.
    ///
    /// This value should be set when using client certificates, or each request will fail
    /// handshake and need to be restarted.
    pub fn set_session_id_context(&mut self, sid_ctx: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            assert!(sid_ctx.len() <= c_uint::max_value() as usize);
            cvt(ffi::SSL_CTX_set_session_id_context(self.as_ptr(),
                                                    sid_ctx.as_ptr(),
                                                    sid_ctx.len() as c_uint))
                .map(|_| ())
        }
    }

    /// Specifies the file that contains certificate
    pub fn set_certificate_file<P: AsRef<Path>>(&mut self,
                                                file: P,
                                                file_type: X509FileType)
                                                -> Result<(), ErrorStack> {
        let file = CString::new(file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            cvt(ffi::SSL_CTX_use_certificate_file(self.as_ptr(),
                                                  file.as_ptr() as *const _,
                                                  file_type.as_raw()))
                .map(|_| ())
        }
    }

    /// Specifies the file that contains certificate chain
    pub fn set_certificate_chain_file<P: AsRef<Path>>(&mut self,
                                                      file: P)
                                                      -> Result<(), ErrorStack> {
        let file = CString::new(file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            cvt(ffi::SSL_CTX_use_certificate_chain_file(self.as_ptr(), file.as_ptr() as *const _))
                .map(|_| ())
        }
    }

    /// Specifies the certificate
    pub fn set_certificate(&mut self, cert: &X509Ref) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_use_certificate(self.as_ptr(), cert.as_ptr())).map(|_| ()) }
    }

    /// Adds a certificate to the certificate chain presented together with the
    /// certificate specified using set_certificate()
    pub fn add_extra_chain_cert(&mut self, cert: X509) -> Result<(), ErrorStack> {
        unsafe {
            try!(cvt(ffi::SSL_CTX_add_extra_chain_cert(self.as_ptr(), cert.as_ptr()) as c_int));
            mem::forget(cert);
            Ok(())
        }
    }

    /// Specifies the file that contains private key
    pub fn set_private_key_file<P: AsRef<Path>>(&mut self,
                                                file: P,
                                                file_type: X509FileType)
                                                -> Result<(), ErrorStack> {
        let file = CString::new(file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            cvt(ffi::SSL_CTX_use_PrivateKey_file(self.as_ptr(),
                                                 file.as_ptr() as *const _,
                                                 file_type.as_raw()))
                .map(|_| ())
        }
    }

    /// Specifies the private key
    pub fn set_private_key(&mut self, key: &PKeyRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_use_PrivateKey(self.as_ptr(), key.as_ptr())).map(|_| ()) }
    }

    pub fn set_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack> {
        let cipher_list = CString::new(cipher_list).unwrap();
        unsafe {
            cvt(ffi::SSL_CTX_set_cipher_list(self.as_ptr(), cipher_list.as_ptr() as *const _))
                .map(|_| ())
        }
    }

    /// If `onoff` is set to `true`, enable ECDHE for key exchange with
    /// compatible clients, and automatically select an appropriate elliptic
    /// curve.
    ///
    /// Requires the `v102` feature and OpenSSL 1.0.2.
    #[cfg(all(feature = "v102", ossl102))]
    pub fn set_ecdh_auto(&mut self, onoff: bool) -> Result<(), ErrorStack> {
        self._set_ecdh_auto(onoff)
    }

    #[cfg(ossl102)]
    fn _set_ecdh_auto(&mut self, onoff: bool) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_set_ecdh_auto(self.as_ptr(), onoff as c_int)).map(|_| ()) }
    }

    pub fn set_options(&mut self, option: SslOption) -> SslOption {
        let ret = unsafe { compat::SSL_CTX_set_options(self.as_ptr(), option.bits()) };
        SslOption::from_bits(ret).unwrap()
    }

    pub fn options(&self) -> SslOption {
        let ret = unsafe { compat::SSL_CTX_get_options(self.as_ptr()) };
        SslOption::from_bits(ret).unwrap()
    }

    pub fn clear_options(&mut self, option: SslOption) -> SslOption {
        let ret = unsafe { compat::SSL_CTX_clear_options(self.as_ptr(), option.bits()) };
        SslOption::from_bits(ret).unwrap()
    }

    /// Set the protocols to be used during Next Protocol Negotiation (the protocols
    /// supported by the application).
    pub fn set_npn_protocols(&mut self, protocols: &[&[u8]]) -> Result<(), ErrorStack> {
        // Firstly, convert the list of protocols to a byte-array that can be passed to OpenSSL
        // APIs -- a list of length-prefixed strings.
        let protocols: Box<Vec<u8>> = Box::new(ssl_encode_byte_strings(protocols));

        unsafe {
            // Attach the protocol list to the OpenSSL context structure,
            // so that we can refer to it within the callback.
            try!(cvt(ffi::SSL_CTX_set_ex_data(self.as_ptr(),
                                              *NPN_PROTOS_IDX,
                                              Box::into_raw(protocols) as *mut c_void)));
            // Now register the callback that performs the default protocol
            // matching based on the client-supported list of protocols that
            // has been saved.
            ffi::SSL_CTX_set_next_proto_select_cb(self.as_ptr(),
                                                  raw_next_proto_select_cb,
                                                  ptr::null_mut());
            // Also register the callback to advertise these protocols, if a server socket is
            // created with the context.
            ffi::SSL_CTX_set_next_protos_advertised_cb(self.as_ptr(),
                                                       raw_next_protos_advertise_cb,
                                                       ptr::null_mut());
            Ok(())
        }
    }

    /// Set the protocols to be used during ALPN (application layer protocol negotiation).
    /// If this is a server, these are the protocols we report to the client.
    /// If this is a client, these are the protocols we try to match with those reported by the
    /// server.
    ///
    /// Note that ordering of the protocols controls the priority with which they are chosen.
    ///
    /// Requires the `v102` or `v110` features and OpenSSL 1.0.2 or OpenSSL 1.1.0.
    #[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
    pub fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<(), ErrorStack> {
        let protocols: Box<Vec<u8>> = Box::new(ssl_encode_byte_strings(protocols));
        unsafe {
            // Set the context's internal protocol list for use if we are a server
            let r = ffi::SSL_CTX_set_alpn_protos(self.as_ptr(),
                                                 protocols.as_ptr(),
                                                 protocols.len() as c_uint);
            // fun fact, SSL_CTX_set_alpn_protos has a reversed return code D:
            if r != 0 {
                return Err(ErrorStack::get());
            }

            // Rather than use the argument to the callback to contain our data, store it in the
            // ssl ctx's ex_data so that we can configure a function to free it later. In the
            // future, it might make sense to pull this into our internal struct Ssl instead of
            // leaning on openssl and using function pointers.
            try!(cvt(ffi::SSL_CTX_set_ex_data(self.as_ptr(),
                                              *ALPN_PROTOS_IDX,
                                              Box::into_raw(protocols) as *mut c_void)));

            // Now register the callback that performs the default protocol
            // matching based on the client-supported list of protocols that
            // has been saved.
            ffi::SSL_CTX_set_alpn_select_cb(self.as_ptr(), raw_alpn_select_cb, ptr::null_mut());

            Ok(())
        }
    }

    /// Checks consistency between the private key and certificate.
    pub fn check_private_key(&self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_check_private_key(self.as_ptr())).map(|_| ()) }
    }

    pub fn build(self) -> SslContext {
        let ctx = SslContext(self.0);
        mem::forget(self);
        ctx
    }
}

type_!(SslContext, SslContextRef, ffi::SSL_CTX, ffi::SSL_CTX_free);

unsafe impl Send for SslContext {}
unsafe impl Sync for SslContext {}

impl Clone for SslContext {
    fn clone(&self) -> Self {
        unsafe {
            compat::SSL_CTX_up_ref(self.as_ptr());
            SslContext::from_ptr(self.as_ptr())
        }
    }
}

// TODO: add useful info here
impl fmt::Debug for SslContext {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SslContext")
    }
}

impl SslContext {
    pub fn builder(method: SslMethod) -> Result<SslContextBuilder, ErrorStack> {
        SslContextBuilder::new(method)
    }
}

impl SslContextRef {
    /// Returns the certificate associated with this `SslContext`, if present.
    ///
    /// Requires the `v102` or `v110` features and OpenSSL 1.0.2 or OpenSSL 1.1.0.
    #[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
    pub fn certificate(&self) -> Option<&X509Ref> {
        unsafe {
            let ptr = ffi::SSL_CTX_get0_certificate(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509Ref::from_ptr(ptr))
            }
        }
    }

    /// Returns the private key associated with this `SslContext`, if present.
    ///
    /// Requires the `v102` or `v110` features and OpenSSL 1.0.2 or OpenSSL 1.1.0.
    #[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
    pub fn private_key(&self) -> Option<&PKeyRef> {
        unsafe {
            let ptr = ffi::SSL_CTX_get0_privatekey(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(PKeyRef::from_ptr(ptr))
            }
        }
    }
}

pub struct CipherBits {
    /// The number of secret bits used for the cipher.
    pub secret: i32,

    /// The number of bits processed by the chosen algorithm.
    pub algorithm: i32,
}

pub struct SslCipher(*mut ffi::SSL_CIPHER);

impl OpenSslType for SslCipher {
    type CType = ffi::SSL_CIPHER;
    type Ref = SslCipherRef;

    unsafe fn from_ptr(ptr: *mut ffi::SSL_CIPHER) -> SslCipher {
        SslCipher(ptr)
    }
}

impl Deref for SslCipher {
    type Target = SslCipherRef;

    fn deref(&self) -> &SslCipherRef {
        unsafe { SslCipherRef::from_ptr(self.0) }
    }
}

impl DerefMut for SslCipher {
    fn deref_mut(&mut self) -> &mut SslCipherRef {
        unsafe { SslCipherRef::from_ptr_mut(self.0) }
    }
}

pub struct SslCipherRef(Opaque);

impl OpenSslTypeRef for SslCipherRef {
    type CType = ffi::SSL_CIPHER;
}

impl SslCipherRef {
    /// Returns the name of cipher.
    pub fn name(&self) -> &str {
        let name = unsafe {
            let ptr = ffi::SSL_CIPHER_get_name(self.as_ptr());
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(name.to_bytes()).unwrap()
    }

    /// Returns the SSL/TLS protocol version that first defined the cipher.
    pub fn version(&self) -> &str {
        let version = unsafe {
            let ptr = ffi::SSL_CIPHER_get_version(self.as_ptr());
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(version.to_bytes()).unwrap()
    }

    /// Returns the number of bits used for the cipher.
    pub fn bits(&self) -> CipherBits {
        unsafe {
            let mut algo_bits = 0;
            let secret_bits = ffi::SSL_CIPHER_get_bits(self.as_ptr(), &mut algo_bits);
            CipherBits {
                secret: secret_bits.into(),
                algorithm: algo_bits.into(),
            }
        }
    }

    /// Returns a textual description of the cipher used
    pub fn description(&self) -> String {
        unsafe {
            // SSL_CIPHER_description requires a buffer of at least 128 bytes.
            let mut buf = [0; 128];
            let ptr = ffi::SSL_CIPHER_description(self.as_ptr(), buf.as_mut_ptr(), 128);
            String::from_utf8(CStr::from_ptr(ptr as *const _).to_bytes().to_vec()).unwrap()
        }
    }
}

type_!(Ssl, SslRef, ffi::SSL, ffi::SSL_free);

impl fmt::Debug for SslRef {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = fmt.debug_struct("Ssl");
        builder.field("state", &self.state_string_long());
        if let Some(err) = self.verify_result() {
            builder.field("verify_result", &err);
        }
        builder.finish()
    }
}

impl SslRef {
    fn get_raw_rbio(&self) -> *mut ffi::BIO {
        unsafe { ffi::SSL_get_rbio(self.as_ptr()) }
    }

    fn read(&mut self, buf: &mut [u8]) -> c_int {
        let len = cmp::min(c_int::max_value() as usize, buf.len()) as c_int;
        unsafe { ffi::SSL_read(self.as_ptr(), buf.as_ptr() as *mut c_void, len) }
    }

    fn write(&mut self, buf: &[u8]) -> c_int {
        let len = cmp::min(c_int::max_value() as usize, buf.len()) as c_int;
        unsafe { ffi::SSL_write(self.as_ptr(), buf.as_ptr() as *const c_void, len) }
    }

    fn get_error(&self, ret: c_int) -> c_int {
        unsafe { ffi::SSL_get_error(self.as_ptr(), ret) }
    }

    /// Sets the verification mode to be used during the handshake process.
    ///
    /// Use `set_verify_callback` to additionally add a callback.
    pub fn set_verify(&mut self, mode: SslVerifyMode) {
        unsafe { ffi::SSL_set_verify(self.as_ptr(), mode.bits as c_int, None) }
    }

    /// Sets the certificate verification callback to be used during the
    /// handshake process.
    ///
    /// The callback is provided with a boolean indicating if the
    /// preveification process was successful, and an object providing access
    /// to the certificate chain. It should return `true` if the certificate
    /// chain is valid and `false` otherwise.
    pub fn set_verify_callback<F>(&mut self, mode: SslVerifyMode, verify: F)
        where F: Fn(bool, &X509StoreContextRef) -> bool + Any + 'static + Sync + Send
    {
        unsafe {
            let verify = Box::new(verify);
            ffi::SSL_set_ex_data(self.as_ptr(),
                                 get_ssl_verify_data_idx::<F>(),
                                 mem::transmute(verify));
            ffi::SSL_set_verify(self.as_ptr(), mode.bits as c_int, Some(ssl_raw_verify::<F>));
        }
    }

    pub fn current_cipher(&self) -> Option<&SslCipherRef> {
        unsafe {
            let ptr = ffi::SSL_get_current_cipher(self.as_ptr());

            if ptr.is_null() {
                None
            } else {
                Some(SslCipherRef::from_ptr(ptr as *mut _))
            }
        }
    }

    pub fn state_string(&self) -> &'static str {
        let state = unsafe {
            let ptr = ffi::SSL_state_string(self.as_ptr());
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(state.to_bytes()).unwrap()
    }

    pub fn state_string_long(&self) -> &'static str {
        let state = unsafe {
            let ptr = ffi::SSL_state_string_long(self.as_ptr());
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(state.to_bytes()).unwrap()
    }

    /// Sets the host name to be used with SNI (Server Name Indication).
    pub fn set_hostname(&mut self, hostname: &str) -> Result<(), ErrorStack> {
        let cstr = CString::new(hostname).unwrap();
        unsafe {
            cvt(ffi::SSL_set_tlsext_host_name(self.as_ptr(), cstr.as_ptr() as *mut _) as c_int)
                .map(|_| ())
        }
    }

    /// Returns the certificate of the peer, if present.
    pub fn peer_certificate(&self) -> Option<X509> {
        unsafe {
            let ptr = ffi::SSL_get_peer_certificate(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509::from_ptr(ptr))
            }
        }
    }

    /// Returns the certificate associated with this `Ssl`, if present.
    pub fn certificate(&self) -> Option<&X509Ref> {
        unsafe {
            let ptr = ffi::SSL_get_certificate(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509Ref::from_ptr(ptr))
            }
        }
    }

    /// Returns the private key associated with this `Ssl`, if present.
    pub fn private_key(&self) -> Option<&PKeyRef> {
        unsafe {
            let ptr = ffi::SSL_get_privatekey(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(PKeyRef::from_ptr(ptr))
            }
        }
    }

    /// Returns the name of the protocol used for the connection, e.g. "TLSv1.2", "SSLv3", etc.
    pub fn version(&self) -> &'static str {
        let version = unsafe {
            let ptr = ffi::SSL_get_version(self.as_ptr());
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(version.to_bytes()).unwrap()
    }

    /// Returns the protocol selected by performing Next Protocol Negotiation, if any.
    ///
    /// The protocol's name is returned is an opaque sequence of bytes. It is up to the client
    /// to interpret it.
    pub fn selected_npn_protocol(&self) -> Option<&[u8]> {
        unsafe {
            let mut data: *const c_uchar = ptr::null();
            let mut len: c_uint = 0;
            // Get the negotiated protocol from the SSL instance.
            // `data` will point at a `c_uchar` array; `len` will contain the length of this array.
            ffi::SSL_get0_next_proto_negotiated(self.as_ptr(), &mut data, &mut len);

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
    /// Requires the `v102` or `v110` features and OpenSSL 1.0.2 or OpenSSL 1.1.0.
    #[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
    pub fn selected_alpn_protocol(&self) -> Option<&[u8]> {
        unsafe {
            let mut data: *const c_uchar = ptr::null();
            let mut len: c_uint = 0;
            // Get the negotiated protocol from the SSL instance.
            // `data` will point at a `c_uchar` array; `len` will contain the length of this array.
            ffi::SSL_get0_alpn_selected(self.as_ptr(), &mut data, &mut len);

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
        unsafe { ffi::SSL_pending(self.as_ptr()) as usize }
    }

    /// Returns the compression currently in use.
    ///
    /// The result will be either None, indicating no compression is in use, or
    /// a string with the compression name.
    pub fn compression(&self) -> Option<&str> {
        self._compression()
    }

    #[cfg(not(osslconf = "OPENSSL_NO_COMP"))]
    fn _compression(&self) -> Option<&str> {
        unsafe {
            let ptr = ffi::SSL_get_current_compression(self.as_ptr());
            if ptr == ptr::null() {
                return None;
            }
            let meth = ffi::SSL_COMP_get_name(ptr);
            Some(str::from_utf8(CStr::from_ptr(meth as *const _).to_bytes()).unwrap())
        }
    }

    #[cfg(osslconf = "OPENSSL_NO_COMP")]
    fn _compression(&self) -> Option<&str> {
        None
    }

    /// Returns the server's name for the current connection
    pub fn servername(&self) -> Option<&str> {
        unsafe {
            let name = ffi::SSL_get_servername(self.as_ptr(), ffi::TLSEXT_NAMETYPE_host_name);
            if name == ptr::null() {
                return None;
            }

            Some(str::from_utf8(CStr::from_ptr(name as *const _).to_bytes()).unwrap())
        }
    }

    /// Changes the context corresponding to the current connection.
    pub fn set_ssl_context(&mut self, ctx: &SslContextRef) -> Result<(), ErrorStack> {
        unsafe { cvt_p(ffi::SSL_set_SSL_CTX(self.as_ptr(), ctx.as_ptr())).map(|_| ()) }
    }

    /// Returns the context corresponding to the current connection
    pub fn ssl_context(&self) -> &SslContextRef {
        unsafe {
            let ssl_ctx = ffi::SSL_get_SSL_CTX(self.as_ptr());
            SslContextRef::from_ptr(ssl_ctx)
        }
    }

    /// Returns the X509 verification configuration.
    ///
    /// Requires the `v102` or `v110` features and OpenSSL 1.0.2 or 1.1.0.
    #[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
    pub fn param_mut(&mut self) -> &mut X509VerifyParamRef {
        self._param_mut()
    }

    #[cfg(any(ossl102, ossl110))]
    fn _param_mut(&mut self) -> &mut X509VerifyParamRef {
        unsafe { X509VerifyParamRef::from_ptr_mut(ffi::SSL_get0_param(self.as_ptr())) }
    }

    /// Returns the result of X509 certificate verification.
    pub fn verify_result(&self) -> Option<X509VerifyError> {
        unsafe { X509VerifyError::from_raw(ffi::SSL_get_verify_result(self.as_ptr())) }
    }
}

unsafe impl Sync for Ssl {}
unsafe impl Send for Ssl {}

impl fmt::Debug for Ssl {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, fmt)
    }
}

impl Ssl {
    pub fn new(ctx: &SslContext) -> Result<Ssl, ErrorStack> {
        unsafe {
            let ssl = try!(cvt_p(ffi::SSL_new(ctx.as_ptr())));
            Ok(Ssl::from_ptr(ssl))
        }
    }

    /// Creates an SSL/TLS client operating over the provided stream.
    ///
    /// # Warning
    ///
    /// OpenSSL's default configuration is insecure. It is highly recommended to use
    /// `SslConnector` rather than `Ssl` directly, as it manages that configuration.
    pub fn connect<S>(self, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
        where S: Read + Write
    {
        let mut stream = SslStream::new_base(self, stream);
        let ret = unsafe { ffi::SSL_connect(stream.ssl.as_ptr()) };
        if ret > 0 {
            Ok(stream)
        } else {
            match stream.make_error(ret) {
                e @ Error::WantWrite(_) |
                e @ Error::WantRead(_) => {
                    Err(HandshakeError::Interrupted(MidHandshakeSslStream {
                        stream: stream,
                        error: e,
                    }))
                }
                err => {
                    Err(HandshakeError::Failure(MidHandshakeSslStream {
                        stream: stream,
                        error: err,
                    }))
                }
            }
        }
    }

    /// Creates an SSL/TLS server operating over the provided stream.
    ///
    /// # Warning
    ///
    /// OpenSSL's default configuration is insecure. It is highly recommended to use
    /// `SslAcceptor` rather than `Ssl` directly, as it manages that configuration.
    pub fn accept<S>(self, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
        where S: Read + Write
    {
        let mut stream = SslStream::new_base(self, stream);
        let ret = unsafe { ffi::SSL_accept(stream.ssl.as_ptr()) };
        if ret > 0 {
            Ok(stream)
        } else {
            match stream.make_error(ret) {
                e @ Error::WantWrite(_) |
                e @ Error::WantRead(_) => {
                    Err(HandshakeError::Interrupted(MidHandshakeSslStream {
                        stream: stream,
                        error: e,
                    }))
                }
                err => {
                    Err(HandshakeError::Failure(MidHandshakeSslStream {
                        stream: stream,
                        error: err,
                    }))
                }
            }
        }
    }
}

/// An SSL stream midway through the handshake process.
#[derive(Debug)]
pub struct MidHandshakeSslStream<S> {
    stream: SslStream<S>,
    error: Error,
}

impl<S> MidHandshakeSslStream<S> {
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }

    /// Returns a shared reference to the `Ssl` of the stream.
    pub fn ssl(&self) -> &SslRef {
        self.stream.ssl()
    }

    /// Returns the underlying error which interrupted this handshake.
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// Consumes `self`, returning its error.
    pub fn into_error(self) -> Error {
        self.error
    }

    /// Restarts the handshake process.
    pub fn handshake(mut self) -> Result<SslStream<S>, HandshakeError<S>> {
        let ret = unsafe { ffi::SSL_do_handshake(self.stream.ssl.as_ptr()) };
        if ret > 0 {
            Ok(self.stream)
        } else {
            match self.stream.make_error(ret) {
                e @ Error::WantWrite(_) |
                e @ Error::WantRead(_) => {
                    self.error = e;
                    Err(HandshakeError::Interrupted(self))
                }
                err => {
                    self.error = err;
                    Err(HandshakeError::Failure(self))
                }
            }
        }
    }
}

/// A stream wrapper which handles SSL encryption for an underlying stream.
pub struct SslStream<S> {
    ssl: Ssl,
    _method: BioMethod, // NOTE: this *must* be after the Ssl field so things drop right
    _p: PhantomData<S>,
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

impl<S: Read + Write> SslStream<S> {
    fn new_base(ssl: Ssl, stream: S) -> Self {
        unsafe {
            let (bio, method) = bio::new(stream).unwrap();
            ffi::SSL_set_bio(ssl.as_ptr(), bio, bio);

            SslStream {
                ssl: ssl,
                _method: method,
                _p: PhantomData,
            }
        }
    }

    /// Like `read`, but returns an `ssl::Error` rather than an `io::Error`.
    ///
    /// This is particularly useful with a nonblocking socket, where the error
    /// value will identify if OpenSSL is waiting on read or write readiness.
    pub fn ssl_read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let ret = self.ssl.read(buf);
        if ret > 0 {
            Ok(ret as usize)
        } else {
            match self.make_error(ret) {
                // Don't treat unexpected EOFs as errors when reading
                Error::Stream(ref e) if e.kind() == io::ErrorKind::ConnectionAborted => Ok(0),
                e => Err(e),
            }
        }
    }

    /// Like `write`, but returns an `ssl::Error` rather than an `io::Error`.
    ///
    /// This is particularly useful with a nonblocking socket, where the error
    /// value will identify if OpenSSL is waiting on read or write readiness.
    pub fn ssl_write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let ret = self.ssl.write(buf);
        if ret > 0 {
            Ok(ret as usize)
        } else {
            Err(self.make_error(ret))
        }
    }

    /// Shuts down the session.
    ///
    /// The shutdown process consists of two steps. The first step sends a
    /// close notify message to the peer, after which `ShutdownResult::Sent`
    /// is returned. The second step awaits the receipt of a close notify
    /// message from the peer, after which `ShutdownResult::Received` is
    /// returned.
    ///
    /// While the connection may be closed after the first step, it is
    /// recommended to fully shut the session down. In particular, it must
    /// be fully shut down if the connection is to be used for further
    /// communication in the future.
    pub fn shutdown(&mut self) -> Result<ShutdownResult, Error> {
        match unsafe { ffi::SSL_shutdown(self.ssl.as_ptr()) } {
            0 => Ok(ShutdownResult::Sent),
            1 => Ok(ShutdownResult::Received),
            n => Err(self.make_error(n)),
        }
    }
}

impl<S> SslStream<S> {
    fn make_error(&mut self, ret: c_int) -> Error {
        self.check_panic();

        match self.ssl.get_error(ret) {
            ffi::SSL_ERROR_SSL => Error::Ssl(ErrorStack::get()),
            ffi::SSL_ERROR_SYSCALL => {
                let errs = ErrorStack::get();
                if errs.errors().is_empty() {
                    match self.get_bio_error() {
                        Some(err) => Error::Stream(err),
                        None => {
                            Error::Stream(io::Error::new(io::ErrorKind::ConnectionAborted,
                                                         "unexpected EOF observed"))
                        }
                    }
                } else {
                    Error::Ssl(errs)
                }
            }
            ffi::SSL_ERROR_ZERO_RETURN => Error::ZeroReturn,
            ffi::SSL_ERROR_WANT_WRITE => {
                let err = match self.get_bio_error() {
                    Some(err) => err,
                    None => {
                        io::Error::new(io::ErrorKind::Other,
                                       "BUG: got an SSL_ERROR_WANT_WRITE with no error in the BIO")
                    }
                };
                Error::WantWrite(err)
            },
            ffi::SSL_ERROR_WANT_READ => {
                let err = match self.get_bio_error() {
                    Some(err) => err,
                    None => {
                        io::Error::new(io::ErrorKind::Other,
                                       "BUG: got an SSL_ERROR_WANT_WRITE with no error in the BIO")
                    }
                };
                Error::WantRead(err)
            },
            err => {
                Error::Stream(io::Error::new(io::ErrorKind::InvalidData,
                                             format!("unexpected error {}", err)))
            }
        }
    }

    fn check_panic(&mut self) {
        if let Some(err) = unsafe { bio::take_panic::<S>(self.ssl.get_raw_rbio()) } {
            ::std::panic::resume_unwind(err)
        }
    }

    fn get_bio_error(&mut self) -> Option<io::Error> {
        unsafe { bio::take_error::<S>(self.ssl.get_raw_rbio()) }
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
    pub fn ssl(&self) -> &SslRef {
        &self.ssl
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

/// The result of a shutdown request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShutdownResult {
    /// A close notify message has been sent to the peer.
    Sent,

    /// A close notify response message has been received from the peer.
    Received,
}

#[cfg(ossl110)]
mod compat {
    use std::ptr;

    use ffi;
    use libc::c_int;

    pub use ffi::{SSL_CTX_get_options, SSL_CTX_set_options};
    pub use ffi::{SSL_CTX_clear_options, SSL_CTX_up_ref};

    pub unsafe fn get_new_idx(f: ffi::CRYPTO_EX_free) -> c_int {
        ffi::CRYPTO_get_ex_new_index(ffi::CRYPTO_EX_INDEX_SSL_CTX,
                                     0,
                                     ptr::null_mut(),
                                     None,
                                     None,
                                     Some(f))
    }

    pub unsafe fn get_new_ssl_idx(f: ffi::CRYPTO_EX_free) -> c_int {
        ffi::CRYPTO_get_ex_new_index(ffi::CRYPTO_EX_INDEX_SSL,
                                     0,
                                     ptr::null_mut(),
                                     None,
                                     None,
                                     Some(f))
    }

    pub fn tls_method() -> *const ffi::SSL_METHOD {
        unsafe { ffi::TLS_method() }
    }

    pub fn dtls_method() -> *const ffi::SSL_METHOD {
        unsafe { ffi::DTLS_method() }
    }
}

#[cfg(ossl10x)]
#[allow(bad_style)]
mod compat {
    use std::ptr;

    use ffi;
    use libc::{self, c_long, c_ulong, c_int};

    pub unsafe fn SSL_CTX_get_options(ctx: *const ffi::SSL_CTX) -> c_ulong {
        ffi::SSL_CTX_ctrl(ctx as *mut _, ffi::SSL_CTRL_OPTIONS, 0, ptr::null_mut()) as c_ulong
    }

    pub unsafe fn SSL_CTX_set_options(ctx: *const ffi::SSL_CTX, op: c_ulong) -> c_ulong {
        ffi::SSL_CTX_ctrl(ctx as *mut _,
                          ffi::SSL_CTRL_OPTIONS,
                          op as c_long,
                          ptr::null_mut()) as c_ulong
    }

    pub unsafe fn SSL_CTX_clear_options(ctx: *const ffi::SSL_CTX, op: c_ulong) -> c_ulong {
        ffi::SSL_CTX_ctrl(ctx as *mut _,
                          ffi::SSL_CTRL_CLEAR_OPTIONS,
                          op as c_long,
                          ptr::null_mut()) as c_ulong
    }

    pub unsafe fn get_new_idx(f: ffi::CRYPTO_EX_free) -> c_int {
        ffi::SSL_CTX_get_ex_new_index(0, ptr::null_mut(), None, None, Some(f))
    }

    pub unsafe fn get_new_ssl_idx(f: ffi::CRYPTO_EX_free) -> c_int {
        ffi::SSL_get_ex_new_index(0, ptr::null_mut(), None, None, Some(f))
    }

    pub unsafe fn SSL_CTX_up_ref(ssl: *mut ffi::SSL_CTX) -> libc::c_int {
        ffi::CRYPTO_add_lock(&mut (*ssl).references,
                             1,
                             ffi::CRYPTO_LOCK_SSL_CTX,
                             "mod.rs\0".as_ptr() as *const _,
                             line!() as libc::c_int);
        0
    }

    pub fn tls_method() -> *const ffi::SSL_METHOD {
        unsafe { ffi::SSLv23_method() }
    }

    pub fn dtls_method() -> *const ffi::SSL_METHOD {
        unsafe { ffi::DTLSv1_method() }
    }
}
