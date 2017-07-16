use ffi;
use libc::{c_int, c_uint, c_char, c_uchar, c_void};
use std::any::Any;
use std::ffi::CStr;
use std::ptr;
use std::slice;
use std::mem;
use foreign_types::ForeignTypeRef;

use error::ErrorStack;
use dh::Dh;
#[cfg(any(all(feature = "v101", ossl101), all(feature = "v102", ossl102)))]
use ec_key::EcKey;
use ssl::{get_callback_idx, get_ssl_callback_idx, SslRef, SniError, NPN_PROTOS_IDX};
#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
use ssl::ALPN_PROTOS_IDX;
use x509::X509StoreContextRef;

pub extern "C" fn raw_verify<F>(preverify_ok: c_int, x509_ctx: *mut ffi::X509_STORE_CTX) -> c_int
where
    F: Fn(bool, &X509StoreContextRef) -> bool + Any + 'static + Sync + Send,
{
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
        let verify = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
        let verify: &F = &*(verify as *mut F);

        let ctx = X509StoreContextRef::from_ptr(x509_ctx);

        verify(preverify_ok != 0, ctx) as c_int
    }
}

#[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
pub extern "C" fn raw_psk<F>(
    ssl: *mut ffi::SSL,
    hint: *const c_char,
    identity: *mut c_char,
    max_identity_len: c_uint,
    psk: *mut c_uchar,
    max_psk_len: c_uint,
) -> c_uint
where
    F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8], &mut [u8]) -> Result<usize, ErrorStack>
        + Any
        + 'static
        + Sync
        + Send,
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
        let ssl = SslRef::from_ptr_mut(ssl);
        let callback = &*(callback as *mut F);
        let hint = if hint != ptr::null() {
            Some(CStr::from_ptr(hint).to_bytes())
        } else {
            None
        };
        // Give the callback mutable slices into which it can write the identity and psk.
        let identity_sl = slice::from_raw_parts_mut(identity as *mut u8, max_identity_len as usize);
        let psk_sl = slice::from_raw_parts_mut(psk as *mut u8, max_psk_len as usize);
        match callback(ssl, hint, identity_sl, psk_sl) {
            Ok(psk_len) => psk_len as u32,
            _ => 0,
        }
    }
}

pub extern "C" fn ssl_raw_verify<F>(
    preverify_ok: c_int,
    x509_ctx: *mut ffi::X509_STORE_CTX,
) -> c_int
where
    F: Fn(bool, &X509StoreContextRef) -> bool + Any + 'static + Sync + Send,
{
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let verify = ffi::SSL_get_ex_data(ssl as *const _, get_ssl_callback_idx::<F>());
        let verify: &F = &*(verify as *mut F);

        let ctx = X509StoreContextRef::from_ptr(x509_ctx);

        verify(preverify_ok != 0, ctx) as c_int
    }
}

pub extern "C" fn raw_sni<F>(ssl: *mut ffi::SSL, al: *mut c_int, _arg: *mut c_void) -> c_int
where
    F: Fn(&mut SslRef) -> Result<(), SniError> + Any + 'static + Sync + Send,
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
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

pub unsafe fn select_proto_using(
    ssl: *mut ffi::SSL,
    out: *mut *mut c_uchar,
    outlen: *mut c_uchar,
    inbuf: *const c_uchar,
    inlen: c_uint,
    ex_data: c_int,
) -> c_int {

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
        ffi::OPENSSL_NPN_NEGOTIATED
    {
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
pub extern "C" fn raw_next_proto_select_cb(
    ssl: *mut ffi::SSL,
    out: *mut *mut c_uchar,
    outlen: *mut c_uchar,
    inbuf: *const c_uchar,
    inlen: c_uint,
    _arg: *mut c_void,
) -> c_int {
    unsafe { select_proto_using(ssl, out, outlen, inbuf, inlen, *NPN_PROTOS_IDX) }
}

#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
pub extern "C" fn raw_alpn_select_cb(
    ssl: *mut ffi::SSL,
    out: *mut *const c_uchar,
    outlen: *mut c_uchar,
    inbuf: *const c_uchar,
    inlen: c_uint,
    _arg: *mut c_void,
) -> c_int {
    unsafe { select_proto_using(ssl, out as *mut _, outlen, inbuf, inlen, *ALPN_PROTOS_IDX) }
}

pub unsafe extern "C" fn raw_tmp_dh<F>(
    ssl: *mut ffi::SSL,
    is_export: c_int,
    keylength: c_int,
) -> *mut ffi::DH
where
    F: Fn(&mut SslRef, bool, u32) -> Result<Dh, ErrorStack> + Any + 'static + Sync + Send,
{
    let ctx = ffi::SSL_get_SSL_CTX(ssl);
    let callback = ffi::SSL_CTX_get_ex_data(ctx, get_callback_idx::<F>());
    let callback = &*(callback as *mut F);

    let ssl = SslRef::from_ptr_mut(ssl);
    match callback(ssl, is_export != 0, keylength as u32) {
        Ok(dh) => {
            let ptr = dh.as_ptr();
            mem::forget(dh);
            ptr
        }
        Err(_) => {
            // FIXME reset error stack
            ptr::null_mut()
        }
    }
}

#[cfg(any(all(feature = "v101", ossl101), all(feature = "v102", ossl102)))]
pub unsafe extern "C" fn raw_tmp_ecdh<F>(
    ssl: *mut ffi::SSL,
    is_export: c_int,
    keylength: c_int,
) -> *mut ffi::EC_KEY
where
    F: Fn(&mut SslRef, bool, u32) -> Result<EcKey, ErrorStack> + Any + 'static + Sync + Send,
{
    let ctx = ffi::SSL_get_SSL_CTX(ssl);
    let callback = ffi::SSL_CTX_get_ex_data(ctx, get_callback_idx::<F>());
    let callback = &*(callback as *mut F);

    let ssl = SslRef::from_ptr_mut(ssl);
    match callback(ssl, is_export != 0, keylength as u32) {
        Ok(ec_key) => {
            let ptr = ec_key.as_ptr();
            mem::forget(ec_key);
            ptr
        }
        Err(_) => {
            // FIXME reset error stack
            ptr::null_mut()
        }
    }
}

pub unsafe extern "C" fn raw_tmp_dh_ssl<F>(
    ssl: *mut ffi::SSL,
    is_export: c_int,
    keylength: c_int,
) -> *mut ffi::DH
where
    F: Fn(&mut SslRef, bool, u32) -> Result<Dh, ErrorStack> + Any + 'static + Sync + Send,
{
    let callback = ffi::SSL_get_ex_data(ssl, get_ssl_callback_idx::<F>());
    let callback = &*(callback as *mut F);

    let ssl = SslRef::from_ptr_mut(ssl);
    match callback(ssl, is_export != 0, keylength as u32) {
        Ok(dh) => {
            let ptr = dh.as_ptr();
            mem::forget(dh);
            ptr
        }
        Err(_) => {
            // FIXME reset error stack
            ptr::null_mut()
        }
    }
}

#[cfg(any(all(feature = "v101", ossl101), all(feature = "v102", ossl102)))]
pub unsafe extern "C" fn raw_tmp_ecdh_ssl<F>(
    ssl: *mut ffi::SSL,
    is_export: c_int,
    keylength: c_int,
) -> *mut ffi::EC_KEY
where
    F: Fn(&mut SslRef, bool, u32) -> Result<EcKey, ErrorStack> + Any + 'static + Sync + Send,
{
    let callback = ffi::SSL_get_ex_data(ssl, get_ssl_callback_idx::<F>());
    let callback = &*(callback as *mut F);

    let ssl = SslRef::from_ptr_mut(ssl);
    match callback(ssl, is_export != 0, keylength as u32) {
        Ok(ec_key) => {
            let ptr = ec_key.as_ptr();
            mem::forget(ec_key);
            ptr
        }
        Err(_) => {
            // FIXME reset error stack
            ptr::null_mut()
        }
    }
}

pub unsafe extern "C" fn raw_tlsext_status<F>(ssl: *mut ffi::SSL, _: *mut c_void) -> c_int
where
    F: Fn(&mut SslRef) -> Result<bool, ErrorStack> + Any + 'static + Sync + Send,
{
    let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
    let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
    let callback = &*(callback as *mut F);

    let ssl = SslRef::from_ptr_mut(ssl);
    let ret = callback(ssl);

    if ssl.is_server() {
        match ret {
            Ok(true) => ffi::SSL_TLSEXT_ERR_OK,
            Ok(false) => ffi::SSL_TLSEXT_ERR_NOACK,
            Err(_) => {
                // FIXME reset error stack
                ffi::SSL_TLSEXT_ERR_ALERT_FATAL
            }
        }
    } else {
        match ret {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => {
                // FIXME reset error stack
                -1
            }
        }
    }
}

/// The function is given as the callback to `SSL_CTX_set_next_protos_advertised_cb`.
///
/// It causes the parameter `out` to point at a `*const c_uchar` instance that
/// represents the list of protocols that the server should advertise as those
/// that it supports.
/// The list of supported protocols is found in the extra data of the OpenSSL
/// context.
pub extern "C" fn raw_next_protos_advertise_cb(
    ssl: *mut ffi::SSL,
    out: *mut *const c_uchar,
    outlen: *mut c_uint,
    _arg: *mut c_void,
) -> c_int {
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
