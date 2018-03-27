use ffi;
use libc::{c_char, c_int, c_uchar, c_uint, c_void};
#[cfg(ossl111)]
use libc::size_t;
use std::ffi::CStr;
use std::ptr;
use std::slice;
use std::mem;
#[cfg(ossl111)]
use std::str;
use foreign_types::ForeignTypeRef;
use foreign_types::ForeignType;

use error::ErrorStack;
use dh::Dh;
#[cfg(any(ossl101, ossl102))]
use ec::EcKey;
use pkey::Params;
use ssl::{get_callback_idx, get_ssl_callback_idx, SniError, SslAlert, SslContextRef, SslRef,
          SslSession, SslSessionRef};
#[cfg(any(ossl102, ossl110))]
use ssl::AlpnError;
use x509::X509StoreContextRef;
#[cfg(ossl111)]
use ssl::ExtensionContext;
#[cfg(ossl111)]
use x509::X509Ref;

pub extern "C" fn raw_verify<F>(preverify_ok: c_int, x509_ctx: *mut ffi::X509_STORE_CTX) -> c_int
where
    F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
        let verify = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
        let verify: &F = &*(verify as *mut F);

        let ctx = X509StoreContextRef::from_ptr_mut(x509_ctx);

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
    F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    unsafe {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(x509_ctx, idx);
        let verify = ffi::SSL_get_ex_data(ssl as *const _, get_ssl_callback_idx::<F>());
        let verify: &F = &*(verify as *mut F);

        let ctx = X509StoreContextRef::from_ptr_mut(x509_ctx);

        verify(preverify_ok != 0, ctx) as c_int
    }
}

pub extern "C" fn raw_sni<F>(ssl: *mut ffi::SSL, al: *mut c_int, _arg: *mut c_void) -> c_int
where
    F: Fn(&mut SslRef, &mut SslAlert) -> Result<(), SniError> + 'static + Sync + Send,
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
        let callback: &F = &*(callback as *mut F);
        let ssl = SslRef::from_ptr_mut(ssl);
        let mut alert = SslAlert(*al);

        let r = callback(ssl, &mut alert);
        *al = alert.0;
        match r {
            Ok(()) => ffi::SSL_TLSEXT_ERR_OK,
            Err(e) => e.0,
        }
    }
}

#[cfg(any(ossl102, ossl110))]
pub extern "C" fn raw_alpn_select<F>(
    ssl: *mut ffi::SSL,
    out: *mut *const c_uchar,
    outlen: *mut c_uchar,
    inbuf: *const c_uchar,
    inlen: c_uint,
    _arg: *mut c_void,
) -> c_int
where
    F: for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError> + 'static + Sync + Send,
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
        let callback: &F = &*(callback as *mut F);
        let ssl = SslRef::from_ptr_mut(ssl);
        let protos = slice::from_raw_parts(inbuf as *const u8, inlen as usize);

        match callback(ssl, protos) {
            Ok(proto) => {
                *out = proto.as_ptr() as *const c_uchar;
                *outlen = proto.len() as c_uchar;
                ffi::SSL_TLSEXT_ERR_OK
            }
            Err(e) => e.0,
        }
    }
}

pub unsafe extern "C" fn raw_tmp_dh<F>(
    ssl: *mut ffi::SSL,
    is_export: c_int,
    keylength: c_int,
) -> *mut ffi::DH
where
    F: Fn(&mut SslRef, bool, u32) -> Result<Dh<Params>, ErrorStack> + 'static + Sync + Send,
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
        Err(e) => {
            e.put();
            ptr::null_mut()
        }
    }
}

#[cfg(any(ossl101, ossl102))]
pub unsafe extern "C" fn raw_tmp_ecdh<F>(
    ssl: *mut ffi::SSL,
    is_export: c_int,
    keylength: c_int,
) -> *mut ffi::EC_KEY
where
    F: Fn(&mut SslRef, bool, u32) -> Result<EcKey<Params>, ErrorStack> + 'static + Sync + Send,
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
        Err(e) => {
            e.put();
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
    F: Fn(&mut SslRef, bool, u32) -> Result<Dh<Params>, ErrorStack> + 'static + Sync + Send,
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
        Err(e) => {
            e.put();
            ptr::null_mut()
        }
    }
}

#[cfg(any(ossl101, ossl102))]
pub unsafe extern "C" fn raw_tmp_ecdh_ssl<F>(
    ssl: *mut ffi::SSL,
    is_export: c_int,
    keylength: c_int,
) -> *mut ffi::EC_KEY
where
    F: Fn(&mut SslRef, bool, u32) -> Result<EcKey<Params>, ErrorStack> + 'static + Sync + Send,
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
        Err(e) => {
            e.put();
            ptr::null_mut()
        }
    }
}

pub unsafe extern "C" fn raw_tlsext_status<F>(ssl: *mut ffi::SSL, _: *mut c_void) -> c_int
where
    F: Fn(&mut SslRef) -> Result<bool, ErrorStack> + 'static + Sync + Send,
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
            Err(e) => {
                e.put();
                ffi::SSL_TLSEXT_ERR_ALERT_FATAL
            }
        }
    } else {
        match ret {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(e) => {
                e.put();
                -1
            }
        }
    }
}

pub unsafe extern "C" fn raw_new_session<F>(
    ssl: *mut ffi::SSL,
    session: *mut ffi::SSL_SESSION,
) -> c_int
where
    F: Fn(&mut SslRef, SslSession) + 'static + Sync + Send,
{
    let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
    let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
    let callback = &*(callback as *mut F);

    let ssl = SslRef::from_ptr_mut(ssl);
    let session = SslSession::from_ptr(session);

    callback(ssl, session);

    // the return code doesn't indicate error vs success, but whether or not we consumed the session
    1
}

pub unsafe extern "C" fn raw_remove_session<F>(
    ctx: *mut ffi::SSL_CTX,
    session: *mut ffi::SSL_SESSION,
) where
    F: Fn(&SslContextRef, &SslSessionRef) + 'static + Sync + Send,
{
    let callback = ffi::SSL_CTX_get_ex_data(ctx, get_callback_idx::<F>());
    let callback = &*(callback as *mut F);

    let ctx = SslContextRef::from_ptr(ctx);
    let session = SslSessionRef::from_ptr(session);

    callback(ctx, session)
}

#[cfg(any(ossl110))]
type DataPtr = *const c_uchar;
#[cfg(not(any(ossl110)))]
type DataPtr = *mut c_uchar;

pub unsafe extern "C" fn raw_get_session<F>(
    ssl: *mut ffi::SSL,
    data: DataPtr,
    len: c_int,
    copy: *mut c_int,
) -> *mut ffi::SSL_SESSION
where
    F: Fn(&mut SslRef, &[u8]) -> Option<SslSession> + 'static + Sync + Send,
{
    let ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
    let callback = ffi::SSL_CTX_get_ex_data(ctx, get_callback_idx::<F>());
    let callback = &*(callback as *mut F);

    let ssl = SslRef::from_ptr_mut(ssl);
    let data = slice::from_raw_parts(data as *const u8, len as usize);

    match callback(ssl, data) {
        Some(session) => {
            let p = session.as_ptr();
            mem::forget(p);
            *copy = 0;
            p
        }
        None => ptr::null_mut(),
    }
}

#[cfg(ossl111)]
pub unsafe extern "C" fn raw_keylog<F>(ssl: *const ffi::SSL, line: *const c_char)
where
    F: Fn(&SslRef, &str) + 'static + Sync + Send,
{
    let ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
    let callback = ffi::SSL_CTX_get_ex_data(ctx, get_callback_idx::<F>());
    let callback = &*(callback as *mut F);

    let ssl = SslRef::from_ptr(ssl as *mut _);
    let line = CStr::from_ptr(line).to_bytes();
    let line = str::from_utf8_unchecked(line);

    callback(ssl, line);
}

#[cfg(ossl111)]
pub extern "C" fn raw_stateless_cookie_generate<F>(
    ssl: *mut ffi::SSL,
    cookie: *mut c_uchar,
    cookie_len: *mut size_t,
) -> c_int
where
    F: Fn(&mut SslRef, &mut [u8]) -> Result<usize, ErrorStack> + 'static + Sync + Send,
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
        let ssl = SslRef::from_ptr_mut(ssl);
        let callback = &*(callback as *mut F);
        let slice =
            slice::from_raw_parts_mut(cookie as *mut u8, ffi::SSL_COOKIE_LENGTH as usize);
        match callback(ssl, slice) {
            Ok(len) => {
                *cookie_len = len as size_t;
                1
            }
            Err(e) => {
                e.put();
                0
            }
        }
    }
}

#[cfg(ossl111)]
pub extern "C" fn raw_stateless_cookie_verify<F>(
    ssl: *mut ffi::SSL,
    cookie: *const c_uchar,
    cookie_len: size_t,
) -> c_int
where
    F: Fn(&mut SslRef, &[u8]) -> bool + 'static + Sync + Send,
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
        let ssl = SslRef::from_ptr_mut(ssl);
        let callback = &*(callback as *mut F);
        let slice =
            slice::from_raw_parts(cookie as *const c_uchar as *const u8, cookie_len as usize);
        callback(ssl, slice) as c_int
    }
}

pub extern "C" fn raw_cookie_generate<F>(
    ssl: *mut ffi::SSL,
    cookie: *mut c_uchar,
    cookie_len: *mut c_uint,
) -> c_int
where
    F: Fn(&mut SslRef, &mut [u8]) -> Result<usize, ErrorStack> + 'static + Sync + Send,
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
        let ssl = SslRef::from_ptr_mut(ssl);
        let callback = &*(callback as *mut F);
        // We subtract 1 from DTLS1_COOKIE_LENGTH as the ostensible value, 256, is erroneous but retained for
        // compatibility. See comments in dtls1.h.
        let slice =
            slice::from_raw_parts_mut(cookie as *mut u8, ffi::DTLS1_COOKIE_LENGTH as usize - 1);
        match callback(ssl, slice) {
            Ok(len) => {
                *cookie_len = len as c_uint;
                1
            }
            Err(e) => {
                e.put();
                0
            }
        }
    }
}

#[cfg(ossl110)]
type CookiePtr = *const c_uchar;

#[cfg(not(ossl110))]
type CookiePtr = *mut c_uchar;

pub extern "C" fn raw_cookie_verify<F>(
    ssl: *mut ffi::SSL,
    cookie: CookiePtr,
    cookie_len: c_uint,
) -> c_int
where
    F: Fn(&mut SslRef, &[u8]) -> bool + 'static + Sync + Send,
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
        let ssl = SslRef::from_ptr_mut(ssl);
        let callback = &*(callback as *mut F);
        let slice =
            slice::from_raw_parts(cookie as *const c_uchar as *const u8, cookie_len as usize);
        callback(ssl, slice) as c_int
    }
}

#[cfg(ossl111)]
pub struct CustomExtAddState<T>(Option<T>);

#[cfg(ossl111)]
pub extern "C" fn raw_custom_ext_add<F, T>(
    ssl: *mut ffi::SSL,
    _: c_uint,
    context: c_uint,
    out: *mut *const c_uchar,
    outlen: *mut size_t,
    x: *mut ffi::X509,
    chainidx: size_t,
    al: *mut c_int,
    _: *mut c_void,
) -> c_int
where
    F: Fn(&mut SslRef, ExtensionContext, Option<(usize, &X509Ref)>) -> Result<Option<T>, SslAlert>
        + 'static,
    T: AsRef<[u8]> + 'static + Sync + Send,
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
        let callback = &*(callback as *mut F);
        let ssl = SslRef::from_ptr_mut(ssl);
        let ectx = ExtensionContext::from_bits_truncate(context);
        let cert = if ectx.contains(ExtensionContext::TLS1_3_CERTIFICATE) {
            Some((chainidx, X509Ref::from_ptr(x)))
        } else {
            None
        };
        match (callback)(ssl, ectx, cert) {
            Ok(None) => 0,
            Ok(Some(buf)) => {
                *outlen = buf.as_ref().len() as size_t;
                *out = buf.as_ref().as_ptr();

                let idx = get_ssl_callback_idx::<CustomExtAddState<T>>();
                let ptr = ffi::SSL_get_ex_data(ssl.as_ptr(), idx);
                if ptr.is_null() {
                    let x = Box::into_raw(Box::<CustomExtAddState<T>>::new(CustomExtAddState(
                        Some(buf),
                    ))) as *mut c_void;
                    ffi::SSL_set_ex_data(ssl.as_ptr(), idx, x);
                } else {
                    *(ptr as *mut _) = CustomExtAddState(Some(buf))
                }
                1
            }
            Err(alert) => {
                *al = alert.0;
                -1
            }
        }
    }
}

#[cfg(ossl111)]
pub extern "C" fn raw_custom_ext_free<T>(
    ssl: *mut ffi::SSL,
    _: c_uint,
    _: c_uint,
    _: *mut *const c_uchar,
    _: *mut c_void,
) where
    T: 'static + Sync + Send,
{
    unsafe {
        let state = ffi::SSL_get_ex_data(ssl, get_ssl_callback_idx::<CustomExtAddState<T>>());
        let state = &mut (*(state as *mut CustomExtAddState<T>)).0;
        state.take();
    }
}

#[cfg(ossl111)]
pub extern "C" fn raw_custom_ext_parse<F>(
    ssl: *mut ffi::SSL,
    _: c_uint,
    context: c_uint,
    input: *const c_uchar,
    inlen: size_t,
    x: *mut ffi::X509,
    chainidx: size_t,
    al: *mut c_int,
    _: *mut c_void,
) -> c_int
where
    F: FnMut(&mut SslRef, ExtensionContext, &[u8], Option<(usize, &X509Ref)>) -> Result<(), SslAlert>
        + 'static,
{
    unsafe {
        let ssl_ctx = ffi::SSL_get_SSL_CTX(ssl as *const _);
        let callback = ffi::SSL_CTX_get_ex_data(ssl_ctx, get_callback_idx::<F>());
        let ssl = SslRef::from_ptr_mut(ssl);
        let callback = &mut *(callback as *mut F);
        let ectx = ExtensionContext::from_bits_truncate(context);
        let slice = slice::from_raw_parts(input as *const u8, inlen as usize);
        let cert = if ectx.contains(ExtensionContext::TLS1_3_CERTIFICATE) {
            Some((chainidx, X509Ref::from_ptr(x)))
        } else {
            None
        };
        match callback(ssl, ectx, slice, cert) {
            Ok(()) => 1,
            Err(alert) => {
                *al = alert.0;
                0
            }
        }
    }
}
