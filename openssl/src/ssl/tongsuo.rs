use std::{mem::ManuallyDrop, marker::PhantomData, path::Path, os::unix::prelude::AsRawFd, io::{Write, Read}, ffi::CString};

use crate::{error::ErrorStack, cvt_p};

use super::{ClientHelloResponse, SslRef, bio::{self, BioMethod, StreamState}, Ssl, SslStream, SslFiletype, SslContextBuilder};
use ffi::{BIO, BIO_new, BIO_set_data, BIO_set_init};
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use openssl_macros::corresponds;
#[cfg(ossl111)]
impl ClientHelloResponse {
    pub const ERROR: ClientHelloResponse = ClientHelloResponse(ffi::SSL_CLIENT_HELLO_ERROR);
}
impl<S: Read + Write + AsRawFd> SslStream<S> {
    #[corresponds(SSL_set_bio)]
    pub fn new_tongsuo_stream(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        let (bio, method) = new_tongsuo(stream)?;
        unsafe {
            ffi::SSL_set_bio(ssl.as_ptr(), bio, bio);
        }

        Ok(SslStream {
            ssl: ManuallyDrop::new(ssl),
            method: ManuallyDrop::new(method),
            _p: PhantomData,
        })
    }
}
impl SslRef {
    #[cfg(feature = "tongsuo")]
    /// 只能在client hello callback中调用
    pub fn get_client_cipher_list_name(&mut self) -> Vec<String> {
        use std::{ptr, slice, ffi::CStr};

        let mut lists = vec![];
        unsafe {
            let mut ptr = ptr::null();
            let tmp: *mut *const _ = &mut ptr;
            let len = ffi::SSL_client_hello_get0_ciphers(self.as_ptr(), tmp as *mut _);
            let ciphers = slice::from_raw_parts::<u16>(ptr, len as usize);
            for index in ciphers {
                let c = ffi::SSL_CIPHER_find(self.as_ptr(), index as *const _ as *const _);
                let name = ffi::SSL_CIPHER_get_name(c);
                let s = CStr::from_ptr(name).to_str().unwrap().to_string();
                lists.push(s);
            }
            lists
        }
    }
    #[cfg(feature = "tongsuo")]
    #[corresponds(SSL_use_Private_Key_file)]
    pub fn set_private_key_file<P: AsRef<Path>>(&mut self, path: P, ssl_file_type: SslFiletype) {

        let key_file = CString::new(path.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            ffi::SSL_use_PrivateKey_file(self.as_ptr(), key_file.as_ptr(), ssl_file_type.as_raw())
        };
    }
    #[cfg(feature = "tongsuo")]
    #[corresponds(SSL_use_PrivateKey)]
    pub fn use_private_key_pem(&mut self, key: &[u8]) {
        use crate::pkey;
        let pkey = pkey::PKey::private_key_from_pem(key).unwrap();
        unsafe {
            ffi::SSL_use_PrivateKey(self.as_ptr(), pkey.as_ptr());
        };
    }
    #[cfg(feature = "tongsuo")]
    #[corresponds(SSL_use_certificate)]
    pub fn use_certificate_pem(&mut self, cert: &[u8]) {
        use crate::x509;
        let cert = x509::X509::from_pem(cert).unwrap();
        unsafe {
            ffi::SSL_use_certificate(self.as_ptr(), cert.as_ptr());
        };
    }

    #[cfg(feature = "tongsuo")]
    #[corresponds(SSL_use_certificate_chain_file)]
    pub fn set_certificate_chain_file<P: AsRef<Path>>(&mut self, path: P) {
        let cert_file = CString::new(path.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            ffi::SSL_use_certificate_chain_file(self.as_ptr(), cert_file.as_ptr());
        };
    }
    #[cfg(feature = "tongsuo")]
    pub fn use_ntls_key_content_and_cert_content_pem(
        &mut self,
        sign_private_key_content: &[u8],
        sign_cert_content: &[u8],
        enc_private_key_content: &[u8],
        enc_cert_content: &[u8],
    ) -> Result<(), ErrorStack> {
        use crate::{pkey, x509};

        //sign_private_key_content is not null, unwrap is safe
        let sign_pkey = pkey::PKey::private_key_from_pem(sign_private_key_content).unwrap();
        let sign_cert = x509::X509::from_pem(sign_cert_content)?;
        let enc_pkey = pkey::PKey::private_key_from_pem(enc_private_key_content).unwrap();
        let enc_cert = x509::X509::from_pem(enc_cert_content).unwrap();
        unsafe {
            ffi::SSL_use_sign_PrivateKey(self.as_ptr(), sign_pkey.as_ptr());
            ffi::SSL_use_sign_certificate(self.as_ptr(), sign_cert.as_ptr());
            ffi::SSL_use_enc_PrivateKey(self.as_ptr(), enc_pkey.as_ptr());
            ffi::SSL_use_enc_certificate(self.as_ptr(), enc_cert.as_ptr());
        };
        Ok(())
    }
    #[cfg(feature = "tongsuo")]
    pub fn use_ntls_key_and_cert<P: AsRef<Path>>(
        &mut self,
        sign_private_key_file: P,
        sign_cert_file: P,
        enc_private_key_file: P,
        enc_cert_file: P,
    ) -> Result<(), ErrorStack> {
        use std::ffi::CString;

        let sign_key =
            CString::new(sign_private_key_file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        let sign_certificate =
            CString::new(sign_cert_file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        let enc_key =
            CString::new(enc_private_key_file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        let enc_certificate =
            CString::new(enc_cert_file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            if ffi::SSL_use_sign_PrivateKey_file(
                self.as_ptr(),
                sign_key.as_ptr(),
                SslFiletype::PEM.as_raw(),
            ) == 0
            {}
            if ffi::SSL_use_sign_certificate_file(
                self.as_ptr(),
                sign_certificate.as_ptr(),
                SslFiletype::PEM.as_raw(),
            ) == 0
            {}
            if ffi::SSL_use_enc_PrivateKey_file(
                self.as_ptr(),
                enc_key.as_ptr(),
                SslFiletype::PEM.as_raw(),
            ) == 0
            {}
            if ffi::SSL_use_enc_certificate_file(
                self.as_ptr(),
                enc_certificate.as_ptr(),
                SslFiletype::PEM.as_raw(),
            ) == 0
            {}
        }
        Ok(())
    }
}

impl SslContextBuilder {
    pub fn enable_ntls(&self) {
        unsafe {
            ffi::SSL_CTX_enable_ntls(self.as_ptr());
        }
    }
}

pub fn new_tongsuo<S: Read + Write + AsRawFd>(
    stream: S,
) -> Result<(*mut BIO, BioMethod), ErrorStack> {
    let method = BioMethod::new::<S>()?;
    let fd = stream.as_raw_fd();
    let state = Box::new(StreamState {
        stream,
        error: None,
        panic: None,
        dtls_mtu_size: 0,
        fd: Some(fd),
    });

    unsafe {
        let bio = cvt_p(BIO_new(method.0.get()))?;
        BIO_set_data(bio, Box::into_raw(state) as *mut _);
        BIO_set_init(bio, 1);

        Ok((bio, method))
    }
}