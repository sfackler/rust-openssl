use std::{marker::PhantomData, mem, os::raw::c_int, ptr};

use libc::c_void;

use ffi::X509V3_ADD_REPLACE;
use foreign_types::{ForeignType, ForeignTypeRef};

use crate::{
    asn1::{Asn1IntegerRef, Asn1TimeRef},
    conf::ConfRef,
    cvt, cvt_p,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKeyRef, Private},
    x509::{X509ExtensionRef, X509NameRef, X509Ref, X509v3Context},
};

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_CRL;
    fn drop = ffi::X509_CRL_free;

    pub struct X509Crl;
    pub struct X509CrlRef;
}

impl X509Crl {
    pub fn new() -> Result<X509Crl, ErrorStack> {
        ffi::init();

        unsafe { cvt_p(ffi::X509_CRL_new()).map(X509Crl) }
    }

    pub fn set_version(&mut self, version: i64) -> Result<c_int, ErrorStack> {
        unsafe { cvt(ffi::X509_CRL_set_version(self.as_ptr(), version)) }
    }

    pub fn set_last_update(&mut self, time: &Asn1TimeRef) -> Result<c_int, ErrorStack> {
        unsafe { cvt(ffi::X509_CRL_set1_lastUpdate(self.as_ptr(), time.as_ptr())) }
    }

    pub fn set_next_update(&mut self, time: &Asn1TimeRef) -> Result<c_int, ErrorStack> {
        unsafe { cvt(ffi::X509_CRL_set1_nextUpdate(self.as_ptr(), time.as_ptr())) }
    }

    pub fn set_issuer_name(&mut self, name: &X509NameRef) -> Result<c_int, ErrorStack> {
        unsafe { cvt(ffi::X509_CRL_set_issuer_name(self.as_ptr(), name.as_ptr())) }
    }

    pub fn x509v3_context<'a>(
        &'a self,
        issuer: &'a X509Ref,
        conf: Option<&'a ConfRef>,
    ) -> X509v3Context<'a> {
        unsafe {
            let mut ctx = mem::zeroed();

            ffi::X509V3_set_ctx(
                &mut ctx,
                issuer.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                self.as_ptr(),
                0,
            );

            if let Some(conf) = conf {
                ffi::X509V3_set_nconf(&mut ctx, conf.as_ptr());
            }

            X509v3Context(ctx, PhantomData)
        }
    }

    pub fn append_extension(&mut self, extension: &X509ExtensionRef) -> Result<c_int, ErrorStack> {
        unsafe { cvt(ffi::X509_CRL_add_ext(self.as_ptr(), extension.as_ptr(), -1)) }
    }

    pub fn set_crl_number(&mut self, crl_number: &Asn1IntegerRef) -> Result<c_int, ErrorStack> {
        unsafe {
            cvt(ffi::X509_CRL_add1_ext_i2d(
                self.as_ptr(),
                Nid::CRL_NUMBER.as_raw(),
                crl_number.as_ptr() as *mut c_void,
                0,
                X509V3_ADD_REPLACE,
            ))
        }
    }

    pub fn add_revoked(&mut self, revoked: X509Revoked) -> Result<c_int, ErrorStack> {
        let ret = unsafe { cvt(ffi::X509_CRL_add0_revoked(self.as_ptr(), revoked.as_ptr()))? };

        std::mem::forget(revoked);

        Ok(ret)
    }

    pub fn sort(&mut self) -> Result<c_int, ErrorStack> {
        unsafe { cvt(ffi::X509_CRL_sort(self.as_ptr())) }
    }

    pub fn sign(
        &mut self,
        pkey: &PKeyRef<Private>,
        digest: MessageDigest,
    ) -> Result<c_int, ErrorStack> {
        unsafe {
            cvt(ffi::X509_CRL_sign(
                self.as_ptr(),
                pkey.as_ptr(),
                digest.as_ptr(),
            ))
        }
    }

    from_pem! {
        from_pem,
        X509Crl,
        ffi::PEM_read_bio_X509_CRL
    }

    from_der! {
        from_der,
        X509Crl,
        ffi::d2i_X509_CRL
    }
}

impl X509CrlRef {
    to_pem! {
        to_pem,
        ffi::PEM_write_bio_X509_CRL
    }

    to_der! {
        to_der,
        ffi::i2d_X509_CRL
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_REVOKED;
    fn drop = ffi::X509_REVOKED_free;

    pub struct X509Revoked;
    pub struct X509RevokedRef;
}

impl X509Revoked {
    pub fn new() -> Result<X509Revoked, ErrorStack> {
        ffi::init();

        unsafe { cvt_p(ffi::X509_REVOKED_new()).map(X509Revoked) }
    }

    pub fn set_serial_number(
        &mut self,
        serial_number: &Asn1IntegerRef,
    ) -> Result<c_int, ErrorStack> {
        unsafe {
            cvt(ffi::X509_REVOKED_set_serialNumber(
                self.as_ptr(),
                serial_number.as_ptr(),
            ))
        }
    }

    pub fn set_revoked_date(&mut self, revoke_date: &Asn1TimeRef) -> Result<c_int, ErrorStack> {
        unsafe {
            cvt(ffi::X509_REVOKED_set_revocationDate(
                self.as_ptr(),
                revoke_date.as_ptr(),
            ))
        }
    }
}
