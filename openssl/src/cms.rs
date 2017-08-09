//! CMS archive

use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::ptr;
use error::ErrorStack;

use bio::{MemBio, MemBioSlice};

use x509::X509;
use pkey::PKeyRef;

use cvt;
use cvt_p;

foreign_type! {
    type CType = ffi::CMS_ContentInfo;
    fn drop = ffi::CMS_ContentInfo_free;

    pub struct CmsContentInfo;
    pub struct CmsContentInfoRef;
}

impl CmsContentInfoRef {
    pub fn decrypt(&self, pkey: &PKeyRef, cert: &X509) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let pkey = pkey.as_ptr();
            let cert = cert.as_ptr();
            let out = try!(MemBio::new());
            let flags: u32 = 0;

            try!(cvt(ffi::CMS_decrypt(
                self.as_ptr(),
                pkey,
                cert,
                ptr::null_mut(),
                out.as_ptr(),
                flags.into(),
            )));

            Ok(out.get_buf().to_owned())
        }
    }

}

impl CmsContentInfo {
    pub fn smime_read_cms(smime: &[u8]) -> Result<CmsContentInfo, ErrorStack> {
        unsafe {
            let bio = try!(MemBioSlice::new(smime));

            let cms = try!(cvt_p(ffi::SMIME_read_CMS(
                bio.as_ptr(),
                ptr::null_mut(),
            )));

            Ok(CmsContentInfo::from_ptr(cms))
        }
    }
}
