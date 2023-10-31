use foreign_types::ForeignType;

use std::ffi::CString;
use std::ptr;

use crate::cvt_p;
use crate::error::ErrorStack;
use crate::pkey::{PKey, Private};

pub struct Store(*mut ffi::OSSL_STORE_CTX);

impl Drop for Store {
    fn drop(&mut self) {
        unsafe {
            ffi::OSSL_STORE_close(self.0);
        }
    }
}

impl Store {
    pub fn private_key_from_uri(uri: &str) -> Result<Option<PKey<Private>>, ErrorStack> {
        let uri = CString::new(uri).unwrap();
        unsafe {
            let store = cvt_p(ffi::OSSL_STORE_open(
                uri.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            ))
            .map(|p| Store(p))?;

            let mut store_info = cvt_p(ffi::OSSL_STORE_load(store.0))?;

            while store_info != ptr::null_mut() {
                let type_ = ffi::OSSL_STORE_INFO_get_type(store_info);
                if type_ == ffi::OSSL_STORE_INFO_PKEY {
                    let pkey_ptr = cvt_p(ffi::OSSL_STORE_INFO_get1_PKEY(store_info))?;
                    return Ok(Some(PKey::from_ptr(pkey_ptr)));
                }

                ffi::OSSL_STORE_INFO_free(store_info);

                store_info = cvt_p(ffi::OSSL_STORE_load(store.0))?;
            }

            // error?
            Ok(None)
        }
    }
}
