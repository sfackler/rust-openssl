use ffi;
use std::ops::Deref;

use cvt_p;
use error::ErrorStack;
use nid::Nid;
use opaque::Opaque;

pub struct EcKeyRef(Opaque);

impl EcKeyRef {
    pub unsafe fn from_ptr<'a>(ptr: *mut ffi::EC_KEY) -> &'a EcKeyRef {
        &*(ptr as *mut _)
    }

    pub fn as_ptr(&self) -> *mut ffi::EC_KEY {
        self as *const _ as *mut _
    }
}

pub struct EcKey(*mut ffi::EC_KEY);

impl Drop for EcKey {
    fn drop(&mut self) {
        unsafe {
            ffi::EC_KEY_free(self.0);
        }
    }
}

impl EcKey {
    pub fn new_by_curve_name(nid: Nid) -> Result<EcKey, ErrorStack> {
        unsafe {
            cvt_p(ffi::EC_KEY_new_by_curve_name(nid.as_raw())).map(EcKey)
        }
    }

    pub unsafe fn from_ptr(ptr: *mut ffi::EC_KEY) -> EcKey {
        EcKey(ptr)
    }
}

impl Deref for EcKey {
    type Target = EcKeyRef;

    fn deref(&self) -> &EcKeyRef {
        unsafe {
            EcKeyRef::from_ptr(self.0)
        }
    }
}

#[cfg(test)]
mod test {
    use nid;
    use super::*;

    #[test]
    fn new_by_curve_name() {
        EcKey::new_by_curve_name(nid::X9_62_PRIME256V1).unwrap();
    }
}
