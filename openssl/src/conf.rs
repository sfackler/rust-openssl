use ffi;

use cvt_p;
use error::ErrorStack;

pub struct ConfMethod(*mut ffi::CONF_METHOD);

impl ConfMethod {
    pub fn default() -> ConfMethod {
        unsafe {
            ffi::init();
            ConfMethod(ffi::NCONF_default())
        }
    }

    pub unsafe fn from_ptr(ptr: *mut ffi::CONF_METHOD) -> ConfMethod {
        ConfMethod(ptr)
    }

    pub fn as_ptr(&self) -> *mut ffi::CONF_METHOD {
        self.0
    }
}

foreign_type! {
    type CType = ffi::CONF;
    fn drop = ffi::NCONF_free;

    pub struct Conf;
    pub struct ConfRef;
}

impl Conf {
    pub fn new(method: ConfMethod) -> Result<Conf, ErrorStack> {
        unsafe { cvt_p(ffi::NCONF_new(method.as_ptr())).map(Conf) }
    }
}
