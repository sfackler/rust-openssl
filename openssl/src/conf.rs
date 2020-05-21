//! Interface for processing OpenSSL configuration files.
use ffi;

use cvt_p;
use error::ErrorStack;

pub struct ConfMethod(*mut ffi::CONF_METHOD);

impl ConfMethod {
    /// Retrieve handle to the default OpenSSL configuration file processing function.
    pub fn default() -> ConfMethod {
        unsafe {
            ffi::init();
            // `NCONF` stands for "New Conf", as described in crypto/conf/conf_lib.c. This is
            // a newer API than the "CONF classic" functions.
            ConfMethod(ffi::NCONF_default())
        }
    }

    /// Construct from raw pointer.
    pub unsafe fn from_ptr(ptr: *mut ffi::CONF_METHOD) -> ConfMethod {
        ConfMethod(ptr)
    }

    /// Convert to raw pointer.
    pub fn as_ptr(&self) -> *mut ffi::CONF_METHOD {
        self.0
    }
}

foreign_type! {
    pub unsafe type Conf : Send + Sync {
      type CType = ffi::CONF;
      fn drop = ffi::NCONF_free;
    }
}

impl Conf {
    /// Create a configuration parser.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl::conf::{Conf, ConfMethod};
    ///
    /// let conf = Conf::new(ConfMethod::default());
    /// ```
    pub fn new(method: ConfMethod) -> Result<Conf, ErrorStack> {
        unsafe { cvt_p(ffi::NCONF_new(method.as_ptr())).map(Conf) }
    }
}
