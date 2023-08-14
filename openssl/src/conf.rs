//! Interface for processing OpenSSL configuration files.

foreign_type_and_impl_send_sync! {
    type CType = ffi::CONF;
    fn drop = ffi::NCONF_free;

    pub struct Conf;
    pub struct ConfRef;
}

#[cfg(not(boringssl))]
mod methods {
    use super::Conf;
    use crate::cvt;
    use crate::cvt_p;
    use crate::error::ErrorStack;
    use libc::{c_int, c_ulong};
    use openssl_macros::corresponds;
    use std::ffi::CString;
    use std::path::Path;
    use std::ptr;

    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct ConfMflags(c_ulong);

    impl ConfMflags {
        pub const IGNORE_ERRORS: ConfMflags = ConfMflags(ffi::CONF_MFLAGS_IGNORE_ERRORS);
        pub const IGNORE_RETURN_CODES: ConfMflags =
            ConfMflags(ffi::CONF_MFLAGS_IGNORE_RETURN_CODES);
        pub const SILENT: ConfMflags = ConfMflags(ffi::CONF_MFLAGS_SILENT);
        pub const NO_DSO: ConfMflags = ConfMflags(ffi::CONF_MFLAGS_NO_DSO);
        pub const IGNORE_MISSING_FILE: ConfMflags =
            ConfMflags(ffi::CONF_MFLAGS_IGNORE_MISSING_FILE);
        pub const DEFAULT_SECTION: ConfMflags = ConfMflags(ffi::CONF_MFLAGS_DEFAULT_SECTION);
        pub const DEFAULT_CONF_MFLAGS: ConfMflags = ConfMflags(
            ffi::CONF_MFLAGS_DEFAULT_SECTION
                | ffi::CONF_MFLAGS_IGNORE_MISSING_FILE
                | ffi::CONF_MFLAGS_IGNORE_RETURN_CODES,
        );

        /// Constructs an `ConfMflags` from a raw OpenSSL value.
        pub fn from_raw(id: c_ulong) -> Self {
            ConfMflags(id)
        }

        /// Returns the raw OpenSSL value represented by this type.
        pub fn as_raw(&self) -> c_ulong {
            self.0
        }
    }
    pub struct ConfMethod(*mut ffi::CONF_METHOD);

    impl ConfMethod {
        /// Retrieve handle to the default OpenSSL configuration file processing function.
        #[corresponds(NCONF_default)]
        #[allow(clippy::should_implement_trait)]
        pub fn default() -> ConfMethod {
            unsafe {
                ffi::init();
                // `NCONF` stands for "New Conf", as described in crypto/conf/conf_lib.c. This is
                // a newer API than the "CONF classic" functions.
                ConfMethod(ffi::NCONF_default())
            }
        }

        /// Construct from raw pointer.
        ///
        /// # Safety
        ///
        /// The caller must ensure that the pointer is valid.
        pub unsafe fn from_ptr(ptr: *mut ffi::CONF_METHOD) -> ConfMethod {
            ConfMethod(ptr)
        }

        /// Convert to raw pointer.
        pub fn as_ptr(&self) -> *mut ffi::CONF_METHOD {
            self.0
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
        #[corresponds(NCONF_new)]
        pub fn new(method: ConfMethod) -> Result<Conf, ErrorStack> {
            unsafe { cvt_p(ffi::NCONF_new(method.as_ptr())).map(Conf) }
        }
    }

    /// configures OpenSSL using file filename and application name appname.
    /// If filename is None the standard OpenSSL configuration file is used
    /// If appname is None the standard OpenSSL application name openssl_conf is used.
    /// The behaviour can be customized using flags.
    #[corresponds(CONF_modules_load_file)]
    pub fn modules_load_file<P: AsRef<Path>>(
        filename: Option<P>,
        appname: Option<String>,
        flags: ConfMflags,
    ) -> Result<c_int, ErrorStack> {
        let filename =
            filename.map(|f| CString::new(f.as_ref().as_os_str().to_str().unwrap()).unwrap());
        let appname = appname.map(|a| CString::new(a).unwrap());

        unsafe {
            cvt(ffi::CONF_modules_load_file(
                filename.as_ref().map_or(ptr::null(), |f| f.as_ptr()),
                appname.as_ref().map_or(ptr::null(), |a| a.as_ptr()),
                flags.as_raw() as _,
            ))
        }
    }
}
#[cfg(not(boringssl))]
pub use methods::*;
