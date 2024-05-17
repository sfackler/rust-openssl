use super::super::*;

pub const CONF_MFLAGS_IGNORE_ERRORS: c_ulong = 0x1;
pub const CONF_MFLAGS_IGNORE_RETURN_CODES: c_ulong = 0x2;
pub const CONF_MFLAGS_SILENT: c_ulong = 0x4;
pub const CONF_MFLAGS_NO_DSO: c_ulong = 0x8;
pub const CONF_MFLAGS_IGNORE_MISSING_FILE: c_ulong = 0x10;
pub const CONF_MFLAGS_DEFAULT_SECTION: c_ulong = 0x20;

extern "C" {
    pub fn NCONF_new(meth: *mut CONF_METHOD) -> *mut CONF;
    pub fn NCONF_default() -> *mut CONF_METHOD;
    pub fn NCONF_free(conf: *mut CONF);
    pub fn CONF_modules_load_file(
        filename: *const c_char,
        appname: *const c_char,
        flags: c_ulong,
    ) -> c_int;
}
