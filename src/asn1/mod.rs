pub mod ffi {
    #![allow(dead_code)]
    #![allow(non_camel_case_types)]
    use libc::{c_int, c_long, c_void};

    pub type ASN1_INTEGER = c_void;
    pub type ASN1_TIME = c_void;
    pub type ASN1_STRING = c_void;

    pub static MBSTRING_FLAG: c_int = 0x1000;
    pub static MBSTRING_UTF8: c_int = MBSTRING_FLAG;
    pub static MBSTRING_ASC:  c_int = MBSTRING_FLAG | 1;
    pub static MBSTRING_BMP:  c_int = MBSTRING_FLAG | 2;
    pub static MBSTRING_UNIV: c_int = MBSTRING_FLAG | 4;

    pub static V_ASN1_UTCTIME:         c_int = 23;
    pub static V_ASN1_GENERALIZEDTIME: c_int = 24;

    extern "C" {
        pub fn ASN1_STRING_type_new(ty: c_int) -> *mut ASN1_STRING;
        pub fn ASN1_INTEGER_set(dest: *mut ASN1_INTEGER, value: c_long) -> c_int;
    }
}
