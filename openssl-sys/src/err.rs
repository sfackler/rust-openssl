use libc::*;

pub const ERR_TXT_MALLOCED: c_int = 0x01;
pub const ERR_TXT_STRING: c_int = 0x02;

pub const ERR_LIB_SYS: c_int = 2;
pub const ERR_LIB_PEM: c_int = 9;
pub const ERR_LIB_ASN1: c_int = 13;

cfg_if! {
    if #[cfg(ossl300)] {
        pub const ERR_SYSTEM_FLAG: c_ulong = c_int::max_value() as c_ulong + 1;
        pub const ERR_SYSTEM_MASK: c_ulong = c_int::max_value() as c_ulong;

        pub const ERR_LIB_OFFSET: c_ulong = 23;
        pub const ERR_LIB_MASK: c_ulong = 0xff;
        pub const ERR_RFLAGS_OFFSET: c_ulong = 18;
        pub const ERR_RFLAGS_MASK: c_ulong = 0x1f;
        pub const ERR_REASON_MASK: c_ulong = 0x7FFFFF;

        pub const ERR_RFLAG_FATAL: c_ulong = 0x1 << ERR_RFLAGS_OFFSET;

        const_fn! {
            pub const fn ERR_SYSTEM_ERROR(errcode: c_ulong) -> bool {
                errcode & ERR_SYSTEM_FLAG != 0
            }

            pub const fn ERR_GET_LIB(errcode: c_ulong) -> c_int {
                // hacks since `if` isn't yet stable in const functions :(
                ((ERR_LIB_SYS as c_ulong * (ERR_SYSTEM_ERROR(errcode) as c_ulong)) |
                (((errcode >> ERR_LIB_OFFSET) & ERR_LIB_MASK)) * (!ERR_SYSTEM_ERROR(errcode) as c_ulong)) as c_int
            }

            pub const fn ERR_GET_FUNC(_errcode: c_ulong) -> c_int {
                0
            }

            pub const fn ERR_GET_REASON(errcode: c_ulong) -> c_int {
                // hacks since `if` isn't yet stable in const functions :(
                ((ERR_LIB_SYS as c_ulong * (ERR_SYSTEM_ERROR(errcode) as c_ulong)) |
                ((errcode & ERR_REASON_MASK)) * (!ERR_SYSTEM_ERROR(errcode) as c_ulong)) as c_int
            }

            pub const fn ERR_PACK(lib: c_int, _func: c_int, reason: c_int) -> c_ulong {
                ((lib as c_ulong & ERR_LIB_MASK) << ERR_LIB_OFFSET) |
                ((reason as c_ulong & ERR_REASON_MASK))
            }
        }
    } else {
        const_fn! {
            pub const fn ERR_PACK(l: c_int, f: c_int, r: c_int) -> c_ulong {
                ((l as c_ulong & 0x0FF) << 24) |
                ((f as c_ulong & 0xFFF) << 12) |
                (r as c_ulong & 0xFFF)
            }

            pub const fn ERR_GET_LIB(l: c_ulong) -> c_int {
                ((l >> 24) & 0x0FF) as c_int
            }

            pub const fn ERR_GET_FUNC(l: c_ulong) -> c_int {
                ((l >> 12) & 0xFFF) as c_int
            }

            pub const fn ERR_GET_REASON(l: c_ulong) -> c_int {
                (l & 0xFFF) as c_int
            }
        }
    }
}

#[repr(C)]
pub struct ERR_STRING_DATA {
    pub error: c_ulong,
    pub string: *const c_char,
}

cfg_if! {
    if #[cfg(ossl300)] {
        extern "C" {
            pub fn ERR_new();
            pub fn ERR_set_debug(file: *const c_char, line: c_int, func: *const c_char);
            pub fn ERR_set_error(lib: c_int, reason: c_int, fmt: *const c_char, ...);
        }
    } else {
        extern "C" {
            pub fn ERR_put_error(lib: c_int, func: c_int, reason: c_int, file: *const c_char, line: c_int);
        }
    }
}

extern "C" {
    pub fn ERR_set_error_data(data: *mut c_char, flags: c_int);

    pub fn ERR_get_error() -> c_ulong;
    #[cfg(ossl300)]
    pub fn ERR_get_error_all(
        file: *mut *const c_char,
        line: *mut c_int,
        func: *mut *const c_char,
        data: *mut *const c_char,
        flags: *mut c_int,
    ) -> c_ulong;
    pub fn ERR_get_error_line_data(
        file: *mut *const c_char,
        line: *mut c_int,
        data: *mut *const c_char,
        flags: *mut c_int,
    ) -> c_ulong;
    pub fn ERR_peek_last_error() -> c_ulong;
    pub fn ERR_clear_error();
    pub fn ERR_lib_error_string(err: c_ulong) -> *const c_char;
    pub fn ERR_func_error_string(err: c_ulong) -> *const c_char;
    pub fn ERR_reason_error_string(err: c_ulong) -> *const c_char;
    #[cfg(ossl110)]
    pub fn ERR_load_strings(lib: c_int, str: *mut ERR_STRING_DATA) -> c_int;
    #[cfg(not(ossl110))]
    pub fn ERR_load_strings(lib: c_int, str: *mut ERR_STRING_DATA);
    #[cfg(not(ossl110))]
    pub fn ERR_load_crypto_strings();

    pub fn ERR_get_next_error_library() -> c_int;
}
