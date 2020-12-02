use libc::*;

use *;

pub const SRTP_AES128_CM_SHA1_80: c_ulong = 0x0001;
pub const SRTP_AES128_CM_SHA1_32: c_ulong = 0x0002;
pub const SRTP_AES128_F8_SHA1_80: c_ulong = 0x0003;
pub const SRTP_AES128_F8_SHA1_32: c_ulong = 0x0004;
pub const SRTP_NULL_SHA1_80: c_ulong = 0x0005;
pub const SRTP_NULL_SHA1_32: c_ulong = 0x0006;

/* AEAD SRTP protection profiles from RFC 7714 */
#[cfg(ossl110)]
pub const SRTP_AEAD_AES_128_GCM: c_ulong = 0x0007;
#[cfg(ossl110)]
pub const SRTP_AEAD_AES_256_GCM: c_ulong = 0x0008;

extern "C" {
    pub fn SSL_CTX_set_tlsext_use_srtp(ctx: *mut SSL_CTX, profiles: *const c_char) -> c_int;
    pub fn SSL_set_tlsext_use_srtp(ssl: *mut SSL, profiles: *const c_char) -> c_int;

    pub fn SSL_get_srtp_profiles(ssl: *mut SSL) -> *mut stack_st_SRTP_PROTECTION_PROFILE;
    pub fn SSL_get_selected_srtp_profile(ssl: *mut SSL) -> *mut SRTP_PROTECTION_PROFILE;
}
