use libc::*;

pub const TS_STATUS_GRANTED: c_int = 0;
pub const TS_STATUS_GRANTED_WITH_MODS: c_int = 1;
pub const TS_STATUS_REJECTION: c_int = 2;
pub const TS_STATUS_WAITING: c_int = 3;
pub const TS_STATUS_REVOCATION_WARNING: c_int = 4;
pub const TS_STATUS_REVOCATION_NOTIFICATION: c_int = 5;

pub const TS_INFO_BAD_ALG: c_int = 0;
pub const TS_INFO_BAD_REQUEST: c_int = 2;
pub const TS_INFO_BAD_DATA_FORMAT: c_int = 5;
pub const TS_INFO_TIME_NOT_AVAILABLE: c_int = 14;
pub const TS_INFO_UNACCEPTED_POLICY: c_int = 15;
pub const TS_INFO_UNACCEPTED_EXTENSION: c_int = 16;
pub const TS_INFO_ADD_INFO_NOT_AVAILABLE: c_int = 17;
pub const TS_INFO_SYSTEM_FAILURE: c_int = 25;

pub const TS_TSA_NAME: c_int = 0x01;
pub const TS_ORDERING: c_int = 0x02;
pub const TS_ESS_CERT_ID_CHAIN: c_int = 0x04;

pub const TS_MAX_CLOCK_PRECISION_DIGITS: c_int = 6;
#[cfg(any(ossl102, libressl250))]
pub const TS_MAX_STATUS_LENGTH: c_int = 1024 * 1024;

pub const TS_VFY_SIGNATURE: c_uint = 1u32 << 0;
pub const TS_VFY_VERSION: c_uint = 1u32 << 1;
pub const TS_VFY_POLICY: c_uint = 1u32 << 2;
pub const TS_VFY_IMPRINT: c_uint = 1u32 << 3;
pub const TS_VFY_DATA: c_uint = 1u32 << 4;
pub const TS_VFY_NONCE: c_uint = 1u32 << 5;
pub const TS_VFY_SIGNER: c_uint = 1u32 << 6;
pub const TS_VFY_TSA_NAME: c_uint = 1u32 << 7;

pub const TS_VFY_ALL_IMPRINT: c_uint = TS_VFY_SIGNATURE
    | TS_VFY_VERSION
    | TS_VFY_POLICY
    | TS_VFY_IMPRINT
    | TS_VFY_NONCE
    | TS_VFY_SIGNER
    | TS_VFY_TSA_NAME;

pub const TS_VFY_ALL_DATA: c_uint = TS_VFY_SIGNATURE
    | TS_VFY_VERSION
    | TS_VFY_POLICY
    | TS_VFY_DATA
    | TS_VFY_NONCE
    | TS_VFY_SIGNER
    | TS_VFY_TSA_NAME;
