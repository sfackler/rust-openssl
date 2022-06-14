use libc::*;
use *;

/* Possible values for status. */
const TS_STATUS_GRANTED: c_int = 0;
const TS_STATUS_GRANTED_WITH_MODS: c_int = 1;
const TS_STATUS_REJECTION: c_int = 2;
const TS_STATUS_WAITING: c_int = 3;
const TS_STATUS_REVOCATION_WARNING: c_int = 4;
const TS_STATUS_REVOCATION_NOTIFICATION: c_int = 5;

/* Possible values for failure_info. */
const TS_INFO_BAD_ALG: c_int = 0;
const TS_INFO_BAD_REQUEST: c_int = 2;
const TS_INFO_BAD_DATA_FORMAT: c_int = 5;
const TS_INFO_TIME_NOT_AVAILABLE: c_int = 14;
const TS_INFO_UNACCEPTED_POLICY: c_int = 15;
const TS_INFO_UNACCEPTED_EXTENSION: c_int = 16;
const TS_INFO_ADD_INFO_NOT_AVAILABLE: c_int = 17;
const TS_INFO_SYSTEM_FAILURE: c_int = 25;
