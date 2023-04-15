use libc::*;

use super::*;

pub const ASIdOrRange_id: c_int = 0;
pub const ASIdOrRange_range: c_int = 1;

pub const ASIdentifierChoice_inherit: c_int = 0;
pub const ASIdentifierChoice_asIdsOrRanges: c_int = 1;
