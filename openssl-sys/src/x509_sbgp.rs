use libc::*;

use super::*;

pub const ASIdOrRange_id: c_int = 0;
pub const ASIdOrRange_range: c_int = 1;

pub const ASIdentifierChoice_inherit: c_int = 0;
pub const ASIdentifierChoice_asIdsOrRanges: c_int = 1;

pub const IPAddressOrRange_addressPrefix: c_int = 0;
pub const IPAddressOrRange_addressRange: c_int = 1;

pub const IPAddressChoice_inherit: c_int = 0;
pub const IPAddressChoice_addressesOrRanges: c_int = 1;

pub const IANA_AFI_IPV4: c_int = 1;
pub const IANA_AFI_IPV6: c_int = 2;
