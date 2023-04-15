use super::super::*;
use libc::*;

#[repr(C)]
pub struct ASRange {
    pub min: *mut ASN1_INTEGER,
    pub max: *mut ASN1_INTEGER,
}

#[repr(C)]
pub struct _ASIdOrRange {
    pub type_: c_int,
    pub u: ASIdOrRange_st_anon_union,
}

#[repr(C)]
pub union ASIdOrRange_st_anon_union {
    pub id: *mut ASN1_INTEGER,
    pub range: *mut ASRange,
}

stack!(stack_st_ASIdOrRange);

#[repr(C)]
pub struct ASIdentifierChoice {
    pub type_: c_int,
    pub asIdsOrRanges: *mut stack_st_ASIdOrRange,
}

#[repr(C)]
pub struct _ASIdentifiers {
    pub asnum: *mut ASIdentifierChoice,
    pub rdi: *mut ASIdentifierChoice,
}

extern "C" {
    pub fn ASIdentifiers_free(asi: *mut _ASIdentifiers);
    pub fn ASIdOrRange_free(asi: *mut _ASIdOrRange);
}
