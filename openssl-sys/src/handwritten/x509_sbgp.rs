#[cfg(ossl110)]
use super::super::*;
#[cfg(ossl110)]
use libc::*;

#[repr(C)]
#[cfg(ossl110)]
pub struct ASRange {
    pub min: *mut ASN1_INTEGER,
    pub max: *mut ASN1_INTEGER,
}

#[repr(C)]
#[cfg(ossl110)]
pub struct ASIdOrRange {
    pub type_: c_int,
    pub u: ASIdOrRange_st_anon_union,
}

#[repr(C)]
#[cfg(ossl110)]
pub union ASIdOrRange_st_anon_union {
    pub id: *mut ASN1_INTEGER,
    pub range: *mut ASRange,
}

#[cfg(ossl110)]
stack!(stack_st_ASIdOrRange);

#[repr(C)]
#[cfg(ossl110)]
pub union ASIdentifierChoice_st_anon_union {
    pub asIdsOrRanges: *mut stack_st_ASIdOrRange,
}

#[repr(C)]
#[cfg(ossl110)]
pub struct ASIdentifierChoice {
    pub type_: c_int,
    pub u: ASIdentifierChoice_st_anon_union,
}

#[repr(C)]
#[cfg(ossl110)]
pub struct ASIdentifiers {
    pub asnum: *mut ASIdentifierChoice,
    pub rdi: *mut ASIdentifierChoice,
}

#[repr(C)]
#[cfg(ossl110)]
pub struct IPAddressRange {
    pub min: *mut ASN1_BIT_STRING,
    pub max: *mut ASN1_BIT_STRING,
}

#[repr(C)]
#[cfg(ossl110)]
pub struct IPAddressOrRange {
    pub type_: c_int,
    pub u: IPAddressOrRange_st_anon_union,
}
#[repr(C)]
#[cfg(ossl110)]
pub union IPAddressOrRange_st_anon_union {
    pub addressPrefix: *mut ASN1_BIT_STRING,
    pub addressRange: *mut IPAddressRange,
}

#[cfg(ossl110)]
stack!(stack_st_IPAddressOrRange);
#[cfg(ossl110)]
type IPAddressOrRanges = stack_st_IPAddressOrRange;

#[repr(C)]
#[cfg(ossl110)]
pub union IPAddressChoice_st_anon_union {
    pub addressesOrRanges: *mut IPAddressOrRanges,
}

#[repr(C)]
#[cfg(ossl110)]
pub struct IPAddressChoice {
    pub type_: c_int,
    pub u: IPAddressChoice_st_anon_union,
}

#[repr(C)]
#[cfg(ossl110)]
pub struct IPAddressFamily {
    pub addressFamily: *mut ASN1_OCTET_STRING,
    pub ipAddressChoice: *mut IPAddressChoice,
}

#[cfg(ossl110)]
stack!(stack_st_IPAddressFamily);
#[cfg(ossl110)]
type IPAddrBlocks = stack_st_IPAddressFamily;

#[cfg(ossl110)]
extern "C" {
    pub fn ASIdentifiers_free(asi: *mut ASIdentifiers);
    pub fn ASIdOrRange_free(asi: *mut ASIdOrRange);
    pub fn IPAddressFamily_free(asi: *mut IPAddressFamily);
    pub fn IPAddressOrRange_free(asi: *mut IPAddressOrRange);
    pub fn X509v3_addr_get_range(
        aor: *mut IPAddressOrRange,
        afi: c_uint,
        min: *mut c_uchar,
        max: *mut c_uchar,
        length: c_int,
    ) -> c_int;
    pub fn X509v3_addr_get_afi(f: *const IPAddressFamily) -> c_uint;
}
