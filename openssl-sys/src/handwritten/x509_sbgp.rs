use super::super::*;
use libc::*;

#[repr(C)]
pub struct ASRange {
    pub min: *mut ASN1_INTEGER,
    pub max: *mut ASN1_INTEGER,
}

#[repr(C)]
pub struct ASIdOrRange {
    pub type_: c_int,
    pub u: ASIdOrRange_st_anon_union,
}

#[repr(C)]
pub union ASIdOrRange_st_anon_union {
    pub id: *mut ASN1_INTEGER,
    pub range: *mut ASRange,
}

stack!(stack_st_ASIdOrRange);
type ASIdOrRanges = stack_st_ASIdOrRange;

#[repr(C)]
pub union ASIdentifierChoice_st_anon_union {
    pub asIdsOrRanges: *mut stack_st_ASIdOrRange,
}

#[repr(C)]
pub struct ASIdentifierChoice {
    pub type_: c_int,
    pub u: ASIdentifierChoice_st_anon_union,
}

#[repr(C)]
pub struct ASIdentifiers {
    pub asnum: *mut ASIdentifierChoice,
    pub rdi: *mut ASIdentifierChoice,
}

#[repr(C)]
pub struct IPAddressRange {
    pub min: *mut ASN1_BIT_STRING,
    pub max: *mut ASN1_BIT_STRING,
}

#[repr(C)]
pub struct IPAddressOrRange {
    pub type_: c_int,
    pub u: IPAddressOrRange_st_anon_union,
}
#[repr(C)]
pub union IPAddressOrRange_st_anon_union {
    pub addressPrefix: *mut ASN1_BIT_STRING,
    pub addressRange: *mut IPAddressRange,
}

stack!(stack_st_IPAddressOrRange);
type IPAddressOrRanges = stack_st_IPAddressOrRange;

#[repr(C)]
pub union IPAddressChoice_st_anon_union {
    pub addressesOrRanges: *mut IPAddressOrRanges,
}

#[repr(C)]
pub struct IPAddressChoice {
    pub type_: c_int,
    pub u: IPAddressChoice_st_anon_union,
}

#[repr(C)]
pub struct IPAddressFamily {
    pub addressFamily: *mut ASN1_OCTET_STRING,
    pub ipAddressChoice: *mut IPAddressChoice,
}

stack!(stack_st_IPAddressFamily);
type IPAddrBlocks = stack_st_IPAddressFamily;

extern "C" {
    /*
     * Constructors / Destructors for SBGP autonomousSysNum
     */
    pub fn ASIdentifiers_new() -> *mut ASIdentifiers;
    pub fn ASIdentifiers_free(asi: *mut ASIdentifiers);
    pub fn ASIdOrRange_free(asi: *mut ASIdOrRange);

    /*
     * Constructors / Destructors for SBGP ipAddrBlock
     */
    pub fn IPAddressFamily_free(asi: *mut IPAddressFamily);
    pub fn IPAddressOrRange_free(asi: *mut IPAddressOrRange);

    /*
     * Utility functions for working with RFC 3779 values,
     * since their encodings are a bit tedious.
     */
    pub fn X509v3_asid_add_id_or_range(
        asid: *mut ASIdentifiers,
        which: c_int,
        min: *mut ASN1_INTEGER,
        max: *mut ASN1_INTEGER,
    ) -> c_int;
    pub fn X509v3_asid_add_inherit(asid: *mut ASIdentifiers, which: c_int) -> c_int;
    pub fn X509v3_asid_canonize(asid: *mut ASIdentifiers) -> c_int;
    pub fn X509v3_asid_is_canonical(asid: *mut ASIdentifiers) -> c_int;
    pub fn X509v3_asid_inherits(asid: *mut ASIdentifiers) -> c_int;
    pub fn X509v3_asid_subset(child: *mut ASIdentifiers, parent: *mut ASIdentifiers) -> c_int;
    pub fn X509v3_asid_validate_path(ctx: *mut X509_STORE_CTX) -> c_int;
    pub fn X509v3_asid_validate_resource_set(
        chain: *mut stack_st_X509,
        ext: *mut ASIdentifiers,
        allow_inheritence: c_int,
    ) -> c_int;

    pub fn X509v3_addr_get_range(
        aor: *mut IPAddressOrRange,
        afi: c_uint,
        min: *mut c_uchar,
        max: *mut c_uchar,
        length: c_int,
    ) -> c_int;
    pub fn X509v3_addr_get_afi(f: *const IPAddressFamily) -> c_uint;
    pub fn X509v3_addr_add_range(
        addr: *mut IPAddrBlocks,
        afi: c_uint,
        safi: *const c_uint,
        min: *mut c_uchar,
        max: *mut c_uchar,
    ) -> c_int;
    pub fn X509v3_addr_add_inherit(
        addr: *mut IPAddrBlocks,
        afi: c_uint,
        safi: *const c_uint,
    ) -> c_int;
    pub fn X509v3_addr_canonize(addr: *mut IPAddrBlocks) -> c_int;
    pub fn X509v3_addr_is_canonical(addr: *mut IPAddrBlocks) -> c_int;
    pub fn X509v3_addr_inherits(addr: *mut IPAddrBlocks) -> c_int;
    pub fn X509v3_addr_subset(a: *mut IPAddrBlocks, b: *mut IPAddrBlocks) -> c_int;
    pub fn X509v3_addr_validate_path(ctx: *mut X509_STORE_CTX) -> c_int;
    pub fn X509v3_addr_validate_resource_set(
        chain: *mut stack_st_X509,
        ext: *mut IPAddrBlocks,
        allow_inheritence: c_int,
    ) -> c_int;
}
