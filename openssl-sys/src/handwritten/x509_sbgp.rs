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
}

#[cfg(ossl110)]
pub unsafe fn X509v3_addr_get_afi(f: *mut IPAddressFamily) -> c_int {
    if f.is_null() {
        0
    } else {
        let d = (*f).addressFamily as *mut ASN1_STRING;
        if d.is_null() || ASN1_STRING_length(d) < 2 || ASN1_STRING_get0_data(d).is_null() {
            0
        } else {
            let raw = ASN1_STRING_get0_data(d);
            ((*raw.offset(0) as c_int) << 8) | *raw.offset(1) as c_int
        }
    }
}

#[cfg(ossl110)]
fn length_from_afi(afi: c_int) -> isize {
    match afi {
        IANA_AFI_IPV4 => 4,
        IANA_AFI_IPV6 => 16,
        _ => 0,
    }
}

#[cfg(ossl110)]
struct ASN1_STRING_internal {
    length: c_int,
    type_: c_int,
    data: *mut u8,
    /*
     * The value of the following field depends on the type being held.  It
     * is mostly being used for BIT_STRING so if the input data has a
     * non-zero 'unused bits' value, it will be handled correctly
     */
    flags: c_int,
}

/*
 * Expand the bitstring form of an address into a raw byte array.
 * At the moment this is coded for simplicity, not speed.
 */
#[cfg(ossl110)]
fn addr_expand(addr: *mut u8, bs: *const ASN1_BIT_STRING, length: isize, fill: u8) -> bool {
    unsafe {
        let str = bs as *mut ASN1_STRING;
        let str_len = ASN1_STRING_length(str);
        if str_len < 0 || str_len as isize > length {
            return false;
        }

        if str_len > 0 {
            // copy bytes
            let d = ASN1_STRING_get0_data(str);
            for i in 0..(str_len as isize) {
                *addr.offset(i) = *d.offset(i);
            }

            let internal_str = bs as *mut ASN1_STRING_internal;
            if ((*internal_str).flags & 7) != 0 {
                let mask = 0xFF >> (8 - ((*internal_str).flags & 7));
                let val = if fill == 0 {
                    *d.offset(str_len as isize - 1) & !mask
                } else {
                    *d.offset(str_len as isize - 1) | mask
                };
                *addr.offset(str_len as isize - 1) = val;
            }
        }

        // fill up bytes
        for i in (str_len as isize)..length {
            *addr.offset(i) = fill;
        }
    }

    true
}

/*
 * Extract min and max values from an IPAddressOrRange.
 */
#[cfg(ossl110)]
fn extract_min_max(aor: *mut IPAddressOrRange, min: *mut u8, max: *mut u8, length: isize) -> bool {
    unsafe {
        match (*aor).type_ {
            IPAddressOrRange_addressPrefix => {
                addr_expand(min, (*aor).u.addressPrefix, length, 0x00)
                    && addr_expand(max, (*aor).u.addressPrefix, length, 0xFF)
            }
            IPAddressOrRange_addressRange => {
                addr_expand(min, (*(*aor).u.addressRange).min, length, 0x00)
                    && addr_expand(max, (*(*aor).u.addressRange).max, length, 0xFF)
            }
            _ => false,
        }
    }
}

#[cfg(ossl110)]
pub fn X509v3_addr_get_range(
    aor: *mut IPAddressOrRange,
    afi: c_int,
    min: *mut u8,
    max: *mut u8,
    length: isize,
) -> isize {
    let afi_length = length_from_afi(afi);
    if aor.is_null() || min.is_null() || max.is_null() || afi_length == 0 || length < afi_length {
        return 0;
    }
    if !extract_min_max(aor, min, max, afi_length) {
        return 0;
    }
    afi_length
}
