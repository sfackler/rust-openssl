use ffi::{
    ASIdOrRange_id, ASIdOrRange_range, ASIdentifierChoice_asIdsOrRanges,
    ASIdentifierChoice_inherit, ASN1_INTEGER,
};
use foreign_types::{ForeignType, ForeignTypeRef};

use crate::{
    asn1::Asn1IntegerRef,
    stack::{StackRef, Stackable},
    util::{ForeignTypeExt, ForeignTypeRefExt},
};

use super::X509;

foreign_type_and_impl_send_sync! {
    type CType = ffi::_ASIdOrRange;
    fn drop = ffi::ASIdOrRange_free;

    /// The AS number extension of an `X509` certificate.
    pub struct ASIdOrRange;
    /// Reference to `ASIdOrRange`.
    pub struct ASIdOrRangeRef;
}

impl Stackable for ASIdOrRange {
    type StackType = ffi::stack_st_ASIdOrRange;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::_ASIdentifiers;
    fn drop = ffi::ASIdentifiers_free;

    /// The AS number extension of an `X509` certificate.
    pub struct ASIdentifiers;
    /// Reference to `ASIdentifiers`.
    pub struct ASIdentifiersRef;
}

impl ASIdentifiers {
    pub fn inherited(&self) -> bool {
        unsafe {
            let asptr = self.0;
            let asnum = (*asptr).asnum;
            (*asnum).type_ == ASIdentifierChoice_inherit
        }
    }

    pub fn ranges(&self) -> Option<Vec<(u32, u32)>> {
        let mut r = Vec::new();
        unsafe {
            let asptr = self.0;
            let asnum = (*asptr).asnum;
            if (*asnum).type_ == ASIdentifierChoice_asIdsOrRanges {
                if let Some(s) = StackRef::<ASIdOrRange>::from_const_ptr_opt((*asnum).asIdsOrRanges)
                {
                    for a_ptr in s {
                        let a = a_ptr.as_ptr();
                        if (*a).type_ == ASIdOrRange_id {
                            let asn = Self::parse_asn1_integer((*a).u.id)?;
                            r.push((asn, asn));
                        } else if (*a).type_ == ASIdOrRange_range {
                            let range = (*a).u.range;
                            let asn1 = Self::parse_asn1_integer((*range).min)?;
                            let asn2 = Self::parse_asn1_integer((*range).max)?;
                            r.push((asn1, asn2));
                        }
                    }
                }
            }
        }
        Some(r)
    }

    fn parse_asn1_integer(v: *mut ASN1_INTEGER) -> Option<u32> {
        let v_parsed;
        unsafe {
            v_parsed = Asn1IntegerRef::from_ptr(v);
        }
        v_parsed.to_bn().ok()?.to_dec_str().ok()?.parse().ok()
    }
}

pub trait ExtractASN {
    fn asn(&self) -> Option<ASIdentifiers>;
}

impl ExtractASN for X509 {
    fn asn(&self) -> Option<ASIdentifiers> {
        unsafe {
            let asn = ffi::X509_get_ext_d2i(
                self.as_ptr(),
                ffi::NID_sbgp_autonomousSysNum,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            ASIdentifiers::from_ptr_opt(asn as *mut _)
        }
    }
}
