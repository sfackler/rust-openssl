#[cfg(ossl110)]
use std::mem::MaybeUninit;
#[cfg(ossl110)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(ossl110)]
use ffi::{
    ASIdOrRange_id, ASIdOrRange_range, ASIdentifierChoice_asIdsOrRanges,
    ASIdentifierChoice_inherit, IPAddressChoice_addressesOrRanges, X509v3_addr_get_afi,
    ASN1_INTEGER, IANA_AFI_IPV4, IANA_AFI_IPV6,
};
#[cfg(ossl110)]
use foreign_types::ForeignTypeRef;
#[cfg(ossl110)]
use openssl_macros::corresponds;

#[cfg(ossl110)]
use crate::{
    asn1::Asn1IntegerRef,
    stack::{Stack, StackRef, Stackable},
    util::{ForeignTypeExt, ForeignTypeRefExt},
};

#[cfg(ossl110)]
use super::X509Ref;

#[cfg(ossl110)]
foreign_type_and_impl_send_sync! {
    type CType = ffi::ASIdOrRange;
    fn drop = ffi::ASIdOrRange_free;

    /// The AS number extension of an `X509` certificate.
    pub struct ASIdOrRange;
    /// Reference to `ASIdOrRange`.
    pub struct ASIdOrRangeRef;
}
#[cfg(ossl110)]
impl Stackable for ASIdOrRange {
    type StackType = ffi::stack_st_ASIdOrRange;
}

#[cfg(ossl110)]
foreign_type_and_impl_send_sync! {
    type CType = ffi::ASIdentifiers;
    fn drop = ffi::ASIdentifiers_free;

    /// The AS number extension of an `X509` certificate.
    pub struct ASIdentifiers;
    /// Reference to `ASIdentifiers`.
    pub struct ASIdentifiersRef;
}

#[cfg(ossl110)]
impl ASIdentifiers {
    pub fn inherited(&self) -> bool {
        unsafe {
            let asptr = self.0;
            let asnum = (*asptr).asnum;
            (*asnum).type_ == ASIdentifierChoice_inherit
        }
    }

    pub fn ranges(&self) -> Option<Vec<(u32, u32)>> {
        unsafe {
            let mut result = Vec::new();
            let as_num = (*self.0).asnum;
            if (*as_num).type_ != ASIdentifierChoice_asIdsOrRanges {
                return None;
            }

            let stack = StackRef::<ASIdOrRange>::from_const_ptr_opt((*as_num).u.asIdsOrRanges)?;
            for asi_ref in stack {
                let asi = asi_ref.as_ptr();
                if (*asi).type_ == ASIdOrRange_id {
                    let asn = Self::parse_asn1_integer((*asi).u.id)?;
                    result.push((asn, asn));
                } else if (*asi).type_ == ASIdOrRange_range {
                    let range = (*asi).u.range;
                    let min = Self::parse_asn1_integer((*range).min)?;
                    let max = Self::parse_asn1_integer((*range).max)?;
                    result.push((min, max));
                }
            }

            Some(result)
        }
    }

    fn parse_asn1_integer(v: *mut ASN1_INTEGER) -> Option<u32> {
        unsafe {
            let v_ref = Asn1IntegerRef::from_ptr(v);
            v_ref.to_bn().ok()?.to_dec_str().ok()?.parse().ok()
        }
    }
}

#[cfg(ossl110)]
foreign_type_and_impl_send_sync! {
    type CType = ffi::IPAddressOrRange;
    fn drop = ffi::IPAddressOrRange_free;

    /// The AS number extension of an `X509` certificate.
    pub struct IPAddressOrRange;
    /// Reference to `IPAddressOrRange`.
    pub struct IPAddressOrRangeRef;
}

#[cfg(ossl110)]
impl Stackable for IPAddressOrRange {
    type StackType = ffi::stack_st_IPAddressOrRange;
}

#[cfg(ossl110)]
foreign_type_and_impl_send_sync! {
    type CType = ffi::IPAddressFamily;
    fn drop = ffi::IPAddressFamily_free;

    /// The AS number extension of an `X509` certificate.
    pub struct IPAddressFamily;
    /// Reference to `IPAddressFamily`.
    pub struct IPAddressFamilyRef;
}

#[cfg(ossl110)]
impl Stackable for IPAddressFamily {
    type StackType = ffi::stack_st_IPAddressFamily;
}

#[derive(PartialEq, Eq, Debug)]
#[cfg(ossl110)]
pub enum IPVersion {
    V4,
    V6,
}

#[cfg(ossl110)]
impl IPAddressFamily {
    #[corresponds(X509v3_addr_get_afi)]
    pub fn fam(&self) -> Option<IPVersion> {
        unsafe {
            let ptr = self.0;
            match X509v3_addr_get_afi(ptr) as libc::c_int {
                IANA_AFI_IPV4 => Some(IPVersion::V4),
                IANA_AFI_IPV6 => Some(IPVersion::V6),
                _ => None,
            }
        }
    }

    pub fn range(&self) -> Option<Vec<(IpAddr, IpAddr)>> {
        unsafe {
            let ptr = self.0;
            let mut r = Vec::new();
            let choice = (*ptr).ipAddressChoice;
            if (*choice).type_ != IPAddressChoice_addressesOrRanges {
                return None;
            }
            let stack =
                StackRef::<IPAddressOrRange>::from_const_ptr_opt((*choice).u.addressesOrRanges)?;
            for e in stack {
                let mut min = MaybeUninit::<[u8; 16]>::uninit();
                let mut max = MaybeUninit::<[u8; 16]>::uninit();
                let size = ffi::X509v3_addr_get_range(
                    e.as_ptr(),
                    X509v3_addr_get_afi(ptr),
                    min.as_mut_ptr() as *mut u8,
                    max.as_mut_ptr() as *mut u8,
                    16,
                );
                r.push((
                    Self::data_to_ip_addr(min.assume_init(), size)?,
                    Self::data_to_ip_addr(max.assume_init(), size)?,
                ))
            }
            Some(r)
        }
    }

    fn data_to_ip_addr(data: [u8; 16], len: i32) -> Option<IpAddr> {
        match len {
            4 => Some(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            16 => Some(IpAddr::V6(Ipv6Addr::from(data))),
            _ => None,
        }
    }
}

#[cfg(ossl110)]
impl X509Ref {
    #[corresponds(X509_get_ext_d2i)]
    pub fn sbgp_asn(&self) -> Option<ASIdentifiers> {
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

    #[corresponds(X509_get_ext_d2i)]
    pub fn sbgp_ip_addresses(&self) -> Option<Stack<IPAddressFamily>> {
        unsafe {
            let asn = ffi::X509_get_ext_d2i(
                self.as_ptr(),
                ffi::NID_sbgp_ipAddrBlock,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            Stack::from_ptr_opt(asn as *mut _)
        }
    }
}
