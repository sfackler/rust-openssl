use std::mem::MaybeUninit;

use ffi::{
    ASIdOrRange_id, ASIdOrRange_range, ASIdentifierChoice_asIdsOrRanges,
    ASIdentifierChoice_inherit, IPAddressChoice_addressesOrRanges, X509v3_addr_get_afi,
    X509v3_addr_get_range, ASN1_INTEGER, IANA_AFI_IPV4, IANA_AFI_IPV6,
};
use foreign_types::{ForeignType, ForeignTypeRef};

use crate::{
    asn1::Asn1IntegerRef,
    stack::{Stack, StackRef, Stackable},
    util::{ForeignTypeExt, ForeignTypeRefExt},
};

use super::X509;

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASIdOrRange;
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
    type CType = ffi::ASIdentifiers;
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
        let asptr = self.0;
        unsafe {
            let asnum = (*asptr).asnum;
            if (*asnum).type_ != ASIdentifierChoice_asIdsOrRanges {
                return None;
            }
            if let Some(s) = StackRef::<ASIdOrRange>::from_const_ptr_opt((*asnum).asIdsOrRanges) {
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
            } else {
                return None;
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

foreign_type_and_impl_send_sync! {
    type CType = ffi::IPAddressOrRange;
    fn drop = ffi::IPAddressOrRange_free;

    /// The AS number extension of an `X509` certificate.
    pub struct IPAddressOrRange;
    /// Reference to `IPAddressOrRange`.
    pub struct IPAddressOrRangeRef;
}

impl Stackable for IPAddressOrRange {
    type StackType = ffi::stack_st_IPAddressOrRange;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::IPAddressFamily;
    fn drop = ffi::IPAddressFamily_free;

    /// The AS number extension of an `X509` certificate.
    pub struct IPAddressFamily;
    /// Reference to `IPAddressFamily`.
    pub struct IPAddressFamilyRef;
}

impl Stackable for IPAddressFamily {
    type StackType = ffi::stack_st_IPAddressFamily;
}

#[derive(PartialEq, Eq, Debug)]
pub enum IPVersion {
    V4,
    V6,
}

impl IPAddressFamily {
    pub fn fam(&self) -> Option<IPVersion> {
        let ptr = self.0;
        unsafe {
            match X509v3_addr_get_afi(ptr) {
                IANA_AFI_IPV4 => Some(IPVersion::V4),
                IANA_AFI_IPV6 => Some(IPVersion::V6),
                _ => None,
            }
        }
    }

    pub fn range(&self) -> Option<Vec<(std::net::IpAddr, std::net::IpAddr)>> {
        let ptr = self.0;
        let mut r = Vec::new();
        unsafe {
            let choice = (*ptr).ipAddressChoice;
            if (*choice).type_ != IPAddressChoice_addressesOrRanges {
                return None;
            }
            let stack =
                StackRef::<IPAddressOrRange>::from_const_ptr_opt((*choice).addressesOrRanges)?;
            for e in stack {
                let mut min = MaybeUninit::<[u8; 16]>::uninit();
                let mut max = MaybeUninit::<[u8; 16]>::uninit();
                let size = X509v3_addr_get_range(
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
        }
        Some(r)
    }

    fn data_to_ip_addr(data: [u8; 16], len: isize) -> Option<std::net::IpAddr> {
        match len {
            4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            16 => Some(std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                (data[0] as u16) << 8 | data[1] as u16,
                (data[2] as u16) << 8 | data[3] as u16,
                (data[4] as u16) << 8 | data[5] as u16,
                (data[6] as u16) << 8 | data[7] as u16,
                (data[8] as u16) << 8 | data[9] as u16,
                (data[10] as u16) << 8 | data[11] as u16,
                (data[12] as u16) << 8 | data[13] as u16,
                (data[14] as u16) << 8 | data[15] as u16,
            ))),
            _ => None,
        }
    }
}

pub trait ExtractSBGPInfo {
    fn asn(&self) -> Option<ASIdentifiers>;
    fn ip_addresses(&self) -> Option<Stack<IPAddressFamily>>;
}

impl ExtractSBGPInfo for X509 {
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

    fn ip_addresses(&self) -> Option<Stack<IPAddressFamily>> {
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
