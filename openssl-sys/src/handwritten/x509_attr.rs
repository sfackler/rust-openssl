use libc::*;

use *;

pub enum X509_ATTRIBUTE {}

stack!(stack_st_X509_ATTRIBUTE);

extern "C" {
    pub fn X509_ATTRIBUTE_new() -> *mut X509_ATTRIBUTE;
    pub fn X509_ATTRIBUTE_create(
        nid: c_int,
        atrtype: c_int,
        value: *mut c_void,
    ) -> *mut X509_ATTRIBUTE;
    pub fn X509_ATTRIBUTE_create_by_NID(
        attr: *mut *mut X509_ATTRIBUTE,
        nid: c_int,
        atrtype: c_int,
        data: *const c_void,
        len: c_int,
    ) -> *mut X509_ATTRIBUTE;
    pub fn X509_ATTRIBUTE_create_by_OBJ(
        attr: *mut *mut X509_ATTRIBUTE,
        obj: *const ASN1_OBJECT,
        atrtype: c_int,
        data: *const c_void,
        len: c_int,
    ) -> *mut X509_ATTRIBUTE;
    pub fn X509_ATTRIBUTE_create_by_txt(
        attr: *mut *mut X509_ATTRIBUTE,
        atrname: *const c_char,
        atrtype: c_int,
        bytes: *const c_uchar,
        len: c_int,
    ) -> *mut X509_ATTRIBUTE;
    pub fn X509_ATTRIBUTE_set1_object(attr: *mut X509_ATTRIBUTE, obj: *const ASN1_OBJECT) -> c_int;
    pub fn X509_ATTRIBUTE_set1_data(
        attr: *mut X509_ATTRIBUTE,
        attrtype: c_int,
        data: *const c_void,
        len: c_int,
    ) -> c_int;
    pub fn X509_ATTRIBUTE_get0_data(
        attr: *mut X509_ATTRIBUTE,
        idx: c_int,
        atrtype: c_int,
        data: *mut c_void,
    ) -> *mut c_void;
}
const_ptr_api! {
    extern "C" {
        pub fn X509_ATTRIBUTE_count(
            attr: #[const_ptr_if(any(ossl110, ossl111, ossl300))] X509_ATTRIBUTE // const since OpenSSL v1.1.0
        ) -> c_int;
    }
}
