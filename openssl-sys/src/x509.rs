use libc::*;

pub const X509_FILETYPE_PEM: c_int = 1;
pub const X509_FILETYPE_ASN1: c_int = 2;
pub const X509_FILETYPE_DEFAULT: c_int = 3;

pub const XN_FLAG_SEP_MASK: c_ulong = 0xf << 16;
pub const XN_FLAG_COMPAT: c_ulong = 0;
pub const XN_FLAG_SEP_COMMA_PLUS: c_ulong = 1 << 16;
pub const XN_FLAG_SEP_CPLUS_SPC: c_ulong = 2 << 16;
pub const XN_FLAG_SEP_SPLUS_SPC: c_ulong = 3 << 16;
pub const XN_FLAG_SEP_MULTILINE: c_ulong = 4 << 16;
pub const XN_FLAG_DN_REV: c_ulong = 1 << 20;
pub const XN_FLAG_FN_MASK: c_ulong = 0x3 << 21;
pub const XN_FLAG_FN_SN: c_ulong = 0;
pub const XN_FLAG_FN_LN: c_ulong = 1 << 21;
pub const XN_FLAG_FN_OID: c_ulong = 2 << 21;
pub const XN_FLAG_FN_NONE: c_ulong = 3 << 21;
pub const XN_FLAG_SPC_EQ: c_ulong = 1 << 23;
pub const XN_FLAG_DUMP_UNKNOWN_FIELDS: c_ulong = 1 << 24;
pub const XN_FLAG_FN_ALIGN: c_ulong = 1 << 25;
pub const XN_FLAG_RFC2253: c_ulong = ASN1_STRFLGS_RFC2253
    | XN_FLAG_SEP_COMMA_PLUS
    | XN_FLAG_DN_REV
    | XN_FLAG_FN_SN
    | XN_FLAG_DUMP_UNKNOWN_FIELDS;
pub const XN_FLAG_ONELINE: c_ulong = ASN1_STRFLGS_RFC2253
    | ASN1_STRFLGS_ESC_QUOTE
    | XN_FLAG_SEP_CPLUS_SPC
    | XN_FLAG_SPC_EQ
    | XN_FLAG_FN_SN;
pub const XN_FLAG_MULTILINE: c_ulong = ASN1_STRFLGS_ESC_CTRL
    | ASN1_STRFLGS_ESC_MSB
    | XN_FLAG_SEP_MULTILINE
    | XN_FLAG_SPC_EQ
    | XN_FLAG_FN_LN
    | XN_FLAG_FN_ALIGN;

pub const ASN1_R_HEADER_TOO_LONG: c_int = 123;

pub const ASN1_STRFLGS_ESC_2253: c_ulong = 1;
pub const ASN1_STRFLGS_ESC_CTRL: c_ulong = 2;
pub const ASN1_STRFLGS_ESC_MSB: c_ulong = 4;
pub const ASN1_STRFLGS_ESC_QUOTE: c_ulong = 8;
pub const ASN1_STRFLGS_UTF8_CONVERT: c_ulong = 0x10;
pub const ASN1_STRFLGS_IGNORE_TYPE: c_ulong = 0x20;
pub const ASN1_STRFLGS_SHOW_TYPE: c_ulong = 0x40;
pub const ASN1_STRFLGS_DUMP_ALL: c_ulong = 0x80;
pub const ASN1_STRFLGS_DUMP_UNKNOWN: c_ulong = 0x100;
pub const ASN1_STRFLGS_DUMP_DER: c_ulong = 0x200;
pub const ASN1_STRFLGS_ESC_2254: c_ulong = 0x400;
pub const ASN1_STRFLGS_RFC2253: c_ulong = ASN1_STRFLGS_ESC_2253
    | ASN1_STRFLGS_ESC_CTRL
    | ASN1_STRFLGS_ESC_MSB
    | ASN1_STRFLGS_UTF8_CONVERT
    | ASN1_STRFLGS_DUMP_UNKNOWN
    | ASN1_STRFLGS_DUMP_DER;

cfg_if! {
    if #[cfg(not(any(ossl110, libressl350)))] {
        pub const X509_LU_FAIL: c_int = 0;
        pub const X509_LU_X509: c_int = 1;
        pub const X509_LU_CRL: c_int = 2;
    }
}
