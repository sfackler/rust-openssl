// vendored from the cfg-if crate to avoid breaking ctest
macro_rules! cfg_if {
    // match if/else chains with a final `else`
    ($(
        if #[cfg($($meta:meta),*)] { $($it:item)* }
    ) else * else {
        $($it2:item)*
    }) => {
        cfg_if! {
            @__items
            () ;
            $( ( ($($meta),*) ($($it)*) ), )*
            ( () ($($it2)*) ),
        }
    };

    // match if/else chains lacking a final `else`
    (
        if #[cfg($($i_met:meta),*)] { $($i_it:item)* }
        $(
            else if #[cfg($($e_met:meta),*)] { $($e_it:item)* }
        )*
    ) => {
        cfg_if! {
            @__items
            () ;
            ( ($($i_met),*) ($($i_it)*) ),
            $( ( ($($e_met),*) ($($e_it)*) ), )*
            ( () () ),
        }
    };

    // Internal and recursive macro to emit all the items
    //
    // Collects all the negated cfgs in a list at the beginning and after the
    // semicolon is all the remaining items
    (@__items ($($not:meta,)*) ; ) => {};
    (@__items ($($not:meta,)*) ; ( ($($m:meta),*) ($($it:item)*) ), $($rest:tt)*) => {
        // Emit all items within one block, applying an approprate #[cfg]. The
        // #[cfg] will require all `$m` matchers specified and must also negate
        // all previous matchers.
        cfg_if! { @__apply cfg(all($($m,)* not(any($($not),*)))), $($it)* }

        // Recurse to emit all other items in `$rest`, and when we do so add all
        // our `$m` matchers to the list of `$not` matchers as future emissions
        // will have to negate everything we just matched as well.
        cfg_if! { @__items ($($not,)* $($m,)*) ; $($rest)* }
    };

    // Internal macro to Apply a cfg attribute to a list of items
    (@__apply $m:meta, $($it:item)*) => {
        $(#[$m] $it)*
    };
}

macro_rules! stack {
    ($t:ident) => {
        cfg_if! {
            if #[cfg(ossl110)] {
                pub enum $t {}
            } else {
                #[repr(C)]
                pub struct $t {
                    pub stack: ::_STACK,
                }
            }
        }
    };
}

#[cfg(const_fn)]
macro_rules! const_fn {
    ($(pub const fn $name:ident($($arg:ident: $t:ty),*) -> $ret:ty $b:block)*) => {
        $(
            pub const fn $name($($arg: $t),*) -> $ret $b
        )*
    }
}

#[cfg(not(const_fn))]
macro_rules! const_fn {
    ($(pub const fn $name:ident($($arg:ident: $t:ty),*) -> $ret:ty $b:block)*) => {
        $(
            pub fn $name($($arg: $t),*) -> $ret $b
        )*
    }
}

// match DECLARE_ASN1_FUNCTIONS #define in openssl, and more functions with a
// rather "standard" signature
//
//
// The list below defines those signatures (the identifier after `# fn` for
// functions and after `# static` for variables); those signatures can depend on
// the usual cfg version flags.
//
// Assuming changes to those signatures are made in a consistent way in
// openssl/libressl this should remove a lot of #[cfg] in the remaining part of
// the bindings.
//
// Use with syntax like this:
//
// ```
// declare_std_functions! {
//     type CType = ASN1_FOOTYPE;
//     static item = ASN1_FOOTYPE_it;
//     fn new = ASN1_FOOTYPE_new;
//     fn free = ASN1_FOOTYPE_free;
//     fn dup = ASN1_FOOTYPE_dup;
//     fn d2i = d2i_ASN1_FOOTYPE;
//     fn i2d = i2d_ASN1_FOOTYPE;
// }
// ```
//
// While the syntax does not suggest it, you can define multiple functions for
// the same signature like this:
// ```
//     fn d2i = d2i_FOOPublicKey;
//     fn d2i = d2i_FOOPrivateKey;
// ```
macro_rules! declare_std_functions {
    // each "item" should be exactly one 'static' or one 'fn', but the macro_rules parser is rather stubborn
    (
        type CType = $ctype:ty;
        $(
            $(#[$attr:meta])*
            $(static $static_id:ident = $static_name:ident)*
            $(fn $fn_id:ident = $fn_name:ident)*
            ;
        )*
    ) => {
        $(
            declare_std_functions!(
                (#
                    $(static $static_id)*
                    $(fn $fn_id)*
                )
                ($ctype) ($(#[$attr])*)
                (
                    $($static_name)*
                    $($fn_name)*
                )
            );
        )*
    };
    // impls for specific static $idents
    ( (# static item) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            $(#[$attr])*
            pub static $name: ASN1_ITEM;
        }
    };
    // impls for specific fn $idents
    ( (# fn new) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            $(#[$attr])*
            pub fn $name() -> *mut $ctype;
        }
    };
    ( (# fn free) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            $(#[$attr])*
            pub fn $name(x: *mut $ctype);
        }
    };
    ( (# fn dup_oldapi) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            // #[cfg(ossl3)] will take `x: *const $ctype`, but in older versions we need *mut
            $(#[$attr])*
            pub fn $name(x: *mut $ctype) -> *mut $ctype;
        }
    };
    ( (# fn dup) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            $(#[$attr])*
            pub fn $name(x: *const $ctype) -> *mut $ctype;
        }
    };
    ( (# fn up_ref) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            $(#[$attr])*
            pub fn $name(x: *mut $ctype) -> c_int;
        }
    };
    ( (# fn d2i) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            $(#[$attr])*
            pub fn $name(a: *mut *mut $ctype, pp: *mut *const c_uchar, length: c_long) -> *mut $ctype;
        }
    };
    ( (# fn i2d_constapi) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            // some i2d functions always took a const ptr
            $(#[$attr])*
            pub fn $name(a: *const $ctype, out: *mut *mut c_uchar) -> c_int;
        }
    };
    ( (# fn i2d) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            // with #[cfg(ossl3)] those will take `a: *const $ctype`
            $(#[$attr])*
            pub fn $name(a: *mut $ctype, out: *mut *mut c_uchar) -> c_int;
        }
    };
    ( (# fn d2i_bio) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            $(#[$attr])*
            pub fn $name(b: *mut BIO, x: *mut *mut $ctype) -> *mut $ctype;
        }
    };
    ( (# fn i2d_bio) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            // with #[cfg(ossl3)] those will take `x: *const $ctype`
            $(#[$attr])*
            pub fn $name(b: *mut BIO, x: *mut $ctype) -> c_int;
        }
    };
    // x509 extension stuff
    ( (# fn ext_delete) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            $(#[$attr])*
            pub fn $name(x: *mut $ctype, loc: c_int) -> *mut X509_EXTENSION;
        }
    };
    ( (# fn ext_add) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            $(#[$attr])*
            pub fn $name(x: *mut $ctype, ext: *mut X509_EXTENSION, loc: c_int) -> c_int;
        }
    };
    ( (# fn ext_add1_i2d) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            $(#[$attr])*
            pub fn $name(
                x: *mut $ctype,
                nid: c_int,
                value: *mut c_void,
                crit: c_int,
                flags: c_ulong,
            ) -> c_int;
        }
    };
    ( (# fn ext_get_count) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            #[cfg(any(ossl110, libressl280))]
            $(#[$attr])*
            pub fn $name(x: *const $ctype) -> c_int;
            #[cfg(not(any(ossl110, libressl280)))]
            $(#[$attr])*
            pub fn $name(x: *mut $ctype) -> c_int;
        }
    };
    ( (# fn ext_get_by_NID) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            #[cfg(any(ossl110, libressl280))]
            $(#[$attr])*
            pub fn $name(x: *const $ctype, nid: c_int, lastpos: c_int) -> c_int;
            #[cfg(not(any(ossl110, libressl280)))]
            $(#[$attr])*
            pub fn $name(x: *mut $ctype, nid: c_int, lastpos: c_int) -> c_int;
        }
    };
    ( (# fn ext_get_by_OBJ) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            #[cfg(any(ossl110, libressl280))]
            $(#[$attr])*
            pub fn $name(x: *const $ctype, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int;
            #[cfg(not(any(ossl110, libressl280)))]
            $(#[$attr])*
            pub fn $name(x: *mut $ctype, obj: *mut ASN1_OBJECT, lastpos: c_int) -> c_int;
        }
    };
    ( (# fn ext_get_by_critical) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            #[cfg(any(ossl110, libressl280))]
            $(#[$attr])*
            pub fn $name(x: *const $ctype, crit: c_int, lastpos: c_int) -> c_int;
            #[cfg(not(any(ossl110, libressl280)))]
            $(#[$attr])*
            pub fn $name(x: *mut $ctype, crit: c_int, lastpos: c_int) -> c_int;
        }
    };
    ( (# fn ext_get) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            #[cfg(any(ossl110, libressl280))]
            $(#[$attr])*
            pub fn $name(x: *const $ctype, loc: c_int) -> *mut X509_EXTENSION;
            #[cfg(not(any(ossl110, libressl280)))]
            $(#[$attr])*
            pub fn $name(x: *mut $ctype, loc: c_int) -> *mut X509_EXTENSION;
        }
    };
    ( (# fn ext_get_d2i) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        extern "C" {
            #[cfg(any(ossl110, libressl280))]
            $(#[$attr])*
            pub fn $name(
                x: *const $ctype,
                nid: c_int,
                crit: *mut c_int,
                idx: *mut c_int,
            ) -> *mut c_void;
            #[cfg(not(any(ossl110, libressl280)))]
            $(#[$attr])*
            pub fn $name(
                x: *mut $ctype,
                nid: c_int,
                crit: *mut c_int,
                idx: *mut c_int,
            ) -> *mut c_void;
        }
    };
    // handle unknown idents
    ( (# $item_type:ident $ident:ident) ($ctype:ty) ($(#[$attr:meta])*) ($name:ident)) => {
        compile_error!(concat!("unknown ASN.1 base ", stringify!($item_type), " ", stringify!($ident)));
    };
}
