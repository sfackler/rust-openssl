use *;

declare_std_functions! {
    type CType = DH;
    fn new = DH_new;
    fn free = DH_free;
    fn d2i = d2i_DHparams;
    fn i2d_constapi = i2d_DHparams;
}

extern "C" {
    #[cfg(ossl102)]
    pub fn DH_get_1024_160() -> *mut DH;
    #[cfg(ossl102)]
    pub fn DH_get_2048_224() -> *mut DH;
    #[cfg(ossl102)]
    pub fn DH_get_2048_256() -> *mut DH;

    #[cfg(any(ossl110, libressl273))]
    pub fn DH_set0_pqg(dh: *mut DH, p: *mut BIGNUM, q: *mut BIGNUM, g: *mut BIGNUM) -> c_int;
}
