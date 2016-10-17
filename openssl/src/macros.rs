#![macro_use]

#[cfg(ossl10x)]
macro_rules! CRYPTO_free {
    ($e:expr) => (::ffi::CRYPTO_free($e))
}

#[cfg(ossl110)]
macro_rules! CRYPTO_free {
    ($e:expr) => (
        ::ffi::CRYPTO_free($e,
                           concat!(file!(), "\0").as_ptr() as *const _,
                           line!() as i32)
    )
}
