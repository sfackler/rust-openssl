#![macro_use]

macro_rules! try_ssl_stream {
    ($e:expr) => (
        match $e {
            Ok(ok) => ok,
            Err(err) => return Err(StreamError(err))
        }
    )
}

/// Shortcut return with SSL error if something went wrong
macro_rules! try_ssl_if {
    ($e:expr) => (
        if $e {
            return Err(::error::ErrorStack::get().into())
        }
    )
}

/// Shortcut return with SSL error if last error result is 0
/// (default)
macro_rules! try_ssl{
    ($e:expr) => (try_ssl_if!($e == 0))
}

/// Shortcut return with SSL if got a null result
macro_rules! try_ssl_null{
    ($e:expr) => ({
        let t = $e;
        try_ssl_if!(t == ptr::null_mut());
        t
    })
}

/// Shortcut return with SSL error if last error result is -1
/// (default for size)
macro_rules! try_ssl_returns_size{
    ($e:expr) => (
        if $e == -1 {
            return Err(::error::ErrorStack::get().into())
        } else {
            $e
        }
    )
}

/// Lifts current SSL error code into Result<(), Error>
/// if expression is true
/// Lifting is actually a shortcut of the following form:
///
/// ```ignore
/// let _ = try!(something)
/// Ok(())
/// ```
macro_rules! lift_ssl_if{
    ($e:expr) => ( {
        if $e {
            Err(::error::ErrorStack::get().into())
        } else {
            Ok(())
        }
    })
}

/// Lifts current SSL error code into Result<(), Error>
/// if SSL returned 0 (default error indication)
macro_rules! lift_ssl {
    ($e:expr) => (lift_ssl_if!($e == 0))
}

/// Lifts current SSL error code into Result<(), Error>
/// if SSL returned -1 (default size error indication)
macro_rules! lift_ssl_returns_size {
    ($e:expr) => ( {
        if $e == -1 {
            Err(::error::ErrorStack::get().into())
        } else {
            Ok($e)
        }
    })
}

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
