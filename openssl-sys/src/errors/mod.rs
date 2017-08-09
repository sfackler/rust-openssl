mod errors_base;
pub use self::errors_base::*;

#[cfg(ossl101)]
pub use self::errors_101::*;
#[cfg(ossl101)]
mod errors_101;

#[cfg(ossl102)]
pub use self::errors_102::*;
#[cfg(ossl102)]
mod errors_102;

#[cfg(ossl110)]
pub use self::errors_110::*;
#[cfg(ossl110)]
mod errors_110;
