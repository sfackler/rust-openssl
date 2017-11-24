#![doc(hidden)]
#![deprecated(since = "0.9.20")]
use string::OpensslString;

#[deprecated(note = "renamed to OpensslString", since = "0.9.7")]
pub type CryptoString = OpensslString;

pub mod pkcs7;
