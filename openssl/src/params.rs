use std::ffi::CStr;
use std::fmt;
use std::mem;
use std::ptr;

use libc::*;

use crate::cvt_p;
use crate::error::ErrorStack;

enum Param {
    I32(*mut c_int),
    String(*mut c_char, usize),
    Vec(*mut c_void, usize),
}

impl Param {
    fn alloc_i32(val: i32) -> Result<Param, ErrorStack> {
        let p = unsafe {
            cvt_p(ffi::CRYPTO_malloc(
                mem::size_of::<c_int>(),
                concat!(file!(), "\0").as_ptr() as *const _,
                line!() as c_int,
            ))
        }? as *mut c_int;
        unsafe { *p = val };

        Ok(Param::I32(p))
    }

    fn alloc_string(val: &[u8]) -> Result<Param, ErrorStack> {
        let p = unsafe {
            cvt_p(ffi::CRYPTO_malloc(
                val.len(),
                concat!(file!(), "\0").as_ptr() as *const _,
                line!() as c_int,
            ))
        }?;
        unsafe { ptr::copy_nonoverlapping(val.as_ptr(), p as *mut u8, val.len()) };

        Ok(Param::String(p as *mut c_char, val.len()))
    }

    fn alloc_vec(val: &[u8]) -> Result<Param, ErrorStack> {
        let p = unsafe {
            cvt_p(ffi::CRYPTO_malloc(
                val.len(),
                concat!(file!(), "\0").as_ptr() as *const _,
                line!() as c_int,
            ))
        }?;
        unsafe { ptr::copy_nonoverlapping(val.as_ptr(), p as *mut u8, val.len()) };

        Ok(Param::Vec(p, val.len()))
    }
}

macro_rules! drop_param {
    ($p:ident) => {{
        #[cfg(not(ossl110))]
        ::ffi::CRYPTO_free($p as *mut c_void);
        #[cfg(ossl110)]
        ::ffi::CRYPTO_free(
            $p as *mut c_void,
            concat!(file!(), "\0").as_ptr() as *const _,
            line!() as c_int,
        );
    }};
}

impl Drop for Param {
    fn drop(&mut self) {
        unsafe {
            match *self {
                Param::I32(p) => drop_param!(p),
                Param::String(p, _) => drop_param!(p),
                Param::Vec(p, _) => drop_param!(p),
            }
        }
    }
}

pub struct ParamsBuilder(Vec<(&'static [u8], Param)>);

impl ParamsBuilder {
    pub fn with_capacity(capacity: usize) -> Self {
        let params = Vec::with_capacity(capacity);
        Self(params)
    }

    pub fn build(self) -> Params {
        let len = self.0.len();

        let mut params = Params {
            fixed: self.0,
            output: Vec::with_capacity(len + 1),
        };

        // Mapping each argument held in the builder, and mapping them to a new output Vec.
        // This new output vec is to be consumed by a EVP_KDF_CTX_set_params or similar function
        // the output vec references data held in the first vec.
        // Data is allocated by the openssl allocator, so assumed in a memory stable realm.
        // It's important the data does not move from the time we create the "output" slice and the
        // moment it's read by the EVP_KDF_CTX_set_params functions.
        for (name, ref mut p) in &mut params.fixed {
            use Param::*;
            let v = unsafe {
                match p {
                    I32(v) => {
                        let pname = name.as_ptr() as *const i8;
                        ffi::OSSL_PARAM_construct_int(pname, *v)
                    }
                    Vec(buf, len) => {
                        let pname = name.as_ptr() as *const i8;
                        ffi::OSSL_PARAM_construct_octet_string(pname, *buf, *len)
                    }
                    String(buf, len) => {
                        let pname = name.as_ptr() as *const i8;
                        ffi::OSSL_PARAM_construct_utf8_string(pname, *buf, *len)
                    }
                }
            };
            params.output.push(v);
        }
        params.output.push(ffi::OSSL_PARAM_END);
        params
    }
}

macro_rules! add_construct {
    ($func:ident, $name:ident, $ty:ty) => {
        impl ParamsBuilder {
            pub fn $func(&mut self, key: &'static [u8], val: $ty) -> Result<(), ErrorStack> {
                self.0.push((key, Param::$name(val)?));
                Ok(())
            }
        }
    };
}

add_construct!(add_i32, alloc_i32, i32);
add_construct!(add_string, alloc_string, &[u8]);
add_construct!(add_slice, alloc_vec, &[u8]);
// TODO(baloo): add u32, etc

pub struct Params {
    fixed: Vec<(&'static [u8], Param)>,
    output: Vec<ffi::OSSL_PARAM>,
}

impl Params {
    pub fn len(&self) -> usize {
        self.output.len()
    }

    pub fn as_mut_ptr(&mut self) -> *mut ffi::OSSL_PARAM {
        self.output.as_mut_ptr()
    }

    pub fn as_ptr(&mut self) -> *const ffi::OSSL_PARAM {
        self.output.as_ptr()
    }
}

impl fmt::Debug for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Params([")?;
        for o in &self.output {
            write!(f, "OSSL_PARAM {{")?;
            if o.data_type != 0 {
                write!(f, "name = {:?}, ", unsafe { CStr::from_ptr(o.key) })?;
                write!(f, "buf = {:?}, ", o.data )?;
                write!(f, "len = {:?}", o.data_size )?;
            } else {
                write!(f, "END")?;
            }

            write!(f, "}}, ")?;
        }
        write!(f, "])")
    }
}
