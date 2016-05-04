use ffi;
use std::fmt;
use ssl::error::{SslError, StreamError};
use std::ptr;
use std::io::{self, Read};

use bn::BigNum;
use bio::MemBio;
use nid::Nid;

pub struct RSA(*mut ffi::RSA);

impl Drop for RSA {
    fn drop(&mut self) {
        unsafe {
            ffi::RSA_free(self.0);
        }
    }
}

impl RSA {
    /// only useful for associating the key material directly with the key, it's safer to use
    /// the supplied load and save methods for DER formatted keys.
    pub fn from_public_components(n: BigNum, e: BigNum) -> Result<RSA, SslError> {
        unsafe {
            let rsa = try_ssl_null!(ffi::RSA_new());
            (*rsa).n = n.into_raw();
            (*rsa).e = e.into_raw();
            Ok(RSA(rsa))
        }
    }
    
    pub fn from_private_components(n: BigNum, e: BigNum, d: BigNum, p: BigNum, q: BigNum, dp: BigNum, dq: BigNum, qi: BigNum) -> Result<RSA, SslError> {
        unsafe {
            let rsa = try_ssl_null!(ffi::RSA_new());
            (*rsa).n = n.into_raw();
            (*rsa).e = e.into_raw();
            (*rsa).d = d.into_raw();
            (*rsa).p = p.into_raw();
            (*rsa).q = q.into_raw();
            (*rsa).dmp1 = dp.into_raw();
            (*rsa).dmq1 = dq.into_raw();
            (*rsa).iqmp = qi.into_raw();
            Ok(RSA(rsa))
        }
    }

    /// the caller should assert that the rsa pointer is valid.
    pub unsafe fn from_raw(rsa: *mut ffi::RSA) -> RSA {
        RSA(rsa)
    }

    /// Reads an RSA private key from PEM formatted data.
    pub fn private_key_from_pem<R>(reader: &mut R) -> Result<RSA, SslError>
    where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio).map_err(StreamError));

        unsafe {
            let rsa = try_ssl_null!(ffi::PEM_read_bio_RSAPrivateKey(mem_bio.get_handle(),
                                                                    ptr::null_mut(),
                                                                    None,
                                                                    ptr::null_mut()));
            Ok(RSA(rsa))
        }
    }

    /// Reads an RSA public key from PEM formatted data.
    pub fn public_key_from_pem<R>(reader: &mut R) -> Result<RSA, SslError>
    where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio).map_err(StreamError));

        unsafe {
            let rsa = try_ssl_null!(ffi::PEM_read_bio_RSA_PUBKEY(mem_bio.get_handle(),
                                                                 ptr::null_mut(),
                                                                 None,
                                                                 ptr::null_mut()));
            Ok(RSA(rsa))
        }
    }
    
    pub fn size(&self) -> Result<u32, SslError> {
        if self.has_n() {
            unsafe {
                Ok(ffi::RSA_size(self.0) as u32)
            }
        } else {
            Err(SslError::OpenSslErrors(vec![]))
        }
    }
    
    pub fn sign(&self, hash_id: Nid, message: &[u8]) -> Result<Vec<u8>, SslError> {
        let k_len = try!(self.size());
        let mut sig = vec![0;k_len as usize];
        let mut sig_len = k_len;
        
        unsafe {
            let result = ffi::RSA_sign(hash_id as i32, message.as_ptr(), message.len() as u32, sig.as_mut_ptr(), &mut sig_len, self.0);
            assert!(sig_len == k_len);
            
            if result == 1 {
                Ok(sig)
            } else {
                Err(SslError::OpenSslErrors(vec![]))
            }
        }
    }
    
    pub fn verify(&self, hash_id: Nid, message: &[u8], sig: &[u8]) -> Result<bool, SslError> {
        unsafe {
            let result = ffi::RSA_verify(hash_id as i32, message.as_ptr(), message.len() as u32, sig.as_ptr(), sig.len() as u32, self.0);
            
            Ok(result == 1)
        }
    }    

    pub fn as_ptr(&self) -> *mut ffi::RSA {
        self.0
    }

    // The following getters are unsafe, since BigNum::new_from_ffi fails upon null pointers
    pub fn n(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi((*self.0).n)
        }
    }

    pub fn has_n(&self) -> bool {
        unsafe {
            !(*self.0).n.is_null()
        }
    }

    pub fn d(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi((*self.0).d)
        }
    }

    pub fn e(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi((*self.0).e)
        }
    }

    pub fn has_e(&self) -> bool {
        unsafe {
            !(*self.0).e.is_null()
        }
    }

    pub fn p(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi((*self.0).p)
        }
    }

    pub fn q(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi((*self.0).q)
        }
    }
}

impl fmt::Debug for RSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RSA")
    }
}
