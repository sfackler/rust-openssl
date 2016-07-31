use ffi;
use std::fmt;
use error::ErrorStack;
use std::ptr;
use std::io::{self, Read, Write};
use libc::{c_uint, c_int, c_char, c_void};

use bn::BigNum;
use bio::MemBio;
use crypto::hash;
use crypto::HashTypeInternals;
use crypto::util::{CallbackState, invoke_passwd_cb};


/// Builder for upfront DSA parameter generateration
pub struct DSAParams(*mut ffi::DSA);

impl DSAParams {
    pub fn with_size(size: usize) -> Result<DSAParams, ErrorStack> {
        unsafe {
            // Wrap it so that if we panic we'll call the dtor
            let dsa = DSAParams(try_ssl_null!(ffi::DSA_new()));
            try_ssl!(ffi::DSA_generate_parameters_ex(dsa.0, size as c_int, ptr::null(), 0,
                                                 ptr::null_mut(), ptr::null_mut(), ptr::null()));
            Ok(dsa)
        }
    }

    /// Generate a key pair from the initialized parameters
    pub fn generate(self) -> Result<DSA, ErrorStack> {
        unsafe {
            try_ssl!(ffi::DSA_generate_key(self.0));
            let dsa = DSA(self.0);
            ::std::mem::forget(self);
            Ok(dsa)
        }
    }
}

impl Drop for DSAParams {
    fn drop(&mut self) {
        unsafe {
            ffi::DSA_free(self.0);
        }
    }
}

pub struct DSA(*mut ffi::DSA);

impl Drop for DSA {
    fn drop(&mut self) {
        unsafe {
            ffi::DSA_free(self.0);
        }
    }
}

impl DSA {
    /// the caller should assert that the dsa pointer is valid.
    pub unsafe fn from_raw(dsa: *mut ffi::DSA) -> DSA {
        DSA(dsa)
    }

    /// Generate a DSA key pair
    /// For more complicated key generation scenarios see the `DSAParams` type
    pub fn generate(size: usize) -> Result<DSA, ErrorStack> {
        let params = try!(DSAParams::with_size(size));
        params.generate()
    }

    /// Reads a DSA private key from PEM formatted data.
    pub fn private_key_from_pem<R>(reader: &mut R) -> io::Result<DSA>
        where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio));

        unsafe {
            let dsa = try_ssl_null!(ffi::PEM_read_bio_DSAPrivateKey(mem_bio.get_handle(),
                                                                    ptr::null_mut(),
                                                                    None,
                                                                    ptr::null_mut()));
            let dsa = DSA(dsa);
            assert!(dsa.has_private_key());
            Ok(dsa)
        }
    }

    /// Read a private key from PEM supplying a password callback to be invoked if the private key
    /// is encrypted.
    ///
    /// The callback will be passed the password buffer and should return the number of characters
    /// placed into the buffer.
    pub fn private_key_from_pem_cb<R, F>(reader: &mut R, pass_cb: F) -> io::Result<DSA>
        where R: Read, F: FnOnce(&mut [c_char]) -> usize
    {
        let mut cb = CallbackState::new(pass_cb);
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio));

        unsafe {
            let cb_ptr = &mut cb as *mut _ as *mut c_void;
            let dsa = try_ssl_null!(ffi::PEM_read_bio_DSAPrivateKey(mem_bio.get_handle(),
                                                                    ptr::null_mut(),
                                                                    Some(invoke_passwd_cb::<F>),
                                                                    cb_ptr));
            let dsa = DSA(dsa);
            assert!(dsa.has_private_key());
            Ok(dsa)
        }
    }

    /// Writes an DSA private key as unencrypted PEM formatted data
    pub fn private_key_to_pem<W>(&self, writer: &mut W) -> io::Result<()>
        where W: Write
    {
        assert!(self.has_private_key());
        let mut mem_bio = try!(MemBio::new());

        unsafe {
            try_ssl!(ffi::PEM_write_bio_DSAPrivateKey(mem_bio.get_handle(), self.0,
                                              ptr::null(), ptr::null_mut(), 0,
                                              None, ptr::null_mut()))
        };


        try!(io::copy(&mut mem_bio, writer));
        Ok(())
    }

    /// Reads an DSA public key from PEM formatted data.
    pub fn public_key_from_pem<R>(reader: &mut R) -> io::Result<DSA>
        where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio));

        unsafe {
            let dsa = try_ssl_null!(ffi::PEM_read_bio_DSA_PUBKEY(mem_bio.get_handle(),
                                                                 ptr::null_mut(),
                                                                 None,
                                                                 ptr::null_mut()));
            Ok(DSA(dsa))
        }
    }

    /// Writes an DSA public key as PEM formatted data
    pub fn public_key_to_pem<W>(&self, writer: &mut W) -> io::Result<()>
        where W: Write
    {
        let mut mem_bio = try!(MemBio::new());

        unsafe { try_ssl!(ffi::PEM_write_bio_DSA_PUBKEY(mem_bio.get_handle(), self.0)) };

        try!(io::copy(&mut mem_bio, writer));
        Ok(())
    }

    pub fn size(&self) -> Option<u32> {
        if self.has_q() {
            unsafe { Some(ffi::DSA_size(self.0) as u32) }
        } else {
            None
        }
    }

    pub fn sign(&self, hash: hash::Type, message: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let k_len = self.size().expect("DSA missing a q") as c_uint;
        let mut sig = vec![0; k_len as usize];
        let mut sig_len = k_len;
        assert!(self.has_private_key());

        unsafe {
            try_ssl!(ffi::DSA_sign(hash.as_nid() as c_int,
                                   message.as_ptr(),
                                   message.len() as c_int,
                                   sig.as_mut_ptr(),
                                   &mut sig_len,
                                   self.0));
            sig.set_len(sig_len as usize);
            sig.shrink_to_fit();
            Ok(sig)
        }
    }

    pub fn verify(&self, hash: hash::Type, message: &[u8], sig: &[u8]) -> Result<bool, ErrorStack> {
        unsafe {
            let result = ffi::DSA_verify(hash.as_nid() as c_int,
                                         message.as_ptr(),
                                         message.len() as c_int,
                                         sig.as_ptr(),
                                         sig.len() as c_int,
                                         self.0);

            try_ssl_if!(result == -1);
            Ok(result == 1)
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::DSA {
        self.0
    }

    // The following getters are unsafe, since BigNum::new_from_ffi fails upon null pointers
    pub fn p(&self) -> Result<BigNum, ErrorStack> {
        unsafe { BigNum::new_from_ffi((*self.0).p) }
    }

    pub fn has_p(&self) -> bool {
        unsafe { !(*self.0).p.is_null() }
    }

    pub fn q(&self) -> Result<BigNum, ErrorStack> {
        unsafe { BigNum::new_from_ffi((*self.0).q) }
    }

    pub fn has_q(&self) -> bool {
        unsafe { !(*self.0).q.is_null() }
    }

    pub fn g(&self) -> Result<BigNum, ErrorStack> {
        unsafe { BigNum::new_from_ffi((*self.0).g) }
    }

    pub fn has_g(&self) -> bool {
        unsafe { !(*self.0).q.is_null() }
    }

    pub fn has_public_key(&self) -> bool {
        unsafe { !(*self.0).pub_key.is_null() }
    }

    pub fn has_private_key(&self) -> bool {
        unsafe { !(*self.0).priv_key.is_null() }
    }
}

impl fmt::Debug for DSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DSA")
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::{Write, Cursor};
    use super::*;
    use crypto::hash::*;

    #[test]
    pub fn test_generate() {
        let key = DSA::generate(1024).unwrap();
        let mut priv_buf = Cursor::new(vec![]);
        let mut pub_buf = Cursor::new(vec![]);

        key.public_key_to_pem(&mut pub_buf).unwrap();
        key.private_key_to_pem(&mut priv_buf).unwrap();

        let input: Vec<u8> = (0..25).cycle().take(1024).collect();

        let digest = {
            let mut sha = Hasher::new(Type::SHA1);
            sha.write_all(&input).unwrap();
            sha.finish()
        };

        let sig = key.sign(Type::SHA1, &digest).unwrap();
        let verified = key.verify(Type::SHA1, &digest, &sig).unwrap();
        assert!(verified);
    }

    #[test]
    pub fn test_sign_verify() {
        let input: Vec<u8> = (0..25).cycle().take(1024).collect();

        let private_key = {
            let mut buffer = File::open("test/dsa.pem").unwrap();
            DSA::private_key_from_pem(&mut buffer).unwrap()
        };

        let public_key = {
            let mut buffer = File::open("test/dsa.pem.pub").unwrap();
            DSA::public_key_from_pem(&mut buffer).unwrap()
        };

        let digest = {
            let mut sha = Hasher::new(Type::SHA1);
            sha.write_all(&input).unwrap();
            sha.finish()
        };

        let sig = private_key.sign(Type::SHA1, &digest).unwrap();
        let verified = public_key.verify(Type::SHA1, &digest, &sig).unwrap();
        assert!(verified);
    }

    #[test]
    pub fn test_sign_verify_fail() {
        let input: Vec<u8> = (0..25).cycle().take(128).collect();
        let private_key = {
            let mut buffer = File::open("test/dsa.pem").unwrap();
            DSA::private_key_from_pem(&mut buffer).unwrap()
        };

        let public_key = {
            let mut buffer = File::open("test/dsa.pem.pub").unwrap();
            DSA::public_key_from_pem(&mut buffer).unwrap()
        };

        let digest = {
            let mut sha = Hasher::new(Type::SHA1);
            sha.write_all(&input).unwrap();
            sha.finish()
        };

        let mut sig = private_key.sign(Type::SHA1, &digest).unwrap();
        // tamper with the sig this should cause a failure
        let len = sig.len();
        sig[len / 2] = 0;
        sig[len - 1] = 0;
        if let Ok(true) = public_key.verify(Type::SHA1, &digest, &sig) {
            panic!("Tampered with signatures should not verify!");
        }
    }

    #[test]
    pub fn test_password() {
        let mut password_queried = false;
        let mut buffer = File::open("test/dsa-encrypted.pem").unwrap();
        DSA::private_key_from_pem_cb(&mut buffer, |password| {
            password_queried = true;
            password[0] = b'm' as _;
            password[1] = b'y' as _;
            password[2] = b'p' as _;
            password[3] = b'a' as _;
            password[4] = b's' as _;
            password[5] = b's' as _;
            6
        }).unwrap();

        assert!(password_queried);
    }
}
