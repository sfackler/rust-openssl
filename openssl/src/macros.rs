
macro_rules! private_key_from_pem {
    ($t:ident, $f:path) => {
        from_pem_inner!(/// Deserializes a PEM-formatted private key.
            private_key_from_pem, $t, $f);

        /// Deserializes a PEM-formatted private key, using the supplied password if the key is
        /// encrypted.
        ///
        /// # Panics
        ///
        /// Panics if `passphrase` contains an embedded null.
        pub fn private_key_from_pem_passphrase(pem: &[u8],
                                               passphrase: &[u8])
                                               -> Result<$t, ::error::ErrorStack> {
            unsafe {
                ffi::init();
                let bio = try!(::bio::MemBioSlice::new(pem));
                let passphrase = ::std::ffi::CString::new(passphrase).unwrap();
                cvt_p($f(bio.as_ptr(),
                         ptr::null_mut(),
                         None,
                         passphrase.as_ptr() as *const _ as *mut _))
                    .map($t)
            }
        }

        /// Deserializes a PEM-formatted private key, using a callback to retrieve a password if the
        /// key is encrypted.
        ///
        /// The callback should copy the password into the provided buffer and return the number of
        /// bytes written.
        pub fn private_key_from_pem_callback<F>(pem: &[u8],
                                                callback: F)
                                                -> Result<$t, ::error::ErrorStack>
            where F: FnOnce(&mut [u8]) -> Result<usize, ::error::ErrorStack>
        {
            unsafe {
                ffi::init();
                let mut cb = ::util::CallbackState::new(callback);
                let bio = try!(::bio::MemBioSlice::new(pem));
                cvt_p($f(bio.as_ptr(),
                         ptr::null_mut(),
                         Some(::util::invoke_passwd_cb::<F>),
                         &mut cb as *mut _ as *mut _))
                    .map($t)
            }
        }
    }
}

macro_rules! private_key_to_pem {
    ($f:path) => {
        /// Serializes the private key to PEM.
        pub fn private_key_to_pem(&self) -> Result<Vec<u8>, ::error::ErrorStack> {
            unsafe {
                let bio = try!(::bio::MemBio::new());
                try!(cvt($f(bio.as_ptr(),
                            self.as_ptr(),
                            ptr::null(),
                            ptr::null_mut(),
                            -1,
                            None,
                            ptr::null_mut())));
                Ok(bio.get_buf().to_owned())
            }
        }

        /// Serializes the private key to PEM, encrypting it with the specified symmetric cipher and
        /// passphrase.
        pub fn private_key_to_pem_passphrase(&self,
                                             cipher: ::symm::Cipher,
                                             passphrase: &[u8])
                                             -> Result<Vec<u8>, ::error::ErrorStack> {
            unsafe {
                let bio = try!(::bio::MemBio::new());
                assert!(passphrase.len() <= ::libc::c_int::max_value() as usize);
                try!(cvt($f(bio.as_ptr(),
                            self.as_ptr(),
                            cipher.as_ptr(),
                            passphrase.as_ptr() as *const _ as *mut _,
                            passphrase.len() as ::libc::c_int,
                            None,
                            ptr::null_mut())));
                Ok(bio.get_buf().to_owned())
            }
        }
    }
}

macro_rules! to_pem_inner {
    (#[$m:meta] $n:ident, $f:path) => {
        #[$m]
        pub fn $n(&self) -> Result<Vec<u8>, ::error::ErrorStack> {
            unsafe {
                let bio = try!(::bio::MemBio::new());
                try!(cvt($f(bio.as_ptr(), self.as_ptr())));
                Ok(bio.get_buf().to_owned())
            }
        }
    }
}

macro_rules! public_key_to_pem {
    ($f:path) => {
        to_pem_inner!(/// Serializes a public key to PEM.
            public_key_to_pem, $f);
    }
}

macro_rules! to_pem {
    ($f:path) => {
        to_pem_inner!(/// Serializes this value to PEM.
            to_pem, $f);
    }
}

macro_rules! to_der_inner {
    (#[$m:meta] $n:ident, $f:path) => {
        #[$m]
        pub fn $n(&self) -> Result<Vec<u8>, ::error::ErrorStack> {
            unsafe {
                let len = try!(::cvt($f(::foreign_types::ForeignTypeRef::as_ptr(self),
                                        ptr::null_mut())));
                let mut buf = vec![0; len as usize];
                try!(::cvt($f(::foreign_types::ForeignTypeRef::as_ptr(self),
                              &mut buf.as_mut_ptr())));
                Ok(buf)
            }
        }
    };
}

macro_rules! to_der {
    ($f:path) => {
        to_der_inner!(/// Serializes this value to DER.
            to_der, $f);
    }
}

macro_rules! private_key_to_der {
    ($f:path) => {
        to_der_inner!(/// Serializes the private key to DER.
            private_key_to_der, $f);
    }
}

macro_rules! public_key_to_der {
    ($f:path) => {
        to_der_inner!(/// Serializes the public key to DER.
            public_key_to_der, $f);
    }
}

macro_rules! from_der_inner {
    (#[$m:meta] $n:ident, $t:ident, $f:path) => {
        #[$m]
        pub fn $n(der: &[u8]) -> Result<$t, ::error::ErrorStack> {
            unsafe {
                ::ffi::init();
                let len = ::std::cmp::min(der.len(), ::libc::c_long::max_value() as usize) as ::libc::c_long;
                ::cvt_p($f(::std::ptr::null_mut(), &mut der.as_ptr(), len))
                    .map($t)
            }
        }
    }
}

macro_rules! from_der {
    ($t:ident, $f:path) => {
        from_der_inner!(/// Deserializes a value from DER-formatted data.
            from_der, $t, $f);
    }
}

macro_rules! private_key_from_der {
    ($t:ident, $f:path) => {
        from_der_inner!(/// Deserializes a private key from DER-formatted data.
            private_key_from_der, $t, $f);
    }
}

macro_rules! public_key_from_der {
    ($t:ident, $f:path) => {
        from_der_inner!(/// Deserializes a public key from DER-formatted data.
            public_key_from_der, $t, $f);
    }
}

macro_rules! from_pem_inner {
    (#[$m:meta] $n:ident, $t:ident, $f:path) => {
        #[$m]
        pub fn $n(pem: &[u8]) -> Result<$t, ::error::ErrorStack> {
            unsafe {
                ::init();
                let bio = try!(::bio::MemBioSlice::new(pem));
                cvt_p($f(bio.as_ptr(), ::std::ptr::null_mut(), None, ::std::ptr::null_mut()))
                    .map($t)
            }
        }
    }
}

macro_rules! public_key_from_pem {
    ($t:ident, $f:path) => {
        from_pem_inner!(/// Deserializes a public key from PEM-formatted data.
            public_key_from_pem, $t, $f);
    }
}

macro_rules! from_pem {
    ($t:ident, $f:path) => {
        from_pem_inner!(/// Deserializes a value from PEM-formatted data.
            from_pem, $t, $f);
    }
}
