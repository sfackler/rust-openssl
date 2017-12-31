
macro_rules! private_key_from_pem {
    ($t:ty, $f:path) => {
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
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
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
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
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
    (#[$m:meta] $n:ident, $t:ty, $f:path) => {
        #[$m]
        pub fn $n(der: &[u8]) -> Result<$t, ::error::ErrorStack> {
            unsafe {
                ::ffi::init();
                let len = ::std::cmp::min(der.len(), ::libc::c_long::max_value() as usize) as ::libc::c_long;
                ::cvt_p($f(::std::ptr::null_mut(), &mut der.as_ptr(), len))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }
    }
}

macro_rules! from_der {
    ($t:ty, $f:path) => {
        from_der_inner!(/// Deserializes a value from DER-formatted data.
            from_der, $t, $f);
    }
}

macro_rules! private_key_from_der {
    ($t:ty, $f:path) => {
        from_der_inner!(/// Deserializes a private key from DER-formatted data.
            private_key_from_der, $t, $f);
    }
}

macro_rules! public_key_from_der {
    ($t:ty, $f:path) => {
        from_der_inner!(/// Deserializes a public key from DER-formatted data.
            public_key_from_der, $t, $f);
    }
}

macro_rules! from_pem_inner {
    (#[$m:meta] $n:ident, $t:ty, $f:path) => {
        #[$m]
        pub fn $n(pem: &[u8]) -> Result<$t, ::error::ErrorStack> {
            unsafe {
                ::init();
                let bio = try!(::bio::MemBioSlice::new(pem));
                cvt_p($f(bio.as_ptr(), ::std::ptr::null_mut(), None, ::std::ptr::null_mut()))
                    .map(|p| ::foreign_types::ForeignType::from_ptr(p))
            }
        }
    }
}

macro_rules! public_key_from_pem {
    ($t:ty, $f:path) => {
        from_pem_inner!(/// Deserializes a public key from PEM-formatted data.
            public_key_from_pem, $t, $f);
    }
}

macro_rules! from_pem {
    ($t:ty, $f:path) => {
        from_pem_inner!(/// Deserializes a value from PEM-formatted data.
            from_pem, $t, $f);
    }
}

macro_rules! foreign_type_and_impl_send_sync {
    (
        $(#[$impl_attr:meta])*
        type CType = $ctype:ty;
        fn drop = $drop:expr;
        $(fn clone = $clone:expr;)*

        $(#[$owned_attr:meta])*
        pub struct $owned:ident;
        $(#[$borrowed_attr:meta])*
        pub struct $borrowed:ident;
    )
        => {
            foreign_type! {
                $(#[$impl_attr])*
                type CType = $ctype;
                fn drop = $drop;
                $(fn clone = $clone;)*
                $(#[$owned_attr])*
                pub struct $owned;
                $(#[$borrowed_attr])*
                pub struct $borrowed;
            }

            unsafe impl Send for $owned{}
            unsafe impl Send for $borrowed{}
            unsafe impl Sync for $owned{}
            unsafe impl Sync for $borrowed{}
        };
}

macro_rules! generic_foreign_type_and_impl_send_sync {
    (
        $(#[$impl_attr:meta])*
        type CType = $ctype:ty;
        fn drop = $drop:expr;
        $(fn clone = $clone:expr;)*

        $(#[$owned_attr:meta])*
        pub struct $owned:ident<T>;
        $(#[$borrowed_attr:meta])*
        pub struct $borrowed:ident<T>;
    ) => {
        $(#[$owned_attr])*
        pub struct $owned<T>(*mut $ctype, ::std::marker::PhantomData<T>);

        $(#[$impl_attr])*
        impl<T> ::foreign_types::ForeignType for $owned<T> {
            type CType = $ctype;
            type Ref = $borrowed<T>;

            #[inline]
            unsafe fn from_ptr(ptr: *mut $ctype) -> $owned<T> {
                $owned(ptr, ::std::marker::PhantomData)
            }

            #[inline]
            fn as_ptr(&self) -> *mut $ctype {
                self.0
            }
        }

        impl<T> Drop for $owned<T> {
            #[inline]
            fn drop(&mut self) {
                unsafe { $drop(self.0) }
            }
        }

        $(
            impl<T> Clone for $owned<T> {
                #[inline]
                fn clone(&self) -> $owned<T> {
                    unsafe {
                        let handle: *mut $ctype = $clone(self.0);
                        ::foreign_types::ForeignType::from_ptr(handle)
                    }
                }
            }

            impl<T> ::std::borrow::ToOwned for $borrowed<T> {
                type Owned = $owned<T>;
                #[inline]
                fn to_owned(&self) -> $owned<T> {
                    unsafe {
                        let handle: *mut $ctype =
                            $clone(::foreign_types::ForeignTypeRef::as_ptr(self));
                        $crate::ForeignType::from_ptr(handle)
                    }
                }
            }
        )*

        impl<T> ::std::ops::Deref for $owned<T> {
            type Target = $borrowed<T>;

            #[inline]
            fn deref(&self) -> &$borrowed<T> {
                unsafe { ::foreign_types::ForeignTypeRef::from_ptr(self.0) }
            }
        }

        impl<T> ::std::ops::DerefMut for $owned<T> {
            #[inline]
            fn deref_mut(&mut self) -> &mut $borrowed<T> {
                unsafe { ::foreign_types::ForeignTypeRef::from_ptr_mut(self.0) }
            }
        }

        impl<T> ::std::borrow::Borrow<$borrowed<T>> for $owned<T> {
            #[inline]
            fn borrow(&self) -> &$borrowed<T> {
                &**self
            }
        }

        impl<T> ::std::convert::AsRef<$borrowed<T>> for $owned<T> {
            #[inline]
            fn as_ref(&self) -> &$borrowed<T> {
                &**self
            }
        }

        $(#[$borrowed_attr])*
        pub struct $borrowed<T>(::foreign_types::Opaque, ::std::marker::PhantomData<T>);

        $(#[$impl_attr])*
        impl<T> ::foreign_types::ForeignTypeRef for $borrowed<T> {
            type CType = $ctype;
        }

        unsafe impl<T> Send for $owned<T>{}
        unsafe impl<T> Send for $borrowed<T>{}
        unsafe impl<T> Sync for $owned<T>{}
        unsafe impl<T> Sync for $borrowed<T>{}
    };
}
