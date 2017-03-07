#![allow(deprecated)]
use libc::{c_int, c_long};
use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::path::Path;
use std::ptr;
use std::slice;
use std::str;

use {cvt, cvt_p};
use asn1::{Asn1StringRef, Asn1Time, Asn1TimeRef, Asn1BitStringRef, Asn1IntegerRef, Asn1ObjectRef};
use bio::MemBioSlice;
use bn::{BigNum, MSB_MAYBE_ZERO};
use conf::ConfRef;
use error::ErrorStack;
use hash::MessageDigest;
use nid::{self, Nid};
use pkey::{PKey, PKeyRef};
use stack::{Stack, StackRef, Stackable};
use string::OpensslString;

#[cfg(ossl10x)]
use ffi::{X509_set_notBefore, X509_set_notAfter, ASN1_STRING_data, X509_STORE_CTX_get_chain};
#[cfg(ossl110)]
use ffi::{X509_set1_notBefore as X509_set_notBefore, X509_set1_notAfter as X509_set_notAfter,
          ASN1_STRING_get0_data as ASN1_STRING_data,
          X509_STORE_CTX_get0_chain as X509_STORE_CTX_get_chain};

#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
pub mod verify;

use x509::extension::{ExtensionType, Extension};

pub mod extension;
pub mod store;

#[cfg(test)]
mod tests;

pub struct X509FileType(c_int);

impl X509FileType {
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

pub const X509_FILETYPE_PEM: X509FileType = X509FileType(ffi::X509_FILETYPE_PEM);
pub const X509_FILETYPE_ASN1: X509FileType = X509FileType(ffi::X509_FILETYPE_ASN1);
pub const X509_FILETYPE_DEFAULT: X509FileType = X509FileType(ffi::X509_FILETYPE_DEFAULT);

foreign_type! {
    type CType = ffi::X509_STORE_CTX;
    fn drop = ffi::X509_STORE_CTX_free;

    pub struct X509StoreContext;
    pub struct X509StoreContextRef;
}

impl X509StoreContextRef {
    pub fn error(&self) -> Option<X509VerifyError> {
        unsafe { X509VerifyError::from_raw(ffi::X509_STORE_CTX_get_error(self.as_ptr()) as c_long) }
    }

    pub fn current_cert(&self) -> Option<&X509Ref> {
        unsafe {
            let ptr = ffi::X509_STORE_CTX_get_current_cert(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509Ref::from_ptr(ptr))
            }
        }
    }

    pub fn error_depth(&self) -> u32 {
        unsafe { ffi::X509_STORE_CTX_get_error_depth(self.as_ptr()) as u32 }
    }

    pub fn chain(&self) -> Option<&StackRef<X509>> {
        unsafe {
            let chain = X509_STORE_CTX_get_chain(self.as_ptr());

            if chain.is_null() {
                return None;
            }

            Some(StackRef::from_ptr(chain))
        }
    }
}

#[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
pub struct X509Generator {
    days: u32,
    names: Vec<(String, String)>,
    extensions: Extensions,
    hash_type: MessageDigest,
}

#[allow(deprecated)]
impl X509Generator {
    /// Creates a new generator with the following defaults:
    ///
    /// validity period: 365 days
    ///
    /// CN: "rust-openssl"
    ///
    /// hash: SHA1
    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
    pub fn new() -> X509Generator {
        X509Generator {
            days: 365,
            names: vec![],
            extensions: Extensions::new(),
            hash_type: MessageDigest::sha1(),
        }
    }

    /// Sets certificate validity period in days since today
    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
    pub fn set_valid_period(mut self, days: u32) -> X509Generator {
        self.days = days;
        self
    }

    /// Add attribute to the name of the certificate
    ///
    /// ```
    /// # let generator = openssl::x509::X509Generator::new();
    /// generator.add_name("CN".to_string(),"example.com".to_string());
    /// ```
    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
    pub fn add_name(mut self, attr_type: String, attr_value: String) -> X509Generator {
        self.names.push((attr_type, attr_value));
        self
    }

    /// Add multiple attributes to the name of the certificate
    ///
    /// ```
    /// # let generator = openssl::x509::X509Generator::new();
    /// generator.add_names(vec![("CN".to_string(),"example.com".to_string())]);
    /// ```
    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
    pub fn add_names<I>(mut self, attrs: I) -> X509Generator
        where I: IntoIterator<Item = (String, String)>
    {
        self.names.extend(attrs);
        self
    }

    /// Add an extension to a certificate
    ///
    /// If the extension already exists, it will be replaced.
    ///
    /// ```
    /// use openssl::x509::extension::Extension::*;
    /// use openssl::x509::extension::KeyUsageOption::*;
    ///
    /// # let generator = openssl::x509::X509Generator::new();
    /// generator.add_extension(KeyUsage(vec![DigitalSignature, KeyEncipherment]));
    /// ```
    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
    pub fn add_extension(mut self, ext: extension::Extension) -> X509Generator {
        self.extensions.add(ext);
        self
    }

    /// Add multiple extensions to a certificate
    ///
    /// If any of the extensions already exist, they will be replaced.
    ///
    /// ```
    /// use openssl::x509::extension::Extension::*;
    /// use openssl::x509::extension::KeyUsageOption::*;
    ///
    /// # let generator = openssl::x509::X509Generator::new();
    /// generator.add_extensions(vec![KeyUsage(vec![DigitalSignature, KeyEncipherment])]);
    /// ```
    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
    pub fn add_extensions<I>(mut self, exts: I) -> X509Generator
        where I: IntoIterator<Item = extension::Extension>
    {
        for ext in exts {
            self.extensions.add(ext);
        }

        self
    }

    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
    pub fn set_sign_hash(mut self, hash_type: MessageDigest) -> X509Generator {
        self.hash_type = hash_type;
        self
    }

    /// Sets the certificate public-key, then self-sign and return it
    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
    pub fn sign(&self, p_key: &PKeyRef) -> Result<X509, ErrorStack> {
        let mut builder = try!(X509::builder());
        try!(builder.set_version(2));

        let mut serial = try!(BigNum::new());
        try!(serial.rand(128, MSB_MAYBE_ZERO, false));
        let serial = try!(serial.to_asn1_integer());
        try!(builder.set_serial_number(&serial));

        let not_before = try!(Asn1Time::days_from_now(0));
        try!(builder.set_not_before(&not_before));
        let not_after = try!(Asn1Time::days_from_now(self.days));
        try!(builder.set_not_after(&not_after));

        try!(builder.set_pubkey(p_key));

        let mut name = try!(X509Name::builder());
        if self.names.is_empty() {
            try!(name.append_entry_by_nid(nid::COMMONNAME, "rust-openssl"));
        } else {
            for &(ref key, ref value) in &self.names {
                try!(name.append_entry_by_text(key, value));
            }
        }
        let name = name.build();

        try!(builder.set_subject_name(&name));
        try!(builder.set_issuer_name(&name));

        for (exttype, ext) in self.extensions.iter() {
            let extension = match exttype.get_nid() {
                Some(nid) => {
                    let ctx = builder.x509v3_context(None, None);
                    try!(X509Extension::new_nid(None, Some(&ctx), nid, &ext.to_string()))
                }
                None => {
                    let ctx = builder.x509v3_context(None, None);
                    try!(X509Extension::new(None,
                                            Some(&ctx),
                                            &exttype.get_name().unwrap(),
                                            &ext.to_string()))
                }
            };
            try!(builder.append_extension(extension));
        }

        try!(builder.sign(p_key, self.hash_type));
        Ok(builder.build())
    }

    /// Obtain a certificate signing request (CSR)
    #[deprecated(since = "0.9.7", note = "use X509Builder and X509ReqBuilder instead")]
    pub fn request(&self, p_key: &PKeyRef) -> Result<X509Req, ErrorStack> {
        let cert = match self.sign(p_key) {
            Ok(c) => c,
            Err(x) => return Err(x),
        };

        unsafe {
            let req = try!(cvt_p(ffi::X509_to_X509_REQ(cert.as_ptr(),
                                                       ptr::null_mut(),
                                                       ptr::null())));
            let req = X509Req::from_ptr(req);

            let exts = compat::X509_get0_extensions(cert.as_ptr());
            if exts != ptr::null_mut() {
                try!(cvt(ffi::X509_REQ_add_extensions(req.as_ptr(), exts as *mut _)));
            }

            let hash_fn = self.hash_type.as_ptr();
            try!(cvt(ffi::X509_REQ_sign(req.as_ptr(), p_key.as_ptr(), hash_fn)));

            Ok(req)
        }
    }
}

/// A builder type which can create `X509` objects.
pub struct X509Builder(X509);

impl X509Builder {
    /// Creates a new builder.
    pub fn new() -> Result<X509Builder, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(ffi::X509_new()).map(|p| X509Builder(X509(p)))
        }
    }

    /// Sets the notAfter constraint on the certificate.
    pub fn set_not_after(&mut self, not_after: &Asn1TimeRef) -> Result<(), ErrorStack> {
        unsafe { cvt(X509_set_notAfter(self.0.as_ptr(), not_after.as_ptr())).map(|_| ()) }
    }

    /// Sets the notBefore constraint on the certificate.
    pub fn set_not_before(&mut self, not_before: &Asn1TimeRef) -> Result<(), ErrorStack> {
        unsafe { cvt(X509_set_notBefore(self.0.as_ptr(), not_before.as_ptr())).map(|_| ()) }
    }

    /// Sets the version of the certificate.
    ///
    /// Note that the version is zero-indexed; that is, a certificate corresponding to version 3 of
    /// the X.509 standard should pass `2` to this method.
    pub fn set_version(&mut self, version: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_set_version(self.0.as_ptr(), version.into())).map(|_| ()) }
    }

    /// Sets the serial number of the certificate.
    pub fn set_serial_number(&mut self,
                             serial_number: &Asn1IntegerRef)
                             -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_set_serialNumber(self.0.as_ptr(), serial_number.as_ptr())).map(|_| ())
        }
    }

    /// Sets the issuer name of the certificate.
    pub fn set_issuer_name(&mut self, issuer_name: &X509NameRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_set_issuer_name(self.0.as_ptr(), issuer_name.as_ptr())).map(|_| ()) }
    }

    /// Sets the subject name of the certificate.
    ///
    /// When building certificates, the `C`, `ST`, and `O` options are common when using the openssl command line tools.
    /// The `CN` field is used for the common name, such as a DNS name.
    ///
    /// ```
    /// use openssl::x509::{X509, X509NameBuilder};
    ///
    /// let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
    /// x509_name.append_entry_by_text("C", "US").unwrap();
    /// x509_name.append_entry_by_text("ST", "CA").unwrap();
    /// x509_name.append_entry_by_text("O", "Some organization").unwrap();
    /// x509_name.append_entry_by_text("CN", "www.example.com").unwrap();
    /// let x509_name = x509_name.build();
    ///
    /// let mut x509 = openssl::x509::X509::builder().unwrap();
    /// x509.set_subject_name(&x509_name).unwrap();
    /// ```
    pub fn set_subject_name(&mut self, subject_name: &X509NameRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_set_subject_name(self.0.as_ptr(), subject_name.as_ptr())).map(|_| ())
        }
    }

    /// Sets the public key associated with the certificate.
    pub fn set_pubkey(&mut self, key: &PKeyRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_set_pubkey(self.0.as_ptr(), key.as_ptr())).map(|_| ()) }
    }

    /// Returns a context object which is needed to create certain X509 extension values.
    ///
    /// Set `issuer` to `None` if the certificate will be self-signed.
    pub fn x509v3_context<'a>(&'a self,
                              issuer: Option<&'a X509Ref>,
                              conf: Option<&'a ConfRef>)
                              -> X509v3Context<'a> {
        unsafe {
            let mut ctx = mem::zeroed();

            let issuer = match issuer {
                Some(issuer) => issuer.as_ptr(),
                None => self.0.as_ptr(),
            };
            let subject = self.0.as_ptr();
            ffi::X509V3_set_ctx(&mut ctx, issuer, subject, ptr::null_mut(), ptr::null_mut(), 0);

            // nodb case taken care of since we zeroed ctx above
            if let Some(conf) = conf {
                ffi::X509V3_set_nconf(&mut ctx, conf.as_ptr());
            }

            X509v3Context(ctx, PhantomData)
        }
    }

    /// Adds an X509 extension value to the certificate.
    pub fn append_extension(&mut self, extension: X509Extension) -> Result<(), ErrorStack> {
        unsafe {
            try!(cvt(ffi::X509_add_ext(self.0.as_ptr(), extension.as_ptr(), -1)));
            mem::forget(extension);
            Ok(())
        }
    }

    /// Signs the certificate with a private key.
    pub fn sign(&mut self, key: &PKeyRef, hash: MessageDigest) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_sign(self.0.as_ptr(), key.as_ptr(), hash.as_ptr())).map(|_| ()) }
    }

    /// Consumes the builder, returning the certificate.
    pub fn build(self) -> X509 {
        self.0
    }
}

foreign_type! {
    type CType = ffi::X509;
    fn drop = ffi::X509_free;

    pub struct X509;
    pub struct X509Ref;
}

impl X509Ref {
    pub fn subject_name(&self) -> &X509NameRef {
        unsafe {
            let name = ffi::X509_get_subject_name(self.as_ptr());
            X509NameRef::from_ptr(name)
        }
    }

    /// Returns this certificate's SAN entries, if they exist.
    pub fn subject_alt_names(&self) -> Option<Stack<GeneralName>> {
        unsafe {
            let stack = ffi::X509_get_ext_d2i(self.as_ptr(),
                                              ffi::NID_subject_alt_name,
                                              ptr::null_mut(),
                                              ptr::null_mut());
            if stack.is_null() {
                return None;
            }

            Some(Stack::from_ptr(stack as *mut _))
        }
    }

    pub fn public_key(&self) -> Result<PKey, ErrorStack> {
        unsafe {
            let pkey = try!(cvt_p(ffi::X509_get_pubkey(self.as_ptr())));
            Ok(PKey::from_ptr(pkey))
        }
    }

    /// Returns certificate fingerprint calculated using provided hash
    pub fn fingerprint(&self, hash_type: MessageDigest) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let evp = hash_type.as_ptr();
            let mut len = ffi::EVP_MAX_MD_SIZE;
            let mut buf = vec![0u8; len as usize];
            try!(cvt(ffi::X509_digest(self.as_ptr(), evp, buf.as_mut_ptr() as *mut _, &mut len)));
            buf.truncate(len as usize);
            Ok(buf)
        }
    }

    /// Returns the certificate's Not After validity period.
    pub fn not_after(&self) -> &Asn1TimeRef {
        unsafe {
            let date = compat::X509_get_notAfter(self.as_ptr());
            assert!(!date.is_null());
            Asn1TimeRef::from_ptr(date)
        }
    }

    /// Returns the certificate's Not Before validity period.
    pub fn not_before(&self) -> &Asn1TimeRef {
        unsafe {
            let date = compat::X509_get_notBefore(self.as_ptr());
            assert!(!date.is_null());
            Asn1TimeRef::from_ptr(date)
        }
    }

    /// Returns the certificate's signature
    pub fn signature(&self) -> &Asn1BitStringRef {
        unsafe {
            let mut signature = ptr::null();
            compat::X509_get0_signature(&mut signature, ptr::null_mut(), self.as_ptr());
            assert!(!signature.is_null());
            Asn1BitStringRef::from_ptr(signature as *mut _)
        }
    }

    /// Returns the certificate's signature algorithm.
    pub fn signature_algorithm(&self) -> &X509AlgorithmRef {
        unsafe {
            let mut algor = ptr::null();
            compat::X509_get0_signature(ptr::null_mut(), &mut algor, self.as_ptr());
            assert!(!algor.is_null());
            X509AlgorithmRef::from_ptr(algor as *mut _)
        }
    }

    /// Returns the list of OCSP responder URLs specified in the certificate's Authority Information
    /// Access field.
    pub fn ocsp_responders(&self) -> Result<Stack<OpensslString>, ErrorStack> {
        unsafe {
            cvt_p(ffi::X509_get1_ocsp(self.as_ptr())).map(|p| Stack::from_ptr(p))
        }
    }

    /// Checks that this certificate issued `subject`.
    pub fn issued(&self, subject: &X509Ref) -> Result<(), X509VerifyError> {
        unsafe {
            let r = ffi::X509_check_issued(self.as_ptr(), subject.as_ptr());
            match X509VerifyError::from_raw(r as c_long) {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }

    to_pem!(ffi::PEM_write_bio_X509);
    to_der!(ffi::i2d_X509);
}

impl ToOwned for X509Ref {
    type Owned = X509;

    fn to_owned(&self) -> X509 {
        unsafe {
            compat::X509_up_ref(self.as_ptr());
            X509::from_ptr(self.as_ptr())
        }
    }
}

impl X509 {
    /// Returns a new builder.
    pub fn builder() -> Result<X509Builder, ErrorStack> {
        X509Builder::new()
    }

    from_pem!(X509, ffi::PEM_read_bio_X509);
    from_der!(X509, ffi::d2i_X509);

    /// Deserializes a list of PEM-formatted certificates.
    pub fn stack_from_pem(pem: &[u8]) -> Result<Vec<X509>, ErrorStack> {
        unsafe {
            ffi::init();
            let bio = try!(MemBioSlice::new(pem));

            let mut certs = vec![];
            loop {
                let r = ffi::PEM_read_bio_X509(bio.as_ptr(),
                                               ptr::null_mut(),
                                               None,
                                               ptr::null_mut());
                if r.is_null() {
                    let err = ffi::ERR_peek_last_error();
                    if ffi::ERR_GET_LIB(err) == ffi::ERR_LIB_PEM
                            && ffi::ERR_GET_REASON(err) == ffi::PEM_R_NO_START_LINE {
                        ffi::ERR_clear_error();
                        break;
                    }

                    return Err(ErrorStack::get());
                } else {
                    certs.push(X509(r));
                }
            }

            Ok(certs)
        }
    }
}

impl Clone for X509 {
    fn clone(&self) -> X509 {
        self.to_owned()
    }
}

impl AsRef<X509Ref> for X509 {
    fn as_ref(&self) -> &X509Ref {
        &*self
    }
}

impl AsRef<X509Ref> for X509Ref {
    fn as_ref(&self) -> &X509Ref {
        self
    }
}

impl Borrow<X509Ref> for X509 {
    fn borrow(&self) -> &X509Ref {
        &*self
    }
}

impl Stackable for X509 {
    type StackType = ffi::stack_st_X509;
}

/// A context object required to construct certain X509 extension values.
pub struct X509v3Context<'a>(ffi::X509V3_CTX, PhantomData<(&'a X509Ref, &'a ConfRef)>);

impl<'a> X509v3Context<'a> {
    pub fn as_ptr(&self) -> *mut ffi::X509V3_CTX {
        &self.0 as *const _ as *mut _
    }
}

foreign_type! {
    type CType = ffi::X509_EXTENSION;
    fn drop = ffi::X509_EXTENSION_free;

    pub struct X509Extension;
    pub struct X509ExtensionRef;
}

impl Stackable for X509Extension {
    type StackType = ffi::stack_st_X509_EXTENSION;
}

impl X509Extension {
    /// Constructs an X509 extension value. See `man x509v3_config` for information on supported
    /// names and their value formats.
    ///
    /// Some extension types, such as `subjectAlternativeName`, require an `X509v3Context` to be
    /// provided.
    ///
    /// See the extension module for builder types which will construct certain common extensions.
    pub fn new(conf: Option<&ConfRef>,
               context: Option<&X509v3Context>,
               name: &str,
               value: &str)
               -> Result<X509Extension, ErrorStack> {
        let name = CString::new(name).unwrap();
        let value = CString::new(value).unwrap();
        unsafe {
            ffi::init();
            let conf = conf.map_or(ptr::null_mut(), ConfRef::as_ptr);
            let context = context.map_or(ptr::null_mut(), X509v3Context::as_ptr);
            let name = name.as_ptr() as *mut _;
            let value = value.as_ptr() as *mut _;

            cvt_p(ffi::X509V3_EXT_nconf(conf, context, name, value)).map(X509Extension)
        }
    }

    /// Constructs an X509 extension value. See `man x509v3_config` for information on supported
    /// extensions and their value formats.
    ///
    /// Some extension types, such as `nid::SUBJECT_ALTERNATIVE_NAME`, require an `X509v3Context` to
    /// be provided.
    ///
    /// See the extension module for builder types which will construct certain common extensions.
    pub fn new_nid(conf: Option<&ConfRef>,
                   context: Option<&X509v3Context>,
                   name: Nid,
                   value: &str)
                   -> Result<X509Extension, ErrorStack> {
        let value = CString::new(value).unwrap();
        unsafe {
            ffi::init();
            let conf = conf.map_or(ptr::null_mut(), ConfRef::as_ptr);
            let context = context.map_or(ptr::null_mut(), X509v3Context::as_ptr);
            let name = name.as_raw();
            let value = value.as_ptr() as *mut _;

            cvt_p(ffi::X509V3_EXT_nconf_nid(conf, context, name, value)).map(X509Extension)
        }
    }
}

pub struct X509NameBuilder(X509Name);

impl X509NameBuilder {
    pub fn new() -> Result<X509NameBuilder, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(ffi::X509_NAME_new()).map(|p| X509NameBuilder(X509Name(p)))
        }
    }

    pub fn append_entry_by_text(&mut self, field: &str, value: &str) -> Result<(), ErrorStack> {
        unsafe {
            let field = CString::new(field).unwrap();
            assert!(value.len() <= c_int::max_value() as usize);
            cvt(ffi::X509_NAME_add_entry_by_txt(self.0.as_ptr(),
                                                field.as_ptr() as *mut _,
                                                ffi::MBSTRING_UTF8,
                                                value.as_ptr(),
                                                value.len() as c_int,
                                                -1,
                                                0))
                .map(|_| ())
        }
    }

    pub fn append_entry_by_nid(&mut self, field: Nid, value: &str) -> Result<(), ErrorStack> {
        unsafe {
            assert!(value.len() <= c_int::max_value() as usize);
            cvt(ffi::X509_NAME_add_entry_by_NID(self.0.as_ptr(),
                                                field.as_raw(),
                                                ffi::MBSTRING_UTF8,
                                                value.as_ptr() as *mut _,
                                                value.len() as c_int,
                                                -1,
                                                0))
                .map(|_| ())
        }
    }

    pub fn build(self) -> X509Name {
        self.0
    }
}

foreign_type! {
    type CType = ffi::X509_NAME;
    fn drop = ffi::X509_NAME_free;

    pub struct X509Name;
    pub struct X509NameRef;
}

impl X509Name {
    /// Returns a new builder.
    pub fn builder() -> Result<X509NameBuilder, ErrorStack> {
        X509NameBuilder::new()
    }

    /// Loads subject names from a file containing PEM-formatted certificates.
    ///
    /// This is commonly used in conjunction with `SslContextBuilder::set_client_ca_list`.
    pub fn load_client_ca_file<P: AsRef<Path>>(file: P) -> Result<Stack<X509Name>, ErrorStack> {
        let file = CString::new(file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            cvt_p(ffi::SSL_load_client_CA_file(file.as_ptr())).map(|p| Stack::from_ptr(p))
        }
    }
}

impl Stackable for X509Name {
    type StackType = ffi::stack_st_X509_NAME;
}

impl X509NameRef {
    pub fn entries_by_nid<'a>(&'a self, nid: Nid) -> X509NameEntries<'a> {
        X509NameEntries {
            name: self,
            nid: nid,
            loc: -1,
        }
    }
}

pub struct X509NameEntries<'a> {
    name: &'a X509NameRef,
    nid: Nid,
    loc: c_int,
}

impl<'a> Iterator for X509NameEntries<'a> {
    type Item = &'a X509NameEntryRef;

    fn next(&mut self) -> Option<&'a X509NameEntryRef> {
        unsafe {
            self.loc =
                ffi::X509_NAME_get_index_by_NID(self.name.as_ptr(), self.nid.as_raw(), self.loc);

            if self.loc == -1 {
                return None;
            }

            let entry = ffi::X509_NAME_get_entry(self.name.as_ptr(), self.loc);
            assert!(!entry.is_null());

            Some(X509NameEntryRef::from_ptr(entry))
        }
    }
}

foreign_type! {
    type CType = ffi::X509_NAME_ENTRY;
    fn drop = ffi::X509_NAME_ENTRY_free;

    pub struct X509NameEntry;
    pub struct X509NameEntryRef;
}

impl X509NameEntryRef {
    pub fn data(&self) -> &Asn1StringRef {
        unsafe {
            let data = ffi::X509_NAME_ENTRY_get_data(self.as_ptr());
            Asn1StringRef::from_ptr(data)
        }
    }
}

pub struct X509ReqBuilder(X509Req);

impl X509ReqBuilder {
    pub fn new() -> Result<X509ReqBuilder, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(ffi::X509_REQ_new()).map(|p| X509ReqBuilder(X509Req(p)))
        }

    }

    pub fn set_version(&mut self, version: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_REQ_set_version(self.0.as_ptr(), version.into())).map(|_| ()) }
    }

    pub fn set_subject_name(&mut self, subject_name: &X509NameRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_REQ_set_subject_name(self.0.as_ptr(), subject_name.as_ptr())).map(|_| ())
        }
    }

    pub fn set_pubkey(&mut self, key: &PKeyRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_REQ_set_pubkey(self.0.as_ptr(), key.as_ptr())).map(|_| ()) }
    }

    pub fn x509v3_context<'a>(&'a self,
                              conf: Option<&'a ConfRef>)
                              -> X509v3Context<'a> {
        unsafe {
            let mut ctx = mem::zeroed();

            ffi::X509V3_set_ctx(&mut ctx,
                                ptr::null_mut(),
                                ptr::null_mut(),
                                self.0.as_ptr(),
                                ptr::null_mut(),
                                0);

            // nodb case taken care of since we zeroed ctx above
            if let Some(conf) = conf {
                ffi::X509V3_set_nconf(&mut ctx, conf.as_ptr());
            }

            X509v3Context(ctx, PhantomData)
        }
    }

    pub fn add_extensions(&mut self,
                          extensions: &StackRef<X509Extension>)
                          -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_REQ_add_extensions(self.0.as_ptr(), extensions.as_ptr())).map(|_| ())
        }
    }

    pub fn sign(&mut self, key: &PKeyRef, hash: MessageDigest) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_REQ_sign(self.0.as_ptr(), key.as_ptr(), hash.as_ptr())).map(|_| ()) }
    }

    pub fn build(self) -> X509Req {
        self.0
    }
}

foreign_type! {
    type CType = ffi::X509_REQ;
    fn drop = ffi::X509_REQ_free;

    pub struct X509Req;
    pub struct X509ReqRef;
}

impl X509Req {
    pub fn builder() -> Result<X509ReqBuilder, ErrorStack> {
        X509ReqBuilder::new()
    }

    /// Reads CSR from PEM
    pub fn from_pem(buf: &[u8]) -> Result<X509Req, ErrorStack> {
        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let handle = try!(cvt_p(ffi::PEM_read_bio_X509_REQ(mem_bio.as_ptr(),
                                                               ptr::null_mut(),
                                                               None,
                                                               ptr::null_mut())));
            Ok(X509Req::from_ptr(handle))
        }
    }

    from_der!(X509Req, ffi::d2i_X509_REQ);
}

impl X509ReqRef {
    to_pem!(ffi::PEM_write_bio_X509_REQ);
    to_der!(ffi::i2d_X509_REQ);

    pub fn version(&self) -> i32
    {
        unsafe {
            compat::X509_REQ_get_version(self.as_ptr()) as i32
        }
    }

    pub fn subject_name(&self) -> &X509NameRef {
        unsafe {
            let name = compat::X509_REQ_get_subject_name(self.as_ptr());
            assert!(!name.is_null());
            X509NameRef::from_ptr(name)
        }
    }
}

/// A collection of X.509 extensions.
///
/// Upholds the invariant that a certificate MUST NOT include more than one
/// instance of a particular extension, according to RFC 3280 §4.2. Also
/// ensures that extensions are added to the certificate during signing
/// in the order they were inserted, which is required for certain
/// extensions like SubjectKeyIdentifier and AuthorityKeyIdentifier.
struct Extensions {
    /// The extensions contained in the collection.
    extensions: Vec<Extension>,
    /// A map of used to keep track of added extensions and their indexes in `self.extensions`.
    indexes: HashMap<ExtensionType, usize>,
}

impl Extensions {
    /// Creates a new `Extensions`.
    pub fn new() -> Extensions {
        Extensions {
            extensions: vec![],
            indexes: HashMap::new(),
        }
    }

    /// Adds a new `Extension`, replacing any existing one of the same
    /// `ExtensionType`.
    pub fn add(&mut self, ext: Extension) {
        let ext_type = ext.get_type();

        if let Some(index) = self.indexes.get(&ext_type) {
            self.extensions[*index] = ext;
            return;
        }

        self.extensions.push(ext);
        self.indexes.insert(ext_type, self.extensions.len() - 1);
    }

    /// Returns an `ExtensionsIter` for the collection.
    pub fn iter(&self) -> ExtensionsIter {
        ExtensionsIter {
            current: 0,
            extensions: &self.extensions,
        }
    }
}

/// An iterator that iterates over `(ExtensionType, Extension)` for each
/// extension in the collection.
struct ExtensionsIter<'a> {
    current: usize,
    extensions: &'a Vec<Extension>,
}

impl<'a> Iterator for ExtensionsIter<'a> {
    type Item = (ExtensionType, &'a Extension);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.extensions.len() {
            let ext = &self.extensions[self.current];

            self.current += 1;

            Some((ext.get_type(), ext))
        } else {
            None
        }
    }
}

pub struct X509VerifyError(c_long);

impl fmt::Debug for X509VerifyError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("X509VerifyError")
            .field("code", &self.0)
            .field("error", &self.error_string())
            .finish()
    }
}

impl fmt::Display for X509VerifyError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.error_string())
    }
}

impl Error for X509VerifyError {
    fn description(&self) -> &str {
        "an X509 validation error"
    }
}

impl X509VerifyError {
    /// Creates an `X509VerifyError` from a raw error number.
    ///
    /// `None` will be returned if `err` is `X509_V_OK`.
    ///
    /// # Safety
    ///
    /// Some methods on `X509VerifyError` are not thread safe if the error
    /// number is invalid.
    pub unsafe fn from_raw(err: c_long) -> Option<X509VerifyError> {
        if err == ffi::X509_V_OK as c_long {
            None
        } else {
            Some(X509VerifyError(err))
        }
    }

    pub fn as_raw(&self) -> c_long {
        self.0
    }

    pub fn error_string(&self) -> &'static str {
        ffi::init();

        unsafe {
            let s = ffi::X509_verify_cert_error_string(self.0);
            str::from_utf8(CStr::from_ptr(s).to_bytes()).unwrap()
        }
    }
}

foreign_type! {
    type CType = ffi::GENERAL_NAME;
    fn drop = ffi::GENERAL_NAME_free;

    pub struct GeneralName;
    pub struct GeneralNameRef;
}

impl GeneralNameRef {
    /// Returns the contents of this `GeneralName` if it is a `dNSName`.
    pub fn dnsname(&self) -> Option<&str> {
        unsafe {
            if (*self.as_ptr()).type_ != ffi::GEN_DNS {
                return None;
            }

            let ptr = ASN1_STRING_data((*self.as_ptr()).d as *mut _);
            let len = ffi::ASN1_STRING_length((*self.as_ptr()).d as *mut _);

            let slice = slice::from_raw_parts(ptr as *const u8, len as usize);
            // dNSNames are stated to be ASCII (specifically IA5). Hopefully
            // OpenSSL checks that when loading a certificate but if not we'll
            // use this instead of from_utf8_unchecked just in case.
            str::from_utf8(slice).ok()
        }
    }

    /// Returns the contents of this `GeneralName` if it is an `iPAddress`.
    pub fn ipaddress(&self) -> Option<&[u8]> {
        unsafe {
            if (*self.as_ptr()).type_ != ffi::GEN_IPADD {
                return None;
            }

            let ptr = ASN1_STRING_data((*self.as_ptr()).d as *mut _);
            let len = ffi::ASN1_STRING_length((*self.as_ptr()).d as *mut _);

            Some(slice::from_raw_parts(ptr as *const u8, len as usize))
        }
    }
}

impl Stackable for GeneralName {
    type StackType = ffi::stack_st_GENERAL_NAME;
}

foreign_type! {
    type CType = ffi::X509_ALGOR;
    fn drop = ffi::X509_ALGOR_free;

    pub struct X509Algorithm;
    pub struct X509AlgorithmRef;
}

impl X509AlgorithmRef {
    /// Returns the ASN.1 OID of this algorithm.
    pub fn object(&self) -> &Asn1ObjectRef {
        unsafe {
            let mut oid = ptr::null();
            compat::X509_ALGOR_get0(&mut oid, ptr::null_mut(), ptr::null_mut(), self.as_ptr());
            assert!(!oid.is_null());
            Asn1ObjectRef::from_ptr(oid as *mut _)
        }
    }
}

#[cfg(ossl110)]
mod compat {
    pub use ffi::X509_getm_notAfter as X509_get_notAfter;
    pub use ffi::X509_getm_notBefore as X509_get_notBefore;
    pub use ffi::X509_up_ref;
    pub use ffi::X509_get0_extensions;
    pub use ffi::X509_REQ_get_version;
    pub use ffi::X509_REQ_get_subject_name;
    pub use ffi::X509_get0_signature;
    pub use ffi::X509_ALGOR_get0;
}

#[cfg(ossl10x)]
#[allow(bad_style)]
mod compat {
    use libc::{c_int, c_void};
    use ffi;

    pub unsafe fn X509_get_notAfter(x: *mut ffi::X509) -> *mut ffi::ASN1_TIME {
        (*(*(*x).cert_info).validity).notAfter
    }

    pub unsafe fn X509_get_notBefore(x: *mut ffi::X509) -> *mut ffi::ASN1_TIME {
        (*(*(*x).cert_info).validity).notBefore
    }

    pub unsafe fn X509_up_ref(x: *mut ffi::X509) {
        ffi::CRYPTO_add_lock(&mut (*x).references,
                             1,
                             ffi::CRYPTO_LOCK_X509,
                             "mod.rs\0".as_ptr() as *const _,
                             line!() as c_int);
    }

    pub unsafe fn X509_get0_extensions(cert: *const ffi::X509)
                                       -> *const ffi::stack_st_X509_EXTENSION {
        let info = (*cert).cert_info;
        if info.is_null() {
            0 as *mut _
        } else {
            (*info).extensions
        }
    }

    pub unsafe fn X509_REQ_get_version(x: *mut ffi::X509_REQ) -> ::libc::c_long
    {
        ::ffi::ASN1_INTEGER_get((*(*x).req_info).version)
    }

    pub unsafe fn X509_REQ_get_subject_name(x: *mut ffi::X509_REQ) -> *mut ::ffi::X509_NAME
    {
        (*(*x).req_info).subject
    }
  
    pub unsafe fn X509_get0_signature(psig: *mut *const ffi::ASN1_BIT_STRING,
                                      palg: *mut *const ffi::X509_ALGOR, 
                                      x: *const ffi::X509) {
        if !psig.is_null() {
            *psig = (*x).signature;
        }
        if !palg.is_null() {
            *palg = (*x).sig_alg;
        }
    }

    pub unsafe fn X509_ALGOR_get0(paobj: *mut *const ffi::ASN1_OBJECT,
                                  pptype: *mut c_int,
                                  pval: *mut *mut c_void,
                                  alg: *const ffi::X509_ALGOR) {
        if !paobj.is_null() {
            *paobj = (*alg).algorithm;
        }
        assert!(pptype.is_null());
        assert!(pval.is_null());
    }
}
