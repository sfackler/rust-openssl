use libc::{c_char, c_int, c_long, c_ulong};
use std::borrow::Borrow;
use std::cmp;
use std::collections::HashMap;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::mem;
use std::path::Path;
use std::ptr;
use std::slice;
use std::str;

use {cvt, cvt_p};
use asn1::{Asn1StringRef, Asn1Time, Asn1TimeRef};
use bio::{MemBio, MemBioSlice};
use hash::MessageDigest;
use pkey::{PKey, PKeyRef};
use rand::rand_bytes;
use error::ErrorStack;
use ffi;
use nid::Nid;
use types::{OpenSslType, OpenSslTypeRef};
use stack::{Stack, StackRef, Stackable};

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

type_!(X509StoreContext, X509StoreContextRef, ffi::X509_STORE_CTX, ffi::X509_STORE_CTX_free);

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

#[allow(non_snake_case)]
/// Generator of private key/certificate pairs
///
/// # Example
///
/// ```
/// use openssl::hash::MessageDigest;
/// use openssl::pkey::PKey;
/// use openssl::rsa::Rsa;
/// use openssl::x509::X509Generator;
/// use openssl::x509::extension::{Extension, KeyUsageOption};
///
/// let rsa = Rsa::generate(2048).unwrap();
/// let pkey = PKey::from_rsa(rsa).unwrap();
///
/// let gen = X509Generator::new()
///        .set_valid_period(365*2)
///        .add_name("CN".to_owned(), "SuperMegaCorp Inc.".to_owned())
///        .set_sign_hash(MessageDigest::sha256())
///        .add_extension(Extension::KeyUsage(vec![KeyUsageOption::DigitalSignature]));
///
/// let cert = gen.sign(&pkey).unwrap();
/// let cert_pem = cert.to_pem().unwrap();
/// let pkey_pem = pkey.private_key_to_pem().unwrap();
/// ```
pub struct X509Generator {
    days: u32,
    names: Vec<(String, String)>,
    extensions: Extensions,
    hash_type: MessageDigest,
}

impl X509Generator {
    /// Creates a new generator with the following defaults:
    ///
    /// validity period: 365 days
    ///
    /// CN: "rust-openssl"
    ///
    /// hash: SHA1
    pub fn new() -> X509Generator {
        X509Generator {
            days: 365,
            names: vec![],
            extensions: Extensions::new(),
            hash_type: MessageDigest::sha1(),
        }
    }

    /// Sets certificate validity period in days since today
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
    pub fn add_extensions<I>(mut self, exts: I) -> X509Generator
        where I: IntoIterator<Item = extension::Extension>
    {
        for ext in exts {
            self.extensions.add(ext);
        }

        self
    }

    pub fn set_sign_hash(mut self, hash_type: MessageDigest) -> X509Generator {
        self.hash_type = hash_type;
        self
    }

    fn add_extension_internal(x509: *mut ffi::X509,
                              exttype: &extension::ExtensionType,
                              value: &str)
                              -> Result<(), ErrorStack> {
        unsafe {
            let mut ctx: ffi::X509V3_CTX = mem::zeroed();
            ffi::X509V3_set_ctx(&mut ctx, x509, x509, ptr::null_mut(), ptr::null_mut(), 0);
            let value = CString::new(value.as_bytes()).unwrap();
            let ext = match exttype.get_nid() {
                Some(nid) => {
                    try!(cvt_p(ffi::X509V3_EXT_nconf_nid(ptr::null_mut(),
                                                         &mut ctx,
                                                         nid.as_raw(),
                                                         value.as_ptr() as *mut c_char)))
                }
                None => {
                    let name = CString::new(exttype.get_name().unwrap().as_bytes()).unwrap();
                    try!(cvt_p(ffi::X509V3_EXT_nconf(ptr::null_mut(),
                                                     &mut ctx,
                                                     name.as_ptr() as *mut c_char,
                                                     value.as_ptr() as *mut c_char)))
                }
            };
            if ffi::X509_add_ext(x509, ext, -1) != 1 {
                ffi::X509_EXTENSION_free(ext);
                Err(ErrorStack::get())
            } else {
                Ok(())
            }
        }
    }

    fn add_name_internal(name: *mut ffi::X509_NAME,
                         key: &str,
                         value: &str)
                         -> Result<(), ErrorStack> {
        let value_len = value.len() as c_int;
        unsafe {
            let key = CString::new(key.as_bytes()).unwrap();
            let value = CString::new(value.as_bytes()).unwrap();
            cvt(ffi::X509_NAME_add_entry_by_txt(name,
                                                key.as_ptr() as *const _,
                                                ffi::MBSTRING_UTF8,
                                                value.as_ptr() as *const _,
                                                value_len,
                                                -1,
                                                0))
                .map(|_| ())
        }
    }

    fn random_serial() -> Result<c_long, ErrorStack> {
        let len = mem::size_of::<c_long>();
        let mut bytes = vec![0; len];
        try!(rand_bytes(&mut bytes));
        let mut res = 0;
        for b in bytes.iter() {
            res = res << 8;
            res |= (*b as c_long) & 0xff;
        }

        // While OpenSSL is actually OK to have negative serials
        // other libraries (for example, Go crypto) can drop
        // such certificates as invalid, so we clear the high bit
        Ok(((res as c_ulong) >> 1) as c_long)
    }

    /// Sets the certificate public-key, then self-sign and return it
    pub fn sign(&self, p_key: &PKeyRef) -> Result<X509, ErrorStack> {
        ffi::init();

        unsafe {
            let x509 = X509::from_ptr(try!(cvt_p(ffi::X509_new())));

            try!(cvt(ffi::X509_set_version(x509.as_ptr(), 2)));
            try!(cvt(ffi::ASN1_INTEGER_set(ffi::X509_get_serialNumber(x509.as_ptr()),
                                           try!(X509Generator::random_serial()))));

            let not_before = try!(Asn1Time::days_from_now(0));
            let not_after = try!(Asn1Time::days_from_now(self.days));

            try!(cvt(X509_set_notBefore(x509.as_ptr(), not_before.as_ptr() as *const _)));
            // If prev line succeded - ownership should go to cert
            mem::forget(not_before);

            try!(cvt(X509_set_notAfter(x509.as_ptr(), not_after.as_ptr() as *const _)));
            // If prev line succeded - ownership should go to cert
            mem::forget(not_after);

            try!(cvt(ffi::X509_set_pubkey(x509.as_ptr(), p_key.as_ptr())));

            let name = try!(cvt_p(ffi::X509_get_subject_name(x509.as_ptr())));

            let default = [("CN", "rust-openssl")];
            let default_iter = &mut default.iter().map(|&(k, v)| (k, v));
            let arg_iter = &mut self.names.iter().map(|&(ref k, ref v)| (&k[..], &v[..]));
            let iter: &mut Iterator<Item = (&str, &str)> = if self.names.len() == 0 {
                default_iter
            } else {
                arg_iter
            };

            for (key, val) in iter {
                try!(X509Generator::add_name_internal(name, &key, &val));
            }
            try!(cvt(ffi::X509_set_issuer_name(x509.as_ptr(), name)));

            for (exttype, ext) in self.extensions.iter() {
                try!(X509Generator::add_extension_internal(x509.as_ptr(),
                                                           &exttype,
                                                           &ext.to_string()));
            }

            let hash_fn = self.hash_type.as_ptr();
            try!(cvt(ffi::X509_sign(x509.as_ptr(), p_key.as_ptr(), hash_fn)));
            Ok(x509)
        }
    }

    /// Obtain a certificate signing request (CSR)
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

type_!(X509, X509Ref, ffi::X509, ffi::X509_free);

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

    /// Returns certificate Not After validity period.
    pub fn not_after<'a>(&'a self) -> &'a Asn1TimeRef {
        unsafe {
            let date = compat::X509_get_notAfter(self.as_ptr());
            assert!(!date.is_null());
            Asn1TimeRef::from_ptr(date)
        }
    }

    /// Returns certificate Not Before validity period.
    pub fn not_before<'a>(&'a self) -> &'a Asn1TimeRef {
        unsafe {
            let date = compat::X509_get_notBefore(self.as_ptr());
            assert!(!date.is_null());
            Asn1TimeRef::from_ptr(date)
        }
    }

    /// Writes certificate as PEM
    pub fn to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());
        unsafe {
            try!(cvt(ffi::PEM_write_bio_X509(mem_bio.as_ptr(), self.as_ptr())));
        }
        Ok(mem_bio.get_buf().to_owned())
    }

    /// Returns a DER serialized form of the certificate
    pub fn to_der(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());
        unsafe {
            ffi::i2d_X509_bio(mem_bio.as_ptr(), self.as_ptr());
        }
        Ok(mem_bio.get_buf().to_owned())
    }
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
    /// Reads a certificate from DER.
    pub fn from_der(buf: &[u8]) -> Result<X509, ErrorStack> {
        unsafe {
            let mut ptr = buf.as_ptr();
            let len = cmp::min(buf.len(), c_long::max_value() as usize) as c_long;
            let x509 = try!(cvt_p(ffi::d2i_X509(ptr::null_mut(), &mut ptr, len)));
            Ok(X509::from_ptr(x509))
        }
    }

    /// Reads a certificate from PEM.
    pub fn from_pem(buf: &[u8]) -> Result<X509, ErrorStack> {
        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let handle = try!(cvt_p(ffi::PEM_read_bio_X509(mem_bio.as_ptr(),
                                                           ptr::null_mut(),
                                                           None,
                                                           ptr::null_mut())));
            Ok(X509::from_ptr(handle))
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

type_!(X509Name, X509NameRef, ffi::X509_NAME, ffi::X509_NAME_free);

impl X509Name {
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

type_!(X509NameEntry, X509NameEntryRef, ffi::X509_NAME_ENTRY, ffi::X509_NAME_ENTRY_free);

impl X509NameEntryRef {
    pub fn data(&self) -> &Asn1StringRef {
        unsafe {
            let data = ffi::X509_NAME_ENTRY_get_data(self.as_ptr());
            Asn1StringRef::from_ptr(data)
        }
    }
}

type_!(X509Req, X509ReqRef, ffi::X509_REQ, ffi::X509_REQ_free);

impl X509ReqRef {
    /// Writes CSR as PEM
    pub fn to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());
        if unsafe { ffi::PEM_write_bio_X509_REQ(mem_bio.as_ptr(), self.as_ptr()) } != 1 {
            return Err(ErrorStack::get());
        }
        Ok(mem_bio.get_buf().to_owned())
    }

    /// Returns a DER serialized form of the CSR
    pub fn to_der(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());
        unsafe {
            ffi::i2d_X509_REQ_bio(mem_bio.as_ptr(), self.as_ptr());
        }
        Ok(mem_bio.get_buf().to_owned())
    }
}

impl X509Req {
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

type_!(GeneralName, GeneralNameRef, ffi::GENERAL_NAME, ffi::GENERAL_NAME_free);

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

#[test]
fn test_negative_serial() {
    // I guess that's enough to get a random negative number
    for _ in 0..1000 {
        assert!(X509Generator::random_serial().unwrap() > 0,
                "All serials should be positive");
    }
}

#[cfg(ossl110)]
mod compat {
    pub use ffi::X509_getm_notAfter as X509_get_notAfter;
    pub use ffi::X509_getm_notBefore as X509_get_notBefore;
    pub use ffi::X509_up_ref;
    pub use ffi::X509_get0_extensions;
}

#[cfg(ossl10x)]
#[allow(bad_style)]
mod compat {
    use libc::c_int;
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
}
