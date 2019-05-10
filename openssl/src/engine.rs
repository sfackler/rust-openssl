use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;

use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_long, c_uint, c_void};

use error::ErrorStack;
use ex_data::{free_data_box, Index};
use ffi;
use pkey::{PKey, Private, Public};
use ssl::SslRef;
use stack::Stack;
use x509::{X509Name, X509};
use {cvt, cvt_n, cvt_p};

bitflags! {
    /// These flags are used to control combinations of algorithm (methods) by bitwise "OR"ing.
    pub struct Method: c_uint {
        const RSA = ffi::ENGINE_METHOD_RSA;
        const DSA = ffi::ENGINE_METHOD_DSA;
        const DH = ffi::ENGINE_METHOD_DH;
        const RAND = ffi::ENGINE_METHOD_RAND;
        #[cfg(not(ossl110))]
        const ECDH = ffi::ENGINE_METHOD_ECDH;
        #[cfg(not(ossl110))]
        const ECDSA = ffi::ENGINE_METHOD_ECDSA;
        const CIPHERS = ffi::ENGINE_METHOD_CIPHERS;
        const DIGESTS = ffi::ENGINE_METHOD_DIGESTS;
        #[cfg(not(ossl110))]
        const STORE = ffi::ENGINE_METHOD_STORE;
        const PKEY_METHS = ffi::ENGINE_METHOD_PKEY_METHS;
        const PKEY_ASN1_METHS = ffi::ENGINE_METHOD_PKEY_ASN1_METHS;
        #[cfg(ossl110)]
        const EC = ffi::ENGINE_METHOD_EC;
        const ALL = ffi::ENGINE_METHOD_ALL;
        const NONE = ffi::ENGINE_METHOD_NONE;
    }
}

bitflags! {
    pub struct TableFlags: c_uint {
        /// This(ese) flag(s) controls behaviour of the ENGINE_TABLE mechanism used
        /// internally to control registration of ENGINE implementations, and can be
        /// set by ENGINE_set_table_flags(). The "NOINIT" flag prevents attempts to
        /// initialise registered ENGINEs if they are not already initialised.
        const NOINIT = ffi::ENGINE_TABLE_FLAG_NOINIT;
    }
}

bitflags! {
    /// ENGINE flags that can be set by `ENGINE_set_flags()`.
    pub struct Flags: c_int {
        /// This flag is for ENGINEs that wish to handle the various 'CMD'-related
        /// control commands on their own. Without this flag, ENGINE_ctrl() handles
        /// these control commands on behalf of the ENGINE using their "cmd_defns" data.
        const MANUAL_CMD_CTRL = ffi::ENGINE_FLAGS_MANUAL_CMD_CTRL;
        /// This flag is for ENGINEs who return new duplicate structures when found
        /// via `ENGINE_by_id()`. When an ENGINE must store state (eg. if
        /// ENGINE_ctrl() commands are called in sequence as part of some stateful
        /// process like key-generation setup and execution), it can set this flag -
        /// then each attempt to obtain the ENGINE will result in it being copied into
        /// a new structure. Normally, ENGINEs don't declare this flag so
        /// ENGINE_by_id() just increments the existing ENGINE's structural reference count.
        const BY_ID_COPY = ffi::ENGINE_FLAGS_BY_ID_COPY;
        /// This flag if for an ENGINE that does not want its methods registered as
        /// part of ENGINE_register_all_complete() for example if the methods are not
        /// usable as default methods.
        const NO_REGISTER_ALL = ffi::ENGINE_FLAGS_NO_REGISTER_ALL;
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ENGINE;
    fn drop = drop;
    fn clone = clone;

    /// A engine.
    pub struct Engine;

    /// Reference to `Engine`
    pub struct EngineRef;
}

unsafe fn drop(e: *mut ffi::ENGINE) {
    ffi::ENGINE_free(e);
}

unsafe fn clone(e: *mut ffi::ENGINE) -> *mut ffi::ENGINE {
    ffi::ENGINE_up_ref(e);
    e
}

impl Engine {
    pub fn default_rsa() -> Option<Engine> {
        let e = unsafe { ffi::ENGINE_get_default_RSA() };

        if e.is_null() {
            None
        } else {
            Some(unsafe { Engine::from_ptr(e) })
        }
    }
    pub fn default_dsa() -> Option<Engine> {
        let e = unsafe { ffi::ENGINE_get_default_DSA() };

        if e.is_null() {
            None
        } else {
            Some(unsafe { Engine::from_ptr(e) })
        }
    }
    #[cfg(not(ossl110))]
    pub fn default_ecdh() -> Option<Engine> {
        let e = unsafe { ffi::ENGINE_get_default_ECDH() };

        if e.is_null() {
            None
        } else {
            Some(unsafe { Engine::from_ptr(e) })
        }
    }
    #[cfg(not(ossl110))]
    pub fn default_ecdsa() -> Option<Engine> {
        let e = unsafe { ffi::ENGINE_get_default_ECDSA() };

        if e.is_null() {
            None
        } else {
            Some(unsafe { Engine::from_ptr(e) })
        }
    }
    #[cfg(ossl110)]
    pub fn default_ec() -> Option<Engine> {
        let e = unsafe { ffi::ENGINE_get_default_EC() };

        if e.is_null() {
            None
        } else {
            Some(unsafe { Engine::from_ptr(e) })
        }
    }
    pub fn default_dh() -> Option<Engine> {
        let e = unsafe { ffi::ENGINE_get_default_DH() };

        if e.is_null() {
            None
        } else {
            Some(unsafe { Engine::from_ptr(e) })
        }
    }
    pub fn default_rand() -> Option<Engine> {
        let e = unsafe { ffi::ENGINE_get_default_RAND() };

        if e.is_null() {
            None
        } else {
            Some(unsafe { Engine::from_ptr(e) })
        }
    }
    pub fn cipher_engine(nid: c_int) -> Option<Engine> {
        let e = unsafe { ffi::ENGINE_get_cipher_engine(nid) };

        if e.is_null() {
            None
        } else {
            Some(unsafe { Engine::from_ptr(e) })
        }
    }
    pub fn digest_engine(nid: c_int) -> Option<Engine> {
        let e = unsafe { ffi::ENGINE_get_digest_engine(nid) };

        if e.is_null() {
            None
        } else {
            Some(unsafe { Engine::from_ptr(e) })
        }
    }
    pub fn pkey_meth_engine(nid: c_int) -> Option<Engine> {
        let e = unsafe { ffi::ENGINE_get_pkey_meth_engine(nid) };

        if e.is_null() {
            None
        } else {
            Some(unsafe { Engine::from_ptr(e) })
        }
    }
    pub fn pkey_asn1_meth_engine(nid: c_int) -> Option<Engine> {
        let e = unsafe { ffi::ENGINE_get_pkey_asn1_meth_engine(nid) };

        if e.is_null() {
            None
        } else {
            Some(unsafe { Engine::from_ptr(e) })
        }
    }

    pub fn set_default_rsa(e: &EngineRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default_RSA(e.as_ptr()) }).map(|_| ())
    }
    pub fn set_default_string(e: &EngineRef, def_list: &str) -> Result<(), ErrorStack> {
        cvt(unsafe {
            ffi::ENGINE_set_default_string(e.as_ptr(), CString::new(def_list).unwrap().as_ptr())
        })
        .map(|_| ())
    }
    pub fn set_default_dsa(e: &EngineRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default_DSA(e.as_ptr()) }).map(|_| ())
    }
    #[cfg(not(ossl110))]
    pub fn set_default_ecdh(e: &EngineRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default_ECDH(e.as_ptr()) }).map(|_| ())
    }
    #[cfg(not(ossl110))]
    pub fn set_default_ecdsa(e: &EngineRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default_ECDSA(e.as_ptr()) }).map(|_| ())
    }
    #[cfg(ossl110)]
    pub fn set_default_ec(e: &EngineRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default_EC(e.as_ptr()) }).map(|_| ())
    }
    pub fn set_default_dh(e: &EngineRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default_DH(e.as_ptr()) }).map(|_| ())
    }
    pub fn set_default_rand(e: &EngineRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default_RAND(e.as_ptr()) }).map(|_| ())
    }
    pub fn set_default_ciphers(e: &EngineRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default_ciphers(e.as_ptr()) }).map(|_| ())
    }
    pub fn set_default_digests(e: &EngineRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default_digests(e.as_ptr()) }).map(|_| ())
    }
    pub fn set_default_pkey_meths(e: &EngineRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default_pkey_meths(e.as_ptr()) }).map(|_| ())
    }
    pub fn set_default_pkey_asn1_meths(e: &EngineRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default_pkey_asn1_meths(e.as_ptr()) }).map(|_| ())
    }
    pub fn set_default(e: &EngineRef, methods: Method) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default(e.as_ptr(), methods.bits) }).map(|_| ())
    }

    pub fn table_flags() -> TableFlags {
        TableFlags::from_bits_truncate(unsafe { ffi::ENGINE_get_table_flags() })
    }
    pub fn set_table_flags(flags: TableFlags) {
        unsafe { ffi::ENGINE_set_table_flags(flags.bits) }
    }

    pub fn load_openssl() {
        unsafe {
            ffi::ENGINE_load_openssl();
        }
    }
    pub fn load_dynamic() {
        unsafe {
            ffi::ENGINE_load_dynamic();
        }
    }
    #[cfg(not(any(libressl, ossl110)))]
    pub fn load_4758cca() {
        unsafe {
            ffi::ENGINE_load_4758cca();
        }
    }
    #[cfg(not(any(libressl, ossl110)))]
    pub fn load_aep() {
        unsafe {
            ffi::ENGINE_load_aep();
        }
    }
    #[cfg(not(any(libressl, ossl110)))]
    pub fn load_atalla() {
        unsafe {
            ffi::ENGINE_load_atalla();
        }
    }
    #[cfg(not(any(libressl, ossl110)))]
    pub fn load_chil() {
        unsafe {
            ffi::ENGINE_load_chil();
        }
    }
    #[cfg(not(any(libressl, ossl110)))]
    pub fn load_cswift() {
        unsafe {
            ffi::ENGINE_load_cswift();
        }
    }
    #[cfg(not(any(libressl, ossl110)))]
    pub fn load_nuron() {
        unsafe {
            ffi::ENGINE_load_nuron();
        }
    }
    #[cfg(not(any(libressl, ossl110)))]
    pub fn load_sureware() {
        unsafe {
            ffi::ENGINE_load_sureware();
        }
    }
    #[cfg(not(any(libressl, ossl110)))]
    pub fn load_ubsec() {
        unsafe {
            ffi::ENGINE_load_ubsec();
        }
    }
    pub fn load_padlock() {
        unsafe {
            ffi::ENGINE_load_padlock();
        }
    }
    #[cfg(not(libressl))]
    pub fn load_capi() {
        unsafe {
            ffi::ENGINE_load_capi();
        }
    }
    #[cfg(ossl110)]
    pub fn load_afalg() {
        unsafe {
            ffi::ENGINE_load_afalg();
        }
    }
    #[cfg(not(libressl))]
    pub fn load_cryptodev() {
        unsafe {
            ffi::ENGINE_load_cryptodev();
        }
    }
    #[cfg(not(libressl))]
    pub fn load_rdrand() {
        unsafe {
            ffi::ENGINE_load_rdrand();
        }
    }
    pub fn load_builtin_engines() {
        unsafe { ffi::ENGINE_load_builtin_engines() }
    }

    pub fn register_all_rsa() {
        unsafe {
            ffi::ENGINE_register_all_RSA();
        }
    }
    pub fn register_all_dsa() {
        unsafe {
            ffi::ENGINE_register_all_DSA();
        }
    }
    #[cfg(not(ossl110))]
    pub fn register_all_ecdh() {
        unsafe {
            ffi::ENGINE_register_all_ECDH();
        }
    }
    #[cfg(not(ossl110))]
    pub fn register_all_ecdsa() {
        unsafe {
            ffi::ENGINE_register_all_ECDSA();
        }
    }
    #[cfg(ossl110)]
    pub fn register_all_ec() {
        unsafe {
            ffi::ENGINE_register_all_EC();
        }
    }
    pub fn register_all_dh() {
        unsafe {
            ffi::ENGINE_register_all_DH();
        }
    }
    pub fn register_all_rand() {
        unsafe {
            ffi::ENGINE_register_all_RAND();
        }
    }
    #[cfg(not(ossl110))]
    pub fn register_all_store() {
        unsafe {
            ffi::ENGINE_register_all_STORE();
        }
    }
    pub fn register_all_ciphers() {
        unsafe {
            ffi::ENGINE_register_all_ciphers();
        }
    }
    pub fn register_all_digests() {
        unsafe {
            ffi::ENGINE_register_all_digests();
        }
    }
    pub fn register_all_pkey_meths() {
        unsafe {
            ffi::ENGINE_register_all_pkey_meths();
        }
    }
    pub fn register_all_pkey_asn1_meths() {
        unsafe {
            ffi::ENGINE_register_all_pkey_asn1_meths();
        }
    }
    pub fn register_all_complete() {
        unsafe {
            ffi::ENGINE_register_all_complete();
        }
    }

    pub fn add_conf_module() {
        unsafe { ffi::ENGINE_add_conf_module() }
    }

    /// If the loading application (or library) and the loaded ENGINE library
    /// share the same static data (eg. they're both dynamically linked to the
    /// same libcrypto.so) we need a way to avoid trying to set system callbacks -
    /// this would fail, and for the same reason that it's unnecessary to try. If
    /// the loaded ENGINE has (or gets from through the loader) its own copy of
    /// the libcrypto static data, we will need to set the callbacks. The easiest
    /// way to detect this is to have a function that returns a pointer to some
    /// static data and let the loading application and loaded ENGINE compare
    /// their respective values.
    pub fn get_static_state() -> *const c_void {
        unsafe { ffi::ENGINE_get_static_state() }
    }

    pub fn cleanup() {
        unsafe { ffi::ENGINE_cleanup() }
    }

    /// These functions are useful for manufacturing new ENGINE structures. They
    /// don't address reference counting at all - one uses them to populate an
    /// ENGINE structure with personalised implementations of things prior to
    /// using it directly or adding it to the builtin ENGINE list in OpenSSL.
    /// These are also here so that the ENGINE structure doesn't have to be
    /// exposed and break binary compatibility!
    pub fn new() -> Self {
        unsafe { Engine::from_ptr(ffi::ENGINE_new()) }
    }

    pub fn into_ptr(self) -> *mut <Self as ForeignType>::CType {
        let raw = self.as_ptr();
        mem::forget(self);
        raw
    }
}

impl Engine {
    pub fn new_ex_index<T>() -> Result<Index<Self, T>, ErrorStack>
    where
        T: 'static + Sync + Send,
    {
        unsafe {
            let idx = cvt_n(ffi::ENGINE_get_ex_new_index(
                0,
                ptr::null_mut(),
                None,
                None,
                Some(free_data_box::<T>),
            ))?;

            Ok(Index::from_raw(idx))
        }
    }
}

impl EngineRef {
    pub fn ex_data<T>(&self, idx: Index<Engine, T>) -> Option<&mut T> {
        unsafe { (ffi::ENGINE_get_ex_data(self.as_ptr(), idx.as_raw()) as *mut T).as_mut() }
    }

    pub fn set_ex_data<T>(
        &self,
        index: Index<Engine, T>,
        data: Option<T>,
    ) -> Result<(), ErrorStack> {
        cvt(unsafe {
            let data = data.map_or_else(ptr::null_mut, |data| {
                Box::into_raw(Box::new(data)) as *mut c_void
            });

            ffi::ENGINE_set_ex_data(self.as_ptr(), index.as_raw(), data)
        })
        .map(|_| ())
    }
}

impl EngineRef {
    pub fn id(&self) -> &CStr {
        unsafe { CStr::from_ptr(ffi::ENGINE_get_id(self.as_ptr())) }
    }

    pub fn name(&self) -> &CStr {
        unsafe { CStr::from_ptr(ffi::ENGINE_get_name(self.as_ptr())) }
    }

    pub fn flags(&self) -> Flags {
        Flags::from_bits_truncate(unsafe { ffi::ENGINE_get_flags(self.as_ptr()) })
    }

    pub fn rsa(&self) -> Option<&ffi::RSA_METHOD> {
        unsafe { ffi::ENGINE_get_RSA(self.as_ptr()).as_ref() }
    }

    pub fn dsa(&self) -> Option<&ffi::DSA_METHOD> {
        unsafe { ffi::ENGINE_get_DSA(self.as_ptr()).as_ref() }
    }

    #[cfg(not(ossl110))]
    pub fn ecdh(&self) -> Option<&ffi::ECDH_METHOD> {
        unsafe { ffi::ENGINE_get_ECDH(self.as_ptr()).as_ref() }
    }

    #[cfg(not(ossl110))]
    pub fn ecdsa(&self) -> Option<&ffi::ECDSA_METHOD> {
        unsafe { ffi::ENGINE_get_ECDSA(self.as_ptr()).as_ref() }
    }

    #[cfg(ossl110)]
    pub fn ec(&self) -> Option<&ffi::EC_KEY_METHOD> {
        unsafe { ffi::ENGINE_get_EC(self.as_ptr()).as_ref() }
    }

    pub fn dh(&self) -> Option<&ffi::DH_METHOD> {
        unsafe { ffi::ENGINE_get_DH(self.as_ptr()).as_ref() }
    }

    pub fn rand(&self) -> Option<&ffi::RAND_METHOD> {
        unsafe { ffi::ENGINE_get_RAND(self.as_ptr()).as_ref() }
    }

    #[cfg(not(ossl110))]
    pub fn store(&self) -> Option<&ffi::STORE_METHOD> {
        unsafe { ffi::ENGINE_get_STORE(self.as_ptr()).as_ref() }
    }

    pub fn init_function(&self) -> ffi::ENGINE_GEN_INT_FUNC_PTR {
        unsafe { ffi::ENGINE_get_init_function(self.as_ptr()) }
    }

    pub fn finish_function(&self) -> ffi::ENGINE_GEN_INT_FUNC_PTR {
        unsafe { ffi::ENGINE_get_finish_function(self.as_ptr()) }
    }

    pub fn destroy_function(&self) -> ffi::ENGINE_GEN_INT_FUNC_PTR {
        unsafe { ffi::ENGINE_get_destroy_function(self.as_ptr()) }
    }

    pub fn ctrl_function(&self) -> ffi::ENGINE_CTRL_FUNC_PTR {
        unsafe { ffi::ENGINE_get_ctrl_function(self.as_ptr()) }
    }

    pub fn load_privkey_function(&self) -> ffi::ENGINE_LOAD_KEY_PTR {
        unsafe { ffi::ENGINE_get_load_privkey_function(self.as_ptr()) }
    }

    pub fn load_pubkey_function(&self) -> ffi::ENGINE_LOAD_KEY_PTR {
        unsafe { ffi::ENGINE_get_load_pubkey_function(self.as_ptr()) }
    }

    pub fn ssl_client_cert_function(&self) -> ffi::ENGINE_SSL_CLIENT_CERT_PTR {
        unsafe { ffi::ENGINE_get_ssl_client_cert_function(self.as_ptr()) }
    }

    pub fn ciphers(&self) -> ffi::ENGINE_CIPHERS_PTR {
        unsafe { ffi::ENGINE_get_ciphers(self.as_ptr()) }
    }

    pub fn digests(&self) -> ffi::ENGINE_DIGESTS_PTR {
        unsafe { ffi::ENGINE_get_digests(self.as_ptr()) }
    }

    pub fn pkey_meths(&self) -> ffi::ENGINE_PKEY_METHS_PTR {
        unsafe { ffi::ENGINE_get_pkey_meths(self.as_ptr()) }
    }

    pub fn pkey_asn1_meths(&self) -> ffi::ENGINE_PKEY_ASN1_METHS_PTR {
        unsafe { ffi::ENGINE_get_pkey_asn1_meths(self.as_ptr()) }
    }

    pub fn cipher(&self, nid: c_int) -> Option<&ffi::EVP_CIPHER> {
        unsafe { ffi::ENGINE_get_cipher(self.as_ptr(), nid).as_ref() }
    }

    pub fn digest(&self, nid: c_int) -> Option<&ffi::EVP_MD> {
        unsafe { ffi::ENGINE_get_digest(self.as_ptr(), nid).as_ref() }
    }

    pub fn pkey_meth(&self, nid: c_int) -> Option<&ffi::EVP_PKEY_METHOD> {
        unsafe { ffi::ENGINE_get_pkey_meth(self.as_ptr(), nid).as_ref() }
    }

    pub fn pkey_asn1_meth(&self, nid: c_int) -> Option<&ffi::EVP_PKEY_ASN1_METHOD> {
        unsafe { ffi::ENGINE_get_pkey_asn1_meth(self.as_ptr(), nid).as_ref() }
    }

    pub fn pkey_asn1_meth_str(&self, method: &str) -> Option<&ffi::EVP_PKEY_ASN1_METHOD> {
        unsafe {
            ffi::ENGINE_get_pkey_asn1_meth_str(
                self.as_ptr(),
                method.as_ptr() as *const _,
                method.len() as i32,
            )
            .as_ref()
        }
    }

    pub fn cmd_defns(&self) -> Option<&ffi::ENGINE_CMD_DEFN> {
        unsafe { ffi::ENGINE_get_cmd_defns(self.as_ptr()).as_ref() }
    }

    pub fn set_id(&self, id: &str) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_id(self.as_ptr(), CString::new(id).unwrap().as_ptr()) })
            .map(|_| ())
    }
    pub fn set_name(&self, name: &str) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_name(self.as_ptr(), CString::new(name).unwrap().as_ptr()) })
            .map(|_| ())
    }
    pub fn set_rsa<T>(&self, meth: Option<&T>) -> Result<(), ErrorStack>
    where
        T: ForeignTypeRef<CType = ffi::RSA_METHOD>,
    {
        cvt(unsafe {
            ffi::ENGINE_set_RSA(
                self.as_ptr(),
                meth.map_or_else(ptr::null_mut, ForeignTypeRef::as_ptr),
            )
        })
        .map(|_| ())
    }
    pub fn set_dsa(&self, meth: Option<&ffi::DSA_METHOD>) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_DSA(self.as_ptr(), meth.map_or_else(ptr::null, |v| &*v)) })
            .map(|_| ())
    }
    #[cfg(not(ossl110))]
    pub fn set_ecdh(&self, meth: Option<&ffi::ECDH_METHOD>) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_ECDH(self.as_ptr(), meth.map_or_else(ptr::null, |v| &*v)) })
            .map(|_| ())
    }
    #[cfg(not(ossl110))]
    pub fn set_ecdsa(&self, meth: Option<&ffi::ECDSA_METHOD>) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_ECDSA(self.as_ptr(), meth.map_or_else(ptr::null, |v| &*v)) })
            .map(|_| ())
    }
    #[cfg(ossl110)]
    pub fn set_ec(&self, meth: Option<&ffi::EC_KEY_METHOD>) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_EC(self.as_ptr(), meth.map_or_else(ptr::null, |v| &*v)) })
            .map(|_| ())
    }
    pub fn set_dh(&self, meth: Option<&ffi::DH_METHOD>) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_DH(self.as_ptr(), meth.map_or_else(ptr::null, |v| &*v)) })
            .map(|_| ())
    }
    pub fn set_rand(&self, meth: Option<&ffi::RAND_METHOD>) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_RAND(self.as_ptr(), meth.map_or_else(ptr::null, |v| &*v)) })
            .map(|_| ())
    }
    #[cfg(not(ossl110))]
    pub fn set_store(&self, meth: Option<&ffi::STORE_METHOD>) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_STORE(self.as_ptr(), meth.map_or_else(ptr::null, |v| &*v)) })
            .map(|_| ())
    }
    pub fn set_destroy_function(&self, f: ffi::ENGINE_GEN_INT_FUNC_PTR) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_destroy_function(self.as_ptr(), f) }).map(|_| ())
    }
    pub fn set_init_function(&self, f: ffi::ENGINE_GEN_INT_FUNC_PTR) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_init_function(self.as_ptr(), f) }).map(|_| ())
    }
    pub fn set_finish_function(&self, f: ffi::ENGINE_GEN_INT_FUNC_PTR) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_finish_function(self.as_ptr(), f) }).map(|_| ())
    }
    pub fn set_ctrl_function(&self, f: ffi::ENGINE_CTRL_FUNC_PTR) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_ctrl_function(self.as_ptr(), f) }).map(|_| ())
    }
    pub fn set_load_privkey_function(&self, f: ffi::ENGINE_LOAD_KEY_PTR) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_load_privkey_function(self.as_ptr(), f) }).map(|_| ())
    }
    pub fn set_load_pubkey_function(&self, f: ffi::ENGINE_LOAD_KEY_PTR) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_load_pubkey_function(self.as_ptr(), f) }).map(|_| ())
    }
    pub fn set_load_ssl_client_cert_function(
        &self,
        f: ffi::ENGINE_SSL_CLIENT_CERT_PTR,
    ) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_load_ssl_client_cert_function(self.as_ptr(), f) }).map(|_| ())
    }
    pub fn set_ciphers(&self, f: ffi::ENGINE_CIPHERS_PTR) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_ciphers(self.as_ptr(), f) }).map(|_| ())
    }
    pub fn set_digests(&self, f: ffi::ENGINE_DIGESTS_PTR) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_digests(self.as_ptr(), f) }).map(|_| ())
    }
    pub fn set_pkey_meths(&self, f: ffi::ENGINE_PKEY_METHS_PTR) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_pkey_meths(self.as_ptr(), f) }).map(|_| ())
    }
    pub fn set_pkey_asn1_meths(
        &self,
        f: ffi::ENGINE_PKEY_ASN1_METHS_PTR,
    ) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_pkey_asn1_meths(self.as_ptr(), f) }).map(|_| ())
    }
    pub fn set_flags(&self, flags: Flags) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_flags(self.as_ptr(), flags.bits) }).map(|_| ())
    }
    pub fn set_cmd_defns(&self, defns: &[ffi::ENGINE_CMD_DEFN]) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_cmd_defns(self.as_ptr(), defns.as_ptr()) }).map(|_| ())
    }

    pub fn register_rsa(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_RSA(self.as_ptr()) }).map(|_| ())
    }
    pub fn register_dsa(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_DSA(self.as_ptr()) }).map(|_| ())
    }
    #[cfg(not(ossl110))]
    pub fn register_ecdh(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_ECDH(self.as_ptr()) }).map(|_| ())
    }
    #[cfg(not(ossl110))]
    pub fn register_ecdsa(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_ECDSA(self.as_ptr()) }).map(|_| ())
    }
    #[cfg(ossl110)]
    pub fn register_ec(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_EC(self.as_ptr()) }).map(|_| ())
    }
    pub fn register_dh(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_DH(self.as_ptr()) }).map(|_| ())
    }
    pub fn register_rand(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_RAND(self.as_ptr()) }).map(|_| ())
    }
    #[cfg(not(ossl110))]
    pub fn register_store(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_STORE(self.as_ptr()) }).map(|_| ())
    }
    pub fn register_ciphers(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_ciphers(self.as_ptr()) }).map(|_| ())
    }
    pub fn register_digests(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_digests(self.as_ptr()) }).map(|_| ())
    }
    pub fn register_pkey_meths(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_pkey_meths(self.as_ptr()) }).map(|_| ())
    }
    pub fn register_pkey_asn1_meths(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_pkey_asn1_meths(self.as_ptr()) }).map(|_| ())
    }
    pub fn register_complete(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_register_complete(self.as_ptr()) }).map(|_| ())
    }

    pub fn unregister_rsa(&self) {
        unsafe {
            ffi::ENGINE_unregister_RSA(self.as_ptr());
        }
    }
    pub fn unregister_dsa(&self) {
        unsafe {
            ffi::ENGINE_unregister_DSA(self.as_ptr());
        }
    }
    #[cfg(not(ossl110))]
    pub fn unregister_ecdh(&self) {
        unsafe {
            ffi::ENGINE_unregister_ECDH(self.as_ptr());
        }
    }
    #[cfg(not(ossl110))]
    pub fn unregister_ecdsa(&self) {
        unsafe {
            ffi::ENGINE_unregister_ECDSA(self.as_ptr());
        }
    }
    #[cfg(ossl110)]
    pub fn unregister_ec(&self) {
        unsafe {
            ffi::ENGINE_unregister_EC(self.as_ptr());
        }
    }
    pub fn unregister_dh(&self) {
        unsafe {
            ffi::ENGINE_unregister_DH(self.as_ptr());
        }
    }
    pub fn unregister_rand(&self) {
        unsafe {
            ffi::ENGINE_unregister_RAND(self.as_ptr());
        }
    }
    #[cfg(not(ossl110))]
    pub fn unregister_store(&self) {
        unsafe {
            ffi::ENGINE_unregister_STORE(self.as_ptr());
        }
    }
    pub fn unregister_ciphers(&self) {
        unsafe {
            ffi::ENGINE_unregister_ciphers(self.as_ptr());
        }
    }
    pub fn unregister_digests(&self) {
        unsafe {
            ffi::ENGINE_unregister_digests(self.as_ptr());
        }
    }
    pub fn unregister_pkey_meths(&self) {
        unsafe {
            ffi::ENGINE_unregister_pkey_meths(self.as_ptr());
        }
    }
    pub fn unregister_pkey_asn1_meths(&self) {
        unsafe {
            ffi::ENGINE_unregister_pkey_asn1_meths(self.as_ptr());
        }
    }

    /// Initialise a engine type for use (or up its reference count if it's
    /// already in use). This will fail if the engine is not currently operational
    /// and cannot initialise.
    pub fn init(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_init(self.as_ptr()) }).map(|_| ())
    }

    /// Free a functional reference to a engine type. This does not require a
    /// corresponding call to ENGINE_free as it also releases a structural
    /// reference.
    pub fn finish(&self) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_finish(self.as_ptr()) }).map(|_| ())
    }

    /// Send parameterised control commands to the engine. The possibilities to
    /// send down an integer, a pointer to data or a function pointer are
    /// provided. Any of the parameters may or may not be NULL, depending on the
    /// command number. In actuality, this function only requires a structural
    /// (rather than functional) reference to an engine, but many control commands
    /// may require the engine be functional. The caller should be aware of trying
    /// commands that require an operational ENGINE, and only use functional
    /// references in such situations.
    pub fn ctrl(
        &self,
        cmd: c_int,
        i: Option<c_long>,
        p: Option<*mut c_void>,
        f: Option<unsafe extern "C" fn()>,
    ) -> Result<(), ErrorStack> {
        cvt(unsafe {
            ffi::ENGINE_ctrl(
                self.as_ptr(),
                cmd,
                i.unwrap_or_default(),
                p.unwrap_or_else(ptr::null_mut),
                f,
            )
        })
        .map(|_| ())
    }

    /// This function tests if an ENGINE-specific command is usable as a
    /// "setting". Eg. in an application's config file that gets processed through
    /// ENGINE_ctrl_cmd_string(). If this returns zero, it is not available to
    /// ENGINE_ctrl_cmd_string(), only ENGINE_ctrl().
    pub fn cmd_is_executable(&self, cmd: c_int) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_cmd_is_executable(self.as_ptr(), cmd) }).map(|_| ())
    }

    /// This function works like ENGINE_ctrl() with the exception of taking a
    /// command name instead of a command number, and can handle optional
    /// commands. See the comment on ENGINE_ctrl_cmd_string() for an explanation
    /// on how to use the cmd_name and cmd_optional.
    pub fn ctrl_cmd(
        &self,
        cmd: &str,
        i: Option<c_long>,
        p: Option<*mut c_void>,
        f: Option<unsafe extern "C" fn()>,
        cmd_optional: c_int,
    ) -> Result<(), ErrorStack> {
        cvt(unsafe {
            ffi::ENGINE_ctrl_cmd(
                self.as_ptr(),
                CString::new(cmd).unwrap().as_ptr(),
                i.unwrap_or_default(),
                p.unwrap_or_else(ptr::null_mut),
                f,
                cmd_optional,
            )
        })
        .map(|_| ())
    }

    /// This function passes a command-name and argument to an ENGINE. The
    /// cmd_name is converted to a command number and the control command is
    /// called using 'arg' as an argument (unless the ENGINE doesn't support such
    /// a command, in which case no control command is called). The command is
    /// checked for input flags, and if necessary the argument will be converted
    /// to a numeric value. If cmd_optional is non-zero, then if the ENGINE
    /// doesn't support the given cmd_name the return value will be success
    /// anyway. This function is intended for applications to use so that users
    /// (or config files) can supply engine-specific config data to the ENGINE at
    /// run-time to control behaviour of specific engines. As such, it shouldn't
    /// be used for calling ENGINE_ctrl() functions that return data, deal with
    /// binary data, or that are otherwise supposed to be used directly through
    /// ENGINE_ctrl() in application code. Any "return" data from an ENGINE_ctrl()
    /// operation in this function will be lost - the return value is interpreted
    /// as failure if the return value is zero, success otherwise, and this
    /// function returns a boolean value as a result. In other words, vendors of
    /// 'ENGINE'-enabled devices should write ENGINE implementations with
    /// parameterisations that work in this scheme, so that compliant ENGINE-based
    /// applications can work consistently with the same configuration for the
    /// same ENGINE-enabled devices, across applications.
    pub fn ctrl_cmd_string(
        &self,
        cmd_name: &str,
        arg: &str,
        cmd_optional: c_int,
    ) -> Result<(), ErrorStack> {
        cvt(unsafe {
            ffi::ENGINE_ctrl_cmd_string(
                self.as_ptr(),
                CString::new(cmd_name).unwrap().as_ptr(),
                CString::new(arg).unwrap().as_ptr(),
                cmd_optional,
            )
        })
        .map(|_| ())
    }

    pub fn load_private_key<T>(
        &self,
        key_id: &str,
        ui_method: Option<&mut ffi::UI_METHOD>,
        callback_data: Option<&mut T>,
    ) -> Result<PKey<Private>, ErrorStack> {
        cvt_p(unsafe {
            ffi::ENGINE_load_private_key(
                self.as_ptr(),
                CString::new(key_id).unwrap().as_ptr(),
                ui_method.map_or_else(ptr::null_mut, |v| &mut *v),
                callback_data.map_or_else(ptr::null_mut, |v| &mut *v) as *mut _,
            )
        })
        .map(|p| unsafe { PKey::from_ptr(p) })
    }

    pub fn load_public_key<T>(
        &self,
        key_id: &str,
        ui_method: Option<&mut ffi::UI_METHOD>,
        callback_data: Option<&mut T>,
    ) -> Result<PKey<Public>, ErrorStack> {
        cvt_p(unsafe {
            ffi::ENGINE_load_public_key(
                self.as_ptr(),
                CString::new(key_id).unwrap().as_ptr(),
                ui_method.map_or_else(ptr::null_mut, |v| &mut *v),
                callback_data.map_or_else(ptr::null_mut, |v| &mut *v) as *mut _,
            )
        })
        .map(|p| unsafe { PKey::from_ptr(p) })
    }

    pub fn load_ssl_client_cert<T>(
        &self,
        ssl: &SslRef,
        ca_dn: &Stack<X509Name>,
        ui_method: Option<&mut ffi::UI_METHOD>,
        callback_data: Option<&mut T>,
    ) -> Result<(X509, PKey<Private>, Stack<X509>), ErrorStack> {
        let mut pcert = ptr::null_mut();
        let mut ppkey = ptr::null_mut();
        let mut pother = ptr::null_mut();

        cvt(unsafe {
            ffi::ENGINE_load_ssl_client_cert(
                self.as_ptr(),
                ssl.as_ptr(),
                ca_dn.as_ptr(),
                &mut pcert,
                &mut ppkey,
                &mut pother,
                ui_method.map_or_else(ptr::null_mut, |v| &mut *v),
                callback_data.map_or_else(ptr::null_mut, |v| &mut *v) as *mut _,
            )
        })
        .map(|_| unsafe {
            (
                X509::from_ptr(pcert),
                PKey::from_ptr(ppkey),
                Stack::<X509>::from_ptr(pother),
            )
        })
    }
}

/// Get the first "ENGINE" type available.
pub fn first() -> Option<Engine> {
    cvt_p(unsafe { ffi::ENGINE_get_first() })
        .map(|e| unsafe { Engine::from_ptr(e) })
        .ok()
}

/// Get the last "ENGINE" type available.
pub fn last() -> Option<Engine> {
    cvt_p(unsafe { ffi::ENGINE_get_last() })
        .map(|e| unsafe { Engine::from_ptr(e) })
        .ok()
}

/// Iterate to the next "ENGINE" type
pub fn next(e: &EngineRef) -> Option<Engine> {
    cvt_p(unsafe { ffi::ENGINE_get_next(e.as_ptr()) })
        .map(|e| unsafe { Engine::from_ptr(e) })
        .ok()
}

/// Iterate to the previous "ENGINE" type
pub fn prev(e: &EngineRef) -> Option<Engine> {
    cvt_p(unsafe { ffi::ENGINE_get_prev(e.as_ptr()) })
        .map(|e| unsafe { Engine::from_ptr(e) })
        .ok()
}

/// Add another "ENGINE" type into the array.
pub fn add(e: &EngineRef) -> Result<(), ErrorStack> {
    cvt(unsafe { ffi::ENGINE_add(e.as_ptr()) }).map(|_| ())
}

/// Remove an existing "ENGINE" type from the array.
pub fn remove(e: &EngineRef) -> Result<(), ErrorStack> {
    cvt(unsafe { ffi::ENGINE_remove(e.as_ptr()) }).map(|_| ())
}

/// Retrieve an engine from the list by its unique "id" value.
pub fn by_id(id: &str) -> Option<Engine> {
    cvt_p(unsafe { ffi::ENGINE_by_id(CString::new(id).unwrap().as_ptr()) })
        .map(|e| unsafe { Engine::from_ptr(e) })
        .ok()
}
