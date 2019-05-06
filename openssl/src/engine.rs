use std::ffi::{CStr, CString};
use std::ptr;

use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_long, c_uint, c_void};

use error::ErrorStack;
use ffi;
use {cvt, cvt_n, ex_data::Index};

bitflags! {
    /// These flags are used to control combinations of algorithm (methods) by bitwise "OR"ing.
    pub struct EngineMethod: c_uint {
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
    pub struct EngineFlags: c_int {
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
    pub fn set_default(e: &EngineRef, methods: EngineMethod) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_default(e.as_ptr(), methods.bits) }).map(|_| ())
    }

    pub fn table_flags() -> TableFlags {
        TableFlags::from_bits_truncate(unsafe { ffi::ENGINE_get_table_flags() })
    }
    pub fn set_table_flags(flags: TableFlags) {
        unsafe { ffi::ENGINE_set_table_flags(flags.bits) }
    }

    pub fn cleanup() {
        unsafe { ffi::ENGINE_cleanup() }
    }
}

impl EngineRef {
    pub fn id(&self) -> &CStr {
        unsafe { CStr::from_ptr(ffi::ENGINE_get_id(self.as_ptr())) }
    }

    pub fn name(&self) -> &CStr {
        unsafe { CStr::from_ptr(ffi::ENGINE_get_name(self.as_ptr())) }
    }

    pub fn flags(&self) -> EngineFlags {
        EngineFlags::from_bits_truncate(unsafe { ffi::ENGINE_get_flags(self.as_ptr()) })
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
    pub fn set_rsa(&self, meth: Option<&ffi::RSA_METHOD>) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_RSA(self.as_ptr(), meth.map_or_else(ptr::null, |v| &*v)) })
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
    pub fn set_flags(&self, flags: EngineFlags) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::ENGINE_set_flags(self.as_ptr(), flags.bits) }).map(|_| ())
    }
    pub fn set_cmd_defns(&self, defns: Option<&ffi::ENGINE_CMD_DEFN>) -> Result<(), ErrorStack> {
        cvt(unsafe {
            ffi::ENGINE_set_cmd_defns(self.as_ptr(), defns.map_or_else(ptr::null, |v| &*v))
        })
        .map(|_| ())
    }

    pub fn new_ex_index<T>() -> Result<Index<Engine, T>, ErrorStack>
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

    pub fn ex_data<T>(&self, idx: Index<Engine, T>) -> Option<&T> {
        unsafe { (ffi::ENGINE_get_ex_data(self.as_ptr(), idx.as_raw()) as *const T).as_ref() }
    }

    pub fn set_ex_data<T>(&mut self, index: Index<Engine, T>, data: T) -> Result<(), ErrorStack> {
        cvt(unsafe {
            let data = Box::new(data);

            ffi::ENGINE_set_ex_data(
                self.as_ptr(),
                index.as_raw(),
                Box::into_raw(data) as *mut c_void,
            )
        })
        .map(|_| ())
    }
}

unsafe extern "C" fn free_data_box<T>(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut ffi::CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if !ptr.is_null() {
        Box::<T>::from_raw(ptr as *mut T);
    }
}
