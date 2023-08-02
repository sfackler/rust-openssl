use crate::error::ErrorStack;
use crate::{cvt, cvt_p};
use libc::strlen;
use openssl_macros::corresponds;
use std::ffi::{c_void, CString};

struct Engine(*mut ffi::ENGINE);

impl Engine {
    /// Creates a new Engine.
    #[corresponds(ENGINE_new)]
    #[inline]
    pub fn new() -> Result<Self, ErrorStack> {
        ffi::init();
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_new())?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::ENGINE {
        self.0
    }

    pub fn from_ptr(ptr: *mut ffi::ENGINE) -> Engine {
        Engine(ptr)
    }

    /// Returns the "first" ENGINE type available.
    #[corresponds(ENGINE_get_first)]
    #[inline]
    pub fn get_first() -> Result<Self, ErrorStack> {
        ffi::init();
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_get_first())?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    /// Returns the "last" ENGINE type available.
    #[corresponds(ENGINE_get_last)]
    #[inline]
    pub fn get_last() -> Result<Self, ErrorStack> {
        ffi::init();
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_get_last())?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    /// Returns the "next" ENGINE type available, after the passed in ENGINE.
    #[corresponds(ENGINE_get_next)]
    #[inline]
    pub fn get_next(&mut self) -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_get_next(self.as_ptr()))?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    /// Returns the "previous" ENGINE type available, before the passed in ENGINE.
    #[corresponds(ENGINE_get_prev)]
    #[inline]
    pub fn get_prev(&mut self) -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_get_prev(self.as_ptr()))?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    /// Adds the engine to OpenSSL's internal engine list.
    #[corresponds(ENGINE_add)]
    #[inline]
    pub fn add(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_add(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Removes the engine from OpenSSL's internal engine list.
    #[corresponds(ENGINE_remove)]
    #[inline]
    pub fn remove(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_remove(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Returns an engine with the passed in `id`.
    #[corresponds(ENGINE_by_id)]
    #[inline]
    pub fn by_id(id: &str) -> Result<Self, ErrorStack> {
        let id = CString::new(id).unwrap();
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_by_id(id.as_ptr()))?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    /// Remove all references to the passed in engine.
    #[corresponds(ENGINE_finish)]
    #[inline]
    pub fn finish(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_finish(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Loads the builtin engines.
    #[corresponds(ENGINE_load_builtin_engines)]
    #[inline]
    pub fn load_builtin_engines() {
        unsafe {
            ffi::ENGINE_load_builtin_engines();
        }
    }

    /// Returns the default engine for the "RSA" algorithm.
    #[corresponds(ENGINE_get_default_RSA)]
    #[inline]
    pub fn get_default_rsa() -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_get_default_RSA())?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    /// Returns the default engine for the "DSA" algorithm.
    #[corresponds(ENGINE_get_default_DSA)]
    #[inline]
    pub fn get_default_dsa() -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_get_default_DSA())?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    /// Returns the default engine for the "DH" algorithm.
    #[corresponds(ENGINE_get_default_DH)]
    #[inline]
    pub fn get_default_dh() -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_get_default_DH())?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    /// Returns the default engine for the "RAND" algorithm.
    #[corresponds(ENGINE_get_default_RAND)]
    #[inline]
    pub fn get_default_rand() -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_get_default_RAND())?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    /// Returns the default cipher engine.
    #[corresponds(ENGINE_get_default_cipher_engine)]
    #[inline]
    pub fn get_cipher_engine(nid: i32) -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_get_cipher_engine(nid))?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    /// Returns the default digest engine.
    #[corresponds(ENGINE_get_digest_engine)]
    #[inline]
    pub fn get_digest_engine(nid: i32) -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::ENGINE_get_digest_engine(nid))?;
            Ok(Engine::from_ptr(ptr))
        }
    }

    /// Sets the default RSA engine.
    #[corresponds(ENGINE_set_default_RSA)]
    #[inline]
    pub fn set_default_rsa(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_set_default_RSA(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Sets the default DSA engine.
    #[corresponds(ENGINE_set_default_DSA)]
    #[inline]
    pub fn set_default_dsa(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_set_default_DSA(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Sets the default DH engine.
    #[corresponds(ENGINE_set_default_DH)]
    #[inline]
    pub fn set_default_dh(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_set_default_DH(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Sets the default RAND engine.
    #[corresponds(ENGINE_set_default_RAND)]
    #[inline]
    pub fn set_default_rand(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_set_default_RAND(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Sets the default ciphers engine.
    #[corresponds(ENGINE_set_default_ciphers)]
    #[inline]
    pub fn set_default_ciphers(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_set_default_ciphers(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Sets the default digests engine.
    #[corresponds(ENGINE_set_default_digests)]
    #[inline]
    pub fn set_default_digests(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_set_default_digests(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Sets the default string for the engine.
    #[corresponds(ENGINE_set_default_string)]
    #[inline]
    pub fn set_default_string(&mut self, list: &str) -> Result<(), ErrorStack> {
        let list = CString::new(list).unwrap();
        unsafe {
            cvt(ffi::ENGINE_set_default_string(self.as_ptr(), list.as_ptr()))?;
        }
        Ok(())
    }

    /// Sets the default engine.
    #[corresponds(ENGINE_set_default)]
    #[inline]
    pub fn set_default(&mut self, flags: u32) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_set_default(self.as_ptr(), flags))?;
        }
        Ok(())
    }

    /// Returns the (global?) engine table flags.
    #[corresponds(ENGINE_get_table_flags)]
    #[inline]
    pub fn get_table_flags() -> u32 {
        unsafe {
            ffi::ENGINE_get_table_flags()
        }
    }

    /// Sets the (global?) engine table flags.
    #[corresponds(ENGINE_set_table_flags)]
    #[inline]
    pub fn set_table_flags(flags: u32) {
        unsafe {
            ffi::ENGINE_set_table_flags(flags);
        }
    }

    /// Registers the input engine as the RSA engine.
    #[corresponds(ENGINE_register_RSA)]
    #[inline]
    pub fn register_rsa(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_register_RSA(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Unregisters the input engine as the RSA engine.
    #[corresponds(ENGINE_unregister_RSA)]
    #[inline]
    pub fn unregister_rsa(&mut self) {
        unsafe {
            ffi::ENGINE_unregister_RSA(self.as_ptr());
        }
    }

    /// Registers all of the engines as RSA.
    #[corresponds(ENGINE_register_all_RSA)]
    #[inline]
    pub fn register_all_rsa(&mut self) {
        unsafe {
            ffi::ENGINE_register_all_RSA();
        }
    }

    /// Registers the input engine as the DSA engine.
    #[corresponds(ENGINE_register_DSA)]
    #[inline]
    pub fn register_dsa(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_register_DSA(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Unregisters the input engine as the DSA engine.
    #[corresponds(ENGINE_unregister_DSA)]
    #[inline]
    pub fn unregister_dsa(&mut self) {
        unsafe {
            ffi::ENGINE_unregister_DSA(self.as_ptr());
        }
    }

    /// Registers all of the engines as DSA.
    #[corresponds(ENGINE_unregister_DSA)]
    #[inline]
    pub fn register_all_dsa() {
        unsafe {
            ffi::ENGINE_register_all_DSA();
        }
    }

    /// Registers the input engine as the DH engine.
    #[corresponds(ENGINE_register_DH)]
    #[inline]
    pub fn register_dh(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_register_DH(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Unregisters the input engine as the DH engine.
    #[corresponds(ENGINE_unregister_DH)]
    #[inline]
    pub fn unregister_dh(&mut self) {
        unsafe {
            ffi::ENGINE_unregister_DH(self.as_ptr());
        }
    }

    /// Registers all of the engines as DH.
    #[corresponds(ENGINE_unregister_DH)]
    #[inline]
    pub fn register_all_dh() {
        unsafe {
            ffi::ENGINE_register_all_DH();
        }
    }

    /// Registers the input engine as the RAND engine.
    #[corresponds(ENGINE_register_RAND)]
    #[inline]
    pub fn register_rand(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_register_RAND(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Unregisters the input engine as the RAND engine.
    #[corresponds(ENGINE_unregister_RAND)]
    #[inline]
    pub fn unregister_rand(&mut self) {
        unsafe {
            ffi::ENGINE_unregister_RAND(self.as_ptr());
        }
    }

    /// Registers all of the engines as RAND.
    #[corresponds(ENGINE_unregister_RAND)]
    #[inline]
    pub fn register_all_rand() {
        unsafe {
            ffi::ENGINE_register_all_RAND();
        }
    }

    /// Registers ciphers from the input engine.
    #[corresponds(ENGINE_register_ciphers)]
    #[inline]
    pub fn register_ciphers(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_register_ciphers(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Unregisters the ciphers from the input engine.
    #[corresponds(ENGINE_unregister_ciphers)]
    #[inline]
    pub fn unregister_ciphers(&mut self) {
        unsafe {
            ffi::ENGINE_unregister_ciphers(self.as_ptr());
        }
    }

    /// Registers all ciphers from the input engine.
    #[corresponds(ENGINE_unregister_ciphers)]
    #[inline]
    pub fn register_all_ciphers() {
        unsafe {
            ffi::ENGINE_register_all_ciphers();
        }
    }

    /// Registers digests from the input engine.
    #[corresponds(ENGINE_register_digests)]
    #[inline]
    pub fn register_digests(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_register_digests(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Unregisters the digests from the input engine.
    #[corresponds(ENGINE_unregister_digests)]
    #[inline]
    pub fn unregister_digests(&mut self) {
        unsafe {
            ffi::ENGINE_unregister_digests(self.as_ptr());
        }
    }

    /// Registers all digests from the input engine.
    #[corresponds(ENGINE_unregister_digests)]
    #[inline]
    pub fn register_all_digests() {
        unsafe {
            ffi::ENGINE_register_all_digests();
        }
    }

    pub fn register_complete(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_register_complete(self.as_ptr()))?;
        }
        Ok(())
    }

    pub fn register_all_complete() -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_register_all_complete())?;
        }
        Ok(())
    }

    pub fn ctrl(
        &mut self,
        _cmd: i32,
        _i: i64,
        _p: *mut c_void,
        _f: extern "C" fn(),
    ) -> Result<(), ErrorStack> {
        todo!();
    }

    pub fn cmd_is_executable(&mut self, cmd: i32) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_cmd_is_executable(self.as_ptr(), cmd))?;
        }
        Ok(())
    }

    pub fn ctrl_cmd(&mut self, _cmd: &str, _arg: &str, _param: i32) -> Result<(), ErrorStack> {
        todo!();
    }

    pub fn ctrl_cmd_string(
        &mut self,
        _cmd: &str,
        _arg: &str,
        _optional: i32,
    ) -> Result<(), ErrorStack> {
        todo!();
    }

    pub fn up_ref(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_up_ref(self.as_ptr()))?;
        }
        Ok(())
    }

    /// Sets the ID on the engine.
    #[corresponds(ENGINE_set_id)]
    #[inline]
    pub fn set_id(&mut self, id: &str) -> Result<(), ErrorStack> {
        let id = CString::new(id).unwrap();
        unsafe {
            cvt(ffi::ENGINE_set_id(self.as_ptr(), id.as_ptr()))?;
        }
        Ok(())
    }

    /// Sets the name on the engine.
    #[corresponds(ENGINE_set_name)]
    #[inline]
    pub fn set_name(&mut self, name: &str) -> Result<(), ErrorStack> {
        let name = CString::new(name).unwrap();
        unsafe {
            cvt(ffi::ENGINE_set_name(self.as_ptr(), name.as_ptr()))?;
        }
        Ok(())
    }

    /// Sets the RSA method on the engine.
    #[corresponds(ENGINE_set_RSA)]
    #[inline]
    pub fn set_rsa(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets the DSA method on the engine.
    #[corresponds(ENGINE_set_DSA)]
    #[inline]
    pub fn set_dsa(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets the DH method on the engine.
    #[corresponds(ENGINE_set_DH)]
    #[inline]
    pub fn set_dh(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets the RAND method on the engine.
    #[corresponds(ENGINE_set_RAND)]
    #[inline]
    pub fn set_rand(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets the destroy function on the engine.
    #[corresponds(ENGINE_set_destroy_function)]
    #[inline]
    pub fn set_destroy_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets the init function on the engine.
    #[corresponds(ENGINE_set_init_function)]
    #[inline]
    pub fn set_init_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets the finish function on the engine.
    #[corresponds(ENGINE_set_finish_function)]
    #[inline]
    pub fn set_finish_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets the ctrl function on the engine.
    #[corresponds(ENGINE_set_ctrl_function)]
    #[inline]
    pub fn set_ctrl_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets the `load_privkey` function on the engine.
    #[corresponds(ENGINE_set_load_privkey_function)]
    #[inline]
    pub fn set_load_privkey_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets the `load_pubkey` function on the engine.
    #[corresponds(ENGINE_set_load_pubkey_function)]
    #[inline]
    pub fn set_load_pubkey_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets the ciphers pointer on the engine.
    #[corresponds(ENGINE_set_ciphers)]
    #[inline]
    pub fn set_ciphers(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets the digests pointer on the engine.
    #[corresponds(ENGINE_set_digests)]
    #[inline]
    pub fn set_digests(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Sets command definitions on the engine.
    #[corresponds(ENGINE_set_cmd_defns)]
    #[inline]
    pub fn set_cmd_defns(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's ID.
    #[corresponds(ENGINE_get_id)]
    #[inline]
    pub fn get_id(&mut self) -> Result<String, ErrorStack> {
        unsafe {
            let ptr = ffi::ENGINE_get_id(self.as_ptr());
            if ptr.is_null() {
                return Err(ErrorStack::get());
            }

            let slice = std::slice::from_raw_parts(ptr as *const u8, strlen(ptr));
            let s = std::str::from_utf8_unchecked(slice).to_string();

            Ok(s)
        }
    }

    /// Returns the engine's name.
    #[corresponds(ENGINE_get_name)]
    #[inline]
    pub fn get_name(&mut self) -> Result<String, ErrorStack> {
        unsafe {
            let ptr = ffi::ENGINE_get_name(self.as_ptr());
            if ptr.is_null() {
                return Err(ErrorStack::get());
            }

            let slice = std::slice::from_raw_parts(ptr as *const u8, strlen(ptr));
            let s = std::str::from_utf8_unchecked(slice).to_string();

            Ok(s)
        }
    }

    /// Returns the engine's currently set RSA method.
    #[corresponds(ENGINE_get_RSA)]
    #[inline]
    pub fn get_rsa(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's currently set DSA method.
    #[corresponds(ENGINE_get_DSA)]
    #[inline]
    pub fn get_dsa(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's currently set DH method.
    #[corresponds(ENGINE_get_DH)]
    #[inline]
    pub fn get_dh(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's currently set RAND method.
    #[corresponds(ENGINE_get_RAND)]
    #[inline]
    pub fn get_rand(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's currently set destroy function.
    #[corresponds(ENGINE_get_destroy_function)]
    #[inline]
    pub fn get_destroy_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's currently set init function.
    #[corresponds(ENGINE_get_init_function)]
    #[inline]
    pub fn get_init_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's currently set finish function.
    #[corresponds(ENGINE_get_finish_function)]
    #[inline]
    pub fn get_finish_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's currently set ctrl function.
    #[corresponds(ENGINE_get_ctrl_function)]
    #[inline]
    pub fn get_ctrl_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's currently set `load_privkey_function` function.
    #[corresponds(ENGINE_get_load_privkey_function)]
    #[inline]
    pub fn get_load_privkey_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's currently set `load_pubkey_function` function.
    #[corresponds(ENGINE_get_load_pubkey_function)]
    #[inline]
    pub fn get_load_pubkey_function(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's currently set ciphers.
    #[corresponds(ENGINE_get_ciphers)]
    #[inline]
    pub fn get_ciphers(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's current set digests.
    #[corresponds(ENGINE_get_digests)]
    #[inline]
    pub fn get_digests(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the cipher for the passed `nid` value.
    #[corresponds(ENGINE_get_cipher)]
    #[inline]
    pub fn get_cipher(&mut self, _nid: i32) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the digest for the passed `nid` value.
    #[corresponds(ENGINE_get_digest)]
    #[inline]
    pub fn get_digest(&mut self, _nid: i32) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Returns the engine's flags.
    #[corresponds(ENGINE_get_flags)]
    #[inline]
    pub fn get_flags(&mut self) -> i32 {
        // TODO should these flags be a different type?
        unsafe { ffi::ENGINE_get_flags(self.as_ptr()) }
    }

    /// Returns the command definitions.
    #[corresponds(ENGINE_get_cmd_defns)]
    #[inline]
    pub fn get_cmd_defns(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Load a private key into the engine.
    #[corresponds(ENGINE_load_private_key)]
    #[inline]
    pub fn load_private_key(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }

    /// Load a public key into the engine.
    #[corresponds(ENGINE_load_public_key)]
    #[inline]
    pub fn load_public_key(&mut self) -> Result<(), ErrorStack> {
        todo!();
    }
}

impl Drop for Engine {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::ENGINE_free(self.as_ptr());
        }
    }
}

mod test {
    use super::*;

    // #[test]
    fn test_basic_engine_creation() {
        let mut engine = Engine::new().unwrap();

        let name = String::from("engine_name");
        let id = String::from("engine_id");

        // there should not be errors on setting id or name
        assert!(engine.set_id(&id).is_ok());
        assert!(engine.set_name(&name).is_ok());

        assert_eq!(id, engine.get_id().unwrap().as_str());
        assert_eq!(name, engine.get_name().unwrap().as_str());
    }

    #[test]
    fn iterate_through_engines() {
        let mut engine = Engine::get_first().unwrap();

        let mut has_engines = true;
        let mut engine_cnt = 1;

        println!("Engines:");

        while has_engines {
            println!(
                "  {}, name={}, id={}",
                engine_cnt,
                engine.get_name().unwrap(),
                engine.get_id().unwrap()
            );
            match engine.get_next() {
                Ok(e) => engine = e,
                Err(_) => has_engines = false,
            }

            engine_cnt += 1;
        }
    }
}
