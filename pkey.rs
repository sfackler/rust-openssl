use libc::{c_int, c_uint};

#[allow(non_camel_case_types)]
type EVP_PKEY = *libc::c_void;

#[allow(non_camel_case_types)]
type ANYKEY = *libc::c_void;

#[allow(non_camel_case_types)]
type RSA = *libc::c_void;

#[link_name = "crypto"]
#[abi = "cdecl"]
extern mod libcrypto {
    fn EVP_PKEY_new() -> *EVP_PKEY;
    fn EVP_PKEY_free(k: *EVP_PKEY);
    fn EVP_PKEY_assign(k: *EVP_PKEY, t: c_int, inner: *ANYKEY);
    fn EVP_PKEY_get1_RSA(k: *EVP_PKEY) -> *RSA;

    fn i2d_PublicKey(k: *EVP_PKEY, buf: &*mut u8) -> c_int;
    fn d2i_PublicKey(t: c_int, k: &*EVP_PKEY, buf: &*u8, len: c_uint) -> *EVP_PKEY;
    fn i2d_PrivateKey(k: *EVP_PKEY, buf: &*mut u8) -> c_int;
    fn d2i_PrivateKey(t: c_int, k: &*EVP_PKEY, buf: &*u8, len: c_uint) -> *EVP_PKEY;

    fn RSA_generate_key(modsz: c_uint, e: c_uint, cb: *u8, cbarg: *u8) -> *RSA;
    fn RSA_size(k: *RSA) -> c_uint;

    fn RSA_public_encrypt(flen: c_uint, from: *u8, to: *mut u8, k: *RSA,
                          pad: c_int) -> c_int;
    fn RSA_private_decrypt(flen: c_uint, from: *u8, to: *mut u8, k: *RSA,
                           pad: c_int) -> c_int;
    fn RSA_sign(t: c_int, m: *u8, mlen: c_uint, sig: *mut u8, siglen: *c_uint,
                k: *RSA) -> c_int;
    fn RSA_verify(t: c_int, m: *u8, mlen: c_uint, sig: *u8, siglen: c_uint,
                  k: *RSA) -> c_int;
}

enum Parts {
    Neither,
    Public,
    Both
}

#[doc = "Represents a role an asymmetric key might be appropriate for."]
pub enum Role {
    Encrypt,
    Decrypt,
    Sign,
    Verify
}

fn rsa_to_any(rsa: *RSA) -> *ANYKEY unsafe {
    cast::reinterpret_cast(&rsa)
}

fn any_to_rsa(anykey: *ANYKEY) -> *RSA unsafe {
    cast::reinterpret_cast(&anykey)
}

pub struct PKey {
    priv mut evp: *EVP_PKEY,
    priv mut parts: Parts,
}

pub fn PKey() -> PKey {
    PKey { evp: libcrypto::EVP_PKEY_new(), parts: Neither }
}

priv impl PKey {
    fn _tostr(f: fn@(*EVP_PKEY, &*mut u8) -> c_int) -> ~[u8] unsafe {
        let buf = ptr::mut_null();
        let len = f(self.evp, &buf);
        if len < 0 as c_int { return ~[]; }
        let mut s = vec::from_elem(len as uint, 0u8);

        let r = do vec::as_mut_buf(s) |ps, _len| {
            f(self.evp, &ps)
        };

        vec::slice(s, 0u, r as uint)
    }

    fn _fromstr(
        s: &[u8],
        f: fn@(c_int, &*EVP_PKEY, &*u8, c_uint) -> *EVP_PKEY
    ) unsafe {
        do vec::as_imm_buf(s) |ps, len| {
            let evp = ptr::null();
            f(6 as c_int, &evp, &ps, len as c_uint);
            self.evp = evp;
        }
    }
}

///Represents a public key, optionally with a private key attached.
pub impl PKey {
    fn gen(keysz: uint) unsafe {
        let rsa = libcrypto::RSA_generate_key(
            keysz as c_uint,
            65537u as c_uint,
            ptr::null(),
            ptr::null()
        );

        let rsa_ = rsa_to_any(rsa);
        // XXX: 6 == NID_rsaEncryption
        libcrypto::EVP_PKEY_assign(self.evp, 6 as c_int, rsa_);
        self.parts = Both;
    }

    /**
     * Returns a serialized form of the public key, suitable for load_pub().
     */
    fn save_pub() -> ~[u8] {
        self._tostr(libcrypto::i2d_PublicKey)
    }

    /**
     * Loads a serialized form of the public key, as produced by save_pub().
     */
    fn load_pub(s: &[u8]) {
        self._fromstr(s, libcrypto::d2i_PublicKey);
        self.parts = Public;
    }

    /**
     * Returns a serialized form of the public and private keys, suitable for
     * load_priv().
     */
    fn save_priv() -> ~[u8] {
        self._tostr(libcrypto::i2d_PrivateKey)
    }
    /**
     * Loads a serialized form of the public and private keys, as produced by
     * save_priv().
     */
    fn load_priv(s: &[u8]) {
        self._fromstr(s, libcrypto::d2i_PrivateKey);
        self.parts = Both;
    }

    /**
     * Returns the size of the public key modulus.
     */
    fn size() -> uint {
        libcrypto::RSA_size(libcrypto::EVP_PKEY_get1_RSA(self.evp)) as uint
    }

    /**
     * Returns whether this pkey object can perform the specified role.
     */
    fn can(r: Role) -> bool {
        match r {
            Encrypt =>
                match self.parts {
                    Neither => false,
                    _ => true,
                },
            Verify =>
                match self.parts {
                    Neither => false,
                    _ => true,
                },
            Decrypt =>
                match self.parts {
                    Both => true,
                    _ => false,
                },
            Sign =>
                match self.parts {
                    Both => true,
                    _ => false,
                },
        }
    }

    /**
     * Returns the maximum amount of data that can be encrypted by an encrypt()
     * call.
     */
    fn max_data() -> uint unsafe {
        let rsa = libcrypto::EVP_PKEY_get1_RSA(self.evp);
        let len = libcrypto::RSA_size(rsa);

        // 41 comes from RSA_public_encrypt(3) for OAEP
        len as uint - 41u
    }

    /**
     * Encrypts data using OAEP padding, returning the encrypted data. The
     * supplied data must not be larger than max_data().
     */
    fn encrypt(s: &[u8]) -> ~[u8] unsafe {
        let rsa = libcrypto::EVP_PKEY_get1_RSA(self.evp);
        let len = libcrypto::RSA_size(rsa);

        // 41 comes from RSA_public_encrypt(3) for OAEP
        assert s.len() < libcrypto::RSA_size(rsa) as uint - 41u;

        let mut r = vec::from_elem(len as uint + 1u, 0u8);

        do vec::as_mut_buf(r) |pr, _len| {
            do vec::as_imm_buf(s) |ps, s_len| {
                // XXX: 4 == RSA_PKCS1_OAEP_PADDING
                let rv = libcrypto::RSA_public_encrypt(
                    s_len as c_uint,
                    ps,
                    pr,
                    rsa, 4 as c_int
                );

                if rv < 0 as c_int {
                    ~[]
                } else {
                    vec::slice(r, 0u, rv as uint)
                }
            }
        }
    }

    /**
     * Decrypts data, expecting OAEP padding, returning the decrypted data.
     */
    fn decrypt(s: &[u8]) -> ~[u8] unsafe {
        let rsa = libcrypto::EVP_PKEY_get1_RSA(self.evp);
        let len = libcrypto::RSA_size(rsa);

        assert s.len() as c_uint == libcrypto::RSA_size(rsa);

        let mut r = vec::from_elem(len as uint + 1u, 0u8);

        do vec::as_mut_buf(r) |pr, _len| {
            do vec::as_imm_buf(s) |ps, s_len| {
                // XXX: 4 == RSA_PKCS1_OAEP_PADDING
                let rv = libcrypto::RSA_private_decrypt(
                    s_len as c_uint,
                    ps,
                    pr,
                    rsa,
                    4 as c_int
                );

                if rv < 0 as c_int {
                    ~[]
                } else {
                    vec::slice(r, 0u, rv as uint)
                }
            }
        }
    }

    /**
     * Signs data, using OpenSSL's default scheme and sha256. Unlike encrypt(),
     * can process an arbitrary amount of data; returns the signature.
     */
    fn sign(s: &[u8]) -> ~[u8] unsafe {
        let rsa = libcrypto::EVP_PKEY_get1_RSA(self.evp);
        let len = libcrypto::RSA_size(rsa);
        let mut r = vec::from_elem(len as uint + 1u, 0u8);

        do vec::as_mut_buf(r) |pr, _len| {
            do vec::as_imm_buf(s) |ps, s_len| {
                let plen = ptr::addr_of(len);

                // XXX: 672 == NID_sha256
                let rv = libcrypto::RSA_sign(
                    672 as c_int,
                    ps,
                    s_len as c_uint,
                    pr,
                    plen,
                    rsa);

                if rv < 0 as c_int {
                    ~[]
                } else {
                    vec::slice(r, 0u, *plen as uint)
                }
            }
        }
    }

    /**
     * Verifies a signature s (using OpenSSL's default scheme and sha256) on a
     * message m. Returns true if the signature is valid, and false otherwise.
     */
    fn verify(m: &[u8], s: &[u8]) -> bool unsafe {
        let rsa = libcrypto::EVP_PKEY_get1_RSA(self.evp);

        do vec::as_imm_buf(m) |pm, m_len| {
            do vec::as_imm_buf(s) |ps, s_len| {
                // XXX: 672 == NID_sha256
                let rv = libcrypto::RSA_verify(
                    672 as c_int,
                    pm,
                    m_len as c_uint,
                    ps,
                    s_len as c_uint,
                    rsa
                );

                rv == 1 as c_int
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_gen_pub() {
        let k0 = PKey();
        let k1 = PKey();
        k0.gen(512u);
        k1.load_pub(k0.save_pub());
        assert(k0.save_pub() == k1.save_pub());
        assert(k0.size() == k1.size());
        assert(k0.can(Encrypt));
        assert(k0.can(Decrypt));
        assert(k0.can(Verify));
        assert(k0.can(Sign));
        assert(k1.can(Encrypt));
        assert(!k1.can(Decrypt));
        assert(k1.can(Verify));
        assert(!k1.can(Sign));
    }

    #[test]
    fn test_gen_priv() {
        let k0 = PKey();
        let k1 = PKey();
        k0.gen(512u);
        k1.load_priv(k0.save_priv());
        assert(k0.save_priv() == k1.save_priv());
        assert(k0.size() == k1.size());
        assert(k0.can(Encrypt));
        assert(k0.can(Decrypt));
        assert(k0.can(Verify));
        assert(k0.can(Sign));
        assert(k1.can(Encrypt));
        assert(k1.can(Decrypt));
        assert(k1.can(Verify));
        assert(k1.can(Sign));
    }

    #[test]
    fn test_encrypt() {
        let k0 = PKey();
        let k1 = PKey();
        let msg = ~[0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
        k0.gen(512u);
        k1.load_pub(k0.save_pub());
        let emsg = k1.encrypt(msg);
        let dmsg = k0.decrypt(emsg);
        assert(msg == dmsg);
    }

    #[test]
    fn test_sign() {
        let k0 = PKey();
        let k1 = PKey();
        let msg = ~[0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
        k0.gen(512u);
        k1.load_pub(k0.save_pub());
        let sig = k0.sign(msg);
        let rv = k1.verify(msg, sig);
        assert(rv == true);
    }
}
