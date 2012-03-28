import core::ptr;
import core::str;
import core::unsafe;
import core::vec;

import libc::{c_int, c_uint};

export pkeyrole, encrypt, decrypt, sign, verify;
export pkey, mk_pkey;
export _native;

type EVP_PKEY = *libc::c_void;
type ANYKEY = *libc::c_void;
type RSA = *libc::c_void;

#[link_name = "crypto"]
#[abi = "cdecl"]
native mod _native {
    fn EVP_PKEY_new() -> *EVP_PKEY;
    fn EVP_PKEY_free(k: *EVP_PKEY);
    fn EVP_PKEY_assign(k: *EVP_PKEY, t: c_int, inner: *ANYKEY);
    fn EVP_PKEY_get1_RSA(k: *EVP_PKEY) -> *RSA;

    fn i2d_PublicKey(k: *EVP_PKEY, buf: **u8) -> c_int;
    fn d2i_PublicKey(t: c_int, k: **EVP_PKEY, buf: **u8, len: c_uint) -> *EVP_PKEY;
    fn i2d_PrivateKey(k: *EVP_PKEY, buf: **u8) -> c_int;
    fn d2i_PrivateKey(t: c_int, k: **EVP_PKEY, buf: **u8, len: c_uint) -> *EVP_PKEY;

    fn RSA_generate_key(modsz: c_uint, e: c_uint, cb: *u8, cbarg: *u8) -> *RSA;
    fn RSA_size(k: *RSA) -> c_uint;

    fn RSA_public_encrypt(flen: c_uint, from: *u8, to: *u8, k: *RSA,
                          pad: c_int) -> c_int;
    fn RSA_private_decrypt(flen: c_uint, from: *u8, to: *u8, k: *RSA,
                           pad: c_int) -> c_int;
    fn RSA_sign(t: c_int, m: *u8, mlen: c_uint, sig: *u8, siglen: *c_uint,
                k: *RSA) -> c_int;
    fn RSA_verify(t: c_int, m: *u8, mlen: c_uint, sig: *u8, siglen: c_uint,
                  k: *RSA) -> c_int;
}

enum pkeyparts {
    neither,
    public,
    both
}

/*
Tag: pkeyrole

Represents a role an asymmetric key might be appropriate for.
*/
enum pkeyrole {
    encrypt,
    decrypt,
    sign,
    verify
}

/*
Object: pkey

Represents a public key, optionally with a private key attached.
*/
iface pkey {
    /*
    Method: save_pub

    Returns a serialized form of the public key, suitable for load_pub().
    */
    fn save_pub() -> [u8];

    /*
    Method: load_pub

    Loads a serialized form of the public key, as produced by save_pub().
    */
    fn load_pub(s: [u8]);

    /*
    Method: save_priv

    Returns a serialized form of the public and private keys, suitable for
    load_priv().
    */
    fn save_priv() -> [u8];

    /*
    Method: load_priv

    Loads a serialized form of the public and private keys, as produced by
    save_priv().
    */
    fn load_priv(s: [u8]);

    /*
    Method: size()

    Returns the size of the public key modulus.
    */
    fn size() -> uint;

    /*
    Method: gen()

    Generates a public/private keypair of the specified size.
    */
    fn gen(keysz: uint);

    /*
    Method: can()

    Returns whether this pkey object can perform the specified role.
    */
    fn can(role: pkeyrole) -> bool;

    /*
    Method: max_data()

    Returns the maximum amount of data that can be encrypted by an encrypt()
    call.
    */
    fn max_data() -> uint;

    /*
    Method: encrypt()

    Encrypts data using OAEP padding, returning the encrypted data. The supplied
    data must not be larger than max_data().
    */
    fn encrypt(s: [u8]) -> [u8];

    /*
    Method: decrypt()

    Decrypts data, expecting OAEP padding, returning the decrypted data.
    */
    fn decrypt(s: [u8]) -> [u8];

    /*
    Method: sign()

    Signs data, using OpenSSL's default scheme and sha256. Unlike encrypt(), can
    process an arbitrary amount of data; returns the signature.
    */
    fn sign(s: [u8]) -> [u8];

    /*
    Method: verify()

    Verifies a signature s (using OpenSSL's default scheme and sha256) on a
    message m. Returns true if the signature is valid, and false otherwise.
    */
    fn verify(m: [u8], s: [u8]) -> bool;
}

fn rsa_to_any(rsa: *RSA) -> *ANYKEY unsafe {
    unsafe::reinterpret_cast::<*RSA, *ANYKEY>(rsa)
}

fn any_to_rsa(anykey: *ANYKEY) -> *RSA unsafe {
    unsafe::reinterpret_cast::<*ANYKEY, *RSA>(anykey)
}

fn mk_pkey() -> pkey {
    type pkeystate = {
        mut evp: *EVP_PKEY,
        mut parts: pkeyparts
    };

    fn _tostr(st: pkeystate,
              f: fn@(*EVP_PKEY, **u8) -> c_int) -> [u8] unsafe {
        let len = f(st.evp, ptr::null());
        if len < 0 as c_int { ret []; }
        let s: [mut u8] = vec::to_mut(vec::from_elem::<u8>(len as uint, 0u8));
        let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
        let pps: **u8 = ptr::addr_of(ps);
        let r = f(st.evp, pps);
        let bytes = vec::slice::<u8>(s, 0u, r as uint);
        ret bytes;
    }

    fn _fromstr(st: pkeystate,
                f: fn@(c_int, **EVP_PKEY, **u8, c_uint) -> *EVP_PKEY,
                s: [u8]) unsafe {
            let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
            let pps: **u8 = ptr::addr_of(ps);
            let evp: *EVP_PKEY = ptr::null();
            let pevp: **EVP_PKEY = ptr::addr_of(evp);
            f(6 as c_int, pevp, pps, vec::len(s) as c_uint);
            st.evp = *pevp;
    }

    impl of pkey for pkeystate {
        fn gen(keysz: uint) unsafe {
            let rsa = _native::RSA_generate_key(keysz as c_uint, 65537u as c_uint,
                                                ptr::null(), ptr::null());
            let rsa_ = rsa_to_any(rsa);
            // XXX: 6 == NID_rsaEncryption
            _native::EVP_PKEY_assign(self.evp, 6 as c_int, rsa_);
            self.parts = both;
        }

        fn save_pub() -> [u8] {
            // FIXME: https://github.com/graydon/rust/issues/1281
            let f = bind _native::i2d_PublicKey(_, _);
            _tostr(self, f)
        }
        fn load_pub(s: [u8]) {
            // FIXME: https://github.com/graydon/rust/issues/1281
            let f = bind _native::d2i_PublicKey(_, _, _, _);
            _fromstr(self, f, s);
            self.parts = public;
        }
        fn save_priv() -> [u8] {
            // FIXME: https://github.com/graydon/rust/issues/1281
            let f = bind _native::i2d_PrivateKey(_, _);
            _tostr(self, f)
        }
        fn load_priv(s: [u8]) {
            // FIXME: https://github.com/graydon/rust/issues/1281
            let f = bind _native::d2i_PrivateKey(_, _, _, _);
            _fromstr(self, f, s);
            self.parts = both;
        }
        fn size() -> uint {
            _native::RSA_size(_native::EVP_PKEY_get1_RSA(self.evp)) as uint
        }
        fn can(r: pkeyrole) -> bool {
            alt r {
                encrypt { self.parts != neither }
                verify { self.parts != neither }
                decrypt { self.parts == both }
                sign { self.parts == both }
            }
        }
        fn max_data() -> uint unsafe {
            let rsa = _native::EVP_PKEY_get1_RSA(self.evp);
            let len = _native::RSA_size(rsa);
            // 41 comes from RSA_public_encrypt(3) for OAEP
            ret len as uint - 41u;
        }
        fn encrypt(s: [u8]) -> [u8] unsafe {
            let rsa = _native::EVP_PKEY_get1_RSA(self.evp);
            let len = _native::RSA_size(rsa);
            // 41 comes from RSA_public_encrypt(3) for OAEP
            assert(vec::len(s) < _native::RSA_size(rsa) as uint - 41u);
            let r: [mut u8] = vec::to_mut(vec::from_elem::<u8>(len as uint + 1u, 0u8));
            let pr: *u8 = vec::unsafe::to_ptr::<u8>(r);
            let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
            // XXX: 4 == RSA_PKCS1_OAEP_PADDING
            let rv = _native::RSA_public_encrypt(vec::len(s) as c_uint, ps, pr,
                                                 rsa, 4 as c_int);
            if rv < 0 as c_int { ret []; }
            ret vec::slice::<u8>(r, 0u, rv as uint);
        }
        fn decrypt(s: [u8]) -> [u8] unsafe {
            let rsa = _native::EVP_PKEY_get1_RSA(self.evp);
            let len = _native::RSA_size(rsa);
            assert(vec::len(s) as c_uint == _native::RSA_size(rsa));
            let r: [mut u8] = vec::to_mut(vec::from_elem::<u8>(len as uint + 1u, 0u8));
            let pr: *u8 = vec::unsafe::to_ptr::<u8>(r);
            let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
            // XXX: 4 == RSA_PKCS1_OAEP_PADDING
            let rv = _native::RSA_private_decrypt(vec::len(s) as c_uint, ps,
                                                  pr, rsa, 4 as c_int);
            if rv < 0 as c_int { ret []; }
            ret vec::slice::<u8>(r, 0u, rv as uint);
        }
        fn sign(s: [u8]) -> [u8] unsafe {
            let rsa = _native::EVP_PKEY_get1_RSA(self.evp);
            let len = _native::RSA_size(rsa);
            let r: [mut u8] = vec::to_mut(vec::from_elem::<u8>(len as uint + 1u, 0u8));
            let pr: *u8 = vec::unsafe::to_ptr::<u8>(r);
            let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
            let plen: *c_uint = ptr::addr_of(len);
            // XXX: 672 == NID_sha256
            let rv = _native::RSA_sign(672 as c_int, ps,
                                       vec::len(s) as c_uint, pr,
                                       plen, rsa);
            if rv < 0 as c_int { ret []; }
            ret vec::slice::<u8>(r, 0u, *plen as uint);
        }
        fn verify(m: [u8], s: [u8]) -> bool unsafe {
            let rsa = _native::EVP_PKEY_get1_RSA(self.evp);
            let pm: *u8 = vec::unsafe::to_ptr::<u8>(m);
            let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
            // XXX: 672 == NID_sha256
            let rv = _native::RSA_verify(672 as c_int, pm,
                                         vec::len(m) as c_uint, ps,
                                         vec::len(s) as c_uint, rsa);
            ret rv == 1 as c_int;
        }
    }

    let st = { mut evp: _native::EVP_PKEY_new(), mut parts: neither };
    let p = st as pkey;
    ret p;
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_gen_pub() {
        let k0 = mk_pkey();
        let k1 = mk_pkey();
        k0.gen(512u);
        k1.load_pub(k0.save_pub());
        assert(k0.save_pub() == k1.save_pub());
        assert(k0.size() == k1.size());
        assert(k0.can(encrypt));
        assert(k0.can(decrypt));
        assert(k0.can(verify));
        assert(k0.can(sign));
        assert(k1.can(encrypt));
        assert(!k1.can(decrypt));
        assert(k1.can(verify));
        assert(!k1.can(sign));
    }

    #[test]
    fn test_gen_priv() {
        let k0 = mk_pkey();
        let k1 = mk_pkey();
        k0.gen(512u);
        k1.load_priv(k0.save_priv());
        assert(k0.save_priv() == k1.save_priv());
        assert(k0.size() == k1.size());
        assert(k0.can(encrypt));
        assert(k0.can(decrypt));
        assert(k0.can(verify));
        assert(k0.can(sign));
        assert(k1.can(encrypt));
        assert(k1.can(decrypt));
        assert(k1.can(verify));
        assert(k1.can(sign));
    }

    #[test]
    fn test_encrypt() {
        let k0 = mk_pkey();
        let k1 = mk_pkey();
        let msg: [u8] = [0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
        k0.gen(512u);
        k1.load_pub(k0.save_pub());
        let emsg = k1.encrypt(msg);
        let dmsg = k0.decrypt(emsg);
        assert(msg == dmsg);
    }

    #[test]
    fn test_sign() {
        let k0 = mk_pkey();
        let k1 = mk_pkey();
        let msg: [u8] = [0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
        k0.gen(512u);
        k1.load_pub(k0.save_pub());
        let sig = k0.sign(msg);
        let rv = k1.verify(msg, sig);
        assert(rv == true);
    }
}
