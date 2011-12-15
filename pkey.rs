import core::ptr;
import core::str;
import core::unsafe;
import core::vec;

export pkeyrole, encrypt, decrypt, sign, verify;
export pkey, mk_pkey;
export _native;

#[link_name = "crypto"]
#[abi = "cdecl"]
native mod _native {
    type EVP_PKEY;
    type ANYKEY;
    type RSA;

    fn EVP_PKEY_new() -> *EVP_PKEY;
    fn EVP_PKEY_free(k: *EVP_PKEY);
    fn EVP_PKEY_assign(k: *EVP_PKEY, t: int, inner: *ANYKEY);
    fn EVP_PKEY_get0(k: *EVP_PKEY) -> *ANYKEY;

    fn i2d_PublicKey(k: *EVP_PKEY, buf: **u8) -> int;
    fn d2i_PublicKey(t: int, k: **EVP_PKEY, buf: **u8, len: uint) -> *EVP_PKEY;
    fn i2d_PrivateKey(k: *EVP_PKEY, buf: **u8) -> int;
    fn d2i_PrivateKey(t: int, k: **EVP_PKEY, buf: **u8, len: uint) -> *EVP_PKEY;

    fn RSA_generate_key(modsz: uint, e: uint, cb: *u8, cbarg: *u8) -> *RSA;
    fn RSA_size(k: *RSA) -> uint;

    fn RSA_public_encrypt(flen: uint, from: *u8, to: *u8, k: *RSA, pad: int) -> int;
    fn RSA_private_decrypt(flen: uint, from: *u8, to: *u8, k: *RSA, pad: int) -> int;
    fn RSA_sign(t: int, m: *u8, mlen: uint, sig: *u8, siglen: *uint, k: *RSA) -> int;
    fn RSA_verify(t: int, m: *u8, mlen: uint, sig: *u8, siglen: uint, k: *RSA) -> int;
}

tag pkeyparts {
    neither;
    public;
    both;
}

/*
Tag: pkeyrole

Represents a role an asymmetric key might be appropriate for.
*/
tag pkeyrole {
    encrypt;
    decrypt;
    sign;
    verify;
}

/*
Object: pkey

Represents a public key, optionally with a private key attached.
*/
type pkey = obj {
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
};

fn rsa_to_any(rsa: *_native::RSA) -> *_native::ANYKEY unsafe {
    unsafe::reinterpret_cast::<*_native::RSA, *_native::ANYKEY>(rsa)
}

fn any_to_rsa(anykey: *_native::ANYKEY) -> *_native::RSA unsafe {
    unsafe::reinterpret_cast::<*_native::ANYKEY, *_native::RSA>(anykey)
}

fn mk_pkey() -> pkey {
    type pkeystate = {
        mutable evp: *_native::EVP_PKEY,
        mutable parts: pkeyparts
    };

    fn _tostr(st: pkeystate,
              f: fn@(*_native::EVP_PKEY, **u8) -> int) -> [u8] unsafe {
        let len = f(st.evp, ptr::null());
        if len < 0 { ret []; }
        let s: [mutable u8] = vec::init_elt_mut::<u8>(0u8, len as uint);
        let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
        let pps: **u8 = ptr::addr_of(ps);
        let r = f(st.evp, pps);
        let bytes = vec::slice::<u8>(s, 0u, r as uint);
        ret bytes;
    }

    fn _fromstr(st: pkeystate,
                f: fn@(int, **_native::EVP_PKEY, **u8, uint) -> *_native::EVP_PKEY,
                s: [u8]) unsafe {
            let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
            let pps: **u8 = ptr::addr_of(ps);
            let evp: *_native::EVP_PKEY = ptr::null();
            let pevp: **_native::EVP_PKEY = ptr::addr_of(evp);
            f(6, pevp, pps, vec::len(s));
            st.evp = *pevp;
    }

    obj pkey(st: pkeystate) {
        fn gen(keysz: uint) unsafe {
            let rsa = _native::RSA_generate_key(keysz, 65537u, ptr::null(), ptr::null());
            let rsa_ = rsa_to_any(rsa);
            // XXX: 6 == NID_rsaEncryption
            _native::EVP_PKEY_assign(st.evp, 6, rsa_);
            st.parts = both;
        }

        fn save_pub() -> [u8] {
            // FIXME: https://github.com/graydon/rust/issues/1281
            let f = bind _native::i2d_PublicKey(_, _);
            _tostr(st, f)
        }
        fn load_pub(s: [u8]) {
            // FIXME: https://github.com/graydon/rust/issues/1281
            let f = bind _native::d2i_PublicKey(_, _, _, _);
            _fromstr(st, f, s);
            st.parts = public;
        }
        fn save_priv() -> [u8] {
            // FIXME: https://github.com/graydon/rust/issues/1281
            let f = bind _native::i2d_PrivateKey(_, _);
            _tostr(st, f)
        }
        fn load_priv(s: [u8]) {
            // FIXME: https://github.com/graydon/rust/issues/1281
            let f = bind _native::d2i_PrivateKey(_, _, _, _);
            _fromstr(st, f, s);
            st.parts = both;
        }
        fn size() -> uint {
            _native::RSA_size(any_to_rsa(_native::EVP_PKEY_get0(st.evp)))
        }
        fn can(r: pkeyrole) -> bool {
            alt r {
                encrypt. { st.parts != neither }
                verify. { st.parts != neither }
                decrypt. { st.parts == both }
                sign. { st.parts == both }
            }
        }
        fn max_data() -> uint unsafe {
            let rsa = any_to_rsa(_native::EVP_PKEY_get0(st.evp));
            let len = _native::RSA_size(rsa);
            // 41 comes from RSA_public_encrypt(3) for OAEP
            ret len - 41u;
        }
        fn encrypt(s: [u8]) -> [u8] unsafe {
            let rsa = any_to_rsa(_native::EVP_PKEY_get0(st.evp));
            let len = _native::RSA_size(rsa);
            // 41 comes from RSA_public_encrypt(3) for OAEP
            assert(vec::len(s) < _native::RSA_size(rsa) - 41u);
            let r: [mutable u8] = vec::init_elt_mut::<u8>(0u8, len + 1u);
            let pr: *u8 = vec::unsafe::to_ptr::<u8>(r);
            let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
            // XXX: 4 == RSA_PKCS1_OAEP_PADDING
            let rv = _native::RSA_public_encrypt(vec::len(s), ps, pr, rsa, 4);
            if rv < 0 { ret []; }
            ret vec::slice::<u8>(r, 0u, rv as uint);
        }
        fn decrypt(s: [u8]) -> [u8] unsafe {
            let rsa = any_to_rsa(_native::EVP_PKEY_get0(st.evp));
            let len = _native::RSA_size(rsa);
            assert(vec::len(s) == _native::RSA_size(rsa));
            let r: [mutable u8] = vec::init_elt_mut::<u8>(0u8, len + 1u);
            let pr: *u8 = vec::unsafe::to_ptr::<u8>(r);
            let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
            // XXX: 4 == RSA_PKCS1_OAEP_PADDING
            let rv = _native::RSA_private_decrypt(vec::len(s), ps, pr, rsa, 4);
            if rv < 0 { ret []; }
            ret vec::slice::<u8>(r, 0u, rv as uint);
        }
        fn sign(s: [u8]) -> [u8] unsafe {
            let rsa = any_to_rsa(_native::EVP_PKEY_get0(st.evp));
            let len = _native::RSA_size(rsa);
            let r: [mutable u8] = vec::init_elt_mut::<u8>(0u8, len + 1u);
            let pr: *u8 = vec::unsafe::to_ptr::<u8>(r);
            let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
            let plen: *uint = ptr::addr_of(len);
            // XXX: 672 == NID_sha256
            let rv = _native::RSA_sign(672, ps, vec::len(s), pr, plen, rsa);
            if rv < 0 { ret []; }
            ret vec::slice::<u8>(r, 0u, *plen as uint);
        }
        fn verify(m: [u8], s: [u8]) -> bool unsafe {
            let rsa = any_to_rsa(_native::EVP_PKEY_get0(st.evp));
            let pm: *u8 = vec::unsafe::to_ptr::<u8>(m);
            let ps: *u8 = vec::unsafe::to_ptr::<u8>(s);
            // XXX: 672 == NID_sha256
            let rv = _native::RSA_verify(672, pm, vec::len(m), ps, vec::len(s), rsa);
            ret rv == 1;
        }
    }

    let st = { mutable evp: _native::EVP_PKEY_new(), mutable parts: neither };
    let p = pkey(st);
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
