/*
 * Copyright 2013 Jack Lloyd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use libc::{c_int, c_uint};
use std::iter::repeat;
use std::io;
use std::io::prelude::*;

use crypto::hash::Type;
use ffi;

#[derive(PartialEq, Copy, Clone)]
enum State {
    Reset,
    Updated,
    Finalized,
}

use self::State::*;

/// Provides HMAC computation.
///
/// # Examples
///
/// Calculate a HMAC in one go.
///
/// ```
/// use openssl::crypto::hash::Type;
/// use openssl::crypto::hmac::hmac;
/// let key = b"Jefe";
/// let data = b"what do ya want for nothing?";
/// let spec = b"\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38";
/// let res = hmac(Type::MD5, key, data);
/// assert_eq!(res, spec);
/// ```
///
/// Use the `Write` trait to supply the input in chunks.
///
/// ```
/// use std::io::prelude::*;
/// use openssl::crypto::hash::Type;
/// use openssl::crypto::hmac::HMAC;
/// let key = b"Jefe";
/// let data: &[&[u8]] = &[b"what do ya ", b"want for nothing?"];
/// let spec = b"\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38";
/// let mut h = HMAC::new(Type::MD5, &*key);
/// h.write_all(data[0]);
/// h.write_all(data[1]);
/// let res = h.finish();
/// assert_eq!(res, spec);
/// ```
pub struct HMAC {
    ctx: ffi::HMAC_CTX,
    type_: Type,
    state: State,
}

impl HMAC {
    /// Creates a new `HMAC` with the specified hash type using the `key`.
    pub fn new(ty: Type, key: &[u8]) -> HMAC {
        ffi::init();

        let ctx = unsafe {
            let mut ctx = ::std::mem::uninitialized();
            ffi::HMAC_CTX_init(&mut ctx);
            ctx
        };
        let md = ty.evp_md();

        let mut h = HMAC { ctx: ctx, type_: ty, state: Finalized };
        h.init_once(md, key);
        h
    }

    #[inline]
    fn init_once(&mut self, md: *const ffi::EVP_MD, key: &[u8]) {
        unsafe {
            let r = ffi::HMAC_Init_ex(&mut self.ctx,
                                      key.as_ptr(), key.len() as c_int,
                                      md, 0 as *const _);
            assert_eq!(r, 1);
        }
        self.state = Reset;
    }

    #[inline]
    fn init(&mut self) {
        match self.state {
            Reset => return,
            Updated => { self.finalize(); },
            Finalized => (),
        }
        // If the key and/or md is not supplied it's reused from the last time
        // avoiding redundant initializations
        unsafe {
            let r = ffi::HMAC_Init_ex(&mut self.ctx,
                                      0 as *const _, 0,
                                      0 as *const _, 0 as *const _);
            assert_eq!(r, 1);
        }
        self.state = Reset;
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        if self.state == Finalized {
            self.init();
        }
        unsafe {
            let r = ffi::HMAC_Update(&mut self.ctx, data.as_ptr(), data.len() as c_uint);
            assert_eq!(r, 1);
        }
        self.state = Updated;
    }

    #[inline]
    fn finalize(&mut self) -> Vec<u8> {
        if self.state == Finalized {
            self.init();
        }
        let md_len = self.type_.md_len();
        let mut res: Vec<u8> = repeat(0).take(md_len).collect();
        unsafe {
            let mut len = 0;
            let r = ffi::HMAC_Final(&mut self.ctx, res.as_mut_ptr(), &mut len);
            self.state = Finalized;
            assert_eq!(len as usize, md_len);
            assert_eq!(r, 1);
        }
        res
    }

    /// Returns the hash of the data written since creation or
    /// the last `finish` and resets the hasher.
    #[inline]
    pub fn finish(&mut self) -> Vec<u8> {
        self.finalize()
    }
}

impl Write for HMAC {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Clone for HMAC {
    fn clone(&self) -> HMAC {
        let mut ctx: ffi::HMAC_CTX;
        unsafe {
            ctx = ::std::mem::uninitialized();
            let r = ffi::HMAC_CTX_copy(&mut ctx, &self.ctx);
            assert_eq!(r, 1);
        }
        HMAC { ctx: ctx, type_: self.type_, state: self.state }
    }
}

impl Drop for HMAC {
    fn drop(&mut self) {
        unsafe {
            if self.state != Finalized {
                let mut buf: Vec<u8> = repeat(0).take(self.type_.md_len()).collect();
                let mut len = 0;
                ffi::HMAC_Final(&mut self.ctx, buf.as_mut_ptr(), &mut len);
            }
            ffi::HMAC_CTX_cleanup(&mut self.ctx);
        }
    }
}

/// Computes the HMAC of the `data` with the hash `t` and `key`.
pub fn hmac(t: Type, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut h = HMAC::new(t, key);
    let _ = h.write_all(data);
    h.finish()
}

#[cfg(test)]
mod tests {
    use std::iter::repeat;
    use serialize::hex::FromHex;
    use crypto::hash::Type;
    use crypto::hash::Type::*;
    use super::{hmac, HMAC};
    use std::io::prelude::*;

    fn test_hmac(ty: Type, tests: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) {
        for &(ref key, ref data, ref res) in tests.iter() {
            assert_eq!(hmac(ty, &**key, &**data), *res);
        }
    }

    fn test_hmac_recycle(h: &mut HMAC, test: &(Vec<u8>, Vec<u8>, Vec<u8>)) {
        let &(_, ref data, ref res) = test;
        let _ = h.write_all(&**data);
        assert_eq!(h.finish(), *res);
    }

    #[test]
    fn test_hmac_md5() {
        // test vectors from RFC 2202
        let tests: [(Vec<u8>, Vec<u8>, Vec<u8>); 7] = [
            (repeat(0x0b_u8).take(16).collect(), b"Hi There".to_vec(),
             "9294727a3638bb1c13f48ef8158bfc9d".from_hex().unwrap()),
            (b"Jefe".to_vec(),
             b"what do ya want for nothing?".to_vec(),
             "750c783e6ab0b503eaa86e310a5db738".from_hex().unwrap()),
            (repeat(0xaa_u8).take(16).collect(), repeat(0xdd_u8).take(50).collect(),
             "56be34521d144c88dbb8c733f0e8b3f6".from_hex().unwrap()),
            ("0102030405060708090a0b0c0d0e0f10111213141516171819".from_hex().unwrap(),
             repeat(0xcd_u8).take(50).collect(),
             "697eaf0aca3a3aea3a75164746ffaa79".from_hex().unwrap()),
            (repeat(0x0c_u8).take(16).collect(),
             b"Test With Truncation".to_vec(),
             "56461ef2342edc00f9bab995690efd4c".from_hex().unwrap()),
            (repeat(0xaa_u8).take(80).collect(),
             b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
             "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd".from_hex().unwrap()),
            (repeat(0xaa_u8).take(80).collect(),
             b"Test Using Larger Than Block-Size Key \
               and Larger Than One Block-Size Data".to_vec(),
             "6f630fad67cda0ee1fb1f562db3aa53e".from_hex().unwrap())
        ];

        test_hmac(MD5, &tests);
    }

    #[test]
    fn test_hmac_md5_recycle() {
        let tests: [(Vec<u8>, Vec<u8>, Vec<u8>); 2] = [
            (repeat(0xaa_u8).take(80).collect(),
             b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
             "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd".from_hex().unwrap()),
            (repeat(0xaa_u8).take(80).collect(),
             b"Test Using Larger Than Block-Size Key \
               and Larger Than One Block-Size Data".to_vec(),
             "6f630fad67cda0ee1fb1f562db3aa53e".from_hex().unwrap())
        ];

        let mut h = HMAC::new(MD5, &*tests[0].0);
        for i in 0..100usize {
            let test = &tests[i % 2];
            test_hmac_recycle(&mut h, test);
        }
    }

    #[test]
    fn test_finish_twice() {
        let test: (Vec<u8>, Vec<u8>, Vec<u8>) =
            (repeat(0xaa_u8).take(80).collect(),
             b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
             "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd".from_hex().unwrap());

        let mut h = HMAC::new(Type::MD5, &*test.0);
        let _ = h.write_all(&*test.1);
        let _ = h.finish();
        let res = h.finish();
        let null = hmac(Type::MD5, &*test.0, &[]);
        assert_eq!(res, null);
    }

    #[test]
    fn test_clone() {
        let tests: [(Vec<u8>, Vec<u8>, Vec<u8>); 2] = [
            (repeat(0xaa_u8).take(80).collect(),
             b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
             "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd".from_hex().unwrap()),
            (repeat(0xaa_u8).take(80).collect(),
             b"Test Using Larger Than Block-Size Key \
               and Larger Than One Block-Size Data".to_vec(),
             "6f630fad67cda0ee1fb1f562db3aa53e".from_hex().unwrap()),
        ];
        let p = tests[0].0.len() / 2;
        let h0 = HMAC::new(Type::MD5, &*tests[0].0);

        println!("Clone a new hmac");
        let mut h1 = h0.clone();
        let _ = h1.write_all(&tests[0].1[..p]);
        {
            println!("Clone an updated hmac");
            let mut h2 = h1.clone();
            let _ = h2.write_all(&tests[0].1[p..]);
            let res = h2.finish();
            assert_eq!(res, tests[0].2);
        }
        let _ = h1.write_all(&tests[0].1[p..]);
        let res = h1.finish();
        assert_eq!(res, tests[0].2);

        println!("Clone a finished hmac");
        let mut h3 = h1.clone();
        let _ = h3.write_all(&*tests[1].1);
        let res = h3.finish();
        assert_eq!(res, tests[1].2);
    }

    #[test]
    fn test_hmac_sha1() {
        // test vectors from RFC 2202
        let tests: [(Vec<u8>, Vec<u8>, Vec<u8>); 7] = [
            (repeat(0x0b_u8).take(20).collect(), b"Hi There".to_vec(),
             "b617318655057264e28bc0b6fb378c8ef146be00".from_hex().unwrap()),
            (b"Jefe".to_vec(),
             b"what do ya want for nothing?".to_vec(),
             "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79".from_hex().unwrap()),
            (repeat(0xaa_u8).take(20).collect(), repeat(0xdd_u8).take(50).collect(),
             "125d7342b9ac11cd91a39af48aa17b4f63f175d3".from_hex().unwrap()),
            ("0102030405060708090a0b0c0d0e0f10111213141516171819".from_hex().unwrap(),
             repeat(0xcd_u8).take(50).collect(),
             "4c9007f4026250c6bc8414f9bf50c86c2d7235da".from_hex().unwrap()),
            (repeat(0x0c_u8).take(20).collect(),
             b"Test With Truncation".to_vec(),
             "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04".from_hex().unwrap()),
            (repeat(0xaa_u8).take(80).collect(),
             b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
             "aa4ae5e15272d00e95705637ce8a3b55ed402112".from_hex().unwrap()),
            (repeat(0xaa_u8).take(80).collect(),
             b"Test Using Larger Than Block-Size Key \
               and Larger Than One Block-Size Data".to_vec(),
             "e8e99d0f45237d786d6bbaa7965c7808bbff1a91".from_hex().unwrap())
        ];

        test_hmac(SHA1, &tests);
    }

    #[test]
    fn test_hmac_sha1_recycle() {
        let tests: [(Vec<u8>, Vec<u8>, Vec<u8>); 2] = [
            (repeat(0xaa_u8).take(80).collect(),
             b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
             "aa4ae5e15272d00e95705637ce8a3b55ed402112".from_hex().unwrap()),
            (repeat(0xaa_u8).take(80).collect(),
             b"Test Using Larger Than Block-Size Key \
               and Larger Than One Block-Size Data".to_vec(),
             "e8e99d0f45237d786d6bbaa7965c7808bbff1a91".from_hex().unwrap())
        ];

        let mut h = HMAC::new(SHA1, &*tests[0].0);
        for i in 0..100usize {
            let test = &tests[i % 2];
            test_hmac_recycle(&mut h, test);
        }
    }



    fn test_sha2(ty: Type, results: &[Vec<u8>]) {
        // test vectors from RFC 4231
        let tests: [(Vec<u8>, Vec<u8>); 6] = [
            (repeat(0xb_u8).take(20).collect(), b"Hi There".to_vec()),
            (b"Jefe".to_vec(),
             b"what do ya want for nothing?".to_vec()),
            (repeat(0xaa_u8).take(20).collect(), repeat(0xdd_u8).take(50).collect()),
            ("0102030405060708090a0b0c0d0e0f10111213141516171819".from_hex().unwrap(),
             repeat(0xcd_u8).take(50).collect()),
            (repeat(0xaa_u8).take(131).collect(),
             b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec()),
            (repeat(0xaa_u8).take(131).collect(),
             b"This is a test using a larger than block-size key and a \
               larger than block-size data. The key needs to be hashed \
               before being used by the HMAC algorithm.".to_vec())
        ];

        for (&(ref key, ref data), res) in tests.iter().zip(results.iter()) {
            assert_eq!(hmac(ty, &**key, &**data), *res);
        }

        // recycle test
        let mut h = HMAC::new(ty, &*tests[5].0);
        for i in 0..100usize {
            let test = &tests[4 + i % 2];
            let tup = (test.0.clone(), test.1.clone(), results[4 + i % 2].clone());
            test_hmac_recycle(&mut h, &tup);
        }
    }

    #[test]
    fn test_hmac_sha224() {
        let results = [
            "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22".from_hex().unwrap(),
            "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44".from_hex().unwrap(),
            "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea".from_hex().unwrap(),
            "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a".from_hex().unwrap(),
            "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e".from_hex().unwrap(),
            "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1".from_hex().unwrap()
        ];
        test_sha2(SHA224, &results);
    }

    #[test]
    fn test_hmac_sha256() {
        let results = [
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7".from_hex().unwrap(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843".from_hex().unwrap(),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe".from_hex().unwrap(),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b".from_hex().unwrap(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54".from_hex().unwrap(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2".from_hex().unwrap()
        ];
        test_sha2(SHA256, &results);
    }

    #[test]
    fn test_hmac_sha384() {
        let results = [
            "afd03944d84895626b0825f4ab46907f\
             15f9dadbe4101ec682aa034c7cebc59c\
             faea9ea9076ede7f4af152e8b2fa9cb6".from_hex().unwrap(),
            "af45d2e376484031617f78d2b58a6b1b\
             9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649".from_hex().unwrap(),
            "88062608d3e6ad8a0aa2ace014c8a86f\
             0aa635d947ac9febe83ef4e55966144b\
             2a5ab39dc13814b94e3ab6e101a34f27".from_hex().unwrap(),
            "3e8a69b7783c25851933ab6290af6ca7\
             7a9981480850009cc5577c6e1f573b4e\
             6801dd23c4a7d679ccf8a386c674cffb".from_hex().unwrap(),
            "4ece084485813e9088d2c63a041bc5b4\
             4f9ef1012a2b588f3cd11f05033ac4c6\
             0c2ef6ab4030fe8296248df163f44952".from_hex().unwrap(),
            "6617178e941f020d351e2f254e8fd32c\
             602420feb0b8fb9adccebb82461e99c5\
             a678cc31e799176d3860e6110c46523e".from_hex().unwrap()
        ];
        test_sha2(SHA384, &results);
    }

    #[test]
    fn test_hmac_sha512() {
        let results = [
            "87aa7cdea5ef619d4ff0b4241a1d6cb0\
             2379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4\
             be9d914eeb61f1702e696c203a126854".from_hex().unwrap(),
            "164b7a7bfcf819e2e395fbe73b56e0a3\
             87bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fd\
             caeab1a34d4a6b4b636e070a38bce737".from_hex().unwrap(),
            "fa73b0089d56a284efb0f0756c890be9\
             b1b5dbdd8ee81a3655f83e33b2279d39\
             bf3e848279a722c806b485a47e67c807\
             b946a337bee8942674278859e13292fb".from_hex().unwrap(),
            "b0ba465637458c6990e5a8c5f61d4af7\
             e576d97ff94b872de76f8050361ee3db\
             a91ca5c11aa25eb4d679275cc5788063\
             a5f19741120c4f2de2adebeb10a298dd".from_hex().unwrap(),
            "80b24263c7c1a3ebb71493c1dd7be8b4\
             9b46d1f41b4aeec1121b013783f8f352\
             6b56d037e05f2598bd0fd2215d6a1e52\
             95e64f73f63f0aec8b915a985d786598".from_hex().unwrap(),
            "e37b6a775dc87dbaa4dfa9f96e5e3ffd\
             debd71f8867289865df5a32d20cdc944\
             b6022cac3c4982b10d5eeb55c3e4de15\
             134676fb6de0446065c97440fa8c6a58".from_hex().unwrap()
        ];
        test_sha2(SHA512, &results);
    }
}
