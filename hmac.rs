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

use hash::*;
use std::{libc,ptr,vec};

#[allow(non_camel_case_types)]
pub struct HMAC_CTX {
    md: EVP_MD,
    md_ctx: EVP_MD_CTX,
    i_ctx: EVP_MD_CTX,
    o_ctx: EVP_MD_CTX,
    key_length: libc::c_uint,
    key: [libc::c_uchar, ..128]
}

#[link_args = "-lcrypto"]
#[abi = "cdecl"]
extern {
    fn HMAC_CTX_init(ctx: *mut HMAC_CTX, key: *u8, keylen: libc::c_int, md: EVP_MD);

    fn HMAC_Update(ctx: *mut HMAC_CTX, input: *u8, len: libc::c_uint);

    fn HMAC_Final(ctx: *mut HMAC_CTX, output: *mut u8, len: *mut libc::c_uint);
}

pub struct HMAC {
    priv ctx: HMAC_CTX,
    priv len: uint,
}

pub fn HMAC(ht: HashType, key: ~[u8]) -> HMAC {
    unsafe {

        let (evp, mdlen) = evpmd(ht);

        let mut ctx : HMAC_CTX = HMAC_CTX {
            md: ptr::null(),
            md_ctx: ptr::null(),
            i_ctx: ptr::null(),
            o_ctx: ptr::null(),
            key_length: 0,
            key: [0u8, .. 128]
        };

        HMAC_CTX_init(&mut ctx,
                                 vec::raw::to_ptr(key),
                                 key.len() as libc::c_int,
                                 evp);

        HMAC { ctx: ctx, len: mdlen }
    }
}

impl HMAC {
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            do data.as_imm_buf |pdata, len| {
                HMAC_Update(&mut self.ctx, pdata, len as libc::c_uint)
            }
        }
    }

    pub fn final(&mut self) -> ~[u8] {
        unsafe {
            let mut res = vec::from_elem(self.len, 0u8);
            let mut outlen: libc::c_uint = 0;
            do res.as_mut_buf |pres, _len| {
                HMAC_Final(&mut self.ctx, pres, &mut outlen);
                assert!(self.len == outlen as uint)
            }
            res
        }
    }
}

fn main() {
    let mut h = HMAC(SHA512, ~[00u8]);

    h.update([00u8]);

    println(fmt!("%?", h.final()))
}
