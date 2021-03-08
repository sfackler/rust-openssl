use libc::*;
use *;

const EVP_PKEY_CTRL_TLS_MD: c_int = EVP_PKEY_ALG_CTRL;
const EVP_PKEY_CTRL_TLS_SECRET: c_int = EVP_PKEY_ALG_CTRL + 1;
const EVP_PKEY_CTRL_TLS_SEED: c_int = EVP_PKEY_ALG_CTRL + 2;
const EVP_PKEY_CTRL_HKDF_MD: c_int = EVP_PKEY_ALG_CTRL + 3;
const EVP_PKEY_CTRL_HKDF_SALT: c_int = EVP_PKEY_ALG_CTRL + 4;
const EVP_PKEY_CTRL_HKDF_KEY: c_int = EVP_PKEY_ALG_CTRL + 5;
const EVP_PKEY_CTRL_HKDF_INFO: c_int = EVP_PKEY_ALG_CTRL + 6;
const EVP_PKEY_CTRL_HKDF_MODE: c_int = EVP_PKEY_ALG_CTRL + 7;
const EVP_PKEY_CTRL_PASS: c_int = EVP_PKEY_ALG_CTRL + 8;
const EVP_PKEY_CTRL_SCRYPT_SALT: c_int = EVP_PKEY_ALG_CTRL + 9;
const EVP_PKEY_CTRL_SCRYPT_N: c_int = EVP_PKEY_ALG_CTRL + 10;
const EVP_PKEY_CTRL_SCRYPT_R: c_int = EVP_PKEY_ALG_CTRL + 11;
const EVP_PKEY_CTRL_SCRYPT_P: c_int = EVP_PKEY_ALG_CTRL + 12;
const EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES: c_int = EVP_PKEY_ALG_CTRL + 13;

const EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND: c_int = 0;
const EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY: c_int = 1;
const EVP_PKEY_HKDEF_MODE_EXPAND_ONLY: c_int = 2;

pub unsafe extern "C" fn EVP_PKEY_CTX_set_tls1_prf_md(
    pctx: *mut crate::EVP_PKEY_CTX,
    md: *const crate::EVP_MD,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_TLS_MD,
        0,
        md as *mut c_void,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_set1_tls1_prf_secret(
    pctx: *mut crate::EVP_PKEY_CTX,
    sec: *mut c_uchar,
    seclen: c_int,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_TLS_SECRET,
        seclen,
        sec as *mut c_void,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_add1_tls1_prf_seed(
    pctx: *mut crate::EVP_PKEY_CTX,
    seed: *mut c_uchar,
    seedlen: c_int,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_TLS_SEED,
        seedlen,
        seed as *mut c_void,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_set_hkdf_md(
    pctx: *mut crate::EVP_PKEY_CTX,
    md: *const crate::EVP_MD,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_HKDF_MD,
        0,
        md as *mut c_void,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_set1_hkdf_salt(
    pctx: *mut crate::EVP_PKEY_CTX,
    salt: *mut c_uchar,
    saltlen: c_int,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_HKDF_SALT,
        saltlen,
        salt as *mut c_void,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_set1_hkdf_key(
    pctx: *mut crate::EVP_PKEY_CTX,
    key: *mut c_uchar,
    keylen: c_int,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_HKDF_KEY,
        keylen,
        key as *mut c_void,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_add1_hkdf_info(
    pctx: *mut crate::EVP_PKEY_CTX,
    info: *mut c_uchar,
    infolen: c_int,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_HKDF_INFO,
        infolen,
        info as *mut c_void,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_hkdf_mode(
    pctx: *mut crate::EVP_PKEY_CTX,
    mode: c_int,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_HKDF_MODE,
        mode,
        std::ptr::null_mut(),
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_set1_pbe_pass(
    pctx: *mut crate::EVP_PKEY_CTX,
    pass: *mut c_uchar,
    passlen: c_int,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_PASS,
        passlen,
        pass as *mut c_void,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_set1_scrypt_salt(
    pctx: *mut crate::EVP_PKEY_CTX,
    salt: *mut c_uchar,
    saltlen: c_int,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_SCRYPT_SALT,
        saltlen,
        salt as *mut c_void,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_N(
    pctx: *mut crate::EVP_PKEY_CTX,
    n: u64,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl_uint64(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_SCRYPT_N,
        n,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_r(
    pctx: *mut crate::EVP_PKEY_CTX,
    r: u64,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl_uint64(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_SCRYPT_R,
        r,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_p(
    pctx: *mut crate::EVP_PKEY_CTX,
    p: u64,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl_uint64(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_SCRYPT_P,
        p,
    )
}

pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_maxmem_bytes(
    pctx: *mut crate::EVP_PKEY_CTX,
    maxmem_bytes: u64,
) -> c_int {
    crate::EVP_PKEY_CTX_ctrl_uint64(
        pctx,
        -1,
        crate::EVP_PKEY_OP_DERIVE,
        EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES,
        maxmem_bytes,
    )
}
