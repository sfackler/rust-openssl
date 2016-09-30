extern crate ctest;

use std::env;

fn main() {
    let mut cfg = ctest::TestGenerator::new();
    let target = env::var("TARGET").unwrap();

    if let Ok(out) = env::var("DEP_OPENSSL_INCLUDE") {
        cfg.include(&out);
    }

    // Needed to get OpenSSL to correctly undef symbols that are already on
    // Windows like X509_NAME
    if target.contains("windows") {
        cfg.header("windows.h");

        // weird "different 'const' qualifiers" error on Windows, maybe a cl.exe
        // thing?
        if target.contains("msvc") {
            cfg.flag("/wd4090");
        }
    }

    if env::var("DEP_OPENSSL_IS_101").is_ok() {
        cfg.cfg("ossl101", None);
    }
    if env::var("DEP_OPENSSL_IS_102").is_ok() {
        cfg.cfg("ossl102", None);
    }
    if env::var("DEP_OPENSSL_IS_110").is_ok() {
        cfg.cfg("ossl110", None);
    }

    cfg.header("openssl/comp.h")
       .header("openssl/dh.h")
       .header("openssl/ossl_typ.h")
       .header("openssl/stack.h")
       .header("openssl/x509.h")
       .header("openssl/bio.h")
       .header("openssl/x509v3.h")
       .header("openssl/safestack.h")
       .header("openssl/hmac.h")
       .header("openssl/ssl.h")
       .header("openssl/err.h")
       .header("openssl/rand.h")
       .header("openssl/pkcs12.h")
       .header("openssl/bn.h");
    cfg.type_name(|s, is_struct| {
        // Add some `*` on some callback parameters to get function pointer to
        // typecheck in C, especially on MSVC.
        if s == "PasswordCallback" {
            format!("pem_password_cb*")
        } else if s == "bio_info_cb" {
            format!("bio_info_cb*")
        } else if s == "_STACK" {
            format!("struct stack_st")
        } else if is_struct && s.chars().next().unwrap().is_lowercase() {
            format!("struct {}", s)
        } else {
            format!("{}", s)
        }
    });
    cfg.skip_type(|s| {
        // function pointers are declared without a `*` in openssl so their
        // sizeof is 1 which isn't what we want.
        s == "PasswordCallback" ||
            s == "bio_info_cb" ||
            s.starts_with("CRYPTO_EX_")
    });
    cfg.skip_struct(|s| {
        s == "ProbeResult"
    });
    cfg.skip_fn(move |s| {
        s == "CRYPTO_memcmp" ||                 // uses volatile
            s == "X509V3_EXT_conf_nid" ||       // weird lhash first param
            s == "X509V3_EXT_conf" ||           // weird lhash first param

            // one parameter is `const` in OpenSSL 1.0.1, no need for a new
            // definition or a new file here.
            (s == "BIO_new_mem_buf" && env::var("DEP_OPENSSL_IS_101").is_ok()) ||

        // Skip some functions with function pointers on windows, not entirely
        // sure how to get them to work out...
        (target.contains("windows") && {
            s == "SSL_get_ex_new_index" ||
            s == "SSL_CTX_get_ex_new_index" ||
            s == "CRYPTO_get_ex_new_index"
        })
    });
    cfg.skip_field_type(|s, field| {
        (s == "EVP_PKEY" && field == "pkey") ||      // union
            (s == "GENERAL_NAME" && field == "d")    // union
    });
    cfg.skip_signededness(|s| {
        s.ends_with("_cb") ||
            s.starts_with("CRYPTO_") ||
            s == "PasswordCallback"
    });
    cfg.field_name(|_s, field| {
        if field == "type_" {
            format!("type")
        } else {
            format!("{}", field)
        }
    });
    cfg.fn_cname(|rust, link_name| link_name.unwrap_or(rust).to_string());
    cfg.generate("../openssl-sys/src/lib.rs", "all.rs");
}

