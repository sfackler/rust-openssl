extern crate ctest;

use std::env;
use std::path;
use std::fs;

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

    if let Ok(_) = env::var("DEP_OPENSSL_LIBRESSL") {
        cfg.cfg("libressl", None);
    } else if let Ok(version) = env::var("DEP_OPENSSL_VERSION") {
        cfg.cfg(&format!("ossl{}", version), None);
    }
    if let (Ok(version), Ok(patch)) = (env::var("DEP_OPENSSL_VERSION"), env::var("DEP_OPENSSL_PATCH")) {
        cfg.cfg(&format!("ossl{}{}", version, patch), None);
    }
    if let Ok(vars) = env::var("DEP_OPENSSL_CONF") {
        for var in vars.split(",") {
            cfg.cfg("osslconf", Some(var));
        }
    }

    // Exclude these headers (because they cause errors), include everything else
    let exclude_headers = [
        "openssl/asn1_mac.h",
        "openssl/dtls1.h"
    ];

    let header_dir = env::var("DEP_OPENSSL_INCLUDE").unwrap();
    let include_location = path::Path::new(&header_dir);

    if let Ok(entries) = fs::read_dir(include_location.join("openssl")) {
        for header in entries {
            let header_path = header.unwrap().path();
            // some/path/openssl/file.h -> openssl/file.h
            let header_suffix = header_path.strip_prefix(include_location).unwrap();
            let header_str = header_suffix.to_str().unwrap();
            // Exclude files we don't want
            if exclude_headers.iter().position(|&x| x == header_str).is_none() {
                cfg.header(header_str);
            }
        }
    }

    cfg.type_name(|s, is_struct| {
        // Add some `*` on some callback parameters to get function pointer to
        // typecheck in C, especially on MSVC.
        if s == "PasswordCallback" {
            format!("pem_password_cb*")
        } else if s == "bio_info_cb" {
            format!("bio_info_cb*")
        } else if s == "_STACK" {
            format!("struct stack_st")
        // This logic should really be cleaned up
        } else if is_struct && s != "point_conversion_form_t" && s.chars().next().unwrap().is_lowercase() {
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
            s.ends_with("_CB") ||
            s.ends_with("_cb_fn") ||
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
