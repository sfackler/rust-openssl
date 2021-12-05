use bindgen::callbacks::{MacroParsingBehavior, ParseCallbacks};
use bindgen::RustTarget;
use std::env;
use std::path::PathBuf;

const INCLUDES: &str = "
#include <openssl/crypto.h>
#include <openssl/stack.h>
";

pub fn run(include_dirs: &[PathBuf]) {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let mut builder = bindgen::builder()
        .parse_callbacks(Box::new(OpensslCallbacks))
        .rust_target(RustTarget::Stable_1_47)
        .ctypes_prefix("::libc")
        .raw_line("use libc::*;")
        .allowlist_file(".*/openssl/[^/]+.h")
        .allowlist_recursively(false)
        // libc is missing pthread_once_t on macOS
        .blocklist_type("CRYPTO_ONCE")
        .blocklist_function("CRYPTO_THREAD_run_once")
        .layout_tests(false)
        .header_contents("includes.h", INCLUDES);

    for include_dir in include_dirs {
        builder = builder
            .clang_arg("-I")
            .clang_arg(include_dir.display().to_string());
    }

    builder
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("bindgen.rs"))
        .unwrap();
}

#[derive(Debug)]
struct OpensslCallbacks;

impl ParseCallbacks for OpensslCallbacks {
    // for now we'll continue hand-writing constants
    fn will_parse_macro(&self, _name: &str) -> MacroParsingBehavior {
        MacroParsingBehavior::Ignore
    }

    // Our original definitions of these are wrong (missing the Option layer), so we need to rename to avoid breakage
    fn item_name(&self, original_item_name: &str) -> Option<String> {
        match original_item_name {
            "CRYPTO_EX_new" | "CRYPTO_EX_dup" | "CRYPTO_EX_free" => {
                Some(format!("{}2", original_item_name))
            }
            _ => None,
        }
    }
}
