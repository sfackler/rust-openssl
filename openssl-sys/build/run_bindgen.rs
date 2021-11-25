use bindgen::callbacks::{MacroParsingBehavior, ParseCallbacks};
use bindgen::RustTarget;
use std::env;
use std::path::{Path, PathBuf};

const INCLUDES: &str = "
#include <openssl/stack.h>
";

pub fn run(include_dir: &Path) {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    bindgen::builder()
        .parse_callbacks(Box::new(OpensslCallbacks))
        .rust_target(RustTarget::Stable_1_47)
        .ctypes_prefix("::libc")
        .clang_arg("-I")
        .clang_arg(include_dir.display().to_string())
        .header_contents("includes.h", INCLUDES)
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
}
