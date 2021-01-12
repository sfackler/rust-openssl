use std::env;
use std::path::{Path, PathBuf};

use conan::*;

///
/// Assumes the user provides:
/// 1. (optional) define the conan command with CONAN environment variable
/// 2. the conan command is on the PATH environment
/// 3. Already defined the expected conan profile, which looks like:
///    windows-x86_64, linux-x86_64, etc...
/// 4. pre-written out a conanfile.txt to read and use
///    preferably with openssl and its options
///
/// Return pair of (Lib dir, Include dir)
pub fn build_with_conan() -> Option<(PathBuf, PathBuf)> {
    println!("cargo:rerun-if-changed=build/build_with_conan.rs");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let conan_profile = format!("{}-{}", target_os, target_arch);

    // Let the user have a chance at configuring where the conanfile.txt file is
    // else assume it's in the local directory, which may not be where they want.
    let conanfile_path = match option_env!("CONANFILE_ROOT") {
        Some(p) => {
            Path::new(p)
            .join("conanfile.txt")
            .as_path()
            .to_owned()
        },
        None => Path::new("conanfile.txt").to_owned()
    };

    // emit the conanfile.txt as a directive to cargo to rerun this
    // in case conanfile.txt changes.
    if let Some(s) = conanfile_path.to_str() {
        println!("cargo:rerun-if-changed={}", s);
    }

    let command = InstallCommandBuilder::new()
        .with_profile(&conan_profile)
        .build_policy(BuildPolicy::Missing)
        .recipe_path(&conanfile_path)
        .build();
        
    if let Some(build_info) = command.generate() {
        println!("using conan build info");
        match build_info.get_dependency("openssl") {
            Some(build_deps) => {
                if let (Some(lib_dir), Some(include_dir)) = (build_deps.get_library_dir(), build_deps.get_include_dir()) {
                    return Some((PathBuf::from(lib_dir), PathBuf::from(include_dir)))
                }
            }
            None => return None
        }
    }


    None
}