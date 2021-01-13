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
pub fn try_build_with_conan(conanfile_path: &PathBuf) -> Option<(PathBuf, PathBuf)> {
    println!("cargo:rerun-if-changed=build/build_with_conan.rs");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let conan_profile = format!("{}-{}", target_os, target_arch);

    // emit changes to the conanfile.txt as a directive to cargo to rerun this
    // build script in case conanfile.txt changes.
    if let Some(s) = conanfile_path.to_str() {
        println!("cargo:rerun-if-changed={}", s);
    }

    // Try and build a `conan install` command with the profile above,
    // build any missing packages that conan needs, and use the conanfile.txt
    // recipe used above
    let command = InstallCommandBuilder::new()
        .with_profile(&conan_profile)
        .build_policy(BuildPolicy::Missing)
        .recipe_path(&conanfile_path)
        .build();

    // If successful, generate build info and use it
    if let Some(build_info) = command.generate() {
        println!("using conan build info");
        match build_info.get_dependency("openssl") {
            Some(openssl_build_dep) => {
                if let (Some(lib_dir), Some(include_dir)) = (
                    openssl_build_dep.get_library_dir(),
                    openssl_build_dep.get_include_dir(),
                ) {
                    return Some((PathBuf::from(lib_dir), PathBuf::from(include_dir)));
                }
            }
            // User did not specify openssl as a dependency
            None => return None,
        }
    }

    // Else, return no value
    None
}

// Let the user have a chance at configuring where the conanfile.txt file is
// else assume it's in the local directory, which may not be where they want.
// Return a value if the file exists, or None
pub fn get_conanfile_path() -> Option<PathBuf> {
    let conanfile_path = match option_env!("CONANFILE_ROOT") {
        Some(p) => Path::new(p).join("conanfile.txt").as_path().to_owned(),
        None => Path::new("conanfile.txt").to_owned(),
    };

    match conanfile_path.exists() {
        true => Some(conanfile_path),
        false => None,
    }
}
