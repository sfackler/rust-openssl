use openssl_src;
use std::path::PathBuf;

pub fn get_openssl(_target: &str) -> (Vec<PathBuf>, PathBuf) {
    let mut builder = openssl_src::Build::new();

    #[cfg(feature = "vendored-engine")]
    builder = builder.force_engine();

    let artifacts = builder.build();
    println!("cargo:vendored=1");
    println!(
        "cargo:root={}",
        artifacts.lib_dir().parent().unwrap().display()
    );

    (
        vec![artifacts.lib_dir().to_path_buf()],
        artifacts.include_dir().to_path_buf(),
    )
}
