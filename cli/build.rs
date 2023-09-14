use quote::quote;
use std::{
    env,
    ffi::OsStr,
    fs::{read_dir, File},
    io::Write,
    path::PathBuf,
    process::Command,
};

#[cfg(target_os = "linux")]
const OS_DYLIB_EXT: &'static str = "so";
#[cfg(target_os = "macos")]
const OS_DYLIB_EXT: &'static str = "dylib";

fn main() {
    println!(
        "cargo:rerun-if-changed={}/../versions",
        env::var_os("CARGO_MANIFEST_DIR").unwrap().to_string_lossy()
    );
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let mut entries = Vec::new();

    for version_dir in std::fs::read_dir("../versions").expect("I/O error") {
        let version_dir = version_dir.expect("I/O error");
        let out_subdir = out_dir.join(version_dir.file_name());

        let version = version_dir.file_name().into_string().unwrap();

        let status = Command::new(env::var_os("CARGO").unwrap())
            .args([
                "build",
                "--release",
                "--target-dir",
                out_subdir.to_str().unwrap(),
            ])
            .current_dir(version_dir.path())
            .status()
            .expect("Version build failed");

        if !status.success() {
            panic!("Version {version} build failed");
        }

        let paths = read_dir(out_subdir.clone()).unwrap();

        for path in paths {
            println!("Name: {}", path.unwrap().path().display())
        }

        let dylib = std::fs::read_dir(out_subdir.join("release"))
            .unwrap()
            .filter_map(Result::ok)
            .find(|item| item.path().extension() == Some(OsStr::new(OS_DYLIB_EXT)))
            .expect("Failed to find .so")
            .path();
        let dylib_path = dylib.to_string_lossy();

        entries.push(quote! {
            map.insert(#version, include_bytes!(#dylib_path).as_slice())
        });
    }

    let mut src = File::create(out_dir.join("versions.rs")).unwrap();

    write!(
        src,
        "{}",
        quote! {
            use std::cell::LazyCell;
            use std::collections::HashMap;
            pub const VERSIONS: LazyCell<HashMap<&'static str, &'static [u8]>> = std::cell::LazyCell::new(|| {
                let mut map = HashMap::new();
                #(#entries);*;
                map
            });
        }
    ).unwrap();
}
