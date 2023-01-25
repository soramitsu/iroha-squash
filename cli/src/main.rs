#![feature(once_cell)]
include!(concat!(env!("OUT_DIR"), "/versions.rs"));

use std::{
    ffi::{CStr, CString},
    io::Write,
};

use argh::FromArgs;
use libloading::{Library, Symbol};
use tempfile::NamedTempFile;

struct Version {
    lib: Library,
    // Should be dropped _after_ the lib
    #[allow(dead_code)]
    file: NamedTempFile,
}

impl Version {
    fn load(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut tempfile = NamedTempFile::new_in("./")?;
        tempfile.write_all(bytes)?;
        let lib = unsafe { libloading::Library::new(tempfile.path())? };
        Ok(Version {
            file: tempfile,
            lib,
        })
    }
}

#[derive(FromArgs)]
/// Squash iroha store
struct Squash {
    /// path to block store
    #[argh(option, short = 's')]
    store: String,
}

fn main() -> anyhow::Result<()> {
    let args: Squash = argh::from_env();

    let ver = Version::load(VERSIONS.get("pre-rc-9").unwrap()).unwrap();

    unsafe {
        let squash_store: Symbol<unsafe extern "C" fn(*const libc::c_char) -> *mut u8> =
            ver.lib.get(b"squash_store")?;
        let free_str: Symbol<unsafe extern "C" fn(*mut u8)> = ver.lib.get(b"free_str").unwrap();
        let s = CString::new(args.store)?;
        let res = squash_store(s.as_c_str().as_ptr());
        println!("{}", CStr::from_ptr(res).to_str()?);
        free_str(res);
    }

    Ok(())
}
