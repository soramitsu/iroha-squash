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

#[derive(FromArgs, PartialEq, Debug)]
/// Iroha squash tool - merge (and upgrade) Iroha 2 block stores
struct Args {
    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Command {
    Squash(Squash),
    Versions(Versions),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "versions")]
/// List supported iroha versions
struct Versions {}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "squash")]
/// Squash iroha block store to a single genesis block
/// Outputs genesis json representation to stdout.
/// Example usage:
/// `cargo run -- squash -s /path/to/store -v pre-rc-9 > genesis.json`
struct Squash {
    /// path to block store
    #[argh(option, short = 's', long = "store")]
    store: String,
    /// iroha version
    #[argh(option, short = 'v', long = "version")]
    version: String,
}

fn squash(args: Squash) -> anyhow::Result<()> {
    let ver = Version::load(
        VERSIONS
            .get(args.version.as_str())
            .expect("Unsupported version"),
    )?;

    unsafe {
        let squash_store: Symbol<unsafe extern "C" fn(*const libc::c_char) -> *mut u8> =
            ver.lib.get(b"squash_store")?;
        let free_str: Symbol<unsafe extern "C" fn(*mut u8)> = ver.lib.get(b"free_str")?;
        let s = CString::new(args.store)?;
        let res = squash_store(s.as_c_str().as_ptr());
        println!("{}", CStr::from_ptr(res).to_str()?);
        free_str(res);
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();

    match args.command {
        Command::Squash(args) => squash(args),
        Command::Versions(_) => {
            println!(
                "Supported iroha versions: \n\t{}",
                VERSIONS.keys().cloned().collect::<Vec<_>>().join("\n\t")
            );
            Ok(())
        }
    }
}
