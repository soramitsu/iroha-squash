#![feature(once_cell)]
#![feature(lazy_cell)]
include!(concat!(env!("OUT_DIR"), "/versions.rs"));

use std::{
    ffi::{CStr, CString},
    fs::File,
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
    Upgrade(Upgrade),
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

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "upgrade")]
/// Upgrade genesis from previous supported iroha version
/// Outputs genesis json representation to stdout.
/// Example usage:
/// `cargo run -- upgrade -g /path/to/genesis.json -v pre-rc-11 > genesis_upgraded.json`
struct Upgrade {
    /// path to genesis
    #[argh(option, short = 'g', long = "genesis")]
    genesis: String,
    /// iroha version to upgrade to
    #[argh(option, short = 'v', long = "version")]
    version: String,
}

fn upgrade(args: Upgrade) -> anyhow::Result<()> {
    let ver = Version::load(
        VERSIONS
            .get(args.version.as_str())
            .expect("Unsupported version"),
    )?;

    unsafe {
        let upgrade_genesis: Symbol<
            unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
        > = ver.lib.get(b"upgrade")?;
        let free_str: Symbol<unsafe extern "C" fn(*mut libc::c_char)> = ver.lib.get(b"free_str")?;
        let contents = std::io::read_to_string(File::open(args.genesis).unwrap()).unwrap();
        let contents = CString::new(contents).expect("Null byte in genesis");
        let res = upgrade_genesis(contents.as_ptr());
        println!("{}", CStr::from_ptr(res).to_str()?);
        free_str(res);
    }

    Ok(())
}

fn squash(args: Squash) -> anyhow::Result<()> {
    let ver = Version::load(
        VERSIONS
            .get(args.version.as_str())
            .expect("Unsupported version"),
    )?;

    unsafe {
        let squash_store: Symbol<unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char> =
            ver.lib.get(b"squash_store")?;
        let free_str: Symbol<unsafe extern "C" fn(*mut libc::c_char)> = ver.lib.get(b"free_str")?;
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
        Command::Upgrade(args) => upgrade(args),
        Command::Versions(_) => {
            println!(
                "Supported iroha versions: \n\t{}",
                VERSIONS.keys().cloned().collect::<Vec<_>>().join("\n\t")
            );
            Ok(())
        }
    }
}
