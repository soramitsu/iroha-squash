# Iroha squash and upgrade tool

For usage: `cargo run help`

Known limitations:
- Supported versions for squashing: pre-rc-9, pre-rc-11, pre-rc-13, pre-rc-16, pre-rc-19, pre-rc-20
- Supported upgrade paths: pre-rc-9 -> pre-rc-11, pre-rc-9 -> pre-rc-13, pre-rc-13 -> pre-rc-16 -> pre-rc-19 -> pre-rc-20
- Information about asset definition registrar is not retained after squash due to Iroha genesis limitations
- Build times (there's no easy way to do this without essentialy building all supported versions of iroha)
- WASM smartcontract upgrade UX: currently smartcontracts are replaced with value "NEEDSREBUILD++{hash}++", where `hash` is sha256 hash of original smartcontract.


## Design
Every supported version of iroha is built as a separate library (found in `versions/`), which is loaded by `cli`.
This is done because trying to depend all supported versions of iroha leads - understandably - to dependency
resulution failures.

Every version defines two functions:
- `extern "C" fn squash_store(path: *const libc::c_char) -> *mut libc::c_char`, which takes
  a path to this version's blockstore, loads it and squashes into a single genesis.
- `extern "C" fn upgrade(from: *const libc::c_char) -> *mut libc::c_char`, which takes
  a path to a `genesis.json` (presumably squashed) for a __previous__ supported version and upgrades it.

There is a `macro` crate with some utility macros, since most of the code is boilerplate that
translates between two structurally identical types that Rust doesn't consider identical since
they're from different iroha versions.

A lot of type conversions are not implemented, either because they're unlikely to be seen
in actual blockchain and are mostly something you would see on a client running queries, or 
because there's no unambiguous mapping from previous version's concept to a new one's, in which
case input from actual users needs to be considered.
