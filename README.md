# Iroha squash and upgrade tool

For usage: `cargo run help`

Known limitations:
- Supported versions for squashing:
  - [pre-rc-9](https://github.com/hyperledger/iroha/tree/v2.0.0-pre-rc.9.1)
  - [pre-rc-11](https://github.com/hyperledger/iroha/tree/a4d5c9f8ddb1ea51f75569b04eb78525d4cf02f2)
  - [pre-rc-13](https://github.com/hyperledger/iroha/tree/v2.0.0-pre-rc.13.1)
  - [pre-rc-16](https://github.com/hyperledger/iroha/tree/e467e1a24124ce47546f52e4ac807b2d55bb6a4d)
  - [pre-rc-19](https://github.com/hyperledger/iroha/tree/v2.0.0-pre-rc.19)
  - [pre-rc-20](https://github.com/hyperledger/iroha/tree/v2.0.0-pre-rc.20.1)
- Supported upgrade paths:
  - pre-rc-9 -> pre-rc-11
  - pre-rc-9 -> pre-rc-13
  - pre-rc-13 -> pre-rc-16
  - pre-rc-16 -> pre-rc-19
  - pre-rc-19 -> pre-rc-20
- Information about asset definition registrar is not retained after squash due to Iroha genesis limitations
- Build times (there's no easy way to do this without essentialy building all supported versions of iroha)
- WASM smartcontract upgrade UX: currently smartcontracts are replaced with value "NEEDSREBUILD++{hash}++", where `hash` is sha256 hash of original smartcontract.

## Usage
* First you need to squash your block store into single `genesis.json` using `squash` command
* Then `genesis.json` can be upgraded to latest version step-by-step, e.g. if you want to upgrade from rc16 to rc20, then you should first upgrade `rc16 → rc19`, and then `rc19 → rc20`

### Example: squash and upgrade from rc9 to rc20
Consider you have block store from rc9 located in directory `store9`. Here are steps needed to upgrade it to rc20:
* `cargo run -- squash -s store9 -v pre-rc-9 >genesis9.json`
* `cargo run -- upgrade -g genesis9.json -v pre-rc-13 >genesis13.json`
* `cargo run -- upgrade -g genesis13.json -v pre-rc-16 >genesis16.json`
* Remove `PermissionTokenDefinition` ISI from `genesis16.json`. If you have non-standart permission tokens, they should be registered in custom executor.
* `cargo run -- upgrade -g genesis16.json -v pre-rc-19 >genesis19.json`
* `cargo run -- upgrade -g genesis19.json -v pre-rc-20 >genesis20.json`

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
