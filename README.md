# Iroha squash and upgrade tool

For usage: `cargo run help`

Known limitations:
- Only squashing for pre-rc-9 and pre-rc-11 is supported at the moment
- Only upgrading from pre-rc-9 to pre-rc-11 is supported at the moment
- Information about asset definition registrar is not retained after squash due to Iroha genesis limitations
- Build times (there's no easy way to do this without essentialy building all supported versions of iroha)
- WASM smartcontract upgrade UX: currently smartcontracts are replaced with value "NEEDSREBUILD++{hash}++", where `hash` is sha256 hash of original smartcontract.
