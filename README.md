# Iroha squash and upgrade tool

For usage: `cargo run help`

Known limitations:
- Supported versions for squashing: pre-rc-9, pre-rc-11, pre-rc-13, pre-rc-16
- Supported upgrade paths: pre-rc-9 -> pre-rc-11, pre-rc-9 -> pre-rc-13, pre-rc-13 -> pre-rc-16
- Information about asset definition registrar is not retained after squash due to Iroha genesis limitations
- Build times (there's no easy way to do this without essentialy building all supported versions of iroha)
- WASM smartcontract upgrade UX: currently smartcontracts are replaced with value "NEEDSREBUILD++{hash}++", where `hash` is sha256 hash of original smartcontract.
