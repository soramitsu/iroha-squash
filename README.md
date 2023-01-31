# Iroha squash (and in the future upgrade) tool

For usage: `cargo run help`

Known limitations:
- Only pre-rc-9 and pre-rc-11 is supported at the moment
- Information about asset definition registrar is not retained after squash due to Iroha genesis limitations
- Build times (there's no easy way to do this without essentialy building all supported versions of iroha)
