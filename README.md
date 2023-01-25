# Iroha squash (and in the future upgrade) tool

Usage: `cargo run -- --store /path/to/store > genesis.json`

Known limitations:
- Only pre-rc-9 is supported at the moment
- Information about asset definition registrar is not retained after squash due to Iroha genesis limitations
