#![feature(lazy_cell)]

use std::cell::LazyCell;
use std::ffi::{CStr, CString};

use iroha_data_model::prelude::*;
use iroha_genesis::{ExecutorMode, ExecutorPath, RawGenesisBlockBuilder};
use iroha_squash_macros::*;
use serde::Deserialize;

use crate::upgrade::Upgrade;

mod upgrade;

const GENESIS_ACCOUNT_NAME: &'static str = "genesis";
const GENESIS_DOMAIN_NAME: &'static str = "genesis";

prelude!();

pub const GENESIS: LazyCell<AccountId> = LazyCell::new(|| {
    AccountId::new(
        GENESIS_ACCOUNT_NAME.parse().expect("Valid"),
        GENESIS_DOMAIN_NAME.parse().expect("Valid"),
    )
});

#[no_mangle]
pub extern "C" fn squash_store(_: *const libc::c_char) -> *mut libc::c_char {
    todo!()
}

#[no_mangle]
pub extern "C" fn upgrade(from: *const libc::c_char) -> *mut libc::c_char {
    let input = unsafe { CStr::from_ptr(from) }
        .to_string_lossy()
        .into_owned();

    #[derive(Deserialize)]
    struct Transaction {
        isi: Vec<from_data_model::isi::InstructionBox>,
    }

    #[derive(Deserialize)]
    struct Genesis {
        transactions: Vec<Transaction>,
    }

    let old_transactions = serde_json::from_str::<Genesis>(&input)
        .unwrap()
        .transactions;

    let mut genesis = RawGenesisBlockBuilder::default()
        .executor(ExecutorMode::Path(ExecutorPath(
            "/needs_rebuild.wasm".parse().unwrap(),
        )))
        .build();

    for instruction in old_transactions
        .into_iter()
        .map(|tx| tx.isi)
        .flatten()
        .map(Upgrade::upgrade)
    {
        genesis
            .first_transaction_mut()
            .unwrap()
            .append_instruction(instruction);
    }

    let serialized = serde_json::to_string(&genesis).unwrap();

    CString::new(serialized)
        .expect("Null bytes in serde_json output")
        .into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn free_str(ptr: *mut libc::c_char) {
    drop(CString::from_raw(ptr));
}
