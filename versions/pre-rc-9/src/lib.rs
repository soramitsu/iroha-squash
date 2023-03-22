#![feature(once_cell)]

use std::cell::LazyCell;
use std::ffi::{CStr, CString};
use std::path::Path;

use dashmap::DashMap;
use gag::Gag;
use iroha_core::genesis::{GenesisTransaction, RawGenesisBlock};
use iroha_core::kura::{BlockStoreTrait, StdFileBlockStore};
use iroha_core::prelude::VersionedCommittedBlock;
use iroha_core::wsv::{World, WorldStateView};
use iroha_data_model::account::GENESIS_ACCOUNT_NAME;
use iroha_data_model::LengthLimits;
use iroha_squash_macros::*;
use parity_scale_codec::DecodeAll;

prelude!();

const GENESIS: LazyCell<AccountId> = LazyCell::new(|| {
    AccountId::new(
        GENESIS_ACCOUNT_NAME.parse().expect("Valid"),
        GENESIS_DOMAIN_NAME.parse().expect("Valid"),
    )
});

fn mint_asset(id: AssetId, value: AssetValue) -> Instruction {
    match value {
        AssetValue::Quantity(v) => Instruction::Mint(MintBox::new(v, id)),
        AssetValue::BigQuantity(v) => Instruction::Mint(MintBox::new(v, id)),
        AssetValue::Fixed(v) => Instruction::Mint(MintBox::new(v, id)),
        AssetValue::Store(meta) => Instruction::Sequence(SequenceBox::new(
            meta.iter()
                .map(|(k, v)| SetKeyValueBox::new(id.clone(), k.clone(), v.clone()))
                .map(Instruction::SetKeyValue)
                .collect(),
        )),
    }
}

fn collect_token_definitions(wsv: &WorldStateView) -> impl Iterator<Item = Instruction> + '_ {
    register! {
        map_values!(wsv.permission_token_definitions())
    }
}

fn collect_roles(wsv: &WorldStateView) -> impl Iterator<Item = Instruction> + '_ {
    let roles = map_values!(wsv.roles()).map(|role| {
        let mut new_role = Role::new(role.id().clone());

        for token in role.permissions() {
            new_role = new_role.add_permission(token.clone());
        }

        new_role
    });
    register!(roles)
}

fn collect_accounts(domain: Domain) -> impl Iterator<Item = Instruction> {
    register! {
        iter_values!(domain.accounts()).map(|account| {
            Account::new(account.id().clone(), account.signatories().cloned())
                .with_metadata(account.metadata().clone())
        })
    }
}

fn collect_asset_definitions(domain: Domain) -> impl Iterator<Item = Instruction> {
    register! {
      iter_values!(domain.asset_definitions())
          .map(|entry| entry.definition().clone())
          .map(|defn| {
              let id = defn.id().clone();
              let new_defn = match defn.value_type() {
                  AssetValueType::Quantity => AssetDefinition::quantity(id),
                  AssetValueType::BigQuantity => AssetDefinition::big_quantity(id),
                  AssetValueType::Fixed => AssetDefinition::fixed(id),
                  AssetValueType::Store => AssetDefinition::store(id),
              }
              .with_metadata(defn.metadata().clone());
              match defn.mintable() {
                  Mintable::Infinitely => new_defn,
                  Mintable::Once | Mintable::Not => new_defn.mintable_once(),
              }
          })
    }
}

fn collect_permissions(
    domain: Domain,
    wsv: &WorldStateView,
) -> impl Iterator<Item = Instruction> + '_ {
    iter_values!(domain.accounts()).flat_map(|account| {
        wsv.account_permission_tokens(&account)
            .into_iter()
            .map(move |token| Instruction::Grant(GrantBox::new(token, account.id().clone())))
    })
}

fn collect_assets(domain: Domain, wsv: &WorldStateView) -> impl Iterator<Item = Instruction> + '_ {
    iter_values!(domain.accounts()).flat_map(|account| {
        wsv.account_assets(account.id())
            .expect("Inconsistent WSV")
            .into_iter()
            .filter_map(|asset| {
                let definition = wsv
                    .asset_definition_entry(&asset.id().definition_id)
                    .expect("Inconsistent WSV")
                    .definition()
                    .clone();
                if definition.mintable() == &Mintable::Once
                    && definition.value_type() != &AssetValueType::Store
                {
                    None
                } else {
                    Some(mint_asset(asset.id().clone(), asset.value().clone()))
                }
            })
    })
}

fn collect_nfts(domain: Domain, wsv: &WorldStateView) -> impl Iterator<Item = Instruction> + '_ {
    let nfts: DashMap<AssetDefinitionId, Vec<_>> = DashMap::new();

    let transfers = iter_values!(domain.accounts())
        .flat_map(|account| {
            wsv.account_assets(account.id())
                .expect("Inconsistent WSV")
                .into_iter()
                .filter_map(|asset| {
                    let (id, value) = (asset.id().clone(), asset.value().clone());
                    let definition = wsv
                        .asset_definition_entry(&id.definition_id)
                        .expect("Inconsistent WSV")
                        .definition()
                        .clone();
                    if definition.mintable() == &Mintable::Once
                        && definition.value_type() != &AssetValueType::Store
                    {
                        nfts.entry(definition.id().clone()).or_default().push(asset);
                        Some(Instruction::Transfer(TransferBox::new(
                            GENESIS.clone(),
                            match value {
                                AssetValue::Quantity(v) => Value::U32(v),
                                AssetValue::BigQuantity(v) => Value::U128(v),
                                AssetValue::Fixed(v) => Value::Fixed(v),
                                AssetValue::Store(_) => unreachable!(),
                            },
                            id.account_id.clone(),
                        )))
                    } else {
                        None
                    }
                })
        })
        .collect::<Vec<_>>();

    nfts.into_iter()
        .map(|(id, assets)| {
            let sum = assets
                .iter()
                .map(|asset| asset.value().clone())
                .reduce(|a, b| match (a, b) {
                    (AssetValue::Quantity(va), AssetValue::Quantity(vb)) => {
                        AssetValue::Quantity(va + vb)
                    }
                    (AssetValue::BigQuantity(va), AssetValue::BigQuantity(vb)) => {
                        AssetValue::BigQuantity(va + vb)
                    }
                    (AssetValue::Fixed(va), AssetValue::Fixed(vb)) => AssetValue::Fixed(
                        va.checked_add(vb).expect("Inconsistent input blockchain"),
                    ),
                    _ => panic!("Inconsistent input blockchain"),
                })
                .expect("Nonempty by construction");
            mint_asset(AssetId::new(id.clone(), GENESIS.clone()), sum)
        })
        .chain(transfers.into_iter())
}

fn collect_triggers(wsv: &WorldStateView) -> impl Iterator<Item = Instruction> + '_ {
    register! {
      wsv.triggers().ids().into_iter().map(|id| {
          wsv.triggers().inspect_by_id(&id, |action| {
              Trigger::new(id.clone(), action.clone_and_box())
          }).expect("By construction")
      })
    }
}

fn collect_domains(wsv: &WorldStateView) -> impl Iterator<Item = Instruction> + '_ {
    register! {
        map_values!(wsv.domains())
        .map(|domain| Domain::new(domain.id().clone()).with_metadata(domain.metadata().clone()))
    }
    .chain(map_values!(wsv.domains()).flat_map(collect_accounts))
    .chain(map_values!(wsv.domains()).flat_map(collect_asset_definitions))
    .chain(map_values!(wsv.domains()).flat_map(|domain| collect_assets(domain, wsv)))
    .chain(map_values!(wsv.domains()).flat_map(|domain| collect_nfts(domain, wsv)))
    .chain(map_values!(wsv.domains()).flat_map(|domain| collect_permissions(domain, wsv)))
}

fn read_store(path: &str) -> anyhow::Result<WorldStateView> {
    let mut wsv = WorldStateView::new(World::new());

    wsv.config.wasm_runtime_config.fuel_limit = u64::MAX;
    wsv.config.wasm_runtime_config.max_memory = u32::MAX;
    wsv.config.ident_length_limits = LengthLimits::new(0, u32::MAX);
    wsv.config.asset_definition_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);
    wsv.config.asset_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);
    wsv.config.domain_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);
    wsv.config.account_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);

    let store = StdFileBlockStore::new(Path::new(path));

    let block_count = store.read_index_count()? as usize;

    let indices = {
        let mut indices = vec![(0, 0); block_count];
        store.read_block_indices(0, &mut indices)?;
        indices
    };

    let mut block_buf = Vec::new();
    let mut blocks = Vec::with_capacity(block_count);

    for (start, len) in indices {
        block_buf.resize(len as usize, 0);
        store.read_block_data(start, &mut block_buf)?;
        let block = VersionedCommittedBlock::decode_all(&mut block_buf.as_ref())?;
        blocks.push(block);
    }

    {
        let _shutup = Gag::stdout().unwrap();
        wsv.init(blocks);
    }

    Ok(wsv)
}

fn squash(path: &str) -> anyhow::Result<String> {
    let wsv = read_store(path)?;

    let isi = collect_token_definitions(&wsv)
        .chain(collect_roles(&wsv))
        .chain(collect_domains(&wsv))
        .chain(collect_triggers(&wsv))
        .collect::<Vec<_>>()
        .into();

    let transactions = vec![GenesisTransaction { isi }].into();

    let genesis = RawGenesisBlock { transactions };

    Ok(serde_json::to_string(&genesis)?)
}

#[no_mangle]
pub extern "C" fn squash_store(path: *const libc::c_char) -> *mut libc::c_char {
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();

    match squash(&path) {
        Ok(serialized) => CString::new(serialized)
            .expect("Null bytes in serde_json output")
            .into_raw(),
        Err(e) => {
            eprintln!("Error squashing blockchain: {}", e);
            CString::new("{}").unwrap().into_raw()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn free_str(ptr: *mut libc::c_char) {
    drop(CString::from_raw(ptr));
}
