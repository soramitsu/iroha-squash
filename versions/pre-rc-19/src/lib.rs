use iroha_core::block::Revalidate;
use iroha_core::kura::{BlockIndex, BlockStore, Kura};
use iroha_core::smartcontracts::triggers::set::LoadedExecutable;
use iroha_core::smartcontracts::Registrable;
use iroha_core::wsv::{World, WorldStateView};
use iroha_crypto::HashOf;
use iroha_data_model::block::VersionedCommittedBlock;
use iroha_data_model::evaluate::ExpressionEvaluator;
use iroha_data_model::prelude::*;
use iroha_data_model::transaction::{Executable, WasmSmartContract};
use iroha_data_model::trigger::action::Action;
use iroha_genesis::{GenesisTransactionBuilder, RawGenesisBlock, ValidatorMode, ValidatorPath};
use iroha_squash_macros::*;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::path::Path;

use dashmap::DashMap;
use gag::Gag;
use once_cell::sync::Lazy;
use parity_scale_codec::DecodeAll;
use serde::Deserialize;
use crate::permissions::DEFAULT_PERMISSION_TOKENS_MAP;

use crate::upgrade::Upgrade;

mod permissions;
mod upgrade;

const GENESIS_ACCOUNT_NAME: &'static str = "genesis";
const GENESIS_DOMAIN_NAME: &'static str = "genesis";

prelude!();

pub const GENESIS: Lazy<AccountId> = Lazy::new(|| {
    AccountId::new(
        GENESIS_ACCOUNT_NAME.parse().expect("Valid"),
        GENESIS_DOMAIN_NAME.parse().expect("Valid"),
    )
});

fn mint_asset(id: AssetId, value: AssetValue) -> InstructionBox {
    match value {
        AssetValue::Quantity(v) => InstructionBox::Mint(MintBox::new(v, id)),
        AssetValue::BigQuantity(v) => InstructionBox::Mint(MintBox::new(v, id)),
        AssetValue::Fixed(v) => InstructionBox::Mint(MintBox::new(v, id)),
        AssetValue::Store(meta) => InstructionBox::Sequence(SequenceBox::new(
            meta.iter()
                .map(|(k, v)| SetKeyValueBox::new(id.clone(), k.clone(), v.clone()))
                .map(InstructionBox::SetKeyValue)
                .collect::<Vec<InstructionBox>>(),
        )),
    }
}

fn collect_roles(wsv: &WorldStateView) -> impl Iterator<Item = InstructionBox> + '_ {
    wsv.roles()
        .into_iter()
        .map(|(id, role)| {
            let mut new_role = Role::new(id.clone());

            for token in role.permissions() {
                new_role = new_role.add_permission(token.clone());
            }

            new_role
        })
        .map(RegisterBox::new)
        .map(InstructionBox::Register)
}

fn collect_accounts(domain: Domain) -> impl Iterator<Item = InstructionBox> {
    iter_values!(domain.accounts())
        .map(|account| {
            Account::new(account.id().clone(), account.signatories().cloned())
                .with_metadata(account.metadata().clone())
        })
        .map(RegisterBox::new)
        .map(InstructionBox::Register)
}

fn collect_asset_definitions(
    domain: Domain,
    wsv: &WorldStateView,
) -> impl Iterator<Item = InstructionBox> + '_ {
    iter_values!(domain.asset_definitions()).map(|defn| {
        let id = defn.id().clone();
        let new_defn = match defn.value_type() {
            AssetValueType::Quantity => AssetDefinition::quantity(id),
            AssetValueType::BigQuantity => AssetDefinition::big_quantity(id),
            AssetValueType::Fixed => AssetDefinition::fixed(id),
            AssetValueType::Store => AssetDefinition::store(id),
        }
        .with_metadata(defn.metadata().clone());
        let new_defn = match defn.mintable {
            Mintable::Infinitely => new_defn,
            Mintable::Once | Mintable::Not => new_defn.mintable_once(),
        };
        InstructionBox::Pair(Box::new(Pair::new(
            InstructionBox::Register(RegisterBox::new(new_defn.clone())),
            InstructionBox::Transfer(TransferBox::new(
                IdBox::AccountId(GENESIS.clone()),
                new_defn.clone().build(&GENESIS),
                IdBox::AccountId(
                    wsv.asset_definition(&new_defn.id())
                        .unwrap()
                        .owned_by()
                        .clone(),
                ),
            )),
        )))
    })
}

fn collect_permissions(
    domain: Domain,
    wsv: &WorldStateView,
) -> impl Iterator<Item = InstructionBox> + '_ {
    domain
        .accounts()
        .flat_map(|account| {
            wsv.account_permission_tokens(account.id())
                .unwrap()
                .map(move |token| {
                    InstructionBox::Grant(GrantBox::new(token.clone(), account.id().clone()))
                })
                .collect::<Vec<_>>()
                .into_iter()
        })
        .collect::<Vec<_>>()
        .into_iter()
}

fn collect_assets(
    domain: Domain,
    wsv: &WorldStateView,
) -> impl Iterator<Item = InstructionBox> + '_ {
    iter_values!(domain.accounts()).flat_map(|account| {
        wsv.account_assets(account.id())
            .expect("Inconsistent WSV")
            .into_iter()
            .filter_map(|asset| {
                let definition = wsv
                    .asset_definition(&asset.id().definition_id)
                    .expect("Inconsistent WSV")
                    .clone();
                if definition.mintable == Mintable::Once
                    && definition.value_type() != AssetValueType::Store
                {
                    None
                } else {
                    Some(mint_asset(asset.id().clone(), asset.value().clone()))
                }
            })
    })
}

fn collect_nfts(domain: Domain, wsv: &WorldStateView) -> impl Iterator<Item = InstructionBox> + '_ {
    let nfts: DashMap<AssetDefinitionId, Vec<_>> = DashMap::new();

    let transfers = iter_values!(domain.accounts())
        .flat_map(|account| {
            wsv.account_assets(account.id())
                .expect("Inconsistent WSV")
                .into_iter()
                .filter_map(|asset| {
                    let (id, value) = (asset.id().clone(), asset.value().clone());
                    let definition = wsv
                        .asset_definition(&id.definition_id)
                        .expect("Inconsistent WSV")
                        .clone();
                    if definition.mintable == Mintable::Once
                        && definition.value_type != AssetValueType::Store
                    {
                        nfts.entry(definition.id().clone()).or_default().push(asset);
                        Some(InstructionBox::Transfer(TransferBox::new(
                            GENESIS.clone(),
                            match value {
                                AssetValue::Quantity(v) => Value::Numeric(NumericValue::U32(v)),
                                AssetValue::BigQuantity(v) => Value::Numeric(NumericValue::U128(v)),
                                AssetValue::Fixed(v) => Value::Numeric(NumericValue::Fixed(v)),
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

fn collect_triggers<'a>(
    wsv: &'a WorldStateView,
    contracts: &'a HashMap<HashOf<WasmSmartContract>, WasmSmartContract>,
) -> impl Iterator<Item = InstructionBox> + 'a {
    wsv.triggers()
        .ids()
        .into_iter()
        .map(|id| {
            wsv.triggers()
                .inspect_by_id(&id, |action| {
                    let Action {
                        executable,
                        repeats,
                        authority,
                        filter,
                        metadata,
                    } = action.clone_and_box();
                    let executable = match executable {
                        LoadedExecutable::Wasm(contract) => {
                            Executable::Wasm(contracts.get(&contract.blob_hash).unwrap().clone())
                        }
                        LoadedExecutable::Instructions(isi) => Executable::Instructions(isi),
                    };
                    let original_action = Action {
                        executable,
                        repeats,
                        authority,
                        filter,
                        metadata,
                    };
                    Trigger::new(id.clone(), original_action)
                })
                .expect("By construction")
        })
        .map(RegisterBox::new)
        .map(InstructionBox::Register)
}

fn collect_domains(wsv: &WorldStateView) -> impl Iterator<Item = InstructionBox> + '_ {
    let domains = || {
        wsv.domains()
            .into_iter()
            .filter(|(id, _)| id.name != GENESIS_DOMAIN_NAME.parse().unwrap())
            .map(|(id, domain)| (id.clone(), domain.clone()))
    };

    domains()
        .map(|(id, domain)| Domain::new(id).with_metadata(domain.metadata().clone()))
        .map(RegisterBox::new)
        .map(InstructionBox::Register)
        .chain(domains().flat_map(|(_, domain)| collect_accounts(domain)))
        .chain(domains().flat_map(|(_, domain)| collect_asset_definitions(domain, wsv)))
        .chain(domains().flat_map(|(_, domain)| collect_assets(domain, wsv)))
        .chain(domains().flat_map(|(_, domain)| collect_nfts(domain, wsv)))
        .chain(domains().flat_map(|(_, domain)| collect_permissions(domain, wsv)))
}

fn extract_triggers(
    mut instructions: Vec<InstructionBox>,
    wsv: &WorldStateView,
) -> anyhow::Result<Vec<WasmSmartContract>> {
    let mut contracts = Vec::new();

    while let Some(instruction) = instructions.pop() {
        match instruction {
            InstructionBox::Register(register) => {
                if let RegistrableBox::Trigger(trigger) = wsv.evaluate(&register.object)? {
                    if let Executable::Wasm(contract) = trigger.action.executable {
                        contracts.push(contract)
                    }
                }
            }
            InstructionBox::If(conditional) => {
                instructions.push(conditional.then);
                if let Some(otherwise) = conditional.otherwise {
                    instructions.push(otherwise)
                }
            }
            InstructionBox::Pair(pair) => {
                instructions.push(pair.left_instruction);
                instructions.push(pair.right_instruction);
            }
            InstructionBox::Sequence(seq) => instructions.extend(seq.instructions),
            _ => {}
        }
    }

    Ok(contracts)
}

fn read_store(
    path: &str,
) -> anyhow::Result<(
    WorldStateView,
    HashMap<HashOf<WasmSmartContract>, WasmSmartContract>,
)> {
    let mut wsv = WorldStateView::new(World::new(), Kura::blank_kura_for_testing());

    wsv.config.wasm_runtime_config.fuel_limit = u64::MAX;
    wsv.config.wasm_runtime_config.max_memory = u32::MAX;
    wsv.config.ident_length_limits = LengthLimits::new(0, u32::MAX);
    wsv.config.asset_definition_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);
    wsv.config.asset_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);
    wsv.config.domain_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);
    wsv.config.account_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);

    let store = BlockStore::new(Path::new(path));

    let block_count = store.read_index_count()? as usize;

    let indices = {
        let mut indices = vec![BlockIndex::default(); block_count];
        store.read_block_indices(0, &mut indices)?;
        indices
    };

    let mut block_buf = Vec::new();
    let mut blocks = Vec::with_capacity(block_count);

    for index in indices {
        block_buf.resize(index.length as usize, 0);
        store.read_block_data(index.start, &mut block_buf)?;
        let block = VersionedCommittedBlock::decode_all(&mut block_buf.as_ref())?;
        blocks.push(block);
    }

    let mut contracts = HashMap::new();

    {
        let _shutup = Gag::stdout().unwrap();
        for (idx, block) in blocks.into_iter().enumerate() {
            let instructions = block
                .as_v1()
                .transactions
                .iter()
                .filter_map(|tx| match &tx.payload().instructions {
                    Executable::Instructions(isi) => Some(isi),
                    Executable::Wasm(_) => None,
                })
                .flatten()
                .cloned()
                .collect();

            for trigger in extract_triggers(instructions, &wsv)? {
                contracts.insert(HashOf::new(&trigger), trigger);
            }

            if let Err(e) = block.revalidate(&mut wsv) {
                drop(_shutup);
                println!("Failed to revalidate block #{idx}: {:?}", e);
                break;
            };

            if let Err(e) = wsv.apply_without_execution(&block) {
                drop(_shutup);
                println!("Couldn't apply block #{idx}: {:?}", e);
                break;
            }
        }
    }

    Ok((wsv, contracts))
}

fn squash(path: &str) -> anyhow::Result<String> {
    let (wsv, contracts) = read_store(path)?;

    let transactions = collect_roles(&wsv)
        .chain(collect_domains(&wsv))
        .chain(collect_triggers(&wsv, &contracts))
        .map(|isi| GenesisTransactionBuilder {
            isi: vec![isi].into(),
        })
        .collect::<Vec<_>>()
        .into();

    let genesis = RawGenesisBlock {
        transactions,
        validator: ValidatorMode::Path(ValidatorPath("./test.wasm".parse().unwrap())),
    };

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
pub extern "C" fn upgrade(from: *const libc::c_char) -> *mut libc::c_char {
    let input = unsafe { CStr::from_ptr(from) }
        .to_string_lossy()
        .into_owned();

    #[derive(Deserialize)]
    #[serde(transparent)]
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

    let isi = old_transactions
        .into_iter()
        .map(|tx| tx.isi)
        .flatten()
        .filter(|isi| !is_register_default_permission_token(isi))
        .map(Upgrade::upgrade)
        .collect();

    let tx = GenesisTransactionBuilder { isi };

    let genesis = RawGenesisBlock {
        transactions: vec![tx].into(),
        validator: ValidatorMode::Path(ValidatorPath("/needs_rebuild.wasm".parse().unwrap())),
    };

    let serialized = serde_json::to_string(&genesis).unwrap();

    CString::new(serialized)
        .expect("Null bytes in serde_json output")
        .into_raw()
}

fn is_register_default_permission_token(isi: &from_data_model::isi::InstructionBox) -> bool {
    use from_data_model::prelude::*;
    let InstructionBox::Register(register) = isi else { return false; };
    let expression = register.object.expression.as_ref();
    let Expression::Raw(value) = expression else { return false; };
    let Value::Identifiable(identifiable) = value else { return false; };
    let IdentifiableBox::PermissionTokenDefinition(token) = identifiable else { return false; };
    let token_id = token.id.name.to_string();
    DEFAULT_PERMISSION_TOKENS_MAP.iter().any(|(id_from, _id_to)| &token_id == id_from)
}

#[no_mangle]
pub unsafe extern "C" fn free_str(ptr: *mut libc::c_char) {
    drop(CString::from_raw(ptr));
}
