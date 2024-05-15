use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::path::Path;
use anyhow::anyhow;

use dashmap::DashMap;
use gag::Gag;
use iroha_core::block::ValidBlock;
use iroha_core::kura::{BlockIndex, BlockStore, Kura, LockStatus};
use iroha_core::PeersIds;
use iroha_core::smartcontracts::Registrable;
use iroha_core::smartcontracts::triggers::set::{LoadedAction, LoadedExecutable};
use iroha_core::sumeragi::network_topology::Topology;
use iroha_core::wsv::{World, WorldStateView};
use iroha_crypto::HashOf;
use iroha_data_model::block::SignedBlock;
use iroha_data_model::evaluate::ExpressionEvaluator;
use iroha_data_model::prelude::*;
use iroha_data_model::transaction::{Executable, WasmSmartContract};
use iroha_data_model::trigger::action::Action;
use iroha_genesis::{ExecutorMode, ExecutorPath, GENESIS_ACCOUNT_ID, GENESIS_DOMAIN_ID, RawGenesisBlockBuilder};
use once_cell::sync::Lazy;
use parity_scale_codec::DecodeAll;
use serde::Deserialize;

use iroha_squash_macros::*;

use crate::upgrade::Upgrade;

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

fn mint_asset(id: AssetId, value: AssetValue) -> InstructionExpr {
    match value {
        AssetValue::Quantity(v) => InstructionExpr::Mint(MintExpr::new(v, id)),
        AssetValue::BigQuantity(v) => InstructionExpr::Mint(MintExpr::new(v, id)),
        AssetValue::Fixed(v) => InstructionExpr::Mint(MintExpr::new(v, id)),
        AssetValue::Store(meta) => InstructionExpr::Sequence(SequenceExpr::new(
            meta.iter()
                .map(|(k, v)| SetKeyValueExpr::new(id.clone(), k.clone(), v.clone()))
                .map(InstructionExpr::SetKeyValue)
                .collect::<Vec<InstructionExpr>>(),
        )),
    }
}

fn collect_roles(wsv: &WorldStateView) -> impl Iterator<Item = InstructionExpr> + '_ {
    wsv.roles()
        .into_iter()
        .map(|(id, role)| {
            let mut new_role = Role::new(id.clone());

            for token in role.permissions() {
                new_role = new_role.add_permission(token.clone());
            }

            new_role
        })
        .map(RegisterExpr::new)
        .map(InstructionExpr::Register)
}

fn collect_accounts(domain: Domain) -> impl Iterator<Item = InstructionExpr> {
    iter_values!(domain.accounts())
        .map(|account| {
            Account::new(account.id().clone(), account.signatories().cloned())
                .with_metadata(account.metadata().clone())
        })
        .map(RegisterExpr::new)
        .map(InstructionExpr::Register)
}

fn collect_asset_definitions(
    domain: Domain,
    wsv: &WorldStateView,
) -> impl Iterator<Item = InstructionExpr> + '_ {
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
        InstructionExpr::Pair(Box::new(PairExpr::new(
            InstructionExpr::Register(RegisterExpr::new(new_defn.clone())),
            InstructionExpr::Transfer(TransferExpr::new(
                IdBox::AccountId(GENESIS.clone()),
                new_defn.clone().build(&GENESIS),
                IdBox::AccountId(
                    wsv.asset_definition(new_defn.id())
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
) -> impl Iterator<Item = InstructionExpr> + '_ {
    domain
        .accounts()
        .flat_map(|account| {
            wsv.account_permission_tokens(account.id())
                .unwrap()
                .map(move |token| {
                    InstructionExpr::Grant(GrantExpr::new(token.clone(), account.id().clone()))
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
) -> impl Iterator<Item = InstructionExpr> + '_ {
    iter_values!(domain.accounts()).flat_map(|account| {
        wsv.account_assets(account.id())
            .expect("Inconsistent WSV")
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

fn collect_nfts(domain: Domain, wsv: &WorldStateView) -> impl Iterator<Item = InstructionExpr> + '_ {
    let nfts: DashMap<AssetDefinitionId, Vec<_>> = DashMap::new();

    let transfers = iter_values!(domain.accounts())
        .flat_map(|account| {
            wsv.account_assets(account.id())
                .expect("Inconsistent WSV")
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
                        Some(InstructionExpr::Transfer(TransferExpr::new(
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
        .chain(transfers)
}

fn collect_triggers<'a>(
    wsv: &'a WorldStateView,
    contracts: &'a HashMap<HashOf<WasmSmartContract>, WasmSmartContract>,
) -> impl Iterator<Item = InstructionExpr> + 'a {
    wsv.triggers()
        .ids()
        .map(|id| {
            wsv.triggers()
                .inspect_by_id(id, |action| {
                    let executable = action.executable().clone();
                    let LoadedAction {
                        repeats,
                        authority,
                        filter,
                        metadata,
                        ..
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
        .map(RegisterExpr::new)
        .map(InstructionExpr::Register)
}

fn collect_domains(wsv: &WorldStateView) -> impl Iterator<Item = InstructionExpr> + '_ {
    let domains = || {
        wsv.domains()
            .into_iter()
            .filter(|(id, _)| id.name != GENESIS_DOMAIN_NAME.parse().unwrap())
            .map(|(id, domain)| (id.clone(), domain.clone()))
    };

    domains()
        .map(|(id, domain)| Domain::new(id).with_metadata(domain.metadata().clone()))
        .map(RegisterExpr::new)
        .map(InstructionExpr::Register)
        .chain(domains().flat_map(|(_, domain)| collect_accounts(domain)))
        .chain(domains().flat_map(|(_, domain)| collect_asset_definitions(domain, wsv)))
        .chain(domains().flat_map(|(_, domain)| collect_assets(domain, wsv)))
        .chain(domains().flat_map(|(_, domain)| collect_nfts(domain, wsv)))
        .chain(domains().flat_map(|(_, domain)| collect_permissions(domain, wsv)))
}

fn extract_triggers(
    mut instructions: Vec<InstructionExpr>,
    wsv: &WorldStateView,
) -> anyhow::Result<Vec<WasmSmartContract>> {
    let mut contracts = Vec::new();

    while let Some(instruction) = instructions.pop() {
        match instruction {
            InstructionExpr::Register(register) => {
                if let RegistrableBox::Trigger(trigger) = wsv.evaluate(&register.object)? {
                    if let Executable::Wasm(contract) = trigger.action.executable {
                        contracts.push(contract)
                    }
                }
            }
            InstructionExpr::If(conditional) => {
                instructions.push(conditional.then);
                if let Some(otherwise) = conditional.otherwise {
                    instructions.push(otherwise)
                }
            }
            InstructionExpr::Pair(pair) => {
                instructions.push(pair.left_instruction);
                instructions.push(pair.right_instruction);
            }
            InstructionExpr::Sequence(seq) => instructions.extend(seq.instructions),
            _ => {}
        }
    }

    Ok(contracts)
}

fn read_blocks(path: &str) -> anyhow::Result<Vec<SignedBlock>> {
    let store = BlockStore::new(Path::new(path), LockStatus::Locked);
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
        let block = SignedBlock::decode_all(&mut block_buf.as_ref())?;
        blocks.push(block);
    }
    Ok(blocks)
}

fn read_store(path: &str) -> anyhow::Result<(
    WorldStateView,
    HashMap<HashOf<WasmSmartContract>, WasmSmartContract>,
)> {
    let blocks = read_blocks(path)?;
    let mut wsv = create_wsv(&blocks);

    let mut contracts = HashMap::new();
    let _shutup = Gag::stdout().unwrap();
    for (idx, block) in blocks.into_iter().enumerate() {
        let instructions = block
            .payload()
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

        let topology = Topology::new(block.payload().commit_topology.clone());
        let validated_block = ValidBlock::validate(block, &topology, &mut wsv)
            .map_err(|e| anyhow!("Failed to revalidate block #{idx}: {:?}", e.1))?;
        let committed_block = validated_block.commit(&topology).expect("Block is valid");

        wsv.apply_without_execution(&committed_block)
            .map_err(|e| anyhow!("Couldn't apply block #{idx}: {:?}", e))?;
    }

    Ok((wsv, contracts))
}

fn create_wsv(blocks: &[SignedBlock]) -> WorldStateView {
    let genesis_public_key = blocks[0]
        .signatures()
        .iter()
        .next()
        .expect("Genesis block not signed")
        .public_key()
        .clone();
    let genesis_domain = genesis_domain(genesis_public_key);
    let world = World::with(vec![genesis_domain], PeersIds::new());
    let mut wsv = WorldStateView::new(world, Kura::blank_kura_for_testing());

    wsv.config.wasm_runtime_config.fuel_limit = u64::MAX;
    wsv.config.wasm_runtime_config.max_memory = u32::MAX;
    wsv.config.ident_length_limits = LengthLimits::new(0, u32::MAX);
    wsv.config.asset_definition_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);
    wsv.config.asset_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);
    wsv.config.domain_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);
    wsv.config.account_metadata_limits = MetadataLimits::new(u32::MAX, u32::MAX);

    wsv
}

fn genesis_domain(genesis_public_key: PublicKey) -> Domain {
    let mut domain = Domain::new(GENESIS_DOMAIN_ID.clone())
        .build(&GENESIS_ACCOUNT_ID);
    let genesis_account = Account::new(GENESIS_ACCOUNT_ID.clone(), [genesis_public_key])
        .build(&GENESIS_ACCOUNT_ID);
    domain.accounts.insert(GENESIS_ACCOUNT_ID.clone(), genesis_account);
    domain
}

fn squash(path: &str) -> anyhow::Result<String> {
    let (wsv, contracts) = read_store(path)?;

    let instructions = collect_roles(&wsv)
        .chain(collect_domains(&wsv))
        .chain(collect_triggers(&wsv, &contracts));

    let mut genesis = RawGenesisBlockBuilder::default()
        .executor(ExecutorMode::Path(ExecutorPath("/test.wasm".parse().unwrap())))
        .build();

    for instruction in instructions {
        genesis
            .first_transaction_mut()
            .unwrap()
            .append_instruction(instruction);
    }

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
