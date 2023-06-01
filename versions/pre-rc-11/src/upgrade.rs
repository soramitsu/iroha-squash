use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::str::FromStr;
use std::time::Duration;

use base64::Engine;
use from::HasMetadata as _;
use from::Identifiable as _;
use from::Registrable as _;
use from_data_model as from;
use iroha_data_model as to;

use iroha_squash_macros::{
    declare_upgrade, forward_enum_upgrade, impl_upgrade, trivial_enum_upgrade, trivial_upgrade,
};

declare_upgrade! {
    from_schema,
    iroha_schema
}

trivial_upgrade!(bool);
trivial_upgrade!(u32);
trivial_upgrade!(u64);
trivial_upgrade!(u128);
trivial_upgrade!(String);
trivial_upgrade!(Duration);

macro_rules! unobtainable {
    ($($seg:ident)::*) => {
        impl Upgrade for from::$($seg)::* {
            type To = to::$($seg)::*;

            fn upgrade(self) -> Self::To {
                unimplemented!()
            }
        }
    };
}

impl Upgrade for from_crypto::PublicKey {
    type To = iroha_crypto::PublicKey;

    fn upgrade(self) -> Self::To {
        format!("{}", self).parse().unwrap()
    }
}

impl Upgrade for from_crypto::Hash {
    type To = iroha_crypto::Hash;

    fn upgrade(self) -> Self::To {
        iroha_crypto::Hash::prehashed(self.into())
    }
}

impl_upgrade! {
    name::Name;
    |from: From| To::from_str(from.as_ref()).unwrap()
}

forward_enum_upgrade! {
    events::Event;
    Pipeline, Data, Time, ExecuteTrigger
}

impl_upgrade! {
    events::pipeline::Status;
    |from: From| {
        match from {
          From::Validating => To::Validating,
          From::Rejected(v) => To::Rejected(v.upgrade()),
          From::Committed => To::Committed,
        }
    }
}

impl_upgrade! {
    events::pipeline::Event;
    |from: From| {
        To {
            entity_kind: from.entity_kind.upgrade(),
            status: from.status.upgrade(),
            hash: from.hash.upgrade()
        }
    }
}

impl_upgrade! {
    events::execute_trigger::Event;
    |from: From| {
        To {
            trigger_id: from.trigger_id.upgrade(),
            authority: from.authority.upgrade()
        }
    }
}

impl_upgrade! {
    events::time::Interval;
    |from: From| {
        To {
            since: from.since.upgrade(),
            length: from.length.upgrade()
        }
    }
}

impl_upgrade! {
    events::time::Event;
    |from: From| {
        To {
            prev_interval: from.prev_interval.upgrade(),
            interval: from.interval.upgrade()
        }
    }
}

forward_enum_upgrade! {
    events::data::Event;
    Peer, Domain, Account, AssetDefinition,
    Asset, Trigger, Role, PermissionToken,
    PermissionValidator
}

forward_enum_upgrade! {
    Parameter;
    MaximumFaultyPeersAmount, BlockTime, CommitTime, TransactionReceiptTime
}

impl_upgrade! {
    permission::token::Token;
    |from: From| To::new(from.definition_id().clone().upgrade())
        .with_params(from.params().map(|(name, value)| (name.clone().upgrade(), value.clone().upgrade())))
}

impl_upgrade! {
    domain::Id;
    |from: From| To::new(from.name.upgrade())
}

impl_upgrade! {
    account::Id;
    |from: From| To::new(from.name.upgrade(), from.domain_id.upgrade())
}

impl_upgrade! {
    asset::DefinitionId;
    |from: From| To::new(from.name.upgrade(), from.domain_id.upgrade())
}

impl_upgrade! {
    asset::Id;
    |from: From| To::new( from.definition_id.upgrade(), from.account_id.upgrade())
}

impl_upgrade! {
    peer::Id;
    |from: From| To::new(&from.address, &from.public_key.upgrade())
}

impl_upgrade! {
    trigger::Id;
    |from: From| {
        if let Some(domain_id) = from.domain_id {
            To::new(from.name.upgrade(), domain_id.upgrade())
        } else {
            format!("{}", from).parse().unwrap()
        }
    }
}

impl_upgrade! {
    role::Id;
    |from: From| To::new(from.name.upgrade())
}

impl_upgrade! {
    permission::validator::Id;
    |from: From| To::new(from.name.upgrade(), from.account_id.upgrade())
}

forward_enum_upgrade! {
    IdBox;
    DomainId, AccountId, AssetDefinitionId, AssetId,
    PeerId, TriggerId, RoleId, PermissionTokenDefinitionId, ValidatorId
}

impl_upgrade! {
    block_value::BlockHeaderValue;
    |from: From| {
        To {
            timestamp: from.timestamp,
            height: from.height,
            previous_block_hash: from.previous_block_hash.upgrade(),
            transactions_hash: from.transactions_hash.upgrade().typed(),
            rejected_transactions_hash: from.rejected_transactions_hash.upgrade().typed(),
            invalidated_blocks_hashes: from.invalidated_blocks_hashes.upgrade(),
            current_block_hash: from.current_block_hash.upgrade()
        }
    }
}

impl_upgrade! {
    transaction::Payload;
    |from: From| {
        To {
            account_id: from.account_id.upgrade(),
            instructions: from.instructions.upgrade(),
            creation_time: from.creation_time.upgrade(),
            time_to_live_ms: from.time_to_live_ms.upgrade(),
            nonce: from.nonce.upgrade(),
            metadata: from.metadata.upgrade()
        }
    }
}

impl<T> Upgrade for from_crypto::SignatureOf<T>
where
    T: Upgrade,
{
    type To = iroha_crypto::SignatureOf<T::To>;

    fn upgrade(self) -> Self::To {
        serde_json::from_value(serde_json::to_value(self).unwrap()).unwrap()
    }
}

impl<T> Upgrade for from_crypto::SignaturesOf<T>
where
    T: Upgrade,
{
    type To = iroha_crypto::SignaturesOf<T::To>;

    fn upgrade(self) -> Self::To {
        let signatures: BTreeSet<_> = self.iter().cloned().map(Upgrade::upgrade).collect();
        signatures.try_into().unwrap()
    }
}

trivial_enum_upgrade! {
    transaction::BlockRejectionReason;
    ConsensusBlockRejection
}

impl_upgrade! {
    transaction::NotPermittedFail;
    |from: From| {
        To { reason: from.reason.upgrade() }
    }
}

impl_upgrade! {
    transaction::InstructionExecutionFail;
    |from: From| {
        To {
            reason:from.reason.upgrade(),
            instruction: from.instruction.upgrade()
        }
    }
}

impl_upgrade! {
    transaction::WasmExecutionFail;
    |from: From| {
        To {
            reason:from.reason.upgrade(),
        }
    }
}

impl_upgrade! {
    transaction::UnsatisfiedSignatureConditionFail;
    |from: From| {
        To { reason: from.reason.upgrade() }
    }
}

impl_upgrade! {
    transaction::TransactionLimitError;
    |from: From| {
        serde_json::from_value(
            serde_json::to_value(from).unwrap()
        ).unwrap()
    }
}

impl_upgrade! {
    transaction::TransactionRejectionReason;
    |from: From| {
        match from {
          From::NotPermitted(v) => To::NotPermitted(v.upgrade()),
          From::UnsatisfiedSignatureCondition(v) => To::UnsatisfiedSignatureCondition(v.upgrade()),
          From::LimitCheck(v) => To::LimitCheck(v.upgrade()),
          From::InstructionExecution(v) => To::InstructionExecution(v.upgrade()),
          From::WasmExecution(v) => To::WasmExecution(v.upgrade()),
          From::UnexpectedGenesisAccountSignature => To::UnexpectedGenesisAccountSignature,
        }
    }
}

forward_enum_upgrade! {
    transaction::RejectionReason;
    Block, Transaction
}

impl_upgrade! {
    transaction::RejectedTransaction;
    |from: From| {
        To {
            payload: from.payload.upgrade(),
            signatures: from.signatures.upgrade(),
            rejection_reason: from.rejection_reason.upgrade()
        }
    }
}

impl_upgrade! {
    transaction::ValidTransaction;
    |from: From| {
        To {
            payload: from.payload.upgrade(),
            signatures: from.signatures.upgrade()
        }
    }
}

forward_enum_upgrade! {
    transaction::VersionedValidTransaction;
    V1
}

forward_enum_upgrade! {
    transaction::VersionedRejectedTransaction;
    V1
}

impl_upgrade! {
    block_value::BlockValue;
    |from: From| {
        To {
            header: from.header.upgrade(),
            transactions: from.transactions.upgrade(),
            rejected_transactions: from.rejected_transactions.upgrade(),
            event_recommendations: from.event_recommendations.upgrade()
        }
    }
}

// TODO:
unobtainable!(account::Account);
unobtainable!(asset::AssetDefinition);
unobtainable!(asset::Asset);
unobtainable!(role::Role);
unobtainable!(domain::Domain);

fn contract_hash(
    contract: from::transaction::WasmSmartContract,
) -> to::transaction::WasmSmartContract {
    let hash = sha256::digest(contract.raw_data.as_slice());
    let magic_bytes = base64::engine::general_purpose::STANDARD
        .decode(format!("NEEDSREBUILD++{}++", hash))
        .unwrap();
    to::transaction::WasmSmartContract {
        raw_data: magic_bytes,
    }
}

impl_upgrade! {
    permission::Validator;
    |from: From| {
        let id = format!("{}", from).parse().unwrap();
        let typ = match from.validator_type() {
            from::permission::validator::Type::Transaction => to::permission::validator::Type::Transaction,
            from::permission::validator::Type::Query => to::permission::validator::Type::Query,
            from::permission::validator::Type::Expression => to::permission::validator::Type::Expression,
            from::permission::validator::Type::Instruction => to::permission::validator::Type::Instruction,
        };
        To::new(id, typ, contract_hash(from.wasm().clone()))
    }
}

impl_upgrade! {
    metadata::Metadata;
    |from: From| {
        let mut new = To::new();
        for (name, value) in from.iter() {
          new.insert_with_limits(
              name.clone().upgrade(),
              value.clone().upgrade(),
              to::metadata::Limits::new(u32::MAX, u32::MAX)
          );
        }
        new
    }
}

impl_upgrade! {
    account::NewAccount;
    |from: From| {
        let acct = from.build();
        to::account::Account::new(
            acct.id().clone().upgrade(),
            acct.signatories().cloned().map(Upgrade::upgrade)
        )
        .with_metadata(acct.metadata().clone().upgrade())
    }
}

impl_upgrade! {
    role::NewRole;
    |from: From| {
        let mut new = to::role::Role::new(from.id().clone().upgrade());
        for permission in from.build().permissions() {
            new = new.add_permission(permission.clone().upgrade());
        }
        new
    }
}

impl_upgrade! {
    domain::NewDomain;
    |from: From| {
        let from = from.build();
        let mut new = to::domain::Domain::new(from.id().clone().upgrade())
            .with_metadata(from.metadata().clone().upgrade());
        if let Some(logo) = from.logo() {
            new = new.with_logo(logo.as_ref().parse().unwrap())
        }
        new
    }
}

impl_upgrade! {
    peer::Peer;
    |from: From| {
        To::new(from.id().clone().upgrade())
    }
}

impl_upgrade! {
    permission::token::Definition;
    |from: From| {
        To::new(from.id().clone().upgrade())
            .with_params(from.params().map(|(k, v)| (k.clone().upgrade(), v.upgrade())))
    }
}

impl_upgrade! {
    ValueKind;
    |from: From| {
        match from {
          From::U32 | From::U128 | From::Fixed => To::Numeric,
          From::Bool => To::Bool,
          From::String => To::String,
          From::Name => To::Name,
          From::Vec => To::Vec,
          From::LimitedMetadata => To::LimitedMetadata,
          From::Id => To::Id,
          From::Identifiable => To::Identifiable,
          From::PublicKey => To::PublicKey,
          From::Parameter => To::Parameter,
          From::SignatureCheckCondition => To::SignatureCheckCondition,
          From::TransactionValue => To::TransactionValue,
          From::TransactionQueryResult => To::TransactionQueryResult,
          From::PermissionToken => To::PermissionToken,
          From::Hash => To::Hash,
          From::Block => To::Block,
          From::BlockHeader => To::BlockHeader,
          From::Ipv4Addr => To::Ipv4Addr,
          From::Ipv6Addr => To::Ipv6Addr,
        }
    }
}

impl_upgrade! {
    permission::token::Id;
    |from: From| {
        To::new(format!("{}", from).parse().unwrap())
    }
}

impl_upgrade! {
    asset::AssetValueType;
    |from: From| {
        match from {
            From::Quantity => To::Quantity,
            From::BigQuantity => To::BigQuantity,
            From::Fixed => To::Fixed,
            From::Store => To::Store
        }
    }
}

impl_upgrade! {
    asset::NewAssetDefinition;
    |from: From| {
        let from = from.build();
        let mut new = to::asset::AssetDefinition::new(
            from.id().clone().upgrade(),
            from.value_type().upgrade()
        );
        if matches!(from.mintable(), from::asset::Mintable::Once) {
            new = new.mintable_once();
        }
        new
    }
}

impl_upgrade! {
    transaction::Executable;
    |from: From| {
        match from {
          From::Instructions(isi) => To::Instructions(isi.upgrade()),
          From::Wasm(contract) => To::Wasm(contract_hash(contract)),
        }
    }
}

impl_upgrade! {
    trigger::action::Repeats;
    |from: From| {
        match from {
          From::Indefinitely => To::Indefinitely,
          From::Exactly(v) => To::Exactly(v.get().into()),
        }
    }
}

trivial_enum_upgrade! {
    events::pipeline::EntityKind;
    Block, Transaction
}

trivial_enum_upgrade! {
    events::pipeline::StatusKind;
    Committed, Validating, Rejected
}

forward_enum_upgrade! {
    events::FilterBox;
    Pipeline, Data, Time, ExecuteTrigger
}

impl_upgrade! {
    events::execute_trigger::EventFilter;
    |from: From| {
        serde_json::from_value(
            serde_json::to_value(from).unwrap()
        ).unwrap()
    }
}

impl_upgrade! {
    events::time::Schedule;
    |from: From| {
        To {
          start: from.start.upgrade(),
          period: from.period.upgrade()
        }
    }
}

impl_upgrade! {
    events::time::prelude::ExecutionTime;
    |from: From| {
        match from {
            From::PreCommit => To::PreCommit,
            From::Schedule(v) => To::Schedule(v.upgrade()),
        }
    }
}

impl_upgrade! {
    events::time::prelude::TimeEventFilter;
    |from: From| {
        to::events::time::prelude::TimeEventFilter(from.0.upgrade())
    }
}

forward_enum_upgrade! {
    events::data::prelude::DataEntityFilter;
    ByPeer, ByRole, ByAsset, ByDomain,
    ByAccount, ByTrigger, ByAssetDefinition
}

impl<F> Upgrade for from::events::data::prelude::FilterOpt<F>
where
    F: from::events::Filter + Upgrade,
    F::To: to::events::Filter,
{
    type To = to::events::data::prelude::FilterOpt<F::To>;

    fn upgrade(self) -> Self::To {
        match self {
            Self::AcceptAll => Self::To::AcceptAll,
            Self::BySome(v) => Self::To::BySome(v.upgrade()),
        }
    }
}

impl_upgrade! {
    events::pipeline::EventFilter;
    |from: From| {
        To {
          entity_kind: from.entity_kind.upgrade(),
          status_kind: from.status_kind.upgrade(),
          hash: from.hash.upgrade()
        }
    }
}

impl Upgrade for from::trigger::action::Action<from::events::FilterBox> {
    type To = to::trigger::action::Action<to::events::FilterBox>;

    fn upgrade(self) -> Self::To {
        Self::To::new(
            self.executable.upgrade(),
            self.repeats.upgrade(),
            self.technical_account.upgrade(),
            self.filter.upgrade(),
        )
        .with_metadata(self.metadata.upgrade())
    }
}

impl Upgrade for from::trigger::Trigger<from::events::FilterBox> {
    type To = to::trigger::Trigger<to::events::FilterBox>;

    fn upgrade(self) -> Self::To {
        Self::To::new(self.id().clone().upgrade(), self.action.upgrade())
    }
}

forward_enum_upgrade! {
    IdentifiableBox;
    Account, Asset, AssetDefinition, Domain, NewAccount, NewAssetDefinition,
    NewDomain, NewRole, Peer, PermissionTokenDefinition, Role, Trigger, Validator
}

forward_enum_upgrade! {
    expression::Expression;
    Add, Subtract, Multiply, Divide, Mod, RaiseTo, Greater,
    Less, Equal, Not, And, Or, If, Raw, Query, Contains, ContainsAll,
    ContainsAny, Where, ContextValue
}

impl_upgrade! {
    expression::Add;
    |from: From| {
        let left = from.left.upgrade().expression;
        let right = from.right.upgrade().expression;
        To::new(
            to::expression::EvaluatesTo::new_unchecked(left),
            to::expression::EvaluatesTo::new_unchecked(right),
        )
    }
}

impl_upgrade! {
    expression::Subtract;
    |from: From| {
        let left = from.left.upgrade().expression;
        let right = from.right.upgrade().expression;
        To::new(
            to::expression::EvaluatesTo::new_unchecked(left),
            to::expression::EvaluatesTo::new_unchecked(right),
        )
    }
}

impl_upgrade! {
    expression::Multiply;
    |from: From| {
        let left = from.left.upgrade().expression;
        let right = from.right.upgrade().expression;
        To::new(
            to::expression::EvaluatesTo::new_unchecked(left),
            to::expression::EvaluatesTo::new_unchecked(right),
        )
    }
}

impl_upgrade! {
    expression::Divide;
    |from: From| {
        let left = from.left.upgrade().expression;
        let right = from.right.upgrade().expression;
        To::new(
            to::expression::EvaluatesTo::new_unchecked(left),
            to::expression::EvaluatesTo::new_unchecked(right),
        )
    }
}

impl_upgrade! {
    expression::Greater;
    |from: From| {
        let left = from.left.upgrade().expression;
        let right = from.right.upgrade().expression;
        To::new(
            to::expression::EvaluatesTo::new_unchecked(left),
            to::expression::EvaluatesTo::new_unchecked(right),
        )
    }
}

impl_upgrade! {
    expression::Less;
    |from: From| {
        let left = from.left.upgrade().expression;
        let right = from.right.upgrade().expression;
        To::new(
            to::expression::EvaluatesTo::new_unchecked(left),
            to::expression::EvaluatesTo::new_unchecked(right),
        )
    }
}

impl_upgrade! {
    expression::RaiseTo;
    |from: From| {
        let left = from.left.upgrade().expression;
        let right = from.right.upgrade().expression;
        To::new(
            to::expression::EvaluatesTo::new_unchecked(left),
            to::expression::EvaluatesTo::new_unchecked(right),
        )
    }
}

impl_upgrade! {
    expression::Mod;
    |from: From| {
        let left = from.left.upgrade().expression;
        let right = from.right.upgrade().expression;
        To::new(
            to::expression::EvaluatesTo::new_unchecked(left),
            to::expression::EvaluatesTo::new_unchecked(right),
        )
    }
}

impl_upgrade! {
    expression::If;
    |from: From| {
        To::new(from.condition.upgrade(), from.then_expression.upgrade(), from.else_expression.upgrade())
    }
}

impl_upgrade! {
    expression::Contains;
    |from: From| {
        To::new(from.collection.upgrade(), from.element.upgrade())
    }
}

impl_upgrade! {
    expression::Equal;
    |from: From| {
        To::new(from.left.upgrade(), from.right.upgrade())
    }
}

impl_upgrade! {
    expression::ContainsAny;
    |from: From| {
        To::new(from.collection.upgrade(), from.elements.upgrade())
    }
}

impl_upgrade! {
    expression::Not;
    |from: From| {
        To::new(from.expression.upgrade())
    }
}

impl_upgrade! {
    expression::And;
    |from: From| {
        To::new(from.left.upgrade(), from.right.upgrade())
    }
}

impl_upgrade! {
    expression::Or;
    |from: From| {
        To::new(from.left.upgrade(), from.right.upgrade())
    }
}

impl_upgrade! {
    expression::Where;
    |from: From| {
        let values = from.values.into_iter()
            .map(|(k, v)| (k.parse().unwrap(), v.upgrade()))
            .collect();
        To::new(from.expression.upgrade(), values)
    }
}

impl_upgrade! {
    expression::ContextValue;
    |from: From| {
        To::new(from.value_name.parse().unwrap())
    }
}

impl_upgrade! {
    expression::ContainsAll;
    |from: From| {
        To::new(from.collection.upgrade(), from.elements.upgrade())
    }
}

forward_enum_upgrade! {
    query::QueryBox;
    FindAllAccounts, FindAccountById, FindAccountKeyValueByIdAndKey, FindAccountsByName,
    FindAccountsByDomainId, FindAccountsWithAsset, FindAllAssets, FindAllAssetsDefinitions,
    FindAssetById, FindAssetDefinitionById, FindAssetsByName, FindAssetsByAccountId,
    FindAssetsByAssetDefinitionId, FindAssetsByDomainId, FindAssetsByDomainIdAndAssetDefinitionId,
    FindAssetQuantityById, FindAssetKeyValueByIdAndKey, FindAssetDefinitionKeyValueByIdAndKey,
    FindAllDomains, FindDomainById, FindDomainKeyValueByIdAndKey, FindAllPeers, FindAllBlocks,
    FindAllBlockHeaders, FindBlockHeaderByHash, FindAllTransactions, FindTransactionsByAccountId,
    FindTransactionByHash, FindPermissionTokensByAccountId, FindAllPermissionTokenDefinitions,
    FindAllActiveTriggerIds, FindTriggerById, FindTriggerKeyValueByIdAndKey, FindTriggersByDomainId,
    FindAllRoles, FindAllRoleIds, FindRoleByRoleId, FindRolesByAccountId
}

impl_upgrade! {
  query::prelude::FindAllAccounts;
  |from: From| {
    to::query::prelude::FindAllAccounts
  }
}

impl_upgrade! {
  query::prelude::FindAccountById;
  |from: From| {
      To::new(from.id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAccountKeyValueByIdAndKey;
  |from: From| {
      To::new(from.id.upgrade(), from.key.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAccountsByName;
  |from: From| {
      To::new(from.name.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAccountsByDomainId;
  |from: From| {
      To::new(from.domain_id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAccountsWithAsset;
  |from: From| {
      To::new(from.asset_definition_id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAllAssets;
  |from: From| {
    to::query::prelude::FindAllAssets
  }
}

impl_upgrade! {
  query::prelude::FindAllAssetsDefinitions;
  |from: From| {
    to::query::prelude::FindAllAssetsDefinitions
  }
}

impl_upgrade! {
  query::prelude::FindAssetById;
  |from: From| {
      To::new(from.id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAssetDefinitionById;
  |from: From| {
      To::new(from.id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAssetsByName;
  |from: From| {
      To::new(from.name.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAssetsByAccountId;
  |from: From| {
      To::new(from.account_id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAssetsByAssetDefinitionId;
  |from: From| {
      To::new(from.asset_definition_id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAssetsByDomainId;
  |from: From| {
      To::new(from.domain_id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAssetsByDomainIdAndAssetDefinitionId;
  |from: From| {
      To::new(from.domain_id.upgrade(), from.asset_definition_id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAssetQuantityById;
  |from: From| {
      To::new(from.id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAssetKeyValueByIdAndKey;
  |from: From| {
      To::new(from.id.upgrade(), from.key.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAssetDefinitionKeyValueByIdAndKey;
  |from: From| {
      To::new(from.id.upgrade(), from.key.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAllDomains;
  |from: From| {
      to::query::prelude::FindAllDomains
  }
}

impl_upgrade! {
  query::prelude::FindDomainById;
  |from: From| {
      To::new(from.id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindDomainKeyValueByIdAndKey;
  |from: From| {
      To::new(from.id.upgrade(), from.key.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAllPeers;
  |from: From| {
      to::query::prelude::FindAllPeers
  }
}

impl_upgrade! {
  query::prelude::FindAllBlocks;
  |from: From| {
      to::query::prelude::FindAllBlocks
  }
}

impl_upgrade! {
  query::prelude::FindAllBlockHeaders;
  |from: From| {
      to::query::prelude::FindAllBlockHeaders
  }
}

impl_upgrade! {
  query::prelude::FindBlockHeaderByHash;
  |from: From| {
      To { hash: from.hash.upgrade() }
  }
}

impl_upgrade! {
  query::prelude::FindAllTransactions;
  |from: From| {
    to::query::prelude::FindAllTransactions
  }
}

impl_upgrade! {
  query::prelude::FindTransactionsByAccountId;
  |from: From| {
      To { account_id: from.account_id.upgrade() }
  }
}

impl_upgrade! {
  query::prelude::FindTransactionByHash;
  |from: From| {
      To::new(from.hash.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindPermissionTokensByAccountId;
  |from: From| {
      To { id: from.id.upgrade() }
  }
}

impl_upgrade! {
  query::prelude::FindAllPermissionTokenDefinitions;
  |from: From| {
    to::query::prelude::FindAllPermissionTokenDefinitions
  }
}

impl_upgrade! {
  query::prelude::FindAllActiveTriggerIds;
  |from: From| {
      to::query::prelude::FindAllActiveTriggerIds
  }
}

impl_upgrade! {
  query::prelude::FindTriggerById;
  |from: From| {
      To { id: from.id.upgrade() }
  }
}

impl_upgrade! {
  query::prelude::FindTriggerKeyValueByIdAndKey;
  |from: From| {
      To {
          id: from.id.upgrade(),
          key: from.key.upgrade()
      }
  }
}

impl_upgrade! {
  query::prelude::FindTriggersByDomainId;
  |from: From| {
      To::new(from.domain_id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindAllRoles;
  |from: From| {
      To::new()
  }
}

impl_upgrade! {
  query::prelude::FindAllRoleIds;
  |from: From| {
      To::new()
  }
}

impl_upgrade! {
  query::prelude::FindRoleByRoleId;
  |from: From| {
      To::new(from.id.upgrade())
  }
}

impl_upgrade! {
  query::prelude::FindRolesByAccountId;
  |from: From| {
      To::new(from.id.upgrade())
  }
}

impl Upgrade for from::events::data::prelude::DomainEvent {
    type To = to::events::data::prelude::DomainEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Account(v) => Self::To::Account(v.upgrade()),
            Self::AssetDefinition(v) => Self::To::AssetDefinition(v.upgrade()),
            Self::Created(v) => Self::To::Created(v.upgrade()),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::MetadataInserted(v) => {
                Self::To::MetadataInserted(to::events::data::prelude::MetadataChanged {
                    target_id: v.upgrade(),
                    key: "_____UNKNOWN".parse().unwrap(),
                    value: Box::new(to::Value::Bool(false)),
                })
            }
            Self::MetadataRemoved(v) => {
                Self::To::MetadataRemoved(to::events::data::prelude::MetadataChanged {
                    target_id: v.upgrade(),
                    key: "_____UNKNOWN".parse().unwrap(),
                    value: Box::new(to::Value::Bool(false)),
                })
            }
            _ => unreachable!(),
        }
    }
}

impl Upgrade for from::events::data::prelude::AssetDefinitionEvent {
    type To = to::events::data::prelude::AssetDefinitionEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Created(v) => Self::To::Created(v.upgrade()),
            Self::MintabilityChanged(v) => Self::To::MintabilityChanged(v.upgrade()),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::MetadataInserted(v) => {
                Self::To::MetadataInserted(to::events::data::prelude::MetadataChanged {
                    target_id: v.upgrade(),
                    key: "_____UNKNOWN".parse().unwrap(),
                    value: Box::new(to::Value::Bool(false)),
                })
            }
            Self::MetadataRemoved(v) => {
                Self::To::MetadataRemoved(to::events::data::prelude::MetadataChanged {
                    target_id: v.upgrade(),
                    key: "_____UNKNOWN".parse().unwrap(),
                    value: Box::new(to::Value::Bool(false)),
                })
            }
            _ => unreachable!(),
        }
    }
}

impl Upgrade for from::events::data::prelude::PermissionValidatorEvent {
    type To = to::events::data::prelude::PermissionValidatorEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Added(v) => Self::To::Added(v.upgrade()),
            Self::Removed(v) => Self::To::Removed(v.upgrade()),
            _ => unreachable!(),
        }
    }
}

impl Upgrade for from::events::data::prelude::TriggerEvent {
    type To = to::events::data::prelude::TriggerEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Created(v) => Self::To::Created(v.upgrade()),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::Extended(v) => Self::To::Extended(
                to::events::data::prelude::TriggerNumberOfExecutionsChanged {
                    trigger_id: v.upgrade(),
                    by: u32::MAX,
                },
            ),
            Self::Extended(v) => Self::To::Shortened(
                to::events::data::prelude::TriggerNumberOfExecutionsChanged {
                    trigger_id: v.upgrade(),
                    by: u32::MAX,
                },
            ),
            _ => unreachable!(),
        }
    }
}

impl_upgrade! {
    events::data::prelude::PermissionRemoved;
    |from: From| {
        To {
            role_id: from.role_id.upgrade(),
            permission_definition_id: from.permission_definition_id.upgrade()
        }
    }
}

impl Upgrade for from::events::data::prelude::RoleEvent {
    type To = to::events::data::prelude::RoleEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Created(v) => Self::To::Created(v.upgrade()),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::PermissionRemoved(v) => Self::To::PermissionRemoved(v.upgrade()),
            _ => unreachable!(),
        }
    }
}

impl Upgrade for from::events::data::prelude::PermissionTokenEvent {
    type To = to::events::data::prelude::PermissionTokenEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::DefinitionCreated(v) => Self::To::DefinitionCreated(v.upgrade()),
            Self::DefinitionDeleted(v) => Self::To::DefinitionDeleted(v.upgrade()),
            _ => unreachable!(),
        }
    }
}

impl Upgrade for from::events::data::prelude::PeerEvent {
    type To = to::events::data::prelude::PeerEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Added(v) => Self::To::Added(v.upgrade()),
            Self::Removed(v) => Self::To::Removed(v.upgrade()),
            _ => unreachable!(),
        }
    }
}

impl Upgrade for from::events::data::prelude::AssetEvent {
    type To = to::events::data::prelude::AssetEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Created(v) => Self::To::Created(v.upgrade()),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::Added(v) => Self::To::Added(to::events::data::prelude::AssetChanged {
                asset_id: v.upgrade(),
                amount: to::asset::AssetValue::Quantity(u32::MAX),
            }),
            Self::Removed(v) => Self::To::Removed(to::events::data::prelude::AssetChanged {
                asset_id: v.upgrade(),
                amount: to::asset::AssetValue::Quantity(u32::MAX),
            }),
            Self::MetadataInserted(v) => {
                Self::To::MetadataInserted(to::events::data::prelude::MetadataChanged {
                    target_id: v.upgrade(),
                    key: "_____UNKNOWN".parse().unwrap(),
                    value: Box::new(to::Value::Bool(false)),
                })
            }
            Self::MetadataRemoved(v) => {
                Self::To::MetadataRemoved(to::events::data::prelude::MetadataChanged {
                    target_id: v.upgrade(),
                    key: "_____UNKNOWN".parse().unwrap(),
                    value: Box::new(to::Value::Bool(false)),
                })
            }
            _ => unreachable!(),
        }
    }
}

impl Upgrade for from::events::data::prelude::AccountEvent {
    type To = to::events::data::prelude::AccountEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Asset(v) => Self::To::Asset(v.upgrade()),
            Self::Created(v) => Self::To::Created(v.upgrade()),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::AuthenticationAdded(v) => Self::To::AuthenticationAdded(v.upgrade()),
            Self::AuthenticationRemoved(v) => Self::To::AuthenticationRemoved(v.upgrade()),
            Self::PermissionAdded(v) => {
                Self::To::PermissionAdded(to::events::data::prelude::AccountPermissionChanged {
                    account_id: v.upgrade(),
                    permission_id: "UNKNOWN".parse().unwrap(),
                })
            }
            Self::PermissionRemoved(v) => {
                Self::To::PermissionRemoved(to::events::data::prelude::AccountPermissionChanged {
                    account_id: v.upgrade(),
                    permission_id: "UNKNOWN".parse().unwrap(),
                })
            }

            Self::RoleRevoked(v) => {
                Self::To::RoleRevoked(to::events::data::prelude::AccountRoleChanged {
                    account_id: v.upgrade(),
                    role_id: "UNKNOWN".parse().unwrap(),
                })
            }

            Self::RoleGranted(v) => {
                Self::To::RoleGranted(to::events::data::prelude::AccountRoleChanged {
                    account_id: v.upgrade(),
                    role_id: "UNKNOWN".parse().unwrap(),
                })
            }
            Self::MetadataInserted(v) => {
                Self::To::MetadataInserted(to::events::data::prelude::MetadataChanged {
                    target_id: v.upgrade(),
                    key: "UNKNOWN".parse().unwrap(),
                    value: Box::new(to::Value::Bool(false)),
                })
            }
            Self::MetadataRemoved(v) => {
                Self::To::MetadataRemoved(to::events::data::prelude::MetadataChanged {
                    target_id: v.upgrade(),
                    key: "_____UNKNOWN".parse().unwrap(),
                    value: Box::new(to::Value::Bool(false)),
                })
            }
            _ => unreachable!(),
        }
    }
}

impl Upgrade for from::events::data::prelude::AccountEventFilter {
    type To = to::events::data::prelude::AccountEventFilter;

    fn upgrade(self) -> Self::To {
        match self {
            Self::ByCreated => Self::To::ByCreated,
            Self::ByDeleted => Self::To::ByDeleted,
            Self::ByAuthenticationAdded => Self::To::ByAuthenticationAdded,
            Self::ByAuthenticationRemoved => Self::To::ByAuthenticationRemoved,
            Self::ByPermissionAdded => Self::To::ByPermissionAdded,
            Self::ByPermissionRemoved => Self::To::ByPermissionRemoved,
            Self::ByRoleRevoked => Self::To::ByRoleRevoked,
            Self::ByRoleGranted => Self::To::ByRoleGranted,
            Self::ByMetadataInserted => Self::To::ByMetadataInserted,
            Self::ByMetadataRemoved => Self::To::ByMetadataRemoved,
            Self::ByAsset(v) => Self::To::ByAsset(v.upgrade()),
        }
    }
}

impl_upgrade! {
    events::data::prelude::AccountFilter;
    |from: From| {
        To::new(
            from.origin_filter().clone().upgrade(),
            from.event_filter().clone().upgrade()
        )
    }
}

impl_upgrade! {
    events::data::prelude::AssetDefinitionFilter;
    |from: From| {
        unimplemented!()
    }
}

impl_upgrade! {
    events::data::prelude::AssetFilter;
    |from: From| {
        unimplemented!()
    }
}

impl_upgrade! {
    events::data::prelude::DomainFilter;
    |from: From| {
        unimplemented!()
    }
}

impl<T> Upgrade for from::events::prelude::OriginFilter<T>
where
    T: Upgrade + from::prelude::HasOrigin,
    <T::Origin as from_data_model::Identifiable>::Id: Upgrade<To = <<<T as Upgrade>::To as iroha_core::tx::HasOrigin>::Origin as iroha_data_model::Identifiable>::Id>
        + std::fmt::Debug
        + Clone
        + Eq
        + Ord
        + std::hash::Hash
        + parity_scale_codec::Decode
        + parity_scale_codec::Encode
        + serde::Serialize
        + from_schema::IntoSchema,
    <T as Upgrade>::To: to::prelude::HasOrigin,
    <<<T as Upgrade>::To as to::prelude::HasOrigin>::Origin as to::Identifiable>::Id:
        std::fmt::Debug
            + Clone
            + Eq
            + Ord
            + std::hash::Hash
            + parity_scale_codec::Decode
            + parity_scale_codec::Encode
            + serde::Serialize
            + iroha_schema::IntoSchema,
{
    type To = to::events::prelude::OriginFilter<T::To>;

    fn upgrade(self) -> Self::To {
        Self::To::new(self.origin_id().clone().upgrade())
    }
}

impl_upgrade! {
    events::data::prelude::PeerFilter;
    |from: From| {
        unimplemented!()
    }
}

impl_upgrade! {
    events::data::prelude::RoleFilter;
    |from: From| {
        unimplemented!()
    }
}

impl_upgrade! {
    events::data::prelude::TriggerFilter;
    |from: From| {
        unimplemented!()
    }
}

impl_upgrade! {
    account::SignatureCheckCondition;
    |from: From| {
        to::account::SignatureCheckCondition(from.0.upgrade())
    }
}

impl_upgrade! {
    Value;
    |from: From| {
        match from {
            // Trivial conversions (essentialy no-ops)
            From::Bool(v) => To::Bool(v),
            From::String(v) => To::String(v),
            From::Ipv4Addr(v) => To::Ipv4Addr(iroha_primitives::addr::Ipv4Addr(v.0)),
            From::Ipv6Addr(v) => To::Ipv6Addr(iroha_primitives::addr::Ipv6Addr(v.0)),
            // Inherent upgrades
            From::U32(v) => To::Numeric(to::NumericValue::U32(v)),
            From::U128(v) => To::Numeric(to::NumericValue::U128(v)),
            From::Fixed(v) => To::Numeric(to::NumericValue::Fixed(f64::from(v).try_into().unwrap())),
            // Forwarded upgrades
            From::Hash(v) => To::Hash(v.upgrade()),
            From::Name(v) => To::Name(v.upgrade()),
            From::Vec(v) => To::Vec(v.into_iter().map(|vv| vv.upgrade()).collect()),
            From::PublicKey(v) => To::PublicKey(v.upgrade()),
            From::Parameter(v) => To::Parameter(v.upgrade()),
            From::PermissionToken(v) => To::PermissionToken(v.upgrade()),
            From::Id(v) => To::Id(v.upgrade()),
            From::Identifiable(v) => To::Identifiable(v.upgrade()),
            From::SignatureCheckCondition(v) => To::SignatureCheckCondition(v.upgrade()),
            From::LimitedMetadata(v) => To::LimitedMetadata(v.upgrade()),
            From::TransactionValue(_) => unimplemented!(),
            From::TransactionQueryResult(_) => unimplemented!(),
            From::Block(_) => unimplemented!(),
            From::BlockHeader(_) => unimplemented!(),
        }
    }
}

forward_enum_upgrade! {
    isi::Instruction;
    Register, Unregister, Mint, Burn, Transfer,
    If, Pair, Sequence, Fail, SetKeyValue, RemoveKeyValue,
    Grant, Revoke, ExecuteTrigger
}

impl_upgrade! {
    isi::Pair;
    |from: From| {
        To::new(from.left_instruction.upgrade(), from.right_instruction.upgrade())
    }
}

impl_upgrade! {
    isi::If;
    |from: From| {
        if let Some(otherwise) = from.otherwise {
            To::with_otherwise(from.condition.upgrade(), from.then.upgrade(), otherwise.upgrade())
        } else {
            To::new(from.condition.upgrade(), from.then.upgrade())
        }
    }
}

forward_enum_upgrade! {
    RegistrableBox;
    Peer, Domain, Account, AssetDefinition, Asset, Trigger,
    Role, PermissionTokenDefinition, Validator
}

impl_upgrade! {
    isi::RegisterBox;
    |from: From| {
        To::new(from.object.upgrade())
    }
}

impl_upgrade! {
    isi::UnregisterBox;
    |from: From| {
        To::new(from.object_id.upgrade())
    }
}

impl_upgrade! {
    isi::FailBox;
    |from: From| {
        To::new(&from.message)
    }
}

impl_upgrade! {
    isi::ExecuteTriggerBox;
    |from: From| {
        To::new(from.trigger_id.upgrade())
    }
}

impl_upgrade! {
    isi::RevokeBox;
    |from: From| {
        To::new(from.object.upgrade(), from.destination_id.upgrade())
    }
}

impl_upgrade! {
    isi::SetKeyValueBox;
    |from: From| {
        To::new(from.object_id.upgrade(), from.key.upgrade(), from.value.upgrade())
    }
}

impl_upgrade! {
    isi::RemoveKeyValueBox;
    |from: From| {
        To::new(from.object_id.upgrade(), from.key.upgrade())
    }
}

impl_upgrade! {
    isi::SequenceBox;
    |from: From| {
        To::new(from.instructions.upgrade())
    }
}

impl_upgrade! {
    isi::GrantBox;
    |from: From| {
        To::new(from.object.upgrade(), from.destination_id.upgrade())
    }
}

impl_upgrade! {
    isi::MintBox;
    |from: From| {
        To::new(from.object.upgrade(), from.destination_id.upgrade())
    }
}

impl_upgrade! {
    isi::BurnBox;
    |from: From| {
        To::new(from.object.upgrade(), from.destination_id.upgrade())
    }
}

impl_upgrade! {
    isi::TransferBox;
    |from: From| {
        To::new(from.source_id.upgrade(), from.object.upgrade(), from.destination_id.upgrade())
    }
}

impl<T> Upgrade for from::expression::EvaluatesTo<T>
where
    T: Upgrade + TryFrom<from::Value>,
    T::To: TryFrom<to::Value>,
{
    type To = to::expression::EvaluatesTo<T::To>;

    fn upgrade(self) -> Self::To {
        to::expression::EvaluatesTo::new_unchecked(self.expression.upgrade())
    }
}
