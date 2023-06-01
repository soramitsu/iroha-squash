use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Deref;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::time::Duration;

use base64::Engine;
use from::HasMetadata as _;
use from::Identifiable as _;
use from::Registrable as _;
use from_data_model as from;
use iroha_core::smartcontracts::Registrable;
use iroha_data_model as to;

use iroha_squash_macros::{
    declare_upgrade, forward_enum_upgrade, impl_upgrade, trivial_enum_upgrade, trivial_upgrade,
};

use crate::GENESIS;

declare_upgrade!(from_schema, iroha_schema);

trivial_upgrade!(bool);
trivial_upgrade!(u32);
trivial_upgrade!(u64);
trivial_upgrade!(u128);
trivial_upgrade!(String);
trivial_upgrade!(Duration);

impl Upgrade for from_primitives::fixed::Fixed {
    type To = iroha_primitives::fixed::Fixed;

    fn upgrade(self) -> Self::To {
        let float: f64 = self.into();
        Self::To::try_from(float).unwrap()
    }
}

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
    events::pipeline::PipelineStatus;
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
    events::pipeline::PipelineEvent;
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
    events::execute_trigger::ExecuteTriggerEvent;
    |from: From| {
        To {
            trigger_id: from.trigger_id.upgrade(),
            authority: from.authority.upgrade()
        }
    }
}

impl_upgrade! {
    events::time::Interval;
    events::time::TimeInterval;
    |from: From| {
        To {
            since: from.since.upgrade(),
            length: from.length.upgrade()
        }
    }
}

impl_upgrade! {
    events::time::Event;
    events::time::TimeEvent;
    |from: From| {
        To {
            prev_interval: from.prev_interval.upgrade(),
            interval: from.interval.upgrade()
        }
    }
}

impl_upgrade! {
    events::data::Event;
    events::data::DataEvent;
    |from: From| {
        match from {
            From::Configuration(v)=>To::Configuration(v.upgrade()),
            From::Peer(v) => To::Peer(v.upgrade()),
            From::Domain(v) => To::Domain(v.upgrade()),
            From::Account(v) => To::Account(v.upgrade()),
            From::AssetDefinition(v) => To::AssetDefinition(v.upgrade()),
            From::Asset(v) => To::Asset(v.upgrade()),
            From::Trigger(v) => To::Trigger(v.upgrade()),
            From::Role(v) => To::Role(v.upgrade()),
            From::PermissionToken(v) => To::PermissionToken(v.upgrade()),
            From::PermissionValidator(_) => To::Validator(to::events::data::prelude::ValidatorEvent::Upgraded),
        }
    }
}

// forward_enum_upgrade! {
//     events::data::Event;
//     events::data::DataEvent;
//     Peer, Domain, Account, AssetDefinition,
//     Asset, Trigger, Role, PermissionToken,
//     PermissionValidator
// }
//
impl_upgrade! {
    Id;
    parameter::ParameterId;
    |from: From| {
        To { name: from.name.upgrade() }
    }
}

impl_upgrade! {
    Parameter;
    parameter::Parameter;
    |from: From| {
        To::new(from.id().clone().upgrade(), from.val().clone().upgrade())
    }
}

//forward_enum_upgrade! {
//    Parameter;
//    MaximumFaultyPeersAmount, BlockTime, CommitTime, TransactionReceiptTime
//}

impl_upgrade! {
    permission::token::Token;
    permission::PermissionToken;
    |from: From| To::new(from.definition_id().clone().upgrade())
        .with_params(from.params().map(|(name, value)| (name.clone().upgrade(), value.clone().upgrade())))
}

impl_upgrade! {
    domain::Id;
    domain::DomainId;
    |from: From| To::new(from.name.upgrade())
}

impl_upgrade! {
    account::Id;
    account::AccountId;
    |from: From| To::new(from.name.upgrade(), from.domain_id.upgrade())
}

impl_upgrade! {
    asset::DefinitionId;
    asset::AssetDefinitionId;
    |from: From| To::new(from.name.upgrade(), from.domain_id.upgrade())
}

impl_upgrade! {
    asset::Id;
    asset::AssetId;
    |from: From| To::new( from.definition_id.upgrade(), from.account_id.upgrade())
}

impl_upgrade! {
    peer::Id;
    peer::PeerId;
    |from: From| {
        let address = from.address.parse().unwrap();
        To::new(&address, &from.public_key.upgrade())
    }
}

impl_upgrade! {
    trigger::Id;
    trigger::TriggerId;
    |from: From| {
        if let Some(domain_id) = from.domain_id {
            To::new(from.name.upgrade(), Some(domain_id.upgrade()))
        } else {
            To::new(from.name.upgrade(), None)
        }
    }
}

impl_upgrade! {
    role::Id;
    role::RoleId;
    |from: From| To::new(from.name.upgrade())
}

impl Upgrade for from::IdBox {
    type To = to::IdBox;
    fn upgrade(self) -> Self::To {
        match self {
            Self::DomainId(v) => Self::To::DomainId(v.upgrade()),
            Self::AccountId(v) => Self::To::AccountId(v.upgrade()),
            Self::AssetDefinitionId(v) => Self::To::AssetDefinitionId(v.upgrade()),
            Self::AssetId(v) => Self::To::AssetId(v.upgrade()),
            Self::PeerId(v) => Self::To::PeerId(v.upgrade()),
            Self::TriggerId(v) => Self::To::TriggerId(v.upgrade()),
            Self::RoleId(v) => Self::To::RoleId(v.upgrade()),
            Self::PermissionTokenDefinitionId(v) => {
                Self::To::PermissionTokenDefinitionId(v.upgrade())
            }
            Self::ParameterId(v) => Self::To::ParameterId(v.upgrade()),
            Self::ValidatorId(_) => unimplemented!(),
        }
    }
}

impl_upgrade! {
    block_value::BlockHeaderValue;
    block::BlockHeader;
    |from: From| {
        To {
            timestamp: from.timestamp,
            height: from.height,
            previous_block_hash: from.previous_block_hash.upgrade().map(|h| h.typed()),
            transactions_hash: from.transactions_hash
                .map(|h| h.deref().clone())
                .upgrade()
                .map(|h| h.typed()),
            rejected_transactions_hash: from.rejected_transactions_hash
                .map(|h| h.deref().clone())
                .upgrade()
                .map(|h| h.typed()),
            committed_with_topology: Vec::new(),
            consensus_estimation: 0,
            view_change_index: 0
        }
    }
}

impl_upgrade! {
    transaction::Payload;
    transaction::TransactionPayload;
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
    block::error::BlockRejectionReason;
    ConsensusBlockRejection
}

impl_upgrade! {
    transaction::NotPermittedFail;
    transaction::error::NotPermittedFail;
    |from: From| {
        To { reason: from.reason.upgrade() }
    }
}

impl_upgrade! {
    transaction::InstructionExecutionFail;
    transaction::error::InstructionExecutionFail;
    |from: From| {
        To {
            reason:from.reason.upgrade(),
            instruction: from.instruction.upgrade()
        }
    }
}

impl_upgrade! {
    transaction::WasmExecutionFail;
    transaction::error::WasmExecutionFail;
    |from: From| {
        To {
            reason:from.reason.upgrade(),
        }
    }
}

impl_upgrade! {
    transaction::UnsatisfiedSignatureConditionFail;
    transaction::error::UnsatisfiedSignatureConditionFail;
    |from: From| {
        To { reason: from.reason.upgrade() }
    }
}

impl_upgrade! {
    transaction::TransactionLimitError;
    transaction::error::TransactionLimitError;
    |from: From| {
        serde_json::from_value(
            serde_json::to_value(from).unwrap()
        ).unwrap()
    }
}

impl_upgrade! {
    transaction::TransactionRejectionReason;
    transaction::error::TransactionRejectionReason;
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
    events::pipeline::PipelineRejectionReason;
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
    block::CommittedBlock;
    |from: From| {
        let keys = iroha_crypto::KeyPair::generate().unwrap();
        let signatures = iroha_crypto::SignaturesOf::new(keys, &()).unwrap();
        To {
            header: from.header.upgrade(),
            transactions: from.transactions.upgrade(),
            rejected_transactions: from.rejected_transactions.upgrade(),
            event_recommendations: from.event_recommendations.upgrade(),
            signatures: signatures.transmute(),
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
    to::transaction::WasmSmartContract::from_compiled(magic_bytes)
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
          ).expect("u32::MAX shouldn't be possible to exceed");
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
    permission::PermissionTokenDefinition;
    |from: From| {
        To::new(from.id().clone().upgrade())
            .with_params(
                from.params()
                .map(|(k, v)| (k.clone().upgrade(), v.upgrade()))
            )
    }
}

impl_upgrade! {
    NumericValue;
    |from: From| {
        match from {
            From::U32(v) => To::U32(v),
            From::U64(v) => To::U64(v),
            From::U128(v) => To::U128(v),
            From::Fixed(v) => To::Fixed(v.upgrade()),
        }
    }
}

impl_upgrade! {
    ValueKind;
    |from: From| {
        match from {
          From::Numeric => To::Numeric,
          From::Bool => To::Bool,
          From::String => To::String,
          From::Name => To::Name,
          From::Vec => To::Vec,
          From::LimitedMetadata => To::LimitedMetadata,
          From::Id => To::Id,
          From::Identifiable => To::Identifiable,
          From::PublicKey => To::PublicKey,
          From::SignatureCheckCondition => To::SignatureCheckCondition,
          From::TransactionValue => To::TransactionValue,
          From::TransactionQueryResult => To::TransactionQueryResult,
          From::PermissionToken => To::PermissionToken,
          From::Hash => To::Hash,
          From::Block => To::Block,
          From::BlockHeader => To::BlockHeader,
          From::Ipv4Addr => To::Ipv4Addr,
          From::Ipv6Addr => To::Ipv6Addr,
          From::MetadataLimits => To::MetadataLimits,
          From::LengthLimits => To::LengthLimits,
          From::TransactionLimits => To::TransactionLimits
        }
    }
}

impl_upgrade! {
    permission::token::Id;
    permission::PermissionTokenId;
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
    events::pipeline::PipelineEntityKind;
    Block, Transaction
}

trivial_enum_upgrade! {
    events::pipeline::StatusKind;
    events::pipeline::PipelineStatusKind;
    Committed, Validating, Rejected
}

forward_enum_upgrade! {
    events::FilterBox;
    Pipeline, Data, Time, ExecuteTrigger
}

impl_upgrade! {
    events::execute_trigger::EventFilter;
    events::execute_trigger::ExecuteTriggerEventFilter;
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
        to::events::time::prelude::TimeEventFilter::new(from.0.upgrade())
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
    events::pipeline::PipelineEventFilter;
    |from: From| {
        let mut to = To::new();
        if let Some(entity_kind) = from.entity_kind.upgrade() {
            to = to.entity_kind(entity_kind)
        }
        if let Some(status_kind) = from.status_kind.upgrade() {
            to = to.status_kind(status_kind)
        }
        if let Some(hash) = from.hash.upgrade() {
            to = to.hash(hash)
        }
        to
    }
}

impl Upgrade for from::trigger::action::Action<from::events::FilterBox> {
    type To = to::trigger::action::Action<to::events::FilterBox, to::transaction::Executable>;

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
    type To = to::trigger::Trigger<to::events::FilterBox, to::transaction::Executable>;

    fn upgrade(self) -> Self::To {
        Self::To::new(self.id().clone().upgrade(), self.action.upgrade())
    }
}

impl Upgrade for from::IdentifiableBox {
    type To = to::IdentifiableBox;
    fn upgrade(self) -> Self::To {
        match self {
            Self::Account(v) => Self::To::Account(v.upgrade()),
            Self::Asset(v) => Self::To::Asset(v.upgrade()),
            Self::AssetDefinition(v) => Self::To::AssetDefinition(v.upgrade()),
            Self::Domain(v) => Self::To::Domain(v.upgrade()),
            Self::NewAccount(v) => Self::To::NewAccount(v.upgrade()),
            Self::NewAssetDefinition(v) => Self::To::NewAssetDefinition(v.upgrade()),
            Self::NewDomain(v) => Self::To::NewDomain(v.upgrade()),
            Self::NewRole(v) => Self::To::NewRole(v.upgrade()),
            Self::Peer(v) => Self::To::Peer(v.upgrade()),
            Self::PermissionTokenDefinition(v) => Self::To::PermissionTokenDefinition(v.upgrade()),
            Self::Role(v) => Self::To::Role(v.upgrade()),
            Self::Trigger(v) => Self::To::Trigger(to::TriggerBox::Raw(*v.upgrade())),
            Self::Parameter(v) => Self::To::Parameter(v.upgrade()),
            Self::Validator(_) => unimplemented!(),
        }
    }
}

impl Upgrade for from::expression::Expression {
    type To = to::expression::Expression;
    fn upgrade(self) -> Self::To {
        match self {
            Self::Add(v) => Self::To::Add(v.upgrade()),
            Self::Subtract(v) => Self::To::Subtract(v.upgrade()),
            Self::Multiply(v) => Self::To::Multiply(v.upgrade()),
            Self::Divide(v) => Self::To::Divide(v.upgrade()),
            Self::Mod(v) => Self::To::Mod(v.upgrade()),
            Self::RaiseTo(v) => Self::To::RaiseTo(v.upgrade()),
            Self::Greater(v) => Self::To::Greater(v.upgrade()),
            Self::Less(v) => Self::To::Less(v.upgrade()),
            Self::Equal(v) => Self::To::Equal(v.upgrade()),
            Self::Not(v) => Self::To::Not(v.upgrade()),
            Self::And(v) => Self::To::And(v.upgrade()),
            Self::Or(v) => Self::To::Or(v.upgrade()),
            Self::If(v) => Self::To::If(v.upgrade()),
            Self::Raw(v) => Self::To::Raw(*v.upgrade()),
            Self::Query(v) => Self::To::Query(v.upgrade()),
            Self::Contains(v) => Self::To::Contains(v.upgrade()),
            Self::ContainsAll(v) => Self::To::ContainsAll(v.upgrade()),
            Self::ContainsAny(v) => Self::To::ContainsAny(v.upgrade()),
            Self::Where(v) => Self::To::Where(v.upgrade()),
            Self::ContextValue(v) => Self::To::ContextValue(v.upgrade()),
        }
    }
}

impl_upgrade! {
    expression::Add;
    |from: From| {
        To::new(
            from.left.upgrade(),
            from.right.upgrade(),
        )
    }
}

impl_upgrade! {
    expression::Subtract;
    |from: From| {
        To::new(
            from.left.upgrade(),
            from.right.upgrade(),
        )
    }
}

impl_upgrade! {
    expression::Multiply;
    |from: From| {
        To::new(
            from.left.upgrade(),
            from.right.upgrade(),
        )
    }
}

impl_upgrade! {
    expression::Divide;
    |from: From| {
        To::new(
          from.left.upgrade(),
          from.right.upgrade(),
        )
    }
}

impl_upgrade! {
    expression::Greater;
    |from: From| {
        To::new(
            from.left.upgrade(),
            from.right.upgrade(),
        )
    }
}

impl_upgrade! {
    expression::Less;
    |from: From| {
        To::new(
            from.left.upgrade(),
            from.right.upgrade(),
        )
    }
}

impl_upgrade! {
    expression::RaiseTo;
    |from: From| {
        To::new(
            from.left.upgrade(),
            from.right.upgrade(),
        )
    }
}

impl_upgrade! {
    expression::Mod;
    |from: From| {
        To::new(
        from.left.upgrade(),
        from.right.upgrade(),
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
        let mut to = To::new(from.expression.upgrade());
        for (k, v) in from.values.into_iter() {
            to = to.with_value(k.upgrade(), v.upgrade())
        }
        to
    }
}

impl_upgrade! {
    expression::ContextValue;
    |from: From| {
        To::new(from.value_name.upgrade())
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
    FindAllRoles, FindAllRoleIds, FindRoleByRoleId, FindRolesByAccountId, FindTotalAssetQuantityByAssetDefinitionId, FindAllParameters
}

impl_upgrade! {
  query::prelude::FindTotalAssetQuantityByAssetDefinitionId;
  |from: From| {
      To {
          id: from.id.upgrade()
      }
  }
}

impl_upgrade! {
  query::prelude::FindAllParameters;
  |_from: From| {
    to::query::prelude::FindAllParameters
  }
}

impl_upgrade! {
  query::prelude::FindAllAccounts;
  |_from: From| {
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
  |_from: From| {
    to::query::prelude::FindAllAssets
  }
}

impl_upgrade! {
  query::prelude::FindAllAssetsDefinitions;
  |_from: From| {
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
  |_from: From| {
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
  |_from: From| {
      to::query::prelude::FindAllPeers
  }
}

impl_upgrade! {
  query::prelude::FindAllBlocks;
  |_from: From| {
      to::query::prelude::FindAllBlocks
  }
}

impl_upgrade! {
  query::prelude::FindAllBlockHeaders;
  |_from: From| {
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
  |_from: From| {
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
  |_from: From| {
    to::query::prelude::FindAllPermissionTokenDefinitions
  }
}

impl_upgrade! {
  query::prelude::FindAllActiveTriggerIds;
  |_from: From| {
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
  |_from: From| {
      to::query::prelude::FindAllRoles
  }
}

impl_upgrade! {
  query::prelude::FindAllRoleIds;
  |_from: From| {
      to::query::prelude::FindAllRoleIds
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
            Self::Created(v) => Self::To::Created(v.upgrade().build(&GENESIS)),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::MetadataInserted(v) => Self::To::MetadataInserted(v.upgrade()),
            Self::MetadataRemoved(v) => Self::To::MetadataRemoved(v.upgrade()),
            _ => unreachable!(),
        }
    }
}

impl Upgrade for from::events::data::prelude::AssetDefinitionEvent {
    type To = to::events::data::prelude::AssetDefinitionEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Created(v) => Self::To::Created(v.upgrade().build(&GENESIS)),
            Self::MintabilityChanged(v) => Self::To::MintabilityChanged(v.upgrade()),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::MetadataInserted(v) => Self::To::MetadataInserted(v.upgrade()),
            Self::MetadataRemoved(v) => Self::To::MetadataInserted(v.upgrade()),
            _ => unreachable!(),
        }
    }
}

impl_upgrade! {
    events::data::prelude::TriggerNumberOfExecutionsChanged;
    |from: From| {
        To {
            by: from.by.upgrade(),
            trigger_id: from.trigger_id.upgrade()
        }
    }
}

impl Upgrade for from::events::data::prelude::TriggerEvent {
    type To = to::events::data::prelude::TriggerEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Created(v) => Self::To::Created(v.upgrade()),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::Extended(v) => Self::To::Extended(v.upgrade()),
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

impl Upgrade for from::events::data::prelude::ConfigurationEvent {
    type To = to::events::data::prelude::ConfigurationEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Changed(v) => Self::To::Changed(v.upgrade()),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::Created(v) => Self::To::Created(v.upgrade()),
            _ => unreachable!(),
        }
    }
}

impl Upgrade for from::events::data::prelude::RoleEvent {
    type To = to::events::data::prelude::RoleEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Created(v) => Self::To::Created(v.upgrade().build(&GENESIS)),
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

forward_enum_upgrade! {
    asset::AssetValue;
    Quantity, BigQuantity, Fixed, Store
}

impl_upgrade! {
    events::data::prelude::AssetChanged;
    |from: From| {
        To {
            asset_id: from.asset_id.upgrade(),
            amount: from.amount.upgrade(),
        }
    }
}

impl Upgrade for from::events::data::prelude::AssetEvent {
    type To = to::events::data::prelude::AssetEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Created(v) => Self::To::Created(v.upgrade()),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::Added(v) => Self::To::Added(v.upgrade()),
            Self::Removed(v) => Self::To::Removed(v.upgrade()),
            Self::MetadataInserted(v) => Self::To::MetadataInserted(v.upgrade()),
            Self::MetadataRemoved(v) => Self::To::MetadataRemoved(v.upgrade()),
            _ => unreachable!(),
        }
    }
}

impl_upgrade! {
    events::data::prelude::AccountPermissionChanged;
    |from: From| {
        To {
            account_id: from.account_id.upgrade(),
            permission_id: from.permission_id.upgrade(),
        }
    }
}

impl<T: Upgrade> Upgrade for from::events::data::prelude::MetadataChanged<T> {
    type To = to::events::data::prelude::MetadataChanged<T::To>;

    fn upgrade(self) -> Self::To {
        Self::To {
            target_id: self.target_id.upgrade(),
            key: self.key.upgrade(),
            value: self.value.upgrade(),
        }
    }
}

impl_upgrade! {
    events::data::prelude::AccountRoleChanged;
    |from: From| {
        To {
            account_id: from.account_id.upgrade(),
            role_id: from.role_id.upgrade()
        }
    }
}

impl Upgrade for from::events::data::prelude::AccountEvent {
    type To = to::events::data::prelude::AccountEvent;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Asset(v) => Self::To::Asset(v.upgrade()),
            Self::Created(v) => Self::To::Created(v.upgrade().build(&GENESIS)),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::AuthenticationAdded(v) => Self::To::AuthenticationAdded(v.upgrade()),
            Self::AuthenticationRemoved(v) => Self::To::AuthenticationRemoved(v.upgrade()),
            Self::PermissionAdded(v) => Self::To::PermissionAdded(v.upgrade()),
            Self::PermissionRemoved(v) => Self::To::PermissionRemoved(v.upgrade()),

            Self::RoleRevoked(v) => Self::To::RoleRevoked(v.upgrade()),
            Self::RoleGranted(v) => Self::To::RoleGranted(v.upgrade()),
            Self::MetadataInserted(v) => Self::To::MetadataInserted(v.upgrade()),
            Self::MetadataRemoved(v) => Self::To::MetadataRemoved(v.upgrade()),
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
    |_from: From| {
        unimplemented!()
    }
}

impl_upgrade! {
    events::data::prelude::AssetFilter;
    |_from: From| {
        unimplemented!()
    }
}

impl_upgrade! {
    events::data::prelude::DomainFilter;
    |_from: From| {
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
    |_from: From| {
        unimplemented!()
    }
}

impl_upgrade! {
    events::data::prelude::RoleFilter;
    |_from: From| {
        unimplemented!()
    }
}

impl_upgrade! {
    events::data::prelude::TriggerFilter;
    |_from: From| {
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
    metadata::Limits;
    |from: From| {
        To {
            max_len: from.max_len.upgrade(),
            max_entry_byte_size: from.max_entry_byte_size.upgrade()
        }
    }
}

impl_upgrade! {
    transaction::TransactionLimits;
    |from: From| {
        To {
            max_instruction_number: from.max_instruction_number.upgrade(),
            max_wasm_size_bytes: from.max_wasm_size_bytes.upgrade()
        }
    }
}

impl_upgrade! {
    LengthLimits;
    |from: From| {
        let range: RangeInclusive<usize> = from.into();
        To::new(*range.start() as u32, *range.end() as u32)
    }
}

impl_upgrade! {
    Value;
    |from: From| {
        match from {
            // Trivial conversions (essentialy no-ops)
            From::Bool(v) => To::Bool(v),
            From::String(v) => To::String(v),
            From::Ipv4Addr(v) => To::Ipv4Addr(iroha_primitives::addr::Ipv4Addr::new(v.0)),
            From::Ipv6Addr(v) => To::Ipv6Addr(iroha_primitives::addr::Ipv6Addr::new(v.0)),
            // Forwarded upgrades
            From::Numeric(v) => To::Numeric(v.upgrade()),
            From::Hash(v) => To::Hash(v.upgrade()),
            From::Name(v) => To::Name(v.upgrade()),
            From::Vec(v) => To::Vec(v.into_iter().map(|vv| vv.upgrade()).collect()),
            From::PublicKey(v) => To::PublicKey(v.upgrade()),
            From::PermissionToken(v) => To::PermissionToken(v.upgrade()),
            From::Id(v) => To::Id(v.upgrade()),
            From::Identifiable(v) => To::Identifiable(v.upgrade()),
            From::SignatureCheckCondition(v) => To::SignatureCheckCondition(v.upgrade()),
            From::LimitedMetadata(v) => To::LimitedMetadata(v.upgrade()),
            From::MetadataLimits(v) => To::MetadataLimits(v.upgrade()),
            From::TransactionLimits(v) => To::TransactionLimits(v.upgrade()),
            From::LengthLimits(v) => To::LengthLimits(v.upgrade()),
            From::TransactionValue(_) => unimplemented!(),
            From::TransactionQueryResult(_) => unimplemented!(),
            From::Block(_) => unimplemented!(),
            From::BlockHeader(_) => unimplemented!(),
        }
    }
}

impl_upgrade! {
    isi::SetParameterBox;
    |from: From| {
        To {
            parameter: from.parameter.upgrade()
        }
    }
}

impl_upgrade! {
    isi::NewParameterBox;
    |from: From| {
        To {
            parameter: from.parameter.upgrade()
        }
    }
}

forward_enum_upgrade! {
    isi::Instruction;
    isi::InstructionBox;
    Register, Unregister, Mint, Burn, Transfer,
    If, Pair, Sequence, Fail, SetKeyValue, RemoveKeyValue,
    Grant, Revoke, ExecuteTrigger, SetParameter, NewParameter
}

impl_upgrade! {
    isi::Pair;
    |from: From| {
        To::new(from.left_instruction.upgrade(), from.right_instruction.upgrade())
    }
}

impl_upgrade! {
    isi::If;
    isi::Conditional;
    |from: From| {
        if let Some(otherwise) = from.otherwise {
            To::with_otherwise(from.condition.upgrade(), from.then.upgrade(), otherwise.upgrade())
        } else {
            To::new(from.condition.upgrade(), from.then.upgrade())
        }
    }
}

impl Upgrade for from::RegistrableBox {
    type To = to::RegistrableBox;
    fn upgrade(self) -> Self::To {
        match self {
            Self::Peer(v) => Self::To::Peer(v.upgrade()),
            Self::Domain(v) => Self::To::Domain(v.upgrade()),
            Self::Account(v) => Self::To::Account(v.upgrade()),
            Self::AssetDefinition(v) => Self::To::AssetDefinition(v.upgrade()),
            Self::Asset(v) => Self::To::Asset(v.upgrade()),
            Self::Trigger(v) => Self::To::Trigger(v.upgrade()),
            Self::Role(v) => Self::To::Role(v.upgrade()),
            Self::PermissionTokenDefinition(v) => Self::To::PermissionTokenDefinition(v.upgrade()),
            Self::Validator(_) => unimplemented!(),
        }
    }
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
        let expr: to::expression::Expression = *self.expression.upgrade();
        Self::To::new_unchecked(expr)
    }
}
