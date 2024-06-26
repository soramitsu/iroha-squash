use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::ops::Deref;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::time::Duration;
use std::{collections::BTreeSet, num::NonZeroU32};

use base64::Engine;
use from::Identifiable as _;
use from_data_model as from;
use iroha_data_model as to;

use iroha_squash_macros::{
    declare_upgrade, forward_enum_upgrade, forward_struct_upgrade, forward_upgrade, impl_upgrade,
    trivial_enum_upgrade, trivial_upgrade,
};
use crate::permissions::DEFAULT_PERMISSION_TOKENS_MAP;

declare_upgrade!(from_schema, iroha_schema);

trivial_upgrade!(bool);
trivial_upgrade!(u32);
trivial_upgrade!(u64);
trivial_upgrade!(u128);
trivial_upgrade!(String);
trivial_upgrade!(Duration);

impl<T: Upgrade> Upgrade for BTreeSet<T>
where
    T::To: Ord,
{
    type To = BTreeSet<T::To>;

    fn upgrade(self) -> Self::To {
        self.into_iter().map(Upgrade::upgrade).collect()
    }
}

impl<T> Upgrade for from_crypto::HashOf<T>
where
    T: Upgrade,
{
    type To = iroha_crypto::HashOf<T::To>;

    fn upgrade(self) -> Self::To {
        Self::To::from_untyped_unchecked(iroha_crypto::Hash::prehashed(*self.as_ref()))
    }
}

impl Upgrade for from_primitives::fixed::Fixed {
    type To = iroha_primitives::fixed::Fixed;

    fn upgrade(self) -> Self::To {
        let float: f64 = self.into();
        Self::To::try_from(float).unwrap()
    }
}

impl Upgrade for from_primitives::addr::SocketAddr {
    type To = iroha_primitives::addr::SocketAddr;

    fn upgrade(self) -> Self::To {
        match self {
            Self::Ipv4(v) => Self::To::Ipv4(v.upgrade()),
            Self::Ipv6(v) => Self::To::Ipv6(v.upgrade()),
            Self::Host(v) => Self::To::Host(v.upgrade()),
        }
    }
}

impl Upgrade for from_primitives::addr::SocketAddrV4 {
    type To = iroha_primitives::addr::SocketAddrV4;

    fn upgrade(self) -> Self::To {
        Self::To {
            ip: self.ip.upgrade(),
            port: self.port,
        }
    }
}

impl Upgrade for from_primitives::addr::SocketAddrV6 {
    type To = iroha_primitives::addr::SocketAddrV6;

    fn upgrade(self) -> Self::To {
        Self::To {
            ip: self.ip.upgrade(),
            port: self.port,
        }
    }
}

impl Upgrade for from_primitives::addr::SocketAddrHost {
    type To = iroha_primitives::addr::SocketAddrHost;

    fn upgrade(self) -> Self::To {
        Self::To {
            host: iroha_primitives::conststr::ConstString::from(self.host.as_ref()),
            port: self.port,
        }
    }
}

impl Upgrade for from_primitives::addr::Ipv4Addr {
    type To = iroha_primitives::addr::Ipv4Addr;

    fn upgrade(self) -> Self::To {
        Self::To::new(*self.as_ref())
    }
}

impl Upgrade for from_primitives::addr::Ipv6Addr {
    type To = iroha_primitives::addr::Ipv6Addr;

    fn upgrade(self) -> Self::To {
        Self::To::new(*self.as_ref())
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

forward_upgrade! {
    enum events::Event;
    Pipeline, Data, Time, ExecuteTrigger
}

impl_upgrade! {
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
    events::execute_trigger::ExecuteTriggerEvent;
    |from: From| {
        To {
            trigger_id: from.trigger_id.upgrade(),
            authority: from.authority.upgrade()
        }
    }
}

impl_upgrade! {
    events::time::TimeInterval;
    |from: From| {
        To {
            since: from.since.upgrade(),
            length: from.length.upgrade()
        }
    }
}

impl_upgrade! {
    events::time::TimeEvent;
    |from: From| {
        To {
            prev_interval: from.prev_interval.upgrade(),
            interval: from.interval.upgrade()
        }
    }
}

impl Upgrade for from::events::data::prelude::ValidatorEvent {
    type To = to::events::data::prelude::ValidatorEvent;
    fn upgrade(self) -> Self::To {
        match self {
            Self::Upgraded => Self::To::Upgraded,
            _ => unreachable!(),
        }
    }
}

impl_upgrade! {
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
            From::Validator(v) => To::Validator(v.upgrade()),
        }
    }
}

forward_upgrade! {
    struct parameter::ParameterId;
    name
}

impl_upgrade! {
    parameter::Parameter;
    |from: From| {
        To {
            id: from.id.clone().upgrade(),
            val: Box::new(from.val.upgrade())
        }
    }
}

//forward_enum_upgrade! {
//    Parameter;
//    MaximumFaultyPeersAmount, BlockTime, CommitTime, TransactionReceiptTime
//}

impl_upgrade! {
    permission::PermissionToken;
    |from: From| To::new(from.definition_id().clone().upgrade(), &from.params().map(|(name, value)| (name.clone().upgrade(), value.clone().upgrade())).collect::<Vec<_>>())
}

impl_upgrade! {
    domain::DomainId;
    |from: From| {
        To { name: from.name.upgrade() }
    }
}

impl_upgrade! {
    account::AccountId;
    |from: From| To { name: from.name.upgrade(), domain_id: from.domain_id.upgrade() }
}

impl_upgrade! {
    asset::AssetDefinitionId;
    |from: From| To { name: from.name.upgrade(), domain_id: from.domain_id.upgrade() }
}

impl_upgrade! {
    asset::AssetId;
    |from: From| To  { definition_id: from.definition_id.upgrade(), account_id: from.account_id.upgrade() }
}

impl_upgrade! {
    peer::PeerId;
    |from: From| {
        To::new(&from.address.upgrade(), &from.public_key.upgrade())
    }
}

impl_upgrade! {
    trigger::TriggerId;
    |from: From| {
        To { name: from.name.upgrade(), domain_id: from.domain_id.upgrade() }
    }
}

impl_upgrade! {
    role::RoleId;
    |from: From| To { name: from.name.upgrade() }
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
            Self::PermissionTokenDefinitionId(v) => Self::To::PermissionTokenId(v.upgrade()),
            Self::ParameterId(v) => Self::To::ParameterId(v.upgrade()),
        }
    }
}

impl_upgrade! {
    block::BlockHeader;
    |from: From| {
        To {
            timestamp: from.timestamp,
            height: from.height,
            previous_block_hash: from.previous_block_hash.upgrade(),
            transactions_hash: from.transactions_hash
                .map(|h| h.deref().clone())
                .upgrade()
                .map(iroha_crypto::HashOf::from_untyped_unchecked),
            rejected_transactions_hash: from.rejected_transactions_hash
                .map(|h| h.deref().clone())
                .upgrade()
                .map(iroha_crypto::HashOf::from_untyped_unchecked),
            committed_with_topology: Vec::new(),
            consensus_estimation: 0,
            view_change_index: 0
        }
    }
}

impl_upgrade! {
    transaction::TransactionPayload;
    |from: From| {
        To {
            authority: from.account_id.upgrade(),
            instructions: from.instructions.upgrade(),
            creation_time_ms: from.creation_time.upgrade(),
            time_to_live_ms: NonZeroU64::new(from.time_to_live_ms),
            nonce: from.nonce.upgrade().map(NonZeroU32::new).flatten(),
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
    block::error::BlockRejectionReason;
    ConsensusBlockRejection
}

// impl_upgrade! {
//     transaction::error::NotPermittedFail;
//     |from: From| {
//         To { reason: from.reason.upgrade() }
//     }
// }

impl_upgrade! {
    transaction::error::InstructionExecutionFail;
    |from: From| {
        To {
            reason:from.reason.upgrade(),
            instruction: from.instruction.upgrade()
        }
    }
}

impl_upgrade! {
    transaction::error::WasmExecutionFail;
    |from: From| {
        To {
            reason:from.reason.upgrade(),
        }
    }
}

// impl_upgrade! {
//     transaction::error::UnsatisfiedSignatureConditionFail;
//     |from: From| {
//         To { reason: from.reason.upgrade() }
//     }
// }

impl_upgrade! {
    transaction::error::TransactionLimitError;
    |from: From| {
        serde_json::from_value(
            serde_json::to_value(from).unwrap()
        ).unwrap()
    }
}

impl_upgrade! {
    transaction::error::TransactionRejectionReason;
    |from: From| {
        match from {
          From::NotPermitted(v) => To::Validation(to::ValidationFail::NotPermitted(v.reason)),
          From::UnsatisfiedSignatureCondition(_) => To::Validation(to::ValidationFail::NotPermitted("signature check condition failed".to_owned())),
          From::LimitCheck(v) => To::LimitCheck(v.upgrade()),
          From::InstructionExecution(v) => To::InstructionExecution(v.upgrade()),
          From::WasmExecution(v) => To::WasmExecution(v.upgrade()),
          From::Expired(_) => To::Expired,
          From::UnexpectedGenesisAccountSignature => To::UnexpectedGenesisAccountSignature,
        }
    }
}

forward_enum_upgrade! {
    events::pipeline::PipelineRejectionReason;
    Block, Transaction
}

//impl_upgrade! {
//    transaction::RejectedTransaction;
//    |from: From| {
//        To {
//            payload: from.payload.upgrade(),
//            signatures: from.signatures.upgrade(),
//            rejection_reason: from.rejection_reason.upgrade()
//        }
//    }
//}

// impl_upgrade! {
//     transaction::ValidTransaction;
//     |from: From| {
//         To {
//             payload: from.payload.upgrade(),
//             signatures: from.signatures.upgrade()
//         }
//     }
// }
//
// forward_enum_upgrade! {
//     transaction::VersionedValidTransaction;
//     V1
// }
//
// forward_enum_upgrade! {
//     transaction::VersionedRejectedTransaction;
//     V1
// }
//
//
//
//

forward_struct_upgrade! {
    transaction::ValidTransaction;
    transaction::SignedTransaction;
    signatures, payload
}

forward_enum_upgrade! {
    transaction::VersionedValidTransaction;
    transaction::VersionedSignedTransaction;
    V1
}

forward_upgrade! {
    enum block::VersionedCommittedBlock;
    V1
}

impl_upgrade! {
    block::CommittedBlock;
    |from: From| {
        let keys = iroha_crypto::KeyPair::generate().unwrap();
        let signatures = iroha_crypto::SignaturesOf::new(keys, &()).unwrap();
        let accepted_txs = from.transactions.upgrade()
                .into_iter()
                .map(|tx| to::transaction::TransactionValue {
                    value: tx,
                    error: None
                });
        let rejected_txs = from.rejected_transactions
                .into_iter()
                .map(|tx| {
                    let from::transaction::RejectedTransaction {
                        payload,
                        signatures,
                        rejection_reason
                    } = tx.into_v1();
                    to::transaction::TransactionValue {
                        value: to::transaction::VersionedSignedTransaction::V1(
                            to::transaction::SignedTransaction {
                              payload: payload.upgrade(),
                              signatures: signatures.upgrade()
                        }),
                        error: Some(rejection_reason.upgrade())
                    }
        });
        To {
            header: from.header.upgrade(),
            transactions: accepted_txs.chain(rejected_txs).collect(),
            event_recommendations: from.event_recommendations.upgrade(),
            signatures: signatures.transmute(),
        }
    }
}

// TODO:
unobtainable!(account::Account);
unobtainable!(asset::AssetDefinition);
unobtainable!(asset::Asset);
unobtainable!(domain::Domain);

fn contract_hash(
    contract: from::transaction::WasmSmartContract,
) -> to::transaction::WasmSmartContract {
    let hash = sha256::digest(contract.as_ref());
    let magic_bytes = base64::engine::general_purpose::STANDARD
        .decode(format!("NEEDSREBUILD++{}++", hash))
        .unwrap();
    to::transaction::WasmSmartContract::from_compiled(magic_bytes)
}

impl_upgrade! {
    transaction::WasmSmartContract;
    |from: From| {
        contract_hash(from)
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
          ).expect("u32::MAX shouldn't be possible to exceed");
        }
        new
    }
}

forward_upgrade! {
    struct account::NewAccount;
    id, signatories, metadata
}

forward_upgrade! {
    struct role::NewRole;
    inner
}

forward_upgrade! {
    struct role::Role;
    id, permissions
}

forward_upgrade! {
    struct domain::NewDomain;
    id, logo, metadata
}

impl_upgrade! {
    ipfs::IpfsPath;
    |from: From| {
        from.as_ref().parse().unwrap()
    }
}

impl_upgrade! {
    peer::Peer;
    |from: From| {
        To::new(from.id().clone().upgrade())
    }
}

// impl_upgrade! {
//     permission::PermissionTokenDefinition;
//     |from: From| {
//         To::new(from.id().clone().upgrade())
//             .with_params(
//                 from.params()
//                 .map(|(k, v)| (k.clone().upgrade(), v.upgrade()))
//             )
//     }
// }

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

// impl_upgrade! {
//     ValueKind;
//     |from: From| {
//         match from {
//           From::Numeric => To::Numeric,
//           From::Bool => To::Bool,
//           From::String => To::String,
//           From::Name => To::Name,
//           From::Vec => To::Vec,
//           From::LimitedMetadata => To::LimitedMetadata,
//           From::Id => To::Id,
//           From::Identifiable => To::Identifiable,
//           From::PublicKey => To::PublicKey,
//           From::SignatureCheckCondition => To::SignatureCheckCondition,
//           From::TransactionValue => To::TransactionValue,
//           From::TransactionQueryResult => To::TransactionQueryResult,
//           From::PermissionToken => To::PermissionToken,
//           From::Hash => To::Hash,
//           From::Block => To::Block,
//           From::BlockHeader => To::BlockHeader,
//           From::Ipv4Addr => To::Ipv4Addr,
//           From::Ipv6Addr => To::Ipv6Addr,
//           From::MetadataLimits => To::MetadataLimits,
//           From::LengthLimits => To::LengthLimits,
//           From::TransactionLimits => To::TransactionLimits,
//           From::Validator => To::Validator,
//         }
//     }
// }

impl_upgrade! {
    permission::PermissionTokenId;
    |from: From| {
        let id = from.name.to_string();
        let id_to = DEFAULT_PERMISSION_TOKENS_MAP
            .iter()
            .find(|(id_from, _id_to)| id_from == &id)
            .map(|(_id_from, id_to)| id_to);
        if let Some(id_to) = id_to {
            return to::name::Name::from_str(id_to).unwrap();
        }

        from.name.upgrade()
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

trivial_enum_upgrade! {
    asset::Mintable;
    Infinitely, Once, Not
}

forward_struct_upgrade! {
    asset::NewAssetDefinition;
    id, value_type, mintable, logo, metadata
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
    events::pipeline::PipelineEntityKind;
    Block, Transaction
}

trivial_enum_upgrade! {
    events::pipeline::PipelineStatusKind;
    Committed, Validating, Rejected
}

forward_enum_upgrade! {
    events::FilterBox;
    Pipeline, Data, Time, ExecuteTrigger
}

impl_upgrade! {
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
        serde_json::from_value(serde_json::to_value(from).unwrap()).unwrap()
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
    events::pipeline::PipelineEventFilter;
    |from: From| {
        serde_json::from_value(serde_json::to_value(from).unwrap()).unwrap()
    }
}

impl<E> Upgrade for from::trigger::action::Action<from::events::FilterBox, E>
where
    E: Upgrade,
{
    type To = to::trigger::action::Action<to::events::FilterBox, E::To>;

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

impl Upgrade for from::trigger::WasmInternalRepr {
    type To = to::trigger::WasmInternalRepr;
    fn upgrade(self) -> Self::To {
        Self::To {
            serialized: self.serialized,
            blob_hash: iroha_crypto::HashOf::from_untyped_unchecked(*self.blob_hash.upgrade()),
        }
    }
}

forward_upgrade! {
    enum trigger::OptimizedExecutable;
    WasmInternalRepr, Instructions
}

impl<E> Upgrade for from::trigger::Trigger<from::events::FilterBox, E>
where
    E: Upgrade,
{
    type To = to::trigger::Trigger<to::events::FilterBox, E::To>;

    fn upgrade(self) -> Self::To {
        Self::To {
            id: self.id.upgrade(),
            action: self.action.upgrade(),
        }
    }
}

forward_upgrade! {
    enum TriggerBox;
    Raw, Optimized
}

impl Upgrade for from::IdentifiableBox {
    type To = to::IdentifiableBox;
    fn upgrade(self) -> Self::To {
        match self {
            Self::Account(v) => Self::To::Account(*v.upgrade()),
            Self::Asset(v) => Self::To::Asset(*v.upgrade()),
            Self::AssetDefinition(v) => Self::To::AssetDefinition(*v.upgrade()),
            Self::Domain(v) => Self::To::Domain(*v.upgrade()),
            Self::NewAccount(v) => Self::To::NewAccount(*v.upgrade()),
            Self::NewAssetDefinition(v) => Self::To::NewAssetDefinition(*v.upgrade()),
            Self::NewDomain(v) => Self::To::NewDomain(*v.upgrade()),
            Self::NewRole(v) => Self::To::NewRole(*v.upgrade()),
            Self::Peer(v) => Self::To::Peer(*v.upgrade()),
            Self::Role(v) => Self::To::Role(*v.upgrade()),
            Self::Trigger(v) => Self::To::Trigger(v.upgrade()),
            Self::Parameter(v) => Self::To::Parameter(*v.upgrade()),
            Self::PermissionTokenDefinition(token) => {
                let token_id = token.id.name.to_string();
                panic!("
PermissionTokenDefinition ISI was removed in Iroha 19.
Custom permission tokens should be defined in custom executor.
You have permission token: `{token_id}`.
(It is either custom or was default in previous iroha version but was deleted in rc19)
                ")
            }
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
            Self::Raw(v) => Self::To::Raw(v.upgrade()),
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

forward_upgrade! {
    struct expression::If;
    condition, then, otherwise
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
        To { value_name: from.value_name.upgrade() }
    }
}

impl_upgrade! {
    expression::ContainsAll;
    |from: From| {
        To::new(from.collection.upgrade(), from.elements.upgrade())
    }
}

forward_upgrade! {
    struct query::asset::IsAssetDefinitionOwner;
    asset_definition_id, account_id
}

impl Upgrade for from::query::permission::DoesAccountHavePermissionToken {
    type To = to::query::permission::DoesAccountHavePermissionToken;
    fn upgrade(self) -> Self::To {
        Self::To {
            account_id: self.account_id.upgrade(),
            permission_token: iroha_data_model::expression::EvaluatesTo::new_unchecked(
                self.permission_token.upgrade(),
            ),
        }
    }
}

impl Upgrade for from::query::QueryBox {
    type To = to::query::QueryBox;
    fn upgrade(self) -> Self::To {
        match self {
            Self::FindAllAccounts(v) => Self::To::FindAllAccounts(v.upgrade()),
            Self::FindAccountById(v) => Self::To::FindAccountById(v.upgrade()),
            Self::FindAccountKeyValueByIdAndKey(v) => {
                Self::To::FindAccountKeyValueByIdAndKey(v.upgrade())
            }
            Self::FindAccountsByName(v) => Self::To::FindAccountsByName(v.upgrade()),
            Self::FindAccountsByDomainId(v) => Self::To::FindAccountsByDomainId(v.upgrade()),
            Self::FindAccountsWithAsset(v) => Self::To::FindAccountsWithAsset(v.upgrade()),
            Self::FindAllAssets(v) => Self::To::FindAllAssets(v.upgrade()),
            Self::FindAllAssetsDefinitions(v) => Self::To::FindAllAssetsDefinitions(v.upgrade()),
            Self::FindAssetById(v) => Self::To::FindAssetById(v.upgrade()),
            Self::FindAssetDefinitionById(v) => Self::To::FindAssetDefinitionById(v.upgrade()),
            Self::FindAssetsByName(v) => Self::To::FindAssetsByName(v.upgrade()),
            Self::FindAssetsByAccountId(v) => Self::To::FindAssetsByAccountId(v.upgrade()),
            Self::FindAssetsByAssetDefinitionId(v) => {
                Self::To::FindAssetsByAssetDefinitionId(v.upgrade())
            }
            Self::FindAssetsByDomainId(v) => Self::To::FindAssetsByDomainId(v.upgrade()),
            Self::FindAssetsByDomainIdAndAssetDefinitionId(v) => {
                Self::To::FindAssetsByDomainIdAndAssetDefinitionId(v.upgrade())
            }
            Self::FindAssetQuantityById(v) => Self::To::FindAssetQuantityById(v.upgrade()),
            Self::FindAssetKeyValueByIdAndKey(v) => {
                Self::To::FindAssetKeyValueByIdAndKey(v.upgrade())
            }
            Self::FindAssetDefinitionKeyValueByIdAndKey(v) => {
                Self::To::FindAssetDefinitionKeyValueByIdAndKey(v.upgrade())
            }
            Self::FindAllDomains(v) => Self::To::FindAllDomains(v.upgrade()),
            Self::FindDomainById(v) => Self::To::FindDomainById(v.upgrade()),
            Self::FindDomainKeyValueByIdAndKey(v) => {
                Self::To::FindDomainKeyValueByIdAndKey(v.upgrade())
            }
            Self::FindAllPeers(v) => Self::To::FindAllPeers(v.upgrade()),
            Self::FindAllBlocks(v) => Self::To::FindAllBlocks(v.upgrade()),
            Self::FindAllBlockHeaders(v) => Self::To::FindAllBlockHeaders(v.upgrade()),
            Self::FindBlockHeaderByHash(v) => Self::To::FindBlockHeaderByHash(v.upgrade()),
            Self::FindAllTransactions(v) => Self::To::FindAllTransactions(v.upgrade()),
            Self::FindTransactionsByAccountId(v) => {
                Self::To::FindTransactionsByAccountId(v.upgrade())
            }
            Self::FindTransactionByHash(v) => Self::To::FindTransactionByHash(v.upgrade()),
            Self::FindPermissionTokensByAccountId(v) => {
                Self::To::FindPermissionTokensByAccountId(v.upgrade())
            }
            Self::FindAllActiveTriggerIds(v) => Self::To::FindAllActiveTriggerIds(v.upgrade()),
            Self::FindTriggerById(v) => Self::To::FindTriggerById(v.upgrade()),
            Self::FindTriggerKeyValueByIdAndKey(v) => {
                Self::To::FindTriggerKeyValueByIdAndKey(v.upgrade())
            }
            Self::FindTriggersByDomainId(v) => Self::To::FindTriggersByDomainId(v.upgrade()),
            Self::FindAllRoles(v) => Self::To::FindAllRoles(v.upgrade()),
            Self::FindAllRoleIds(v) => Self::To::FindAllRoleIds(v.upgrade()),
            Self::FindRoleByRoleId(v) => Self::To::FindRoleByRoleId(v.upgrade()),
            Self::FindRolesByAccountId(v) => Self::To::FindRolesByAccountId(v.upgrade()),
            Self::FindTotalAssetQuantityByAssetDefinitionId(v) => {
                Self::To::FindTotalAssetQuantityByAssetDefinitionId(v.upgrade())
            }
            Self::FindAllParameters(v) => Self::To::FindAllParameters(v.upgrade()),
            Self::IsAssetDefinitionOwner(v) => Self::To::IsAssetDefinitionOwner(v.upgrade()),
            Self::DoesAccountHavePermissionToken(v) => {
                Self::To::DoesAccountHavePermissionToken(v.upgrade())
            }
            Self::FindAllPermissionTokenDefinitions(_) => unreachable!(),
        }
    }
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
      To {
          hash: iroha_data_model::expression::EvaluatesTo::new_unchecked(from.hash.expression().clone().upgrade())
      }
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
      To {
          hash: iroha_data_model::expression::EvaluatesTo::new_unchecked(from.hash.expression().clone().upgrade())
      }
  }
}

impl_upgrade! {
  query::prelude::FindPermissionTokensByAccountId;
  |from: From| {
      To { id: from.id.upgrade() }
  }
}

// impl_upgrade! {
//   query::prelude::FindAllPermissionTokenDefinitions;
//   |_from: From| {
//     to::query::prelude::FindAllPermissionTokenDefinitions
//   }
// }

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
            Self::Created(v) => Self::To::Created(v.upgrade()),
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
            Self::Created(v) => Self::To::Created(v.upgrade()),
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
            permission_token_id: from.permission_definition_id.upgrade()
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
            Self::Created(v) => Self::To::Created(v.upgrade()),
            Self::Deleted(v) => Self::To::Deleted(v.upgrade()),
            Self::PermissionRemoved(v) => Self::To::PermissionRemoved(v.upgrade()),
            _ => unreachable!(),
        }
    }
}

impl Upgrade for from::events::data::prelude::PermissionTokenEvent {
    type To = to::events::data::prelude::PermissionTokenSchemaUpdateEvent;

    fn upgrade(self) -> Self::To {
        panic!("Removed");
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
            Self::Created(v) => Self::To::Created(v.upgrade()),
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
        serde_json::from_value(
            serde_json::to_value(from).unwrap()
        )
        .unwrap()
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
            From::Ipv4Addr(v) => To::Ipv4Addr(v.upgrade()),
            From::Ipv6Addr(v) => To::Ipv6Addr(v.upgrade()),
            // Forwarded upgrades
            From::Numeric(v) => To::Numeric(v.upgrade()),
            From::Hash(v) => To::Hash(iroha_data_model::HashValue::Block(iroha_crypto::HashOf::from_untyped_unchecked(v.upgrade()))),
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
            From::Validator(v) => To::Validator(v.upgrade()),
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

forward_upgrade! {
    struct validator::Validator;
    wasm
}

forward_upgrade! {
    enum UpgradableBox;
    Validator
}

forward_upgrade! {
    struct isi::UpgradeBox;
    object
}

forward_upgrade! {
    enum isi::InstructionBox;
    Register, Unregister, Mint, Burn, Transfer,
    If, Pair, Sequence, Fail, SetKeyValue, RemoveKeyValue,
    Grant, Revoke, ExecuteTrigger, SetParameter, NewParameter, Upgrade
}

impl_upgrade! {
    isi::Pair;
    |from: From| {
        To::new(from.left_instruction.upgrade(), from.right_instruction.upgrade())
    }
}

impl_upgrade! {
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
            Self::Peer(v) => Self::To::Peer(*v.upgrade()),
            Self::Domain(v) => Self::To::Domain(*v.upgrade()),
            Self::Account(v) => Self::To::Account(*v.upgrade()),
            Self::AssetDefinition(v) => Self::To::AssetDefinition(*v.upgrade()),
            Self::Asset(v) => Self::To::Asset(*v.upgrade()),
            Self::Trigger(v) => Self::To::Trigger(*v.upgrade()),
            Self::Role(v) => Self::To::Role(*v.upgrade()),
            Self::PermissionTokenDefinition(_) => unimplemented!(),
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
