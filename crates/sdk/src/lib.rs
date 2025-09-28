//! Namada SDK
#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

extern crate alloc;

pub use namada_core::*;
pub use {
    bip39, masp_primitives, masp_proofs, namada_account as account,
    namada_gas as gas, namada_governance as governance, namada_ibc as ibc,
    namada_parameters as parameters, namada_proof_of_stake as proof_of_stake,
    namada_state as state, namada_storage as storage, namada_token as token,
    tendermint_rpc, zeroize,
};

pub mod eth_bridge;

pub mod rpc;

pub mod args;
pub mod masp;
pub mod signing;
#[allow(clippy::result_large_err)]
pub mod tx;
#[cfg(feature = "wasm-runtime")]
pub mod validation;

pub mod error;
pub mod events;
pub(crate) mod internal_macros;

#[cfg(feature = "migrations")]
pub mod migrations;
pub mod queries;
use std::path::PathBuf;
use std::str::FromStr;

use args::{DeviceTransport, InputAmount, SdkTypes};
use masp_primitives::zip32::PseudoExtendedKey;
use namada_core::address::Address;
use namada_core::dec::Dec;
use namada_core::ethereum_events::EthAddress;
use namada_core::ibc::core::host::types::identifiers::{ChannelId, PortId};
use namada_core::key::*;
pub use namada_core::masp::{
    ExtendedSpendingKey, ExtendedViewingKey, PaymentAddress, TransferSource,
    TransferTarget,
};
pub use namada_core::{control_flow, task_env};
use namada_io::{Client, Io, NamadaIo};
pub use namada_io::{MaybeSend, MaybeSync};
pub use namada_token::masp::{ShieldedUtils, ShieldedWallet};
use namada_tx::Tx;
use namada_tx::data::wrapper::GasLimit;
use rpc::{denominate_amount, format_denominated_amount, query_native_token};
use signing::SigningTxData;
use token::{DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tx::{
    ProcessTxResponse, TX_BECOME_VALIDATOR_WASM, TX_BOND_WASM,
    TX_BRIDGE_POOL_WASM, TX_CHANGE_COMMISSION_WASM,
    TX_CHANGE_CONSENSUS_KEY_WASM, TX_CHANGE_METADATA_WASM,
    TX_CLAIM_REWARDS_WASM, TX_DEACTIVATE_VALIDATOR_WASM, TX_IBC_WASM,
    TX_INIT_ACCOUNT_WASM, TX_INIT_PROPOSAL, TX_REACTIVATE_VALIDATOR_WASM,
    TX_REDELEGATE_WASM, TX_RESIGN_STEWARD, TX_REVEAL_PK, TX_TRANSFER_WASM,
    TX_UNBOND_WASM, TX_UNJAIL_VALIDATOR_WASM, TX_UPDATE_ACCOUNT_WASM,
    TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM,
    VP_USER_WASM,
};
use wallet::{Wallet, WalletIo, WalletStorage};
pub use {namada_io as io, namada_wallet as wallet};

use crate::masp::ShieldedContext;

/// Default gas-limit
pub const DEFAULT_GAS_LIMIT: u64 = 50_000;

/// An interface for high-level interaction with the Namada SDK
#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
#[rustversion::attr(
    nightly,
    allow(elided_named_lifetimes, reason = "Not actually named")
)]
pub trait Namada: NamadaIo {
    /// Captures the interactive parts of the wallet's functioning
    type WalletUtils: WalletIo + WalletStorage + MaybeSend + MaybeSync;
    /// Abstracts platform specific details away from the logic of shielded pool
    /// operations.
    type ShieldedUtils: ShieldedUtils + MaybeSend + MaybeSync;

    /// Obtain read guard on the wallet
    async fn wallet(&self) -> RwLockReadGuard<'_, Wallet<Self::WalletUtils>>;

    /// Obtain write guard on the wallet
    async fn wallet_mut(
        &self,
    ) -> RwLockWriteGuard<'_, Wallet<Self::WalletUtils>>;

    /// Obtain the wallet lock
    fn wallet_lock(&self) -> &RwLock<Wallet<Self::WalletUtils>>;

    /// Obtain read guard on the shielded context
    async fn shielded(
        &self,
    ) -> RwLockReadGuard<'_, ShieldedContext<Self::ShieldedUtils>>;

    /// Obtain write guard on the shielded context
    async fn shielded_mut(
        &self,
    ) -> RwLockWriteGuard<'_, ShieldedContext<Self::ShieldedUtils>>;

    /// Return the native token
    fn native_token(&self) -> Address;

    /// Make a tx builder using no arguments
    fn tx_builder(&self) -> args::Tx {
        args::Tx {
            dry_run: false,
            dry_run_wrapper: false,
            dump_tx: false,
            dump_wrapper_tx: false,
            output_folder: None,
            force: false,
            broadcast_only: false,
            ledger_address: tendermint_rpc::Url::from_str(
                "http://127.0.0.1:26657",
            )
            .unwrap(),
            initialized_account_alias: None,
            wallet_alias_force: false,
            fee_amount: None,
            wrapper_fee_payer: None,
            fee_token: self.native_token(),
            gas_limit: GasLimit::from(DEFAULT_GAS_LIMIT),
            expiration: Default::default(),
            chain_id: None,
            signing_keys: vec![],
            tx_reveal_code_path: PathBuf::from(TX_REVEAL_PK),
            password: None,
            memo: None,
            use_device: false,
            device_transport: DeviceTransport::default(),
        }
    }

    /// Make a TxTransparentTransfer builder from the given minimum set of
    /// arguments
    fn new_transparent_transfer(
        &self,
        sources: Vec<args::TxTransparentSource>,
        targets: Vec<args::TxTransparentTarget>,
    ) -> args::TxTransparentTransfer {
        args::TxTransparentTransfer {
            sources,
            targets,
            tx_code_path: PathBuf::from(TX_TRANSFER_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxShieldedTransfer builder from the given minimum set of
    /// arguments
    fn new_shielded_transfer(
        &self,
        sources: Vec<args::TxShieldedSource>,
        targets: Vec<args::TxShieldedTarget>,
        gas_spending_key: Option<PseudoExtendedKey>,
    ) -> args::TxShieldedTransfer {
        args::TxShieldedTransfer {
            sources,
            targets,
            gas_spending_key,
            tx_code_path: PathBuf::from(TX_TRANSFER_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxShieldingTransfer builder from the given minimum set of
    /// arguments
    fn new_shielding_transfer(
        &self,
        targets: Vec<args::TxShieldedTarget>,
        sources: Vec<args::TxTransparentSource>,
        shielding_fee_payer: common::PublicKey,
        shielding_fee_token: Address,
    ) -> args::TxShieldingTransfer {
        args::TxShieldingTransfer {
            sources,
            targets,
            tx_code_path: PathBuf::from(TX_TRANSFER_WASM),
            tx: self.tx_builder(),
            shielding_fee_payer,
            shielding_fee_token,
        }
    }

    /// Make a TxUnshieldingTransfer builder from the given minimum set of
    /// arguments
    fn new_unshielding_transfer(
        &self,
        sources: Vec<args::TxShieldedSource>,
        targets: Vec<args::TxTransparentTarget>,
        gas_spending_key: Option<PseudoExtendedKey>,
    ) -> args::TxUnshieldingTransfer {
        args::TxUnshieldingTransfer {
            sources,
            targets,
            gas_spending_key,
            tx_code_path: PathBuf::from(TX_TRANSFER_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a InitAccount builder from the given minimum set of arguments
    fn new_init_account(
        &self,
        public_keys: Vec<common::PublicKey>,
        threshold: Option<u8>,
    ) -> args::TxInitAccount {
        args::TxInitAccount {
            tx: self.tx_builder(),
            vp_code_path: PathBuf::from(VP_USER_WASM),
            tx_code_path: PathBuf::from(TX_INIT_ACCOUNT_WASM),
            public_keys,
            threshold,
        }
    }

    /// Make a RevealPK builder from the given minimum set of arguments
    fn new_reveal_pk(&self, public_key: common::PublicKey) -> args::RevealPk {
        args::RevealPk {
            public_key,
            tx: self.tx_builder(),
        }
    }

    /// Make a Bond builder from the given minimum set of arguments
    fn new_bond(
        &self,
        validator: Address,
        amount: token::Amount,
    ) -> args::Bond {
        args::Bond {
            validator,
            amount,
            source: None,
            tx: self.tx_builder(),
            tx_code_path: PathBuf::from(TX_BOND_WASM),
        }
    }

    /// Make a Unbond builder from the given minimum set of arguments
    fn new_unbond(
        &self,
        validator: Address,
        amount: token::Amount,
    ) -> args::Unbond {
        args::Unbond {
            validator,
            amount,
            source: None,
            tx: self.tx_builder(),
            tx_code_path: PathBuf::from(TX_UNBOND_WASM),
        }
    }

    /// Make a Redelegation builder for the given minimum set of arguments
    fn new_redelegation(
        &self,
        source: Address,
        src_validator: Address,
        dest_validator: Address,
        amount: token::Amount,
    ) -> args::Redelegate {
        args::Redelegate {
            tx: self.tx_builder(),
            // Source validator address
            src_validator,
            // Destination validator address
            dest_validator,
            // Owner of the bonds that are being redelegated
            owner: source,
            // The amount of tokens to redelegate
            amount,
            // Path to the TX WASM code file
            tx_code_path: PathBuf::from(TX_REDELEGATE_WASM),
        }
    }

    /// Make a TxIbcTransfer builder from the given minimum set of arguments
    fn new_ibc_transfer(
        &self,
        source: TransferSource,
        receiver: String,
        token: Address,
        amount: InputAmount,
        channel_id: ChannelId,
    ) -> args::TxIbcTransfer {
        args::TxIbcTransfer {
            source,
            receiver,
            token,
            amount,
            channel_id,
            port_id: PortId::from_str("transfer").unwrap(),
            timeout_height: None,
            timeout_sec_offset: None,
            refund_target: None,
            ibc_shielding_data: None,
            ibc_memo: None,
            gas_spending_key: Default::default(),
            tx: self.tx_builder(),
            tx_code_path: PathBuf::from(TX_IBC_WASM),
        }
    }

    /// Make a InitProposal builder from the given minimum set of arguments
    fn new_init_proposal(&self, proposal_data: Vec<u8>) -> args::InitProposal {
        args::InitProposal {
            proposal_data,
            is_pgf_stewards: false,
            is_pgf_funding: false,
            tx_code_path: PathBuf::from(TX_INIT_PROPOSAL),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxUpdateAccount builder from the given minimum set of arguments
    fn new_update_account(
        &self,
        addr: Address,
        public_keys: Vec<common::PublicKey>,
        threshold: u8,
    ) -> args::TxUpdateAccount {
        args::TxUpdateAccount {
            addr,
            vp_code_path: None,
            public_keys,
            threshold: Some(threshold),
            tx_code_path: PathBuf::from(TX_UPDATE_ACCOUNT_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a VoteProposal builder from the given minimum set of arguments
    fn new_proposal_vote(
        &self,
        proposal_id: u64,
        vote: String,
        voter_address: Address,
    ) -> args::VoteProposal {
        args::VoteProposal {
            vote,
            voter_address,
            proposal_id,
            tx_code_path: PathBuf::from(TX_VOTE_PROPOSAL),
            tx: self.tx_builder(),
        }
    }

    /// Make a CommissionRateChange builder from the given minimum set of
    /// arguments
    fn new_change_commission_rate(
        &self,
        rate: Dec,
        validator: Address,
    ) -> args::CommissionRateChange {
        args::CommissionRateChange {
            rate,
            validator,
            tx_code_path: PathBuf::from(TX_CHANGE_COMMISSION_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make ConsensusKeyChange builder from the given minimum set of arguments
    fn new_change_consensus_key(
        &self,
        validator: Address,
        consensus_key: common::PublicKey,
    ) -> args::ConsensusKeyChange {
        args::ConsensusKeyChange {
            validator,
            consensus_key: Some(consensus_key),
            tx_code_path: PathBuf::from(TX_CHANGE_CONSENSUS_KEY_WASM),
            unsafe_dont_encrypt: false,
            tx: self.tx_builder(),
        }
    }

    /// Make a CommissionRateChange builder from the given minimum set of
    /// arguments
    fn new_change_metadata(&self, validator: Address) -> args::MetaDataChange {
        args::MetaDataChange {
            validator,
            email: None,
            description: None,
            website: None,
            discord_handle: None,
            avatar: None,
            name: None,
            commission_rate: None,
            tx_code_path: PathBuf::from(TX_CHANGE_METADATA_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxBecomeValidator builder from the given minimum set of arguments
    #[allow(clippy::too_many_arguments)]
    fn new_become_validator(
        &self,
        address: Address,
        commission_rate: Dec,
        max_commission_rate_change: Dec,
        consesus_key: common::PublicKey,
        eth_cold_key: common::PublicKey,
        eth_hot_key: common::PublicKey,
        protocol_key: common::PublicKey,
        email: String,
    ) -> args::TxBecomeValidator {
        args::TxBecomeValidator {
            address,
            commission_rate,
            max_commission_rate_change,
            scheme: SchemeType::Ed25519,
            consensus_key: Some(consesus_key),
            eth_cold_key: Some(eth_cold_key),
            eth_hot_key: Some(eth_hot_key),
            protocol_key: Some(protocol_key),
            unsafe_dont_encrypt: false,
            tx_code_path: PathBuf::from(TX_BECOME_VALIDATOR_WASM),
            tx: self.tx_builder(),
            email,
            description: None,
            website: None,
            discord_handle: None,
            avatar: None,
            name: None,
        }
    }

    /// Make a TxInitValidator builder from the given minimum set of arguments
    fn new_init_validator(
        &self,
        commission_rate: Dec,
        max_commission_rate_change: Dec,
        email: String,
    ) -> args::TxInitValidator {
        args::TxInitValidator {
            commission_rate,
            max_commission_rate_change,
            scheme: SchemeType::Ed25519,
            account_keys: vec![],
            threshold: None,
            consensus_key: None,
            eth_cold_key: None,
            eth_hot_key: None,
            protocol_key: None,
            validator_vp_code_path: PathBuf::from(VP_USER_WASM),
            unsafe_dont_encrypt: false,
            tx_init_account_code_path: PathBuf::from(TX_INIT_ACCOUNT_WASM),
            tx_become_validator_code_path: PathBuf::from(
                TX_BECOME_VALIDATOR_WASM,
            ),
            tx: self.tx_builder(),
            email,
            description: None,
            website: None,
            discord_handle: None,
            avatar: None,
            name: None,
        }
    }

    /// Make a TxUnjailValidator builder from the given minimum set of arguments
    fn new_unjail_validator(
        &self,
        validator: Address,
    ) -> args::TxUnjailValidator {
        args::TxUnjailValidator {
            validator,
            tx_code_path: PathBuf::from(TX_UNJAIL_VALIDATOR_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxDeactivateValidator builder from the given minimum set of
    /// arguments
    fn new_deactivate_validator(
        &self,
        validator: Address,
    ) -> args::TxDeactivateValidator {
        args::TxDeactivateValidator {
            validator,
            tx_code_path: PathBuf::from(TX_DEACTIVATE_VALIDATOR_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxReactivateValidator builder from the given minimum set of
    /// arguments
    fn new_reactivate_validator(
        &self,
        validator: Address,
    ) -> args::TxReactivateValidator {
        args::TxReactivateValidator {
            validator,
            tx_code_path: PathBuf::from(TX_REACTIVATE_VALIDATOR_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a Withdraw builder from the given minimum set of arguments
    fn new_withdraw(&self, validator: Address) -> args::Withdraw {
        args::Withdraw {
            validator,
            source: None,
            tx_code_path: PathBuf::from(TX_WITHDRAW_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a Claim-rewards builder from the given minimum set of arguments
    fn new_claim_rewards(&self, validator: Address) -> args::ClaimRewards {
        args::ClaimRewards {
            validator,
            source: None,
            tx_code_path: PathBuf::from(TX_CLAIM_REWARDS_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a Withdraw builder from the given minimum set of arguments
    fn new_add_erc20_transfer(
        &self,
        sender: Address,
        recipient: EthAddress,
        asset: EthAddress,
        amount: InputAmount,
    ) -> args::EthereumBridgePool {
        args::EthereumBridgePool {
            sender,
            recipient,
            asset,
            amount,
            fee_amount: InputAmount::Unvalidated(
                token::DenominatedAmount::new(
                    token::Amount::default(),
                    NATIVE_MAX_DECIMAL_PLACES.into(),
                ),
            ),
            fee_payer: None,
            fee_token: self.native_token(),
            nut: false,
            code_path: PathBuf::from(TX_BRIDGE_POOL_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a ResignSteward builder from the given minimum set of arguments
    fn new_resign_steward(&self, steward: Address) -> args::ResignSteward {
        args::ResignSteward {
            steward,
            tx: self.tx_builder(),
            tx_code_path: PathBuf::from(TX_RESIGN_STEWARD),
        }
    }

    /// Make a UpdateStewardCommission builder from the given minimum set of
    /// arguments
    fn new_update_steward_rewards(
        &self,
        steward: Address,
        commission: Vec<u8>,
    ) -> args::UpdateStewardCommission {
        args::UpdateStewardCommission {
            steward,
            commission,
            tx: self.tx_builder(),
            tx_code_path: PathBuf::from(TX_UPDATE_STEWARD_COMMISSION),
        }
    }

    /// Make a TxCustom builder from the given minimum set of arguments
    fn new_custom(&self, owner: Option<Address>) -> args::TxCustom {
        args::TxCustom {
            owner,
            tx: self.tx_builder(),
            code_path: None,
            data_path: None,
            serialized_tx: None,
            signatures: vec![],
            wrapper_signature: None,
        }
    }

    /// Sign the given transaction using the given signing data
    async fn sign<D, F>(
        &self,
        tx: &mut Tx,
        args: &args::Tx,
        signing_data: SigningTxData,
        with: impl Fn(Tx, common::PublicKey, signing::Signable, D) -> F
        + MaybeSend
        + MaybeSync,
        user_data: D,
    ) -> crate::error::Result<()>
    where
        D: Clone + MaybeSend + MaybeSync,
        F: MaybeSend
            + MaybeSync
            + std::future::Future<Output = crate::error::Result<Tx>>,
    {
        signing::sign_tx(
            self.wallet_lock(),
            args,
            tx,
            signing_data,
            with,
            user_data,
        )
        .await
    }

    /// Process the given transaction using the given flags
    async fn submit(
        &self,
        tx: Tx,
        args: &args::Tx,
    ) -> crate::error::Result<ProcessTxResponse> {
        tx::process_tx(self, args, tx).await
    }

    /// Look up the denomination of a token in order to make a correctly
    /// denominated amount.
    async fn denominate_amount(
        &self,
        token: &Address,
        amount: token::Amount,
    ) -> DenominatedAmount {
        denominate_amount(self.client(), self.io(), token, amount).await
    }

    /// Look up the denomination of a token in order to format it correctly as a
    /// string.
    async fn format_amount(
        &self,
        token: &Address,
        amount: token::Amount,
    ) -> String {
        format_denominated_amount(self.client(), self.io(), token, amount).await
    }
}

/// Provides convenience methods for common Namada interactions
pub struct NamadaImpl<C, U, V, I>
where
    C: Client,
    U: WalletIo,
    V: ShieldedUtils,
    I: Io,
{
    /// Used to send and receive messages from the ledger
    pub client: C,
    /// Stores the addresses and keys required for ledger interactions
    pub wallet: RwLock<Wallet<U>>,
    /// Stores the current state of the shielded pool
    pub shielded: RwLock<ShieldedContext<V>>,
    /// Captures the input/output streams used by this object
    pub io: I,
    /// The address of the native token
    pub native_token: Address,
    /// The default builder for a Tx
    prototype: args::Tx,
}

impl<C, U, V, I> NamadaImpl<C, U, V, I>
where
    C: Client + Sync,
    U: WalletIo,
    V: ShieldedUtils,
    I: Io,
{
    /// Construct a new Namada context with the given native token address
    pub fn native_new(
        client: C,
        wallet: Wallet<U>,
        shielded: ShieldedWallet<V>,
        io: I,
        native_token: Address,
    ) -> Self {
        NamadaImpl {
            client,
            wallet: RwLock::new(wallet),
            shielded: RwLock::new(ShieldedContext::new(shielded)),
            io,
            native_token: native_token.clone(),
            prototype: args::Tx {
                dry_run: false,
                dry_run_wrapper: false,
                dump_tx: false,
                dump_wrapper_tx: false,
                output_folder: None,
                force: false,
                broadcast_only: false,
                ledger_address: tendermint_rpc::Url::from_str(
                    "http://127.0.0.1:26657",
                )
                .unwrap(),
                initialized_account_alias: None,
                wallet_alias_force: false,
                fee_amount: None,
                wrapper_fee_payer: None,
                fee_token: native_token,
                gas_limit: GasLimit::from(DEFAULT_GAS_LIMIT),
                expiration: Default::default(),
                chain_id: None,
                signing_keys: vec![],
                tx_reveal_code_path: PathBuf::from(TX_REVEAL_PK),
                password: None,
                memo: None,
                use_device: false,
                device_transport: DeviceTransport::default(),
            },
        }
    }

    /// Construct a new Namada context looking up the native token address
    pub async fn new(
        client: C,
        wallet: Wallet<U>,
        shielded: ShieldedWallet<V>,
        io: I,
    ) -> crate::error::Result<NamadaImpl<C, U, V, I>> {
        let native_token = query_native_token(&client).await?;
        Ok(NamadaImpl::native_new(
            client,
            wallet,
            shielded,
            io,
            native_token,
        ))
    }

    /// Clone the rpc client.
    pub fn clone_client(&self) -> C
    where
        C: Clone,
    {
        self.client.clone()
    }
}

impl<C, U, V, I> NamadaIo for NamadaImpl<C, U, V, I>
where
    C: Client + MaybeSend + Sync,
    U: WalletIo + WalletStorage + MaybeSync + MaybeSend,
    V: ShieldedUtils + MaybeSync + MaybeSend,
    I: Io + MaybeSync + MaybeSend,
{
    type Client = C;
    type Io = I;

    fn client(&self) -> &Self::Client {
        &self.client
    }

    fn io(&self) -> &Self::Io {
        &self.io
    }
}

#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
#[rustversion::attr(
    nightly,
    allow(elided_named_lifetimes, reason = "Not actually named")
)]
impl<C, U, V, I> Namada for NamadaImpl<C, U, V, I>
where
    C: Client + MaybeSend + Sync,
    U: WalletIo + WalletStorage + MaybeSync + MaybeSend,
    V: ShieldedUtils + MaybeSend + MaybeSync,
    I: Io + MaybeSend + MaybeSync,
{
    type ShieldedUtils = V;
    type WalletUtils = U;

    async fn wallet(&self) -> RwLockReadGuard<'_, Wallet<Self::WalletUtils>> {
        self.wallet.read().await
    }

    async fn wallet_mut(
        &self,
    ) -> RwLockWriteGuard<'_, Wallet<Self::WalletUtils>> {
        self.wallet.write().await
    }

    fn wallet_lock(&self) -> &RwLock<Wallet<Self::WalletUtils>> {
        &self.wallet
    }

    async fn shielded(
        &self,
    ) -> RwLockReadGuard<'_, ShieldedContext<Self::ShieldedUtils>> {
        self.shielded.read().await
    }

    async fn shielded_mut(
        &self,
    ) -> RwLockWriteGuard<'_, ShieldedContext<Self::ShieldedUtils>> {
        self.shielded.write().await
    }

    fn native_token(&self) -> Address {
        self.native_token.clone()
    }

    /// Obtain the prototypical Tx builder
    fn tx_builder(&self) -> args::Tx {
        self.prototype.clone()
    }
}

/// Allow the prototypical Tx builder to be modified
impl<C, U, V, I> args::TxBuilder<SdkTypes> for NamadaImpl<C, U, V, I>
where
    C: Client + Sync,
    U: WalletIo,
    V: ShieldedUtils,
    I: Io,
{
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(args::Tx<SdkTypes>) -> args::Tx<SdkTypes>,
    {
        Self {
            prototype: func(self.prototype),
            ..self
        }
    }
}

/// Tests and strategies for transactions
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use governance::ProposalType;
    use masp_primitives::transaction::components::sapling::builder::StoredBuildParams;
    use namada_account::{InitAccount, UpdateAccount};
    use namada_core::address::testing::arb_non_internal_address;
    use namada_core::collections::{HashMap, HashSet};
    use namada_core::eth_bridge_pool::PendingTransfer;
    use namada_core::hash::testing::arb_hash;
    use namada_core::key::testing::arb_common_keypair;
    use namada_core::masp::AssetData;
    use namada_governance::storage::proposal::testing::{
        arb_init_proposal, arb_vote_proposal,
    };
    use namada_governance::{InitProposalData, VoteProposalData};
    use namada_ibc::testing::{arb_ibc_msg_nft_transfer, arb_ibc_msg_transfer};
    use namada_ibc::{MsgNftTransfer, MsgTransfer};
    use namada_token::Transfer;
    use namada_token::masp::ShieldedTransfer;
    use namada_token::testing::{
        arb_denominated_amount, arb_shielded_transfer,
    };
    use namada_tx::data::pgf::UpdateStewardCommission;
    use namada_tx::data::pos::{
        BecomeValidator, Bond, CommissionChange, ConsensusKeyChange,
        MetaDataChange, Redelegation, Unbond, Withdraw,
    };
    use namada_tx::data::{Fee, TxType, WrapperTx};
    use proptest::prelude::{Just, Strategy};
    use proptest::sample::SizeRange;
    use proptest::{arbitrary, collection, option, prop_compose, prop_oneof};
    use token::testing::arb_transparent_transfer;

    use super::*;
    use crate::account::tests::{arb_init_account, arb_update_account};
    use crate::borsh::{
        BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
    };
    use crate::chain::ChainId;
    use crate::eth_bridge_pool::testing::arb_pending_transfer;
    use crate::key::testing::arb_common_pk;
    use crate::time::{DateTime, DateTimeUtc, TimeZone, Utc};
    use crate::tx::data::pgf::tests::arb_update_steward_commission;
    use crate::tx::data::pos::tests::{
        arb_become_validator, arb_bond, arb_commission_change,
        arb_consensus_key_change, arb_metadata_change, arb_redelegation,
        arb_withdraw,
    };
    use crate::tx::{
        Authorization, Code, Commitment, Header, MaspBuilder, Section,
        TxCommitments,
    };

    #[derive(Debug, Clone, BorshDeserialize, BorshSchema, BorshSerialize)]
    #[borsh(crate = "::borsh")]
    #[allow(clippy::large_enum_variant)]
    #[allow(missing_docs)]
    /// To facilitate propagating debugging information
    pub enum TxData {
        CommissionChange(CommissionChange),
        ConsensusKeyChange(ConsensusKeyChange),
        MetaDataChange(MetaDataChange),
        ClaimRewards(Withdraw),
        DeactivateValidator(Address),
        InitAccount(InitAccount),
        InitProposal(InitProposalData),
        InitValidator(BecomeValidator),
        ReactivateValidator(Address),
        RevealPk(common::PublicKey),
        Unbond(Unbond),
        UnjailValidator(Address),
        UpdateAccount(UpdateAccount),
        VoteProposal(VoteProposalData),
        Withdraw(Withdraw),
        Transfer(Transfer, Option<(StoredBuildParams, String)>),
        Bond(Bond),
        Redelegation(Redelegation),
        UpdateStewardCommission(UpdateStewardCommission),
        ResignSteward(Address),
        PendingTransfer(PendingTransfer),
        IbcMsgTransfer(
            MsgTransfer<token::Transfer>,
            Option<(StoredBuildParams, String)>,
        ),
        IbcMsgNftTransfer(
            MsgNftTransfer<token::Transfer>,
            Option<(StoredBuildParams, String)>,
        ),
        Custom,
    }

    prop_compose! {
        /// Generate an arbitrary commitment
        pub fn arb_commitment()(
            commitment in prop_oneof![
                arb_hash().prop_map(Commitment::Hash),
                collection::vec(arbitrary::any::<u8>(), 0..=1024).prop_map(Commitment::Id),
            ],
        ) -> Commitment {
            commitment
        }
    }

    prop_compose! {
        /// Generate an arbitrary code section
        pub fn arb_code()(
            salt: [u8; 8],
            code in arb_commitment(),
            tag in option::of("[a-zA-Z0-9_]*"),
        ) -> Code {
            Code {
                salt,
                code,
                tag,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary utf8 commitment
        pub fn arb_utf8_commitment()(
            commitment in prop_oneof![
                arb_hash().prop_map(Commitment::Hash),
                "[a-zA-Z0-9_]{0,1024}".prop_map(|x| Commitment::Id(x.into_bytes())),
            ],
        ) -> Commitment {
            commitment
        }
    }

    prop_compose! {
        /// Generate an arbitrary code section
        pub fn arb_utf8_code()(
            salt: [u8; 8],
            code in arb_utf8_commitment(),
            tag in option::of("[a-zA-Z0-9_]{0,1024}"),
        ) -> Code {
            Code {
                salt,
                code,
                tag,
            }
        }
    }

    prop_compose! {
        /// Generate a chain ID
        pub fn arb_chain_id()(id in "[a-zA-Z0-9_]*") -> ChainId {
            ChainId(id)
        }
    }

    prop_compose! {
        /// Generate a date and time
        pub fn arb_date_time_utc()(
            secs in Utc.with_ymd_and_hms(0, 1, 1, 0, 0, 0).unwrap().timestamp()..=Utc.with_ymd_and_hms(9999, 12, 31, 23, 59, 59).unwrap().timestamp(),
            nsecs in ..1000000000u32,
        ) -> DateTimeUtc {
            DateTimeUtc(DateTime::<Utc>::from_timestamp(secs, nsecs).unwrap())
        }
    }

    prop_compose! {
        /// Generate an arbitrary fee
        pub fn arb_fee()(
            amount_per_gas_unit in arb_denominated_amount(),
            token in arb_non_internal_address(),
        ) -> Fee {
            Fee {
                amount_per_gas_unit,
                token,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary gas limit
        pub fn arb_gas_limit()(multiplier: u64) -> GasLimit {
            multiplier.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary wrapper transaction. Do not check fee validity
        pub fn arb_unchecked_wrapper_tx()(
            fee in arb_fee(),
            pk in arb_common_pk(),
            gas_limit in arb_gas_limit(),
        ) -> WrapperTx {
            WrapperTx {
                fee,
                pk,
                gas_limit,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary wrapper transaction with valid fees
        pub fn arb_wrapper_tx()(
            wrapper in arb_unchecked_wrapper_tx().prop_filter(
                "wrapper fees overflow",
                |x| x.get_tx_fee().is_ok(),
            ),
        ) -> WrapperTx {
            wrapper
        }
    }

    prop_compose! {
        /// Generate an arbitrary transaction type
        pub fn arb_tx_type()(tx_type in prop_oneof![
            Just(TxType::Raw),
            arb_wrapper_tx().prop_map(|x| TxType::Wrapper(Box::new(x))),
        ]) -> TxType {
            tx_type
        }
    }

    prop_compose! {
        /// Generate an arbitrary tx commitments
        pub fn arb_tx_commitment()(
            code_hash in arb_hash(),
            data_hash in arb_hash(),
            memo_hash in arb_hash(),
        ) -> TxCommitments {
            TxCommitments {
                data_hash,
                code_hash,
                memo_hash
            }
        }
    }

    /// Generate an arbitrary number of tx commitments
    pub fn arb_tx_commitments(
        number_of_cmts: impl Into<SizeRange>,
    ) -> impl Strategy<Value = HashSet<TxCommitments>> {
        collection::hash_set(arb_tx_commitment(), number_of_cmts)
            .prop_map(|s| s.into_iter().collect())
    }

    prop_compose! {
        /// Generate an arbitrary header
        pub fn arb_header(cmt_count: impl Into<SizeRange>,)(
            chain_id in arb_chain_id(),
            expiration in option::of(arb_date_time_utc()),
            timestamp in arb_date_time_utc(),
            batch in arb_tx_commitments(cmt_count),
            atomic in proptest::bool::ANY,
            tx_type in arb_tx_type(),
        ) -> Header {
            Header {
                chain_id,
                expiration,
                timestamp,
                batch,
                atomic,
                tx_type,
            }
        }
    }

    // Maximum number of notes to include in a transaction
    const MAX_ASSETS: usize = 2;

    prop_compose! {
        /// Generate an arbitrary transfer
        pub fn arb_transfer()(
            arb in prop_oneof![
                arb_transparent_transfer(..5).prop_map(|xfer| (xfer, None)),
                arb_shielded_transfer(0..MAX_ASSETS)
                    .prop_map(|(w, x, y, z)| (w, Some((x, y, z))))
            ],
        ) -> (Transfer, Option<(ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams)>) {
            arb
        }
    }

    prop_compose! {
        /// Generate an arbitrary masp transfer transaction
        pub fn arb_transfer_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            code_hash in arb_hash(),
            (transfer, aux) in arb_transfer(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_code_from_hash(code_hash, Some(TX_TRANSFER_WASM.to_owned()));
            tx.add_data(transfer.clone());
            if let Some((shielded_transfer, asset_types, build_params)) = aux {
                let shielded_section_hash =
                    tx.add_masp_tx_section(shielded_transfer.masp_tx).1;
                tx.add_masp_builder(MaspBuilder {
                    asset_types: asset_types.into_keys().collect(),
                    // Store how the Info objects map to Descriptors/Outputs
                    metadata: shielded_transfer.metadata,
                    // Store the data that was used to construct the Transaction
                    builder: shielded_transfer.builder,
                    // Link the Builder to the Transaction by hash code
                    target: shielded_section_hash,
                });
                let build_param_bytes =
                    data_encoding::HEXLOWER.encode(&build_params.serialize_to_vec());
                (tx, TxData::Transfer(transfer, Some((build_params, build_param_bytes))))
            } else {
                (tx, TxData::Transfer(transfer, None))
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary bond transaction
        pub fn arb_bond_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            bond in arb_bond(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(bond.clone());
            tx.add_code_from_hash(code_hash, Some(TX_BOND_WASM.to_owned()));
            (tx, TxData::Bond(bond))
        }
    }

    prop_compose! {
        /// Generate an arbitrary bond transaction
        pub fn arb_unbond_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            unbond in arb_bond(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(unbond.clone());
            tx.add_code_from_hash(code_hash, Some(TX_UNBOND_WASM.to_owned()));
            (tx, TxData::Unbond(unbond))
        }
    }

    prop_compose! {
        /// Generate an arbitrary account initialization transaction
        pub fn arb_init_account_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            mut init_account in arb_init_account(),
            extra_data in arb_code(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            let vp_code_hash = tx.add_section(Section::ExtraData(extra_data)).get_hash();
            init_account.vp_code_hash = vp_code_hash;
            tx.add_data(init_account.clone());
            tx.add_code_from_hash(code_hash, Some(TX_INIT_ACCOUNT_WASM.to_owned()));
            (tx, TxData::InitAccount(init_account))
        }
    }

    prop_compose! {
        /// Generate an arbitrary account initialization transaction
        pub fn arb_become_validator_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            become_validator in arb_become_validator(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(become_validator.clone());
            tx.add_code_from_hash(code_hash, Some(TX_BECOME_VALIDATOR_WASM.to_owned()));
            (tx, TxData::InitValidator(become_validator))
        }
    }

    prop_compose! {
        /// Generate an arbitrary proposal initialization transaction
        pub fn arb_init_proposal_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            mut init_proposal in arb_init_proposal(),
            content_extra_data in arb_code(),
            type_extra_data in arb_code(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            let content_hash = tx.add_section(Section::ExtraData(content_extra_data)).get_hash();
            init_proposal.content = content_hash;
            if let ProposalType::DefaultWithWasm(hash) = &mut init_proposal.r#type {
                let type_hash = tx.add_section(Section::ExtraData(type_extra_data)).get_hash();
                *hash = type_hash;
            }
            tx.add_data(init_proposal.clone());
            tx.add_code_from_hash(code_hash, Some(TX_INIT_PROPOSAL.to_owned()));
            (tx, TxData::InitProposal(init_proposal))
        }
    }

    prop_compose! {
        /// Generate an arbitrary transaction with maybe a valid memo
        pub fn arb_memoed_tx()(
            (mut tx, tx_data) in arb_tx(),
            memo in option::of(arb_utf8_code()),
        ) -> (Tx, TxData) {
            // Clean up any previous memo commitments
            let mut batch: Vec<_> = tx.header.batch.iter().cloned().collect();
            for inner_tx in batch.iter_mut() {
                inner_tx.memo_hash = Default::default();
            }
            tx.header.batch = batch.into_iter().collect();

            if let Some(memo) = memo {
                let sechash = tx
                    .add_section(Section::ExtraData(memo))
                    .get_hash();
                tx.set_memo_sechash(sechash);
            } else {
                tx.set_memo_sechash(Default::default());
            }
            (tx, tx_data)
        }
    }

    prop_compose! {
        /// Generate an arbitrary vote proposal transaction
        pub fn arb_vote_proposal_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            vote_proposal in arb_vote_proposal(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(vote_proposal.clone());
            tx.add_code_from_hash(code_hash, Some(TX_VOTE_PROPOSAL.to_owned()));
            (tx, TxData::VoteProposal(vote_proposal))
        }
    }

    prop_compose! {
        /// Generate an arbitrary reveal public key transaction
        pub fn arb_reveal_pk_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            pk in arb_common_pk(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(pk.clone());
            tx.add_code_from_hash(code_hash, Some(TX_REVEAL_PK.to_owned()));
            (tx, TxData::RevealPk(pk))
        }
    }

    prop_compose! {
        /// Generate an arbitrary account initialization transaction
        pub fn arb_update_account_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            mut update_account in arb_update_account(),
            extra_data in arb_code(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            if let Some(vp_code_hash) = &mut update_account.vp_code_hash {
                let new_code_hash = tx.add_section(Section::ExtraData(extra_data)).get_hash();
                *vp_code_hash = new_code_hash;
            }
            tx.add_data(update_account.clone());
            tx.add_code_from_hash(code_hash, Some(TX_UPDATE_ACCOUNT_WASM.to_owned()));
            (tx, TxData::UpdateAccount(update_account))
        }
    }

    prop_compose! {
        /// Generate an arbitrary reveal public key transaction
        pub fn arb_withdraw_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            withdraw in arb_withdraw(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(withdraw.clone());
            tx.add_code_from_hash(code_hash, Some(TX_WITHDRAW_WASM.to_owned()));
            (tx, TxData::Withdraw(withdraw))
        }
    }

    prop_compose! {
        /// Generate an arbitrary claim rewards transaction
        pub fn arb_claim_rewards_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            claim_rewards in arb_withdraw(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(claim_rewards.clone());
            tx.add_code_from_hash(code_hash, Some(TX_CLAIM_REWARDS_WASM.to_owned()));
            (tx, TxData::ClaimRewards(claim_rewards))
        }
    }

    prop_compose! {
        /// Generate an arbitrary commission change transaction
        pub fn arb_commission_change_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            commission_change in arb_commission_change(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(commission_change.clone());
            tx.add_code_from_hash(code_hash, Some(TX_CHANGE_COMMISSION_WASM.to_owned()));
            (tx, TxData::CommissionChange(commission_change))
        }
    }

    prop_compose! {
        /// Generate an arbitrary commission change transaction
        pub fn arb_metadata_change_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            metadata_change in arb_metadata_change(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(metadata_change.clone());
            tx.add_code_from_hash(code_hash, Some(TX_CHANGE_METADATA_WASM.to_owned()));
            (tx, TxData::MetaDataChange(metadata_change))
        }
    }

    prop_compose! {
        /// Generate an arbitrary unjail validator transaction
        pub fn arb_unjail_validator_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            address in arb_non_internal_address(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(address.clone());
            tx.add_code_from_hash(code_hash, Some(TX_UNJAIL_VALIDATOR_WASM.to_owned()));
            (tx, TxData::UnjailValidator(address))
        }
    }

    prop_compose! {
        /// Generate an arbitrary deactivate validator transaction
        pub fn arb_deactivate_validator_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            address in arb_non_internal_address(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(address.clone());
            tx.add_code_from_hash(code_hash, Some(TX_DEACTIVATE_VALIDATOR_WASM.to_owned()));
            (tx, TxData::DeactivateValidator(address))
        }
    }

    prop_compose! {
        /// Generate an arbitrary reactivate validator transaction
        pub fn arb_reactivate_validator_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            address in arb_non_internal_address(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(address.clone());
            tx.add_code_from_hash(code_hash, Some(TX_REACTIVATE_VALIDATOR_WASM.to_owned()));
            (tx, TxData::ReactivateValidator(address))
        }
    }

    prop_compose! {
        /// Generate an arbitrary consensus key change transaction
        pub fn arb_consensus_key_change_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            consensus_key_change in arb_consensus_key_change(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(consensus_key_change.clone());
            tx.add_code_from_hash(code_hash, Some(TX_CHANGE_CONSENSUS_KEY_WASM.to_owned()));
            (tx, TxData::ConsensusKeyChange(consensus_key_change))
        }
    }

    prop_compose! {
        /// Generate an arbitrary redelegation transaction
        pub fn arb_redelegation_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            redelegation in arb_redelegation(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(redelegation.clone());
            tx.add_code_from_hash(code_hash, Some(TX_REDELEGATE_WASM.to_owned()));
            (tx, TxData::Redelegation(redelegation))
        }
    }

    prop_compose! {
        /// Generate an arbitrary redelegation transaction
        pub fn arb_update_steward_commission_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            update_steward_commission in arb_update_steward_commission(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(update_steward_commission.clone());
            tx.add_code_from_hash(code_hash, Some(TX_UPDATE_STEWARD_COMMISSION.to_owned()));
            (tx, TxData::UpdateStewardCommission(update_steward_commission))
        }
    }

    prop_compose! {
        /// Generate an arbitrary redelegation transaction
        pub fn arb_resign_steward_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            steward in arb_non_internal_address(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(steward.clone());
            tx.add_code_from_hash(code_hash, Some(TX_RESIGN_STEWARD.to_owned()));
            (tx, TxData::ResignSteward(steward))
        }
    }

    prop_compose! {
        /// Generate an arbitrary pending transfer transaction
        pub fn arb_pending_transfer_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            pending_transfer in arb_pending_transfer(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(pending_transfer.clone());
            tx.add_code_from_hash(code_hash, Some(TX_BRIDGE_POOL_WASM.to_owned()));
            (tx, TxData::PendingTransfer(pending_transfer))
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC transfer message
        pub fn arb_msg_transfer()(
            message in arb_ibc_msg_transfer(),
            transfer_aux in option::of(arb_transfer()),
        ) -> (
            MsgTransfer<token::Transfer>,
            Option<(ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams)>,
        ) {
            if let Some((transfer, aux)) = transfer_aux {
                (MsgTransfer { message, transfer: Some(transfer) }, aux)
            } else {
                (MsgTransfer { message, transfer: None }, None)
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC any transaction
        pub fn arb_ibc_msg_transfer_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            (msg_transfer, aux) in arb_msg_transfer(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_serialized_data(msg_transfer.serialize_to_vec());
            tx.add_code_from_hash(code_hash, Some(TX_IBC_WASM.to_owned()));
            if let Some((shielded_transfer, asset_types, build_params)) = aux {
                let shielded_section_hash =
                    tx.add_masp_tx_section(shielded_transfer.masp_tx).1;
                tx.add_masp_builder(MaspBuilder {
                    asset_types: asset_types.into_keys().collect(),
                    // Store how the Info objects map to Descriptors/Outputs
                    metadata: shielded_transfer.metadata,
                    // Store the data that was used to construct the Transaction
                    builder: shielded_transfer.builder,
                    // Link the Builder to the Transaction by hash code
                    target: shielded_section_hash,
                });
                let build_param_bytes =
                    data_encoding::HEXLOWER.encode(&build_params.serialize_to_vec());
                (tx, TxData::IbcMsgTransfer(msg_transfer, Some((build_params, build_param_bytes))))
            } else {
                (tx, TxData::IbcMsgTransfer(msg_transfer, None))
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC NFT transfer message
        pub fn arb_msg_nft_transfer()(
            message in arb_ibc_msg_nft_transfer(),
            transfer_aux in option::of(arb_transfer()),
        ) -> (
            MsgNftTransfer<token::Transfer>,
            Option<(ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams)>,
        ) {
            if let Some((transfer, aux)) = transfer_aux {
                (MsgNftTransfer { message, transfer: Some(transfer) }, aux)
            } else {
                (MsgNftTransfer { message, transfer: None }, None)
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC any transaction
        pub fn arb_ibc_msg_nft_transfer_tx()(
            mut header in arb_header(0),
            wrapper in arb_wrapper_tx(),
            (msg_transfer, aux) in arb_msg_nft_transfer(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_serialized_data(msg_transfer.serialize_to_vec());
            tx.add_code_from_hash(code_hash, Some(TX_IBC_WASM.to_owned()));
            if let Some((shielded_transfer, asset_types, build_params)) = aux {
                let shielded_section_hash =
                    tx.add_masp_tx_section(shielded_transfer.masp_tx).1;
                tx.add_masp_builder(MaspBuilder {
                    asset_types: asset_types.into_keys().collect(),
                    // Store how the Info objects map to Descriptors/Outputs
                    metadata: shielded_transfer.metadata,
                    // Store the data that was used to construct the Transaction
                    builder: shielded_transfer.builder,
                    // Link the Builder to the Transaction by hash code
                    target: shielded_section_hash,
                });
                let build_param_bytes =
                    data_encoding::HEXLOWER.encode(&build_params.serialize_to_vec());
                (tx, TxData::IbcMsgNftTransfer(msg_transfer, Some((build_params, build_param_bytes))))
            } else {
                (tx, TxData::IbcMsgNftTransfer(msg_transfer, None))
            }
        }
    }

    /// Generate an arbitrary tx
    pub fn arb_tx() -> impl Strategy<Value = (Tx, TxData)> {
        prop_oneof![
            arb_transfer_tx(),
            arb_bond_tx(),
            arb_unbond_tx(),
            arb_init_account_tx(),
            arb_become_validator_tx(),
            arb_init_proposal_tx(),
            arb_vote_proposal_tx(),
            arb_reveal_pk_tx(),
            arb_update_account_tx(),
            arb_withdraw_tx(),
            arb_claim_rewards_tx(),
            arb_commission_change_tx(),
            arb_metadata_change_tx(),
            arb_unjail_validator_tx(),
            arb_deactivate_validator_tx(),
            arb_reactivate_validator_tx(),
            arb_consensus_key_change_tx(),
            arb_redelegation_tx(),
            arb_update_steward_commission_tx(),
            arb_resign_steward_tx(),
            arb_pending_transfer_tx(),
            arb_ibc_msg_transfer_tx(),
            arb_ibc_msg_nft_transfer_tx(),
        ]
    }

    prop_compose! {
        /// Generate an arbitrary signature section
        pub fn arb_signature(targets: Vec<namada_core::hash::Hash>)(
            targets in Just(targets),
            secret_keys in collection::btree_map(
                arbitrary::any::<u8>(),
                arb_common_keypair(),
                1..3,
            ),
            signer in option::of(arb_non_internal_address()),
        ) -> Authorization {
            if signer.is_some() {
                Authorization::new(targets, secret_keys, signer)
            } else {
                let secret_keys = secret_keys
                    .into_values()
                    .enumerate()
                    .map(|(k, v)| (k as u8, v))
                    .collect();
                Authorization::new(targets, secret_keys, signer)
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary signed tx
        pub fn arb_signed_tx()(tx in arb_memoed_tx())(
            sigs in collection::vec(arb_signature(tx.0.sechashes()), 0..3),
            mut tx in Just(tx),
        ) -> (Tx, TxData) {
            for sig in sigs {
                // Add all the generated signature sections
                tx.0.add_section(Section::Authorization(sig));
            }
            (tx.0, tx.1)
        }
    }

    prop_compose! {
        /// Generate an arbitrary tx with a valid wrapper signature
        pub fn arb_valid_signed_tx()
        (
            (mut tx, _data) in arb_memoed_tx(),
            signer in arb_common_keypair(),
        ) -> Tx {
            // Sign the wrapper tx
            let mut wrapper = tx.header.wrapper().unwrap();
            wrapper.pk = signer.to_public();
            tx.update_header(TxType::Wrapper(Box::new(wrapper)));
            tx.sign_wrapper(signer);

            tx
        }
    }

    prop_compose! {
        /// Generate an arbitrary tx with a valid raw signature
        pub fn arb_valid_signed_inner_tx(signer: common::SecretKey)
        (
            (mut tx, _data) in arb_memoed_tx(),
        ) -> Tx {
            tx.update_header(TxType::Raw);
            // Sign the inner tx
            tx.sign_raw(
                vec![signer.clone()],
                vec![signer.ref_to()].into_iter().collect(),
                None
            );

            tx
        }
    }

    // An enumeration representing different ways to tamper with a transaction
    #[derive(Debug, Clone)]
    enum TamperTx {
        RemoveSection,
        AddExtraSection,
        SwapSection,
        SwapHeader,
    }

    prop_compose! {
        /// Generate an arbitrary signed wrapped tx that has been tampered with.
        pub fn arb_tampered_wrapper_tx()
        (tx1 in arb_valid_signed_tx())(
            tamper in prop_oneof![
                Just(TamperTx::RemoveSection),
                Just(TamperTx::AddExtraSection),
                Just(TamperTx::SwapSection),
                Just(TamperTx::SwapHeader)
            ],
            tx2 in arb_signed_tx(),
            selector in proptest::prelude::any::<proptest::prelude::prop::sample::Selector>(),
            mut tx in Just(tx1),
        ) -> Tx {
            match tamper {
               TamperTx::RemoveSection => {
                    let to_remove = selector.select(&tx.sections).to_owned();
                    tx.sections.retain(|section| section != &to_remove);

                    tx
                },
               TamperTx::AddExtraSection => {
                    let to_add = selector.select(&tx2.0.sections).to_owned();
                    tx.sections.push(to_add);

                    tx
                },
               TamperTx::SwapSection => {
                    let mut to_remove = selector.select(&tx.sections).to_owned();
                    let mut to_add = selector.select(&tx2.0.sections).to_owned();

                    // Try to pick different sections of the same type for the swap if possible
                    for source in tx.sections.iter() {
                        if let Some(target) = tx2.0.sections.iter().find(|section| {
                            std::mem::discriminant(*section) == std::mem::discriminant(&to_remove) && section.get_hash() != source.get_hash()
                        }) {
                            to_remove = source.to_owned();
                            to_add = target.to_owned();
                            break;
                        }
                    }

                    tx.sections.retain(|section| section != &to_remove);
                    tx.sections.push(to_add);

                    tx
                },
               TamperTx::SwapHeader => {
                    // Maintain the original wrapper signer
                    let mut new_wrapper = tx2.0.header.wrapper().unwrap();
                    new_wrapper.pk =  tx.header.wrapper().unwrap().pk;
                    tx.update_header(TxType::Wrapper(Box::new(new_wrapper)));

                    tx
                },
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary signed inner tx that has been tampered with.
        pub fn arb_tampered_inner_tx(signer: common::SecretKey)
        (tx1 in arb_valid_signed_inner_tx(signer.clone()))(
            tx2 in arb_valid_signed_inner_tx(signer.clone()),
            mut tx in Just(tx1),
        ) -> Tx {
            // Tamper with the header only since signature is computed on this alone
            tx.header = tx2.header;
            tx
        }
    }
}
