//! The CLI commands that are re-used between the executables `namada`,
//! `namada-node` and `namada-client`.
//!
//! The `namada` executable groups together the most commonly used commands
//! inlined from the node and the client. The other commands for the node or the
//! client can be dispatched via `namada node ...` or `namada client ...`,
//! respectively.

pub mod api;
pub mod client;
pub mod context;
pub mod relayer;
mod utils;
pub mod wallet;

use clap::{ArgGroup, ArgMatches, ColorChoice};
use color_eyre::eyre::Result;
use namada_sdk::io::StdIo;
use utils::*;
pub use utils::{Cmd, safe_exit};

pub use self::context::Context;
use crate::cli::api::CliIo;

const APP_NAME: &str = "Namada";

// Main Namada sub-commands
const NODE_CMD: &str = "node";
const CLIENT_CMD: &str = "client";
const WALLET_CMD: &str = "wallet";
const RELAYER_CMD: &str = "relayer";

pub mod cmds {
    use super::args::CliTypes;
    use super::utils::*;
    use super::{
        ArgMatches, CLIENT_CMD, NODE_CMD, RELAYER_CMD, WALLET_CMD, args,
    };
    use crate::wrap;

    /// Commands for `namada` binary.
    #[allow(clippy::large_enum_variant)]
    #[derive(Clone, Debug)]
    pub enum Namada {
        // Sub-binary-commands
        Node(NamadaNode),
        Relayer(NamadaRelayer),
        Client(NamadaClient),
        Wallet(NamadaWallet),

        // Inlined commands from the node.
        Ledger(Ledger),

        // Inlined commands from the relayer.
        EthBridgePool(EthBridgePool),

        // Inlined commands from the client.
        TxCustom(TxCustom),
        TxTransparentTransfer(TxTransparentTransfer),
        TxShieldedTransfer(TxShieldedTransfer),
        TxShieldingTransfer(TxShieldingTransfer),
        TxUnshieldingTransfer(TxUnshieldingTransfer),
        TxIbcTransfer(TxIbcTransfer),
        TxOsmosisSwap(TxOsmosisSwap),
        TxUpdateAccount(TxUpdateAccount),
        TxInitProposal(TxInitProposal),
        TxVoteProposal(TxVoteProposal),
        TxRevealPk(TxRevealPk),

        // Generate CLI completions
        Complete(Complete),
    }

    impl Cmd for Namada {
        fn add_sub(app: App) -> App {
            app.subcommand(NamadaNode::def().display_order(1))
                .subcommand(NamadaClient::def().display_order(1))
                .subcommand(NamadaWallet::def().display_order(1))
                .subcommand(Ledger::def().display_order(2))
                .subcommand(TxCustom::def().display_order(2))
                .subcommand(TxTransparentTransfer::def().display_order(2))
                .subcommand(TxShieldedTransfer::def().display_order(2))
                .subcommand(TxShieldingTransfer::def().display_order(2))
                .subcommand(TxUnshieldingTransfer::def().display_order(2))
                .subcommand(TxIbcTransfer::def().display_order(2))
                .subcommand(TxOsmosisSwap::def().display_order(2))
                .subcommand(TxUpdateAccount::def().display_order(2))
                .subcommand(TxInitProposal::def().display_order(2))
                .subcommand(TxVoteProposal::def().display_order(2))
                .subcommand(TxRevealPk::def().display_order(2))
                .subcommand(Complete::def().display_order(3))
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            let node = SubCmd::parse(matches).map(Self::Node);
            let client = SubCmd::parse(matches).map(Self::Client);
            let wallet = SubCmd::parse(matches).map(Self::Wallet);
            let ledger = SubCmd::parse(matches).map(Self::Ledger);
            let tx_custom = SubCmd::parse(matches).map(Self::TxCustom);
            let tx_transparent_transfer =
                SubCmd::parse(matches).map(Self::TxTransparentTransfer);
            let tx_shielded_transfer =
                SubCmd::parse(matches).map(Self::TxShieldedTransfer);
            let tx_shielding_transfer =
                SubCmd::parse(matches).map(Self::TxShieldingTransfer);
            let tx_unshielding_transfer =
                SubCmd::parse(matches).map(Self::TxUnshieldingTransfer);
            let tx_ibc_transfer =
                SubCmd::parse(matches).map(Self::TxIbcTransfer);
            let tx_osmosis_swap =
                SubCmd::parse(matches).map(Self::TxOsmosisSwap);
            let tx_update_account =
                SubCmd::parse(matches).map(Self::TxUpdateAccount);
            let tx_init_proposal =
                SubCmd::parse(matches).map(Self::TxInitProposal);
            let tx_vote_proposal =
                SubCmd::parse(matches).map(Self::TxVoteProposal);
            let tx_reveal_pk = SubCmd::parse(matches).map(Self::TxRevealPk);
            let complete = SubCmd::parse(matches).map(Self::Complete);
            node.or(client)
                .or(wallet)
                .or(ledger)
                .or(tx_custom)
                .or(tx_transparent_transfer)
                .or(tx_shielded_transfer)
                .or(tx_shielding_transfer)
                .or(tx_unshielding_transfer)
                .or(tx_ibc_transfer)
                .or(tx_osmosis_swap)
                .or(tx_update_account)
                .or(tx_init_proposal)
                .or(tx_vote_proposal)
                .or(tx_reveal_pk)
                .or(complete)
        }
    }

    /// Used as top-level commands (`Cmd` instance) in `namadan` binary.
    /// Used as sub-commands (`SubCmd` instance) in `namada` binary.
    #[derive(Clone, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum NamadaNode {
        Ledger(Ledger),
        Config(Config),
        Utils(NodeUtils),
    }

    impl Cmd for NamadaNode {
        fn add_sub(app: App) -> App {
            app.subcommand(Ledger::def())
                .subcommand(Config::def())
                .subcommand(NodeUtils::def())
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            let ledger = SubCmd::parse(matches).map(Self::Ledger);
            let config = SubCmd::parse(matches).map(Self::Config);
            let utils = SubCmd::parse(matches).map(Self::Utils);
            ledger.or(config).or(utils)
        }
    }
    impl SubCmd for NamadaNode {
        const CMD: &'static str = NODE_CMD;

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .and_then(<Self as Cmd>::parse)
        }

        fn def() -> App {
            <Self as Cmd>::add_sub(
                App::new(Self::CMD)
                    .about(wrap!("Node sub-commands."))
                    .subcommand_required(true)
                    .arg_required_else_help(true),
            )
        }
    }

    /// Used as top-level commands (`Cmd` instance) in `namadar` binary.
    /// Used as sub-commands (`SubCmd` instance) in `namada` binary.
    #[derive(Clone, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum NamadaRelayer {
        EthBridgePool(EthBridgePool),
        ValidatorSet(ValidatorSet),
    }

    impl Cmd for NamadaRelayer {
        fn add_sub(app: App) -> App {
            app.subcommand(EthBridgePool::def())
                .subcommand(ValidatorSet::def())
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            let eth_bridge_pool =
                SubCmd::parse(matches).map(Self::EthBridgePool);
            let validator_set = SubCmd::parse(matches).map(Self::ValidatorSet);
            eth_bridge_pool.or(validator_set)
        }
    }

    impl SubCmd for NamadaRelayer {
        const CMD: &'static str = RELAYER_CMD;

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .and_then(<Self as Cmd>::parse)
        }

        fn def() -> App {
            <Self as Cmd>::add_sub(
                App::new(Self::CMD)
                    .about(wrap!("Relayer sub-commands."))
                    .subcommand_required(true),
            )
        }
    }

    /// Used as top-level commands (`Cmd` instance) in `namadac` binary.
    /// Used as sub-commands (`SubCmd` instance) in `namada` binary.
    #[derive(Clone, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum NamadaClient {
        /// The [`super::Context`] provides access to the wallet and the
        /// config. It will generate a new wallet and config, if they
        /// don't exist.
        WithContext(NamadaClientWithContext),
        /// Utils don't have [`super::Context`], only the global arguments.
        WithoutContext(ClientUtils),
    }

    impl Cmd for NamadaClient {
        fn add_sub(app: App) -> App {
            app
                // Simple transactions
                .subcommand(TxCustom::def().display_order(1))
                .subcommand(TxTransparentTransfer::def().display_order(1))
                .subcommand(TxShieldedTransfer::def().display_order(1))
                .subcommand(TxShieldingTransfer::def().display_order(1))
                .subcommand(TxUnshieldingTransfer::def().display_order(1))
                .subcommand(TxIbcTransfer::def().display_order(1))
                .subcommand(TxOsmosisSwap::def().display_order(1))
                .subcommand(TxUpdateAccount::def().display_order(1))
                .subcommand(TxInitAccount::def().display_order(1))
                .subcommand(TxRevealPk::def().display_order(1))
                // Governance transactions
                .subcommand(TxInitProposal::def().display_order(1))
                .subcommand(TxVoteProposal::def().display_order(1))
                // PoS transactions
                .subcommand(TxBecomeValidator::def().display_order(2))
                .subcommand(TxInitValidator::def().display_order(2))
                .subcommand(TxUnjailValidator::def().display_order(2))
                .subcommand(TxDeactivateValidator::def().display_order(2))
                .subcommand(TxReactivateValidator::def().display_order(2))
                .subcommand(Bond::def().display_order(2))
                .subcommand(Unbond::def().display_order(2))
                .subcommand(Withdraw::def().display_order(2))
                .subcommand(Redelegate::def().display_order(2))
                .subcommand(ClaimRewards::def().display_order(2))
                .subcommand(TxCommissionRateChange::def().display_order(2))
                .subcommand(TxChangeConsensusKey::def().display_order(2))
                .subcommand(TxMetadataChange::def().display_order(2))
                // Ethereum bridge transactions
                .subcommand(AddToEthBridgePool::def().display_order(3))
                // PGF transactions
                .subcommand(TxUpdateStewardCommission::def().display_order(4))
                .subcommand(TxResignSteward::def().display_order(4))
                // Queries
                .subcommand(QueryEpoch::def().display_order(5))
                .subcommand(QueryNextEpochInfo::def().display_order(5))
                .subcommand(QueryStatus::def().display_order(5))
                .subcommand(QueryAccount::def().display_order(5))
                .subcommand(QueryConversions::def().display_order(5))
                .subcommand(QueryMaspRewardTokens::def().display_order(5))
                .subcommand(QueryBlock::def().display_order(5))
                .subcommand(QueryBalance::def().display_order(5))
                .subcommand(
                    QueryShieldingRewardsEstimate::def().display_order(5),
                )
                .subcommand(QueryBonds::def().display_order(5))
                .subcommand(QueryBondedStake::def().display_order(5))
                .subcommand(QuerySlashes::def().display_order(5))
                .subcommand(QueryDelegations::def().display_order(5))
                .subcommand(QueryFindValidator::def().display_order(5))
                .subcommand(QueryIbcRateLimit::def().display_order(5))
                .subcommand(QueryResult::def().display_order(5))
                .subcommand(QueryRawBytes::def().display_order(5))
                .subcommand(QueryProposal::def().display_order(5))
                .subcommand(QueryProposalVotes::def().display_order(5))
                .subcommand(QueryProposalResult::def().display_order(5))
                .subcommand(QueryProtocolParameters::def().display_order(5))
                .subcommand(QueryPgf::def().display_order(5))
                .subcommand(QueryValidatorState::def().display_order(5))
                .subcommand(QueryCommissionRate::def().display_order(5))
                .subcommand(QueryRewards::def().display_order(5))
                .subcommand(QueryMetaData::def().display_order(5))
                .subcommand(QueryTotalSupply::def().display_order(5))
                .subcommand(QueryEffNativeSupply::def().display_order(5))
                .subcommand(QueryStakingRewardsRate::def().display_order(5))
                // Actions
                .subcommand(ShieldedSync::def().display_order(6))
                .subcommand(GenIbcShieldingTransfer::def().display_order(6))
                // Utils
                .subcommand(ClientUtils::def().display_order(7))
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            use NamadaClientWithContext::*;
            let tx_custom = Self::parse_with_ctx(matches, TxCustom);
            let tx_transparent_transfer =
                Self::parse_with_ctx(matches, TxTransparentTransfer);
            let tx_shielded_transfer =
                Self::parse_with_ctx(matches, TxShieldedTransfer);
            let tx_shielding_transfer =
                Self::parse_with_ctx(matches, TxShieldingTransfer);
            let tx_unshielding_transfer =
                Self::parse_with_ctx(matches, TxUnshieldingTransfer);
            let tx_ibc_transfer = Self::parse_with_ctx(matches, TxIbcTransfer);
            let tx_osmosis_swap = Self::parse_with_ctx(matches, |cmd| {
                TxOsmosisSwap(Box::new(cmd))
            });
            let tx_update_account =
                Self::parse_with_ctx(matches, TxUpdateAccount);
            let tx_init_account = Self::parse_with_ctx(matches, TxInitAccount);
            let tx_become_validator =
                Self::parse_with_ctx(matches, TxBecomeValidator);
            let tx_init_validator =
                Self::parse_with_ctx(matches, TxInitValidator);
            let tx_unjail_validator =
                Self::parse_with_ctx(matches, TxUnjailValidator);
            let tx_deactivate_validator =
                Self::parse_with_ctx(matches, TxDeactivateValidator);
            let tx_reactivate_validator =
                Self::parse_with_ctx(matches, TxReactivateValidator);
            let tx_reveal_pk = Self::parse_with_ctx(matches, TxRevealPk);
            let tx_init_proposal =
                Self::parse_with_ctx(matches, TxInitProposal);
            let tx_vote_proposal =
                Self::parse_with_ctx(matches, TxVoteProposal);
            let tx_update_steward_commission =
                Self::parse_with_ctx(matches, TxUpdateStewardCommission);
            let tx_resign_steward =
                Self::parse_with_ctx(matches, TxResignSteward);
            let tx_commission_rate_change =
                Self::parse_with_ctx(matches, TxCommissionRateChange);
            let tx_change_consensus_key =
                Self::parse_with_ctx(matches, TxChangeConsensusKey);
            let tx_change_metadata =
                Self::parse_with_ctx(matches, TxMetadataChange);
            let bond = Self::parse_with_ctx(matches, Bond);
            let unbond = Self::parse_with_ctx(matches, Unbond);
            let withdraw = Self::parse_with_ctx(matches, Withdraw);
            let redelegate = Self::parse_with_ctx(matches, Redelegate);
            let claim_rewards = Self::parse_with_ctx(matches, ClaimRewards);
            let query_epoch = Self::parse_with_ctx(matches, QueryEpoch);
            let query_next_epoch_info =
                Self::parse_with_ctx(matches, QueryNextEpochInfo);
            let query_status = Self::parse_with_ctx(matches, QueryStatus);
            let query_account = Self::parse_with_ctx(matches, QueryAccount);
            let query_conversions =
                Self::parse_with_ctx(matches, QueryConversions);
            let query_masp_reward_tokens =
                Self::parse_with_ctx(matches, QueryMaspRewardTokens);
            let query_block = Self::parse_with_ctx(matches, QueryBlock);
            let query_balance = Self::parse_with_ctx(matches, QueryBalance);
            let query_rewards_estimate =
                Self::parse_with_ctx(matches, QueryShieldingRewardsEstimate);
            let query_bonds = Self::parse_with_ctx(matches, QueryBonds);
            let query_bonded_stake =
                Self::parse_with_ctx(matches, QueryBondedStake);
            let query_slashes = Self::parse_with_ctx(matches, QuerySlashes);
            let query_rewards = Self::parse_with_ctx(matches, QueryRewards);
            let query_delegations =
                Self::parse_with_ctx(matches, QueryDelegations);
            let query_total_supply =
                Self::parse_with_ctx(matches, QueryTotalSupply);
            let query_native_supply =
                Self::parse_with_ctx(matches, QueryEffNativeSupply);
            let query_staking_rewards_rate =
                Self::parse_with_ctx(matches, QueryStakingRewardsRate);
            let query_find_validator =
                Self::parse_with_ctx(matches, QueryFindValidator);
            let query_result = Self::parse_with_ctx(matches, QueryResult);
            let query_raw_bytes = Self::parse_with_ctx(matches, QueryRawBytes);
            let query_proposal = Self::parse_with_ctx(matches, QueryProposal);
            let query_proposal_votes =
                Self::parse_with_ctx(matches, QueryProposalVotes);
            let query_proposal_result =
                Self::parse_with_ctx(matches, QueryProposalResult);
            let query_protocol_parameters =
                Self::parse_with_ctx(matches, QueryProtocolParameters);
            let query_pgf = Self::parse_with_ctx(matches, QueryPgf);
            let query_validator_state =
                Self::parse_with_ctx(matches, QueryValidatorState);
            let query_commission =
                Self::parse_with_ctx(matches, QueryCommissionRate);
            let query_metadata = Self::parse_with_ctx(matches, QueryMetaData);
            let query_ibc_rate_limit =
                Self::parse_with_ctx(matches, QueryIbcRateLimit);
            let add_to_eth_bridge_pool =
                Self::parse_with_ctx(matches, AddToEthBridgePool);
            let shielded_sync = Self::parse_with_ctx(matches, ShieldedSync);
            let gen_ibc_shielding =
                Self::parse_with_ctx(matches, GenIbcShieldingTransfer);
            let utils = SubCmd::parse(matches).map(Self::WithoutContext);
            tx_custom
                .or(tx_transparent_transfer)
                .or(tx_shielded_transfer)
                .or(tx_shielding_transfer)
                .or(tx_unshielding_transfer)
                .or(tx_ibc_transfer)
                .or(tx_osmosis_swap)
                .or(tx_update_account)
                .or(tx_init_account)
                .or(tx_reveal_pk)
                .or(tx_init_proposal)
                .or(tx_vote_proposal)
                .or(tx_become_validator)
                .or(tx_init_validator)
                .or(tx_commission_rate_change)
                .or(tx_change_consensus_key)
                .or(tx_change_metadata)
                .or(tx_unjail_validator)
                .or(tx_deactivate_validator)
                .or(tx_reactivate_validator)
                .or(bond)
                .or(unbond)
                .or(withdraw)
                .or(redelegate)
                .or(claim_rewards)
                .or(add_to_eth_bridge_pool)
                .or(tx_update_steward_commission)
                .or(tx_resign_steward)
                .or(query_epoch)
                .or(query_next_epoch_info)
                .or(query_status)
                .or(query_conversions)
                .or(query_masp_reward_tokens)
                .or(query_block)
                .or(query_balance)
                .or(query_rewards_estimate)
                .or(query_bonds)
                .or(query_bonded_stake)
                .or(query_slashes)
                .or(query_rewards)
                .or(query_delegations)
                .or(query_find_validator)
                .or(query_result)
                .or(query_raw_bytes)
                .or(query_proposal)
                .or(query_proposal_votes)
                .or(query_proposal_result)
                .or(query_protocol_parameters)
                .or(query_pgf)
                .or(query_validator_state)
                .or(query_commission)
                .or(query_metadata)
                .or(query_total_supply)
                .or(query_native_supply)
                .or(query_staking_rewards_rate)
                .or(query_account)
                .or(query_ibc_rate_limit)
                .or(shielded_sync)
                .or(gen_ibc_shielding)
                .or(utils)
        }
    }

    impl NamadaClient {
        /// A helper method to parse sub cmds with context
        fn parse_with_ctx<T: SubCmd>(
            matches: &ArgMatches,
            sub_to_self: impl Fn(T) -> NamadaClientWithContext,
        ) -> Option<Self> {
            SubCmd::parse(matches)
                .map(|sub| Self::WithContext(sub_to_self(sub)))
        }
    }

    impl SubCmd for NamadaClient {
        const CMD: &'static str = CLIENT_CMD;

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .and_then(<Self as Cmd>::parse)
        }

        fn def() -> App {
            <Self as Cmd>::add_sub(
                App::new(Self::CMD)
                    .about(wrap!("Client sub-commands."))
                    .subcommand_required(true)
                    .arg_required_else_help(true),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub enum NamadaClientWithContext {
        // Ledger cmds
        TxCustom(TxCustom),
        TxTransparentTransfer(TxTransparentTransfer),
        TxShieldedTransfer(TxShieldedTransfer),
        TxShieldingTransfer(TxShieldingTransfer),
        TxUnshieldingTransfer(TxUnshieldingTransfer),
        TxIbcTransfer(TxIbcTransfer),
        TxOsmosisSwap(Box<TxOsmosisSwap>),
        QueryResult(QueryResult),
        TxUpdateAccount(TxUpdateAccount),
        TxInitAccount(TxInitAccount),
        TxBecomeValidator(TxBecomeValidator),
        TxInitValidator(TxInitValidator),
        TxCommissionRateChange(TxCommissionRateChange),
        TxChangeConsensusKey(TxChangeConsensusKey),
        TxMetadataChange(TxMetadataChange),
        TxUnjailValidator(TxUnjailValidator),
        TxDeactivateValidator(TxDeactivateValidator),
        TxReactivateValidator(TxReactivateValidator),
        TxInitProposal(TxInitProposal),
        TxVoteProposal(TxVoteProposal),
        TxRevealPk(TxRevealPk),
        Bond(Bond),
        Unbond(Unbond),
        Withdraw(Withdraw),
        ClaimRewards(ClaimRewards),
        Redelegate(Redelegate),
        AddToEthBridgePool(AddToEthBridgePool),
        TxUpdateStewardCommission(TxUpdateStewardCommission),
        TxResignSteward(TxResignSteward),
        QueryEpoch(QueryEpoch),
        QueryNextEpochInfo(QueryNextEpochInfo),
        QueryStatus(QueryStatus),
        QueryAccount(QueryAccount),
        QueryConversions(QueryConversions),
        QueryMaspRewardTokens(QueryMaspRewardTokens),
        QueryBlock(QueryBlock),
        QueryBalance(QueryBalance),
        QueryShieldingRewardsEstimate(QueryShieldingRewardsEstimate),
        QueryBonds(QueryBonds),
        QueryBondedStake(QueryBondedStake),
        QueryCommissionRate(QueryCommissionRate),
        QueryMetaData(QueryMetaData),
        QuerySlashes(QuerySlashes),
        QueryDelegations(QueryDelegations),
        QueryTotalSupply(QueryTotalSupply),
        QueryEffNativeSupply(QueryEffNativeSupply),
        QueryStakingRewardsRate(QueryStakingRewardsRate),
        QueryFindValidator(QueryFindValidator),
        QueryRawBytes(QueryRawBytes),
        QueryProposal(QueryProposal),
        QueryProposalVotes(QueryProposalVotes),
        QueryProposalResult(QueryProposalResult),
        QueryProtocolParameters(QueryProtocolParameters),
        QueryPgf(QueryPgf),
        QueryValidatorState(QueryValidatorState),
        QueryRewards(QueryRewards),
        QueryIbcRateLimit(QueryIbcRateLimit),
        ShieldedSync(ShieldedSync),
        GenIbcShieldingTransfer(GenIbcShieldingTransfer),
    }

    #[allow(clippy::large_enum_variant)]
    #[derive(Clone, Debug)]
    pub enum NamadaWallet {
        /// Key generation
        KeyGen(WalletGen),
        /// Key derivation
        KeyDerive(WalletDerive),
        /// Payment address generation
        PayAddrGen(WalletGenPaymentAddress),
        /// Key / address list
        KeyAddrList(WalletListKeysAddresses),
        /// Key / address search
        KeyAddrFind(WalletFindKeysAddresses),
        /// Key export
        KeyExport(WalletExportKey),
        /// Key convert
        KeyConvert(WalletConvertKey),
        /// Key import
        KeyImport(WalletImportKey),
        /// Key / address add
        KeyAddrAdd(WalletAddKeyAddress),
        /// Key / address remove
        KeyAddrRemove(WalletRemoveKeyAddress),
    }

    impl Cmd for NamadaWallet {
        fn add_sub(app: App) -> App {
            app.subcommand(WalletGen::def())
                .subcommand(WalletDerive::def())
                .subcommand(WalletGenPaymentAddress::def())
                .subcommand(WalletListKeysAddresses::def())
                .subcommand(WalletFindKeysAddresses::def())
                .subcommand(WalletExportKey::def())
                .subcommand(WalletConvertKey::def())
                .subcommand(WalletImportKey::def())
                .subcommand(WalletAddKeyAddress::def())
                .subcommand(WalletRemoveKeyAddress::def())
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            let r#gen = SubCmd::parse(matches).map(Self::KeyGen);
            let derive = SubCmd::parse(matches).map(Self::KeyDerive);
            let pay_addr_gen = SubCmd::parse(matches).map(Self::PayAddrGen);
            let key_addr_list = SubCmd::parse(matches).map(Self::KeyAddrList);
            let key_addr_find = SubCmd::parse(matches).map(Self::KeyAddrFind);
            let export = SubCmd::parse(matches).map(Self::KeyExport);
            let convert = SubCmd::parse(matches).map(Self::KeyConvert);
            let import = SubCmd::parse(matches).map(Self::KeyImport);
            let key_addr_add = SubCmd::parse(matches).map(Self::KeyAddrAdd);
            let key_addr_remove =
                SubCmd::parse(matches).map(Self::KeyAddrRemove);
            r#gen
                .or(derive)
                .or(pay_addr_gen)
                .or(key_addr_list)
                .or(key_addr_find)
                .or(export)
                .or(convert)
                .or(import)
                .or(key_addr_add)
                .or(key_addr_remove)
        }
    }

    impl SubCmd for NamadaWallet {
        const CMD: &'static str = WALLET_CMD;

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .and_then(<Self as Cmd>::parse)
        }

        fn def() -> App {
            <Self as Cmd>::add_sub(
                App::new(Self::CMD)
                    .about(wrap!("Wallet sub-commands."))
                    .subcommand_required(true)
                    .arg_required_else_help(true),
            )
        }
    }

    /// In the transparent setting, generate a new keypair and an implicit
    /// address derived from it. In the shielded setting, generate a new
    /// spending key.
    #[derive(Clone, Debug)]
    pub struct WalletGen(pub args::KeyGen);

    impl SubCmd for WalletGen {
        const CMD: &'static str = "gen";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::KeyGen::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Generates a new transparent / shielded secret key."
                ))
                .long_about(wrap!(
                    "In the transparent setting, generates a keypair with a \
                     given alias and derives the implicit address from its \
                     public key. The address will be stored with the same \
                     alias.\nIn the shielded setting, generates a new \
                     spending key with a given alias.\nIn both settings, by \
                     default, an HD-key with a default derivation path is \
                     generated, with a random mnemonic code."
                ))
                .add_args::<args::KeyGen>()
        }
    }

    /// In the transparent setting, derive a keypair and implicit address from
    /// the mnemonic code.
    /// In the shielded setting, derive a spending key from the mnemonic code.
    #[derive(Clone, Debug)]
    pub struct WalletDerive(pub args::KeyDerive);

    impl SubCmd for WalletDerive {
        const CMD: &'static str = "derive";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::KeyDerive::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Derive transparent / shielded key from the mnemonic code \
                     or a seed stored on the hardware wallet device."
                ))
                .long_about(wrap!(
                    "In the transparent setting, derives a keypair from the \
                     given mnemonic code and HD derivation path and derives \
                     the implicit address from its public key. Stores the \
                     keypair and the address with the given alias.\nIn the \
                     shielded setting, derives a spending key.\nA hardware \
                     wallet can be used, in which case the private key is not \
                     derivable."
                ))
                .add_args::<args::KeyDerive>()
        }
    }

    /// List known keys and addresses
    #[derive(Clone, Debug)]
    pub struct WalletListKeysAddresses(pub args::KeyAddressList);

    impl SubCmd for WalletListKeysAddresses {
        const CMD: &'static str = "list";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| (Self(args::KeyAddressList::parse(matches))))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("List known keys and addresses in the wallet."))
                .long_about(wrap!(
                    "In the transparent setting, list known keypairs and \
                     addresses.\nIn the shielded setting, list known spending \
                     / viewing keys and payment addresses."
                ))
                .add_args::<args::KeyAddressList>()
        }
    }

    /// Find known keys and addresses
    #[derive(Clone, Debug)]
    pub struct WalletFindKeysAddresses(pub args::KeyAddressFind);

    impl SubCmd for WalletFindKeysAddresses {
        const CMD: &'static str = "find";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::KeyAddressFind::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Find known keys and addresses in the wallet."))
                .long_about(wrap!(
                    "In the transparent setting, searches for a keypair / \
                     address by a given alias, public key, or a public key \
                     hash. Looks up an alias of the given address.\nIn the \
                     shielded setting, searches for a spending / viewing key \
                     and payment address by a given alias. Looks up an alias \
                     of the given payment address."
                ))
                .add_args::<args::KeyAddressFind>()
        }
    }

    /// Export key to a file
    #[derive(Clone, Debug)]
    pub struct WalletExportKey(pub args::KeyExport);

    impl SubCmd for WalletExportKey {
        const CMD: &'static str = "export";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| (Self(args::KeyExport::parse(matches))))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Exports a transparent keypair / shielded spending key to \
                     a file."
                ))
                .add_args::<args::KeyExport>()
        }
    }

    /// Export key to a file
    #[derive(Clone, Debug)]
    pub struct WalletConvertKey(pub args::KeyConvert);

    impl SubCmd for WalletConvertKey {
        const CMD: &'static str = "convert";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| (Self(args::KeyConvert::parse(matches))))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Convert to tendermint priv_validator_key.json with your \
                     consensus key alias"
                ))
                .add_args::<args::KeyConvert>()
        }
    }

    /// Import key from a file
    #[derive(Clone, Debug)]
    pub struct WalletImportKey(pub args::KeyImport);

    impl SubCmd for WalletImportKey {
        const CMD: &'static str = "import";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| (Self(args::KeyImport::parse(matches))))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Imports a transparent keypair / shielded spending key \
                     from a file."
                ))
                .add_args::<args::KeyImport>()
        }
    }

    /// Add public / payment address to the wallet
    #[derive(Clone, Debug)]
    pub struct WalletAddKeyAddress(pub args::KeyAddressAdd);

    impl SubCmd for WalletAddKeyAddress {
        const CMD: &'static str = "add";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| (Self(args::KeyAddressAdd::parse(matches))))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Adds the given key or address to the wallet."))
                .add_args::<args::KeyAddressAdd>()
        }
    }

    /// Remove key / address
    #[derive(Clone, Debug)]
    pub struct WalletRemoveKeyAddress(pub args::KeyAddressRemove);

    impl SubCmd for WalletRemoveKeyAddress {
        const CMD: &'static str = "remove";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::KeyAddressRemove::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Remove the given alias and all associated keys / \
                     addresses from the wallet."
                ))
                .add_args::<args::KeyAddressRemove>()
        }
    }

    /// Generate a payment address from a viewing key or payment address
    #[derive(Clone, Debug)]
    pub struct WalletGenPaymentAddress(pub args::PayAddressGen);

    impl SubCmd for WalletGenPaymentAddress {
        const CMD: &'static str = "gen-payment-addr";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::PayAddressGen::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Generate the next payment address for a viewing key."
                ))
                .add_args::<args::PayAddressGen>()
        }
    }

    #[derive(Clone, Debug)]
    pub enum Ledger {
        Run(LedgerRun),
        RunUntil(LedgerRunUntil),
        Reset(LedgerReset),
        DumpDb(LedgerDumpDb),
        QueryDB(LedgerQueryDB),
        RollBack(LedgerRollBack),
    }

    impl SubCmd for Ledger {
        const CMD: &'static str = "ledger";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).and_then(|matches| {
                let run = SubCmd::parse(matches).map(Self::Run);
                let reset = SubCmd::parse(matches).map(Self::Reset);
                let dump_db = SubCmd::parse(matches).map(Self::DumpDb);
                let query_db = SubCmd::parse(matches).map(Self::QueryDB);
                let rollback = SubCmd::parse(matches).map(Self::RollBack);
                let run_until = SubCmd::parse(matches).map(Self::RunUntil);
                run.or(reset)
                    .or(dump_db)
                    .or(query_db)
                    .or(rollback)
                    .or(run_until)
                    // The `run` command is the default if no sub-command given
                    .or(Some(Self::Run(LedgerRun(args::LedgerRun {
                        start_time: None,
                        migration_path: None,
                        migration_hash: None,
                        migration_height: None,
                    }))))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Ledger node sub-commands. If no sub-command specified, \
                     defaults to run the node."
                ))
                .subcommand(LedgerRun::def())
                .subcommand(LedgerRunUntil::def())
                .subcommand(LedgerReset::def())
                .subcommand(LedgerDumpDb::def())
                .subcommand(LedgerQueryDB::def())
                .subcommand(LedgerRollBack::def())
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerRun(pub args::LedgerRun);

    impl SubCmd for LedgerRun {
        const CMD: &'static str = "run";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::LedgerRun::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Run Namada ledger node."))
                .add_args::<args::LedgerRun>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerRunUntil(pub args::LedgerRunUntil);

    impl SubCmd for LedgerRunUntil {
        const CMD: &'static str = "run-until";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::LedgerRunUntil::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Run Namada ledger node until a given height. Then halt \
                     or suspend."
                ))
                .add_args::<args::LedgerRunUntil>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerReset(pub args::LedgerReset);

    impl SubCmd for LedgerReset {
        const CMD: &'static str = "reset";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::LedgerReset::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Delete Namada ledger node's and Tendermint node's \
                     storage data. Unless ran with `--full-reset` flag, this \
                     command will preserve the chain's wallet, local and \
                     genesis configuration and validator key, if any."
                ))
                .add_args::<args::LedgerReset>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerDumpDb(pub args::LedgerDumpDb);

    impl SubCmd for LedgerDumpDb {
        const CMD: &'static str = "dump-db";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::LedgerDumpDb::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Dump Namada ledger node's DB from a block into a file."
                ))
                .add_args::<args::LedgerDumpDb>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerQueryDB(pub args::LedgerQueryDb);

    impl SubCmd for LedgerQueryDB {
        const CMD: &'static str = "query-db";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::LedgerQueryDb::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query the value of keys from the DB while the ledger is \
                     not running."
                ))
                .add_args::<args::LedgerQueryDb>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerRollBack;

    impl SubCmd for LedgerRollBack {
        const CMD: &'static str = "rollback";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|_matches| Self)
        }

        fn def() -> App {
            App::new(Self::CMD).about(wrap!(
                "Roll Namada state back to the previous height. This command \
                 does not create a backup of neither the Namada nor the \
                 Tendermint state before execution: for extra safety, it is \
                 recommended to make a backup in advance."
            ))
        }
    }

    #[derive(Clone, Debug)]
    pub enum Config {
        Gen(ConfigGen),
        UpdateValidatorLocalConfig(ValidatorLocalConfig),
        UpdateLocalConfig(LocalConfig),
    }

    impl SubCmd for Config {
        const CMD: &'static str = "config";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).and_then(|matches| {
                let r#gen = SubCmd::parse(matches).map(Self::Gen);
                let validator_cfg = SubCmd::parse(matches)
                    .map(Self::UpdateValidatorLocalConfig);
                let local_cfg =
                    SubCmd::parse(matches).map(Self::UpdateLocalConfig);
                r#gen.or(validator_cfg).or(local_cfg)
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .subcommand_required(true)
                .arg_required_else_help(true)
                .about(wrap!("Configuration sub-commands."))
                .subcommand(ConfigGen::def())
                .subcommand(ValidatorLocalConfig::def())
                .subcommand(LocalConfig::def())
        }
    }

    #[derive(Clone, Debug)]
    pub struct ConfigGen;

    impl SubCmd for ConfigGen {
        const CMD: &'static str = "gen";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|_matches| Self)
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Generate the default configuration file."))
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidatorLocalConfig(pub args::UpdateValidatorLocalConfig);

    impl SubCmd for ValidatorLocalConfig {
        const CMD: &'static str = "update-validator-local-config";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::UpdateValidatorLocalConfig::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Update the validator's local configuration."))
                .add_args::<args::UpdateValidatorLocalConfig>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct LocalConfig(pub args::UpdateLocalConfig);

    impl SubCmd for LocalConfig {
        const CMD: &'static str = "update-local-config";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::UpdateLocalConfig::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Update the node's local configuration."))
                .add_args::<args::UpdateLocalConfig>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryResult(pub args::QueryResult<args::CliTypes>);

    impl SubCmd for QueryResult {
        const CMD: &'static str = "tx-result";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryResult(args::QueryResult::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query the result of a transaction."))
                .add_args::<args::QueryResult<args::CliTypes>>()
        }
    }

    #[derive(Debug, Clone)]
    pub struct QueryProposalVotes(pub args::QueryProposalVotes<args::CliTypes>);

    impl SubCmd for QueryProposalVotes {
        const CMD: &'static str = "query-proposal-votes";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryProposalVotes(args::QueryProposalVotes::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query votes for the proposal."))
                .arg_required_else_help(true)
                .add_args::<args::QueryProposalVotes<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryProposal(pub args::QueryProposal<args::CliTypes>);

    impl SubCmd for QueryProposal {
        const CMD: &'static str = "query-proposal";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryProposal(args::QueryProposal::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query proposals."))
                .add_args::<args::QueryProposal<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryProposalResult(
        pub args::QueryProposalResult<args::CliTypes>,
    );

    impl SubCmd for QueryProposalResult {
        const CMD: &'static str = "query-proposal-result";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryProposalResult(args::QueryProposalResult::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query proposals result."))
                .add_args::<args::QueryProposalResult<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryProtocolParameters(
        pub args::QueryProtocolParameters<args::CliTypes>,
    );

    impl SubCmd for QueryProtocolParameters {
        const CMD: &'static str = "query-protocol-parameters";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryProtocolParameters(args::QueryProtocolParameters::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query protocol parameters."))
                .add_args::<args::QueryProtocolParameters<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryPgf(pub args::QueryPgf<args::CliTypes>);

    impl SubCmd for QueryPgf {
        const CMD: &'static str = "query-pgf";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryPgf(args::QueryPgf::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query PGF stewards and continuous funding."))
                .add_args::<args::QueryPgf<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxCustom(pub args::TxCustom<args::CliTypes>);

    impl SubCmd for TxCustom {
        const CMD: &'static str = "tx";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| TxCustom(args::TxCustom::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Send a transaction with custom WASM code."))
                .arg_required_else_help(true)
                .add_args::<args::TxCustom<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxTransparentTransfer(
        pub args::TxTransparentTransfer<crate::cli::args::CliTypes>,
    );

    impl SubCmd for TxTransparentTransfer {
        const CMD: &'static str = "transparent-transfer";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxTransparentTransfer(args::TxTransparentTransfer::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Send a transparent transfer transaction."))
                .add_args::<args::TxTransparentTransfer<crate::cli::args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxShieldedTransfer(
        pub args::TxShieldedTransfer<crate::cli::args::CliTypes>,
    );

    impl SubCmd for TxShieldedTransfer {
        const CMD: &'static str = "transfer";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxShieldedTransfer(args::TxShieldedTransfer::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Send a shielded transfer transaction (from a shielded address to a shielded address)."))
                .add_args::<args::TxShieldedTransfer<crate::cli::args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxShieldingTransfer(
        pub args::TxShieldingTransfer<crate::cli::args::CliTypes>,
    );

    impl SubCmd for TxShieldingTransfer {
        const CMD: &'static str = "shield";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxShieldingTransfer(args::TxShieldingTransfer::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Send a shielding transfer transaction (from a transparent address to a shielded address)."))
                .add_args::<args::TxShieldingTransfer<crate::cli::args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxUnshieldingTransfer(
        pub args::TxUnshieldingTransfer<crate::cli::args::CliTypes>,
    );

    impl SubCmd for TxUnshieldingTransfer {
        const CMD: &'static str = "unshield";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxUnshieldingTransfer(args::TxUnshieldingTransfer::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Send an unshielding transfer transaction (from a shielded address to a transparent address)."))
                .add_args::<args::TxUnshieldingTransfer<crate::cli::args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxIbcTransfer(pub args::TxIbcTransfer<args::CliTypes>);

    impl SubCmd for TxIbcTransfer {
        const CMD: &'static str = "ibc-transfer";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxIbcTransfer(args::TxIbcTransfer::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Send a signed IBC transfer transaction."))
                .add_args::<args::TxIbcTransfer<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxOsmosisSwap(pub args::TxOsmosisSwap<args::CliTypes>);

    impl SubCmd for TxOsmosisSwap {
        const CMD: &'static str = "osmosis-swap";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxOsmosisSwap(args::TxOsmosisSwap::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Swap two asset kinds using Osmosis."))
                .add_args::<args::TxOsmosisSwap<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxUpdateAccount(pub args::TxUpdateAccount<args::CliTypes>);

    impl SubCmd for TxUpdateAccount {
        const CMD: &'static str = "update-account";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxUpdateAccount(args::TxUpdateAccount::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Send a signed transaction to update account's validity \
                     predicate."
                ))
                .add_args::<args::TxUpdateAccount<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxInitAccount(pub args::TxInitAccount<args::CliTypes>);

    impl SubCmd for TxInitAccount {
        const CMD: &'static str = "init-account";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxInitAccount(args::TxInitAccount::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Send a signed transaction to create a new established \
                     account."
                ))
                .arg_required_else_help(true)
                .add_args::<args::TxInitAccount<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxBecomeValidator(pub args::TxBecomeValidator<args::CliTypes>);

    impl SubCmd for TxBecomeValidator {
        const CMD: &'static str = "become-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxBecomeValidator(args::TxBecomeValidator::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Send a signed transaction to become a validator."
                ))
                .add_args::<args::TxBecomeValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxInitValidator(pub args::TxInitValidator<args::CliTypes>);

    impl SubCmd for TxInitValidator {
        const CMD: &'static str = "init-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxInitValidator(args::TxInitValidator::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Send a signed transaction to create an established \
                     account and then become a validator."
                ))
                .add_args::<args::TxInitValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxUnjailValidator(pub args::TxUnjailValidator<args::CliTypes>);

    impl SubCmd for TxUnjailValidator {
        const CMD: &'static str = "unjail-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxUnjailValidator(args::TxUnjailValidator::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Send a signed transaction to unjail a jailed validator."
                ))
                .add_args::<args::TxUnjailValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxDeactivateValidator(
        pub args::TxDeactivateValidator<args::CliTypes>,
    );

    impl SubCmd for TxDeactivateValidator {
        const CMD: &'static str = "deactivate-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxDeactivateValidator(args::TxDeactivateValidator::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Send a signed transaction to deactivate a validator."
                ))
                .add_args::<args::TxDeactivateValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxReactivateValidator(
        pub args::TxReactivateValidator<args::CliTypes>,
    );

    impl SubCmd for TxReactivateValidator {
        const CMD: &'static str = "reactivate-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxReactivateValidator(args::TxReactivateValidator::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Send a signed transaction to reactivate an inactive \
                     validator."
                ))
                .add_args::<args::TxReactivateValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ShieldedSync(pub args::ShieldedSync<args::CliTypes>);

    impl SubCmd for ShieldedSync {
        const CMD: &'static str = "shielded-sync";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| ShieldedSync(args::ShieldedSync::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Sync the local shielded context with MASP notes owned by \
                     the provided viewing / spending keys up to an optional \
                     specified block height."
                ))
                .add_args::<args::ShieldedSync<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Bond(pub args::Bond<args::CliTypes>);

    impl SubCmd for Bond {
        const CMD: &'static str = "bond";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Bond(args::Bond::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Bond tokens in PoS system."))
                .add_args::<args::Bond<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Unbond(pub args::Unbond<args::CliTypes>);

    impl SubCmd for Unbond {
        const CMD: &'static str = "unbond";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Unbond(args::Unbond::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Unbond tokens from a PoS bond."))
                .add_args::<args::Unbond<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Withdraw(pub args::Withdraw<args::CliTypes>);

    impl SubCmd for Withdraw {
        const CMD: &'static str = "withdraw";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Withdraw(args::Withdraw::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Withdraw tokens from previously unbonded PoS bond."
                ))
                .add_args::<args::Withdraw<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ClaimRewards(pub args::ClaimRewards<args::CliTypes>);

    impl SubCmd for ClaimRewards {
        const CMD: &'static str = "claim-rewards";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| ClaimRewards(args::ClaimRewards::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Claim available rewards tokens from bonds that \
                     contributed in consensus."
                ))
                .add_args::<args::ClaimRewards<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Redelegate(pub args::Redelegate<args::CliTypes>);

    impl SubCmd for Redelegate {
        const CMD: &'static str = "redelegate";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Redelegate(args::Redelegate::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Redelegate bonded tokens from one validator to another."
                ))
                .add_args::<args::Redelegate<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryEpoch(pub args::Query<args::CliTypes>);

    impl SubCmd for QueryEpoch {
        const CMD: &'static str = "epoch";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryEpoch(args::Query::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query the epoch of the last committed block."))
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryNextEpochInfo(pub args::Query<args::CliTypes>);

    impl SubCmd for QueryNextEpochInfo {
        const CMD: &'static str = "next-epoch-info";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryNextEpochInfo(args::Query::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query some info to help discern when the next epoch will \
                     begin."
                ))
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryStatus(pub args::Query<args::CliTypes>);

    impl SubCmd for QueryStatus {
        const CMD: &'static str = "status";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryStatus(args::Query::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query the node's status."))
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryAccount(pub args::QueryAccount<args::CliTypes>);

    impl SubCmd for QueryAccount {
        const CMD: &'static str = "query-account";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryAccount(args::QueryAccount::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query the substorage space of a specific established \
                     address."
                ))
                .add_args::<args::QueryAccount<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryConversions(pub args::QueryConversions<args::CliTypes>);

    impl SubCmd for QueryConversions {
        const CMD: &'static str = "conversions";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryConversions(args::QueryConversions::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query currently applicable conversions."))
                .add_args::<args::QueryConversions<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryMaspRewardTokens(pub args::Query<args::CliTypes>);

    impl SubCmd for QueryMaspRewardTokens {
        const CMD: &'static str = "masp-reward-tokens";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryMaspRewardTokens(args::Query::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query the tokens which can earn MASP rewards while \
                     shielded."
                ))
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryBlock(pub args::Query<args::CliTypes>);

    impl SubCmd for QueryBlock {
        const CMD: &'static str = "block";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryBlock(args::Query::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query the last committed block."))
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryBalance(pub args::QueryBalance<args::CliTypes>);

    impl SubCmd for QueryBalance {
        const CMD: &'static str = "balance";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryBalance(args::QueryBalance::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query the token balance of some account."))
                .add_args::<args::QueryBalance<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryShieldingRewardsEstimate(
        pub args::QueryShieldingRewardsEstimate<args::CliTypes>,
    );

    impl SubCmd for QueryShieldingRewardsEstimate {
        const CMD: &'static str = "estimate-shielding-rewards";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryShieldingRewardsEstimate(
                    args::QueryShieldingRewardsEstimate::parse(matches),
                )
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Estimate the amount of MASP rewards for the \
                     next MASP epoch. Please run shielded-sync first for best \
                     results."
                ))
                .add_args::<args::QueryShieldingRewardsEstimate<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryBonds(pub args::QueryBonds<args::CliTypes>);

    impl SubCmd for QueryBonds {
        const CMD: &'static str = "bonds";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryBonds(args::QueryBonds::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query PoS bond(s)."))
                .add_args::<args::QueryBonds<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryBondedStake(pub args::QueryBondedStake<args::CliTypes>);

    impl SubCmd for QueryBondedStake {
        const CMD: &'static str = "bonded-stake";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryBondedStake(args::QueryBondedStake::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query PoS bonded stake."))
                .add_args::<args::QueryBondedStake<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryValidatorState(
        pub args::QueryValidatorState<args::CliTypes>,
    );

    impl SubCmd for QueryValidatorState {
        const CMD: &'static str = "validator-state";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryValidatorState(args::QueryValidatorState::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query the state of a PoS validator."))
                .add_args::<args::QueryValidatorState<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryCommissionRate(
        pub args::QueryCommissionRate<args::CliTypes>,
    );

    impl SubCmd for QueryCommissionRate {
        const CMD: &'static str = "commission-rate";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryCommissionRate(args::QueryCommissionRate::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query a validator's commission rate."))
                .add_args::<args::QueryCommissionRate<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryMetaData(pub args::QueryMetaData<args::CliTypes>);

    impl SubCmd for QueryMetaData {
        const CMD: &'static str = "validator-metadata";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryMetaData(args::QueryMetaData::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query a validator's metadata."))
                .add_args::<args::QueryMetaData<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QuerySlashes(pub args::QuerySlashes<args::CliTypes>);

    impl SubCmd for QuerySlashes {
        const CMD: &'static str = "slashes";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QuerySlashes(args::QuerySlashes::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query PoS applied slashes."))
                .add_args::<args::QuerySlashes<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryRewards(pub args::QueryRewards<args::CliTypes>);

    impl SubCmd for QueryRewards {
        const CMD: &'static str = "rewards";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| QueryRewards(args::QueryRewards::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query the rewards available to claim for a given \
                     delegation (or self-bond)."
                ))
                .add_args::<args::QueryRewards<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryDelegations(pub args::QueryDelegations<args::CliTypes>);

    impl SubCmd for QueryDelegations {
        const CMD: &'static str = "delegations";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryDelegations(args::QueryDelegations::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Find PoS delegations from the given owner address."
                ))
                .add_args::<args::QueryDelegations<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryTotalSupply(pub args::QueryTotalSupply<args::CliTypes>);

    impl SubCmd for QueryTotalSupply {
        const CMD: &'static str = "total-supply";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryTotalSupply(args::QueryTotalSupply::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query the total supply in the network of the given \
                     token. For the native token, this will query the raw \
                     total supply and not the effective total supply."
                ))
                .add_args::<args::QueryTotalSupply<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryEffNativeSupply(
        pub args::QueryEffNativeSupply<args::CliTypes>,
    );

    impl SubCmd for QueryEffNativeSupply {
        const CMD: &'static str = "native-supply";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryEffNativeSupply(args::QueryEffNativeSupply::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query the effective total circulating supply of the \
                     native token NAM. This excludes illquid NAM tokens held \
                     in places such as the PGF account. This is the token \
                     amount used in inflation calculations."
                ))
                .add_args::<args::QueryEffNativeSupply<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryStakingRewardsRate(
        pub args::QueryStakingRewardsRate<args::CliTypes>,
    );

    impl SubCmd for QueryStakingRewardsRate {
        const CMD: &'static str = "staking-rewards-rate";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryStakingRewardsRate(args::QueryStakingRewardsRate::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query the latest estimate of the staking rewards rate \
                     based on the most recent minted inflation amount at the \
                     last epoch change."
                ))
                .add_args::<args::QueryStakingRewardsRate<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryFindValidator(pub args::QueryFindValidator<args::CliTypes>);

    impl SubCmd for QueryFindValidator {
        const CMD: &'static str = "find-validator";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryFindValidator(args::QueryFindValidator::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Find a PoS validator and its consensus key by its native \
                     address or Tendermint address."
                ))
                .arg_required_else_help(true)
                .add_args::<args::QueryFindValidator<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryIbcRateLimit(pub args::QueryIbcRateLimit<args::CliTypes>);

    impl SubCmd for QueryIbcRateLimit {
        const CMD: &'static str = "query-ibc-rate-limits";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryIbcRateLimit(args::QueryIbcRateLimit::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query the IBC rate limit for the provided token."
                ))
                .add_args::<args::QueryIbcRateLimit<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryRawBytes(pub args::QueryRawBytes<args::CliTypes>);

    impl SubCmd for QueryRawBytes {
        const CMD: &'static str = "query-bytes";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                QueryRawBytes(args::QueryRawBytes::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Query the raw bytes of a given storage key"))
                .add_args::<args::QueryRawBytes<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxInitProposal(pub args::InitProposal<args::CliTypes>);

    impl SubCmd for TxInitProposal {
        const CMD: &'static str = "init-proposal";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxInitProposal(args::InitProposal::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Create a new proposal."))
                .add_args::<args::InitProposal<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxUpdateStewardCommission(
        pub args::UpdateStewardCommission<args::CliTypes>,
    );

    impl SubCmd for TxUpdateStewardCommission {
        const CMD: &'static str = "update-steward-rewards";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxUpdateStewardCommission(args::UpdateStewardCommission::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Update how steward commissions are split."))
                .add_args::<args::UpdateStewardCommission<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxResignSteward(pub args::ResignSteward<args::CliTypes>);

    impl SubCmd for TxResignSteward {
        const CMD: &'static str = "resign-steward";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxResignSteward(args::ResignSteward::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Craft a transaction to resign as a steward."))
                .add_args::<args::ResignSteward<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxCommissionRateChange(
        pub args::CommissionRateChange<args::CliTypes>,
    );

    impl SubCmd for TxCommissionRateChange {
        const CMD: &'static str = "change-commission-rate";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxCommissionRateChange(args::CommissionRateChange::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Change commission rate."))
                .add_args::<args::CommissionRateChange<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxMetadataChange(pub args::MetaDataChange<args::CliTypes>);

    impl SubCmd for TxMetadataChange {
        const CMD: &'static str = "change-metadata";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxMetadataChange(args::MetaDataChange::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Change validator's metadata, including the commission \
                     rate if desired."
                ))
                .add_args::<args::MetaDataChange<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxChangeConsensusKey(
        pub args::ConsensusKeyChange<args::CliTypes>,
    );

    impl SubCmd for TxChangeConsensusKey {
        const CMD: &'static str = "change-consensus-key";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxChangeConsensusKey(args::ConsensusKeyChange::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Change consensus key."))
                .add_args::<args::ConsensusKeyChange<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxVoteProposal(pub args::VoteProposal<args::CliTypes>);

    impl SubCmd for TxVoteProposal {
        const CMD: &'static str = "vote-proposal";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                TxVoteProposal(args::VoteProposal::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Vote a proposal."))
                .add_args::<args::VoteProposal<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TxRevealPk(pub args::RevealPk<args::CliTypes>);

    impl SubCmd for TxRevealPk {
        const CMD: &'static str = "reveal-pk";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| TxRevealPk(args::RevealPk::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Submit a tx to reveal the public key of an implicit \
                     account. Typically, you don't have to do this manually \
                     and the client will detect when a tx to reveal PK is \
                     needed and submit it automatically. This will write the \
                     PK into the account's storage so that it can be used for \
                     signature verification on transactions authorized by \
                     this account."
                ))
                .add_args::<args::RevealPk<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Complete(pub args::Complete);

    impl SubCmd for Complete {
        const CMD: &'static str = "complete";

        fn parse(matches: &ArgMatches) -> Option<Self>
        where
            Self: Sized,
        {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Complete(args::Complete::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Generate shell completions"))
                .add_args::<args::Complete>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct GenIbcShieldingTransfer(
        pub args::GenIbcShieldingTransfer<args::CliTypes>,
    );

    impl SubCmd for GenIbcShieldingTransfer {
        const CMD: &'static str = "ibc-gen-shielding";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                GenIbcShieldingTransfer(args::GenIbcShieldingTransfer::parse(
                    matches,
                ))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about("Generate shielding transfer for IBC.")
                .add_args::<args::GenIbcShieldingTransfer<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct EpochSleep(pub args::Query<args::CliTypes>);

    impl SubCmd for EpochSleep {
        const CMD: &'static str = "epoch-sleep";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::Query::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query for the current epoch, then sleep until the next \
                     epoch."
                ))
                .add_args::<args::Query<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub enum NodeUtils {
        TestGenesis(TestGenesis),
        DryRunProposal(DryRunProposal),
    }

    impl SubCmd for NodeUtils {
        const CMD: &'static str = "utils";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).and_then(|matches| {
                let test_genesis =
                    SubCmd::parse(matches).map(Self::TestGenesis);
                let dry_run_proposal =
                    SubCmd::parse(matches).map(Self::DryRunProposal);
                test_genesis.or(dry_run_proposal)
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Utilities."))
                .subcommand(TestGenesis::def())
                .subcommand(DryRunProposal::def())
                .subcommand_required(true)
                .arg_required_else_help(true)
        }
    }

    #[derive(Clone, Debug)]
    pub enum ClientUtils {
        JoinNetwork(JoinNetwork),
        ValidateWasm(ValidateWasm),
        InitNetwork(InitNetwork),
        DeriveGenesisAddresses(DeriveGenesisAddresses),
        GenesisBond(GenesisBond),
        InitGenesisEstablishedAccount(InitGenesisEstablishedAccount),
        InitGenesisValidator(InitGenesisValidator),
        PkToTmAddress(PkToTmAddress),
        SignOffline(SignOffline),
        DefaultBaseDir(DefaultBaseDir),
        EpochSleep(EpochSleep),
        ValidateGenesisTemplates(ValidateGenesisTemplates),
        SignGenesisTxs(SignGenesisTxs),
        ParseMigrationJson(MigrationJson),
        DeriveIbcToken(DeriveIbcToken),
        PubKeyToAddr(PubKeyToAddr),
    }

    impl SubCmd for ClientUtils {
        const CMD: &'static str = "utils";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).and_then(|matches| {
                let join_network =
                    SubCmd::parse(matches).map(Self::JoinNetwork);
                let validate_wasm =
                    SubCmd::parse(matches).map(Self::ValidateWasm);
                let init_network =
                    SubCmd::parse(matches).map(Self::InitNetwork);
                let derive_addresses =
                    SubCmd::parse(matches).map(Self::DeriveGenesisAddresses);
                let genesis_bond =
                    SubCmd::parse(matches).map(Self::GenesisBond);
                let init_established = SubCmd::parse(matches)
                    .map(Self::InitGenesisEstablishedAccount);
                let init_genesis =
                    SubCmd::parse(matches).map(Self::InitGenesisValidator);
                let pk_to_tm_address =
                    SubCmd::parse(matches).map(Self::PkToTmAddress);
                let sign_offline =
                    SubCmd::parse(matches).map(Self::SignOffline);
                let default_base_dir =
                    SubCmd::parse(matches).map(Self::DefaultBaseDir);
                let epoch_sleep = SubCmd::parse(matches).map(Self::EpochSleep);
                let validate_genesis_templates =
                    SubCmd::parse(matches).map(Self::ValidateGenesisTemplates);
                let genesis_tx =
                    SubCmd::parse(matches).map(Self::SignGenesisTxs);
                let parse_migrations_json =
                    SubCmd::parse(matches).map(Self::ParseMigrationJson);
                let derive_ibc_token =
                    SubCmd::parse(matches).map(Self::DeriveIbcToken);
                let pubkey_to_addr =
                    SubCmd::parse(matches).map(Self::PubKeyToAddr);
                join_network
                    .or(validate_wasm)
                    .or(init_network)
                    .or(derive_addresses)
                    .or(genesis_bond)
                    .or(init_established)
                    .or(init_genesis)
                    .or(pk_to_tm_address)
                    .or(default_base_dir)
                    .or(epoch_sleep)
                    .or(validate_genesis_templates)
                    .or(genesis_tx)
                    .or(parse_migrations_json)
                    .or(sign_offline)
                    .or(derive_ibc_token)
                    .or(pubkey_to_addr)
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Utilities."))
                .subcommand(JoinNetwork::def())
                .subcommand(ValidateWasm::def())
                .subcommand(InitNetwork::def())
                .subcommand(DeriveGenesisAddresses::def())
                .subcommand(GenesisBond::def())
                .subcommand(InitGenesisEstablishedAccount::def())
                .subcommand(InitGenesisValidator::def())
                .subcommand(PkToTmAddress::def())
                .subcommand(SignOffline::def())
                .subcommand(DefaultBaseDir::def())
                .subcommand(EpochSleep::def())
                .subcommand(ValidateGenesisTemplates::def())
                .subcommand(SignGenesisTxs::def())
                .subcommand(MigrationJson::def())
                .subcommand(DeriveIbcToken::def())
                .subcommand(PubKeyToAddr::def())
                .subcommand_required(true)
                .arg_required_else_help(true)
        }
    }

    #[derive(Clone, Debug)]
    pub struct JoinNetwork(pub args::JoinNetwork);

    impl SubCmd for JoinNetwork {
        const CMD: &'static str = "join-network";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::JoinNetwork::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Configure Namada to join an existing network."))
                .add_args::<args::JoinNetwork>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidateWasm(pub args::ValidateWasm);

    impl SubCmd for ValidateWasm {
        const CMD: &'static str = "validate-wasm";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::ValidateWasm::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Check that the provided wasm code is valid by the Namada \
                     standards."
                ))
                .add_args::<args::ValidateWasm>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct DeriveIbcToken(pub args::DeriveIbcToken);

    impl SubCmd for DeriveIbcToken {
        const CMD: &'static str = "derive-token-address";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::DeriveIbcToken::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Derive the IBC token address on Namada from the denom \
                     string, typically in the form of \
                     'transfer/channel-<num>/<name>'."
                ))
                .add_args::<args::DeriveIbcToken>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct PubKeyToAddr(pub args::PubKeyToAddr);

    impl SubCmd for PubKeyToAddr {
        const CMD: &'static str = "pubkey-to-address";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::PubKeyToAddr::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Derive the implicit address (tnam) associated with a \
                     given public key (tpknam)."
                ))
                .add_args::<args::PubKeyToAddr>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitNetwork(pub args::InitNetwork);

    impl SubCmd for InitNetwork {
        const CMD: &'static str = "init-network";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::InitNetwork::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Initialize a new test network."))
                .add_args::<args::InitNetwork>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct DeriveGenesisAddresses(pub args::DeriveGenesisAddresses);

    impl SubCmd for DeriveGenesisAddresses {
        const CMD: &'static str = "derive-genesis-addresses";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::DeriveGenesisAddresses::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Derive account addresses from a genesis txs toml file."
                ))
                .add_args::<args::DeriveGenesisAddresses>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitGenesisEstablishedAccount(
        pub args::InitGenesisEstablishedAccount,
    );

    impl SubCmd for InitGenesisEstablishedAccount {
        const CMD: &'static str = "init-genesis-established-account";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::InitGenesisEstablishedAccount::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Initialize an established account available at genesis."
                ))
                .add_args::<args::InitGenesisEstablishedAccount>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct GenesisBond(pub args::GenesisBond);

    impl SubCmd for GenesisBond {
        const CMD: &'static str = "genesis-bond";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::GenesisBond::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Bond to a validator at pre-genesis."))
                .add_args::<args::GenesisBond>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitGenesisValidator(pub args::InitGenesisValidator);

    impl SubCmd for InitGenesisValidator {
        const CMD: &'static str = "init-genesis-validator";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::InitGenesisValidator::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Initialize genesis validator's address, consensus key \
                     and validator account key and use it in the ledger's \
                     node. Appends validator creation and self-bond txs to a \
                     .toml file containing an established account tx."
                ))
                .add_args::<args::InitGenesisValidator>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidateGenesisTemplates(pub args::ValidateGenesisTemplates);

    impl SubCmd for ValidateGenesisTemplates {
        const CMD: &'static str = "validate-genesis-templates";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::ValidateGenesisTemplates::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Validate genesis templates."))
                .add_args::<args::ValidateGenesisTemplates>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct TestGenesis(pub args::TestGenesis);

    impl SubCmd for TestGenesis {
        const CMD: &'static str = "test-genesis";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::TestGenesis::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Dry run genesis files and get a report on problems that \
                     may be found."
                ))
                .add_args::<args::TestGenesis>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct DryRunProposal(pub args::DryRunProposal);

    impl SubCmd for DryRunProposal {
        const CMD: &'static str = "dry-run-proposal";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::DryRunProposal::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Dry run a governance proposal code."))
                .add_args::<args::DryRunProposal>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct SignGenesisTxs(pub args::SignGenesisTxs);

    impl SubCmd for SignGenesisTxs {
        const CMD: &'static str = "sign-genesis-txs";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::SignGenesisTxs::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Sign genesis transaction(s)."))
                .add_args::<args::SignGenesisTxs>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct MigrationJson(pub args::MigrationJson);

    impl SubCmd for MigrationJson {
        const CMD: &'static str = "parse-migration-json";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::MigrationJson::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Parse and print a migration JSON file."))
                .add_args::<args::MigrationJson>()
        }
    }

    /// Used as sub-commands (`SubCmd` instance) in `namadar` binary.
    #[derive(Clone, Debug)]
    pub enum EthBridgePool {
        /// The [`super::Context`] provides access to the wallet and the
        /// config. It will generate a new wallet and config, if they
        /// don't exist.
        WithContext(EthBridgePoolWithCtx),
        /// Utils don't have [`super::Context`], only the global arguments.
        WithoutContext(EthBridgePoolWithoutCtx),
    }

    /// Ethereum Bridge pool commands requiring [`super::Context`].
    #[derive(Clone, Debug)]
    pub enum EthBridgePoolWithCtx {
        /// Get a recommendation on a batch of transfers
        /// to relay.
        RecommendBatch(RecommendBatch),
    }

    /// Ethereum Bridge pool commands not requiring [`super::Context`].
    #[derive(Clone, Debug)]
    pub enum EthBridgePoolWithoutCtx {
        /// Construct a proof that a set of transfers is in the pool.
        /// This can be used to relay transfers across the
        /// bridge to Ethereum.
        ConstructProof(ConstructProof),
        /// Construct and relay a Bridge pool proof to
        /// Ethereum directly.
        RelayProof(RelayProof),
        /// Query the contents of the pool.
        QueryPool(QueryEthBridgePool),
        /// Query to provable contents of the pool.
        QuerySigned(QuerySignedBridgePool),
        /// Check the confirmation status of `TransferToEthereum`
        /// events.
        QueryRelays(QueryRelayProgress),
    }

    impl Cmd for EthBridgePool {
        fn add_sub(app: App) -> App {
            app.subcommand(RecommendBatch::def().display_order(1))
                .subcommand(ConstructProof::def().display_order(1))
                .subcommand(RelayProof::def().display_order(1))
                .subcommand(QueryEthBridgePool::def().display_order(1))
                .subcommand(QuerySignedBridgePool::def().display_order(1))
                .subcommand(QueryRelayProgress::def().display_order(1))
        }

        fn parse(matches: &ArgMatches) -> Option<Self> {
            use EthBridgePoolWithCtx::*;
            use EthBridgePoolWithoutCtx::*;

            let recommend = Self::parse_with_ctx(matches, RecommendBatch);
            let construct_proof =
                Self::parse_without_ctx(matches, ConstructProof);
            let relay_proof = Self::parse_without_ctx(matches, RelayProof);
            let query_pool = Self::parse_without_ctx(matches, QueryPool);
            let query_signed = Self::parse_without_ctx(matches, QuerySigned);
            let query_relays = Self::parse_without_ctx(matches, QueryRelays);

            construct_proof
                .or(recommend)
                .or(relay_proof)
                .or(query_pool)
                .or(query_signed)
                .or(query_relays)
        }
    }

    impl EthBridgePool {
        /// A helper method to parse sub cmds with context
        fn parse_with_ctx<T: SubCmd>(
            matches: &ArgMatches,
            sub_to_self: impl Fn(T) -> EthBridgePoolWithCtx,
        ) -> Option<Self> {
            T::parse(matches).map(|sub| Self::WithContext(sub_to_self(sub)))
        }

        /// A helper method to parse sub cmds without context
        fn parse_without_ctx<T: SubCmd>(
            matches: &ArgMatches,
            sub_to_self: impl Fn(T) -> EthBridgePoolWithoutCtx,
        ) -> Option<Self> {
            T::parse(matches).map(|sub| Self::WithoutContext(sub_to_self(sub)))
        }
    }

    impl SubCmd for EthBridgePool {
        const CMD: &'static str = "ethereum-bridge-pool";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).and_then(Cmd::parse)
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Functionality for interacting with the Ethereum bridge \
                     pool. This pool holds transfers waiting to be relayed to \
                     Ethereum."
                ))
                .subcommand_required(true)
                .subcommand(ConstructProof::def().display_order(1))
                .subcommand(RecommendBatch::def().display_order(1))
                .subcommand(RelayProof::def().display_order(1))
                .subcommand(QueryEthBridgePool::def().display_order(1))
                .subcommand(QuerySignedBridgePool::def().display_order(1))
                .subcommand(QueryRelayProgress::def().display_order(1))
        }
    }

    #[derive(Clone, Debug)]
    pub struct AddToEthBridgePool(pub args::EthereumBridgePool<args::CliTypes>);

    impl SubCmd for AddToEthBridgePool {
        const CMD: &'static str = "add-erc20-transfer";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::EthereumBridgePool::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Add a new transfer to the Ethereum Bridge pool."))
                .arg_required_else_help(true)
                .add_args::<args::EthereumBridgePool<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ConstructProof(pub args::BridgePoolProof<args::CliTypes>);

    impl SubCmd for ConstructProof {
        const CMD: &'static str = "construct-proof";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::BridgePoolProof::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Construct a merkle proof that the given transfers are in \
                     the pool."
                ))
                .arg_required_else_help(true)
                .add_args::<args::BridgePoolProof<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct RelayProof(pub args::RelayBridgePoolProof<args::CliTypes>);

    impl SubCmd for RelayProof {
        const CMD: &'static str = "relay-proof";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::RelayBridgePoolProof::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Construct a merkle proof that the given transfers are in \
                     the pool and relay it to Ethereum."
                ))
                .arg_required_else_help(true)
                .add_args::<args::RelayBridgePoolProof<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct RecommendBatch(pub args::RecommendBatch<args::CliTypes>);

    impl SubCmd for RecommendBatch {
        const CMD: &'static str = "recommend-batch";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::RecommendBatch::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Get a recommended batch of transfers from the bridge \
                     pool to relay to Ethereum."
                ))
                .arg_required_else_help(true)
                .add_args::<args::RecommendBatch<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryEthBridgePool(pub args::QueryWithoutCtx<args::CliTypes>);

    impl SubCmd for QueryEthBridgePool {
        const CMD: &'static str = "query";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::QueryWithoutCtx::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Get the contents of the Ethereum Bridge pool."))
                .add_args::<args::QueryWithoutCtx<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QuerySignedBridgePool(pub args::QueryWithoutCtx<args::CliTypes>);

    impl SubCmd for QuerySignedBridgePool {
        const CMD: &'static str = "query-signed";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::QueryWithoutCtx::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Get the contents of the Ethereum Bridge pool with a \
                     signed Merkle root."
                ))
                .add_args::<args::QueryWithoutCtx<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryRelayProgress(pub args::QueryWithoutCtx<args::CliTypes>);

    impl SubCmd for QueryRelayProgress {
        const CMD: &'static str = "query-relayed";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::QueryWithoutCtx::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Get the confirmation status of transfers to Ethereum."
                ))
                .add_args::<args::QueryWithoutCtx<args::CliTypes>>()
        }
    }

    /// Used as sub-commands (`SubCmd` instance) in `namadar` binary.
    #[derive(Clone, Debug)]
    pub enum ValidatorSet {
        /// Query the Bridge validator set in Namada, at the given epoch,
        /// or the latest one, if none is provided.
        BridgeValidatorSet(BridgeValidatorSet),
        /// Query the Governance validator set in Namada, at the given epoch,
        /// or the latest one, if none is provided.
        GovernanceValidatorSet(GovernanceValidatorSet),
        /// Query an Ethereum ABI encoding of a proof of the consensus
        /// validator set in Namada, at the given epoch, or the next
        /// one, if none is provided.
        ValidatorSetProof(ValidatorSetProof),
        /// Relay a validator set update to Namada's Ethereum bridge
        /// smart contracts.
        ValidatorSetUpdateRelay(ValidatorSetUpdateRelay),
    }

    impl SubCmd for ValidatorSet {
        const CMD: &'static str = "validator-set";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).and_then(|matches| {
                let bridge_validator_set = BridgeValidatorSet::parse(matches)
                    .map(Self::BridgeValidatorSet);
                let governance_validator_set =
                    GovernanceValidatorSet::parse(matches)
                        .map(Self::GovernanceValidatorSet);
                let validator_set_proof = ValidatorSetProof::parse(matches)
                    .map(Self::ValidatorSetProof);
                let relay = ValidatorSetUpdateRelay::parse(matches)
                    .map(Self::ValidatorSetUpdateRelay);
                bridge_validator_set
                    .or(governance_validator_set)
                    .or(validator_set_proof)
                    .or(relay)
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Validator set queries, that return data in a format to \
                     be consumed by the Namada Ethereum bridge smart \
                     contracts."
                ))
                .subcommand_required(true)
                .subcommand(BridgeValidatorSet::def().display_order(1))
                .subcommand(GovernanceValidatorSet::def().display_order(1))
                .subcommand(ValidatorSetProof::def().display_order(1))
                .subcommand(ValidatorSetUpdateRelay::def().display_order(1))
        }
    }

    #[derive(Clone, Debug)]
    pub struct BridgeValidatorSet(pub args::BridgeValidatorSet<args::CliTypes>);

    impl SubCmd for BridgeValidatorSet {
        const CMD: &'static str = "bridge";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::BridgeValidatorSet::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query the Bridge validator set in Namada, at the given \
                     epoch, or the latest one, if none is provided."
                ))
                .add_args::<args::BridgeValidatorSet<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct GovernanceValidatorSet(
        pub args::GovernanceValidatorSet<args::CliTypes>,
    );

    impl SubCmd for GovernanceValidatorSet {
        const CMD: &'static str = "governance";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::GovernanceValidatorSet::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query the Governance validator set in Namada, at the \
                     given epoch, or the latest one, if none is provided."
                ))
                .add_args::<args::GovernanceValidatorSet<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidatorSetProof(pub args::ValidatorSetProof<args::CliTypes>);

    impl SubCmd for ValidatorSetProof {
        const CMD: &'static str = "proof";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::ValidatorSetProof::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Query an Ethereum ABI encoding of a proof of the \
                     consensus validator set in Namada, at the requested \
                     epoch, or the next one, if no epoch is provided."
                ))
                .add_args::<args::ValidatorSetProof<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidatorSetUpdateRelay(
        pub args::ValidatorSetUpdateRelay<args::CliTypes>,
    );

    impl SubCmd for ValidatorSetUpdateRelay {
        const CMD: &'static str = "relay";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::ValidatorSetUpdateRelay::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Relay a validator set update to Namada's Ethereum bridge \
                     smart contracts."
                ))
                .add_args::<args::ValidatorSetUpdateRelay<args::CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct PkToTmAddress(pub args::PkToTmAddress);

    impl SubCmd for PkToTmAddress {
        const CMD: &'static str = "pk-to-tm";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::PkToTmAddress::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Convert a validator's consensus public key to a \
                     Tendermint address."
                ))
                .add_args::<args::PkToTmAddress>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct SignOffline(pub args::SignOffline<CliTypes>);

    impl SubCmd for SignOffline {
        const CMD: &'static str = "sign-offline";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches.subcommand_matches(Self::CMD).map(|matches| {
                Self(args::SignOffline::<CliTypes>::parse(matches))
            })
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!("Offline sign a transaction."))
                .add_args::<args::SignOffline<CliTypes>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct DefaultBaseDir(pub args::DefaultBaseDir);

    impl SubCmd for DefaultBaseDir {
        const CMD: &'static str = "default-base-dir";

        fn parse(matches: &ArgMatches) -> Option<Self> {
            matches
                .subcommand_matches(Self::CMD)
                .map(|matches| Self(args::DefaultBaseDir::parse(matches)))
        }

        fn def() -> App {
            App::new(Self::CMD)
                .about(wrap!(
                    "Print the default base directory that would be used if \
                     --base-dir or NAMADA_BASE_DIR were not used to set the \
                     base directory."
                ))
                .add_args::<args::DefaultBaseDir>()
        }
    }
}

pub mod args {
    use std::env;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::str::FromStr;

    use data_encoding::HEXUPPER;
    use either::Either;
    use namada_core::masp::{DiversifierIndex, MaspEpoch, PaymentAddress};
    use namada_sdk::address::{Address, EstablishedAddress};
    pub use namada_sdk::args::*;
    use namada_sdk::chain::{ChainId, ChainIdPrefix};
    use namada_sdk::collections::HashMap;
    use namada_sdk::dec::Dec;
    use namada_sdk::ethereum_events::EthAddress;
    use namada_sdk::hash::Hash;
    use namada_sdk::ibc::core::host::types::identifiers::{ChannelId, PortId};
    use namada_sdk::keccak::KeccakHash;
    use namada_sdk::key::*;
    use namada_sdk::masp::utils::RetryStrategy;
    use namada_sdk::storage::{self, BlockHeight, Epoch};
    use namada_sdk::time::DateTimeUtc;
    use namada_sdk::token::NATIVE_MAX_DECIMAL_PLACES;
    use namada_sdk::tx::data::GasLimit;
    pub use namada_sdk::tx::{
        TX_BECOME_VALIDATOR_WASM, TX_BOND_WASM, TX_BRIDGE_POOL_WASM,
        TX_CHANGE_COMMISSION_WASM, TX_CHANGE_CONSENSUS_KEY_WASM,
        TX_CHANGE_METADATA_WASM, TX_CLAIM_REWARDS_WASM,
        TX_DEACTIVATE_VALIDATOR_WASM, TX_IBC_WASM, TX_INIT_ACCOUNT_WASM,
        TX_INIT_PROPOSAL, TX_REACTIVATE_VALIDATOR_WASM, TX_REDELEGATE_WASM,
        TX_RESIGN_STEWARD, TX_REVEAL_PK, TX_TRANSFER_WASM, TX_UNBOND_WASM,
        TX_UNJAIL_VALIDATOR_WASM, TX_UPDATE_ACCOUNT_WASM,
        TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM,
        VP_USER_WASM,
    };
    use namada_sdk::{DEFAULT_GAS_LIMIT, token};

    use super::context::*;
    use super::utils::*;
    use super::{ArgGroup, ArgMatches};
    use crate::config::genesis::AddrOrPk;
    use crate::config::{self, Action, ActionAtHeight};
    use crate::tendermint::Timeout;
    use crate::tendermint_rpc::Url;
    use crate::wrap;

    pub const ADDRESS: Arg<WalletAddress> = arg("address");
    pub const ADDRESS_OPT: ArgOpt<WalletAddress> = arg_opt("address");
    pub const ADD_PERSISTENT_PEERS: ArgFlag = flag("add-persistent-peers");
    pub const ALIAS_OPT: ArgOpt<String> = ALIAS.opt();
    pub const ALIAS: Arg<String> = arg("alias");
    pub const ALIAS_FORCE: ArgFlag = flag("alias-force");
    pub const ALIAS_MANY: ArgMulti<String, GlobPlus> = arg_multi("aliases");
    pub const ALLOW_DUPLICATE_IP: ArgFlag = flag("allow-duplicate-ip");
    pub const AMOUNT: Arg<token::DenominatedAmount> = arg("amount");
    pub const ARCHIVE_DIR: ArgOpt<PathBuf> = arg_opt("archive-dir");
    pub const AVATAR_OPT: ArgOpt<String> = arg_opt("avatar");
    pub const BALANCE_OWNER: Arg<WalletBalanceOwner> = arg("owner");
    pub const BASE_DIR: ArgDefault<PathBuf> = arg_default(
        "base-dir",
        DefaultFn(|| match env::var("NAMADA_BASE_DIR") {
            Ok(dir) => PathBuf::from(dir),
            Err(_) => config::get_default_namada_folder(),
        }),
    );
    pub const BIRTHDAY: ArgOpt<BlockHeight> = arg_opt("birthday");
    pub const BLOCK_BATCH: ArgDefault<usize> =
        arg_default("block-batch", DefaultFn(|| 10));
    pub const BLOCK_HEIGHT: Arg<BlockHeight> = arg("block-height");
    pub const BLOCK_HEIGHT_OPT: ArgOpt<BlockHeight> = arg_opt("height");
    pub const BLOCK_HEIGHT_TO_OPT: ArgOpt<BlockHeight> = arg_opt("to-height");
    pub const BRIDGE_POOL_GAS_AMOUNT: ArgDefault<token::DenominatedAmount> =
        arg_default(
            "pool-gas-amount",
            DefaultFn(|| {
                token::DenominatedAmount::new(
                    token::Amount::zero(),
                    NATIVE_MAX_DECIMAL_PLACES.into(),
                )
            }),
        );
    pub const BRIDGE_POOL_GAS_PAYER: ArgOpt<WalletAddress> =
        arg_opt("pool-gas-payer");
    pub const BRIDGE_POOL_GAS_TOKEN: ArgDefaultFromCtx<
        WalletAddrOrNativeToken,
    > = arg_default_from_ctx(
        "pool-gas-token",
        DefaultFn(|| "".parse().unwrap()),
    );
    pub const BRIDGE_POOL_TARGET: Arg<EthAddress> = arg("target");
    pub const BROADCAST_ONLY: ArgFlag = flag("broadcast-only");
    pub const CHAIN_ID: Arg<ChainId> = arg("chain-id");
    pub const CHAIN_ID_OPT: ArgOpt<ChainId> = CHAIN_ID.opt();
    pub const CHAIN_ID_PREFIX: Arg<ChainIdPrefix> = arg("chain-prefix");
    pub const CHANNEL_ID: Arg<ChannelId> = arg("channel-id");
    pub const CODE_PATH: Arg<PathBuf> = arg("code-path");
    pub const CODE_PATH_OPT: ArgOpt<PathBuf> = CODE_PATH.opt();
    pub const COMMISSION_RATE: Arg<Dec> = arg("commission-rate");
    pub const COMMISSION_RATE_OPT: ArgOpt<Dec> = COMMISSION_RATE.opt();
    pub const CONSENSUS_TIMEOUT_COMMIT: ArgDefault<Timeout> = arg_default(
        "consensus-timeout-commit",
        DefaultFn(|| Timeout::from_str("1s").unwrap()),
    );
    pub const CONVERSION_TABLE: Arg<PathBuf> = arg("conversion-table");
    pub const DAEMON_MODE: ArgFlag = flag("daemon");
    pub const DAEMON_MODE_RETRY_DUR: ArgOpt<Duration> = arg_opt("retry-sleep");
    pub const DAEMON_MODE_SUCCESS_DUR: ArgOpt<Duration> =
        arg_opt("success-sleep");
    pub const DATA_PATH_OPT: ArgOpt<PathBuf> = arg_opt("data-path");
    pub const DATA_PATH: Arg<PathBuf> = arg("data-path");
    pub const DATED_SPENDING_KEYS: ArgMulti<WalletDatedSpendingKey, GlobStar> =
        arg_multi("spending-keys");
    pub const DATED_VIEWING_KEYS: ArgMulti<WalletDatedViewingKey, GlobStar> =
        arg_multi("viewing-keys");
    pub const DB_KEY: Arg<String> = arg("db-key");
    pub const DB_COLUMN_FAMILY: ArgDefault<String> = arg_default(
        "db-column-family",
        DefaultFn(|| storage::SUBSPACE_CF.to_string()),
    );
    pub const DECRYPT: ArgFlag = flag("decrypt");
    pub const DESCRIPTION_OPT: ArgOpt<String> = arg_opt("description");
    pub const DIVERSIFIER_INDEX: ArgOpt<DiversifierIndex> =
        arg_opt("diversifier-index");
    pub const DESTINATION_VALIDATOR: Arg<WalletAddress> =
        arg("destination-validator");
    pub const DISCORD_OPT: ArgOpt<String> = arg_opt("discord-handle");
    pub const DO_IT: ArgFlag = flag("do-it");
    pub const DRY_RUN_TX: ArgFlag = flag("dry-run");
    pub const DRY_RUN_WRAPPER_TX: ArgFlag = flag("dry-run-wrapper");
    pub const DUMP_TX: ArgFlag = flag("dump-tx");
    pub const DUMP_WRAPPER_TX: ArgFlag = flag("dump-wrapper-tx");
    pub const DUMP_CONVERSION_TREE: ArgFlag = flag("dump-conversion-tree");
    pub const EPOCH: ArgOpt<Epoch> = arg_opt("epoch");
    pub const ERC20: Arg<EthAddress> = arg("erc20");
    pub const ETH_CONFIRMATIONS: Arg<u64> = arg("confirmations");
    pub const ETH_GAS: ArgOpt<u64> = arg_opt("eth-gas");
    pub const ETH_GAS_PRICE: ArgOpt<u64> = arg_opt("eth-gas-price");
    pub const ETH_ADDRESS: Arg<EthAddress> = arg("ethereum-address");
    pub const ETH_ADDRESS_OPT: ArgOpt<EthAddress> = ETH_ADDRESS.opt();
    pub const ETH_RPC_ENDPOINT: ArgDefault<String> = arg_default(
        "eth-rpc-endpoint",
        DefaultFn(|| "http://localhost:8545".into()),
    );
    pub const ETH_SYNC: ArgFlag = flag("sync");
    pub const EXPIRATION_OPT: ArgOpt<DateTimeUtc> = arg_opt("expiration");
    pub const EMAIL: Arg<String> = arg("email");
    pub const EMAIL_OPT: ArgOpt<String> = EMAIL.opt();
    pub const FEE_AMOUNT_OPT: ArgOpt<token::DenominatedAmount> =
        arg_opt("gas-price");
    pub const FEE_PAYER_OPT: ArgOpt<WalletPublicKey> = arg_opt("gas-payer");
    pub const FILE_PATH: Arg<String> = arg("file");
    pub const FORCE: ArgFlag = flag("force");
    pub const FULL_RESET: ArgFlag = flag("full-reset");
    pub const GAS_LIMIT: ArgDefault<GasLimit> = arg_default(
        "gas-limit",
        DefaultFn(|| GasLimit::from(DEFAULT_GAS_LIMIT)),
    );
    pub const GAS_SPENDING_KEY: ArgOpt<WalletSpendingKey> =
        arg_opt("gas-spending-key");
    pub const FEE_TOKEN: ArgDefaultFromCtx<WalletAddrOrNativeToken> =
        arg_default_from_ctx("gas-token", DefaultFn(|| "".parse().unwrap()));
    pub const GENESIS_BOND_SOURCE: ArgOpt<AddrOrPk> = arg_opt("source");
    pub const GENESIS_PATH: Arg<PathBuf> = arg("genesis-path");
    pub const GENESIS_TIME: Arg<DateTimeUtc> = arg("genesis-time");
    pub const GENESIS_VALIDATOR: ArgOpt<String> =
        arg("genesis-validator").opt();
    pub const GENESIS_VALIDATOR_ADDRESS: Arg<EstablishedAddress> =
        arg("validator");
    pub const HALT_ACTION: ArgFlag = flag("halt");
    pub const HASH: Arg<String> = arg("hash");
    pub const HASH_OPT: ArgOpt<String> = arg_opt("hash");
    pub const HASH_LIST: Arg<String> = arg("hash-list");
    pub const HD_DERIVATION_PATH: ArgDefault<String> =
        arg_default("hd-path", DefaultFn(|| "default".to_string()));
    pub const HD_ALLOW_NON_COMPLIANT_DERIVATION_PATH: ArgFlag =
        flag("allow-non-compliant");
    pub const HD_PROMPT_BIP39_PASSPHRASE: ArgFlag = flag("bip39-passphrase");
    pub const HISTORIC: ArgFlag = flag("historic");
    pub const IBC_SHIELDING_DATA_PATH: ArgOpt<PathBuf> =
        arg_opt("ibc-shielding-data");
    pub const IBC_DENOM: Arg<String> = arg("ibc-denom");
    pub const IBC_MEMO: ArgOpt<String> = arg_opt("ibc-memo");
    pub const INPUT_OPT: ArgOpt<PathBuf> = arg_opt("input");
    pub const LEDGER_ADDRESS_ABOUT: &str = textwrap_macros::fill!(
        "Address of a ledger node as \"{scheme}://{host}:{port}\". If the \
         scheme is not supplied, it is assumed to be TCP.",
        60
    );
    pub const CHECK_CAN_SIGN: ArgMulti<AddrOrPk, GlobStar> =
        arg_multi("check-can-sign");
    pub const CONFIG_RPC_LEDGER_ADDRESS: ArgDefaultFromCtx<ConfigRpcAddress> =
        arg_default_from_ctx("node", DefaultFn(|| "".to_string()));

    pub const LEDGER_ADDRESS: ArgDefault<Url> =
        arg("node").default(DefaultFn(|| {
            let raw = "http://127.0.0.1:26657";
            Url::from_str(raw).unwrap()
        }));
    pub const LIST_FIND_ADDRESSES_ONLY: ArgFlag = flag("addr");
    pub const LIST_FIND_KEYS_ONLY: ArgFlag = flag("keys");
    pub const LOCALHOST: ArgFlag = flag("localhost");
    pub const LOCAL_RECOVERY_ADDR: Arg<String> = arg("local-recovery-addr");
    pub const MASP_EPOCH: ArgOpt<MaspEpoch> = arg_opt("masp-epoch");
    pub const MAX_COMMISSION_RATE_CHANGE: Arg<Dec> =
        arg("max-commission-rate-change");
    pub const MAX_CONCURRENT_FETCHES: ArgDefault<usize> =
        arg_default("max-concurrent-fetches", DefaultFn(|| 100));
    pub const MAX_ETH_GAS: ArgOpt<u64> = arg_opt("max_eth-gas");
    pub const MEMO_OPT: ArgOpt<String> = arg_opt("memo");
    pub const MIGRATION_PATH: ArgOpt<PathBuf> = arg_opt("migration-path");
    pub const MINIMUM_AMOUNT: ArgOpt<token::DenominatedAmount> =
        arg_opt("minimum-amount");
    pub const MODE: ArgOpt<String> = arg_opt("mode");
    pub const NET_ADDRESS: Arg<SocketAddr> = arg("net-address");
    pub const NAMADA_START_TIME: ArgOpt<DateTimeUtc> = arg_opt("time");
    pub const NO_CONVERSIONS: ArgFlag = flag("no-conversions");
    pub const NO_EXPIRATION: ArgFlag = flag("no-expiration");
    pub const NUT: ArgFlag = flag("nut");
    pub const OSMOSIS_LCD_RPC: ArgOpt<String> = arg_opt("osmosis-lcd");
    pub const OSMOSIS_SQS_RPC: ArgOpt<String> = arg_opt("osmosis-sqs");
    pub const OUT_FILE_PATH_OPT: ArgOpt<PathBuf> = arg_opt("out-file-path");
    pub const OUTPUT: ArgOpt<PathBuf> = arg_opt("output");
    pub const OUTPUT_DENOM: Arg<String> = arg("output-denom");
    pub const OUTPUT_FOLDER_PATH: ArgOpt<PathBuf> =
        arg_opt("output-folder-path");
    pub const OSMOSIS_POOL_HOP: ArgMulti<OsmosisPoolHop, GlobStar> =
        arg_multi("pool-hop");
    pub const OVERFLOW_OPT: ArgOpt<WalletAddress> = arg_opt("overflow-addr");
    pub const OWNER: Arg<WalletAddress> = arg("owner");
    pub const OWNER_OPT: ArgOpt<WalletAddress> = OWNER.opt();
    pub const PATH: Arg<PathBuf> = arg("path");
    pub const PATH_OPT: ArgOpt<PathBuf> = arg_opt("path");
    pub const PAYMENT_ADDRESS_TARGET: Arg<WalletPaymentAddr> = arg("target");
    pub const PAYMENT_ADDRESS_TARGET_OPT: ArgOpt<WalletPaymentAddr> =
        arg_opt("target-pa");
    pub const PORT_ID: ArgDefault<PortId> = arg_default(
        "port-id",
        DefaultFn(|| PortId::from_str("transfer").unwrap()),
    );
    pub const PRE_GENESIS: ArgFlag = flag("pre-genesis");
    pub const PRIVATE_KEY_OPT: ArgOpt<WalletKeypair> = arg_opt("secret-key");
    pub const PRIVATE_KEYS: ArgMulti<WalletKeypair, GlobStar> =
        arg_multi("secret-keys");
    pub const PROPOSAL_PGF_STEWARD: ArgFlag = flag("pgf-stewards");
    pub const PROPOSAL_PGF_FUNDING: ArgFlag = flag("pgf-funding");
    pub const PROTOCOL_KEY: ArgOpt<WalletPublicKey> = arg_opt("protocol-key");
    pub const PRE_GENESIS_PATH: ArgOpt<PathBuf> = arg_opt("pre-genesis-path");
    pub const PUBLIC_KEY: Arg<WalletPublicKey> = arg("public-key");
    pub const PUBLIC_KEYS: ArgMulti<WalletPublicKey, GlobStar> =
        arg_multi("public-keys");
    pub const PROPOSAL_ID: Arg<u64> = arg("proposal-id");
    pub const PROPOSAL_ID_OPT: ArgOpt<u64> = arg_opt("proposal-id");
    pub const PROPOSAL_VOTE_PGF_OPT: ArgOpt<String> = arg_opt("pgf");
    pub const PROPOSAL_VOTE_ETH_OPT: ArgOpt<String> = arg_opt("eth");
    pub const PROPOSAL_VOTE: Arg<String> = arg("vote");
    pub const RAW_ADDRESS: Arg<Address> = arg("address");
    pub const RAW_ADDRESS_ESTABLISHED: Arg<EstablishedAddress> = arg("address");
    pub const RAW_ADDRESS_OPT: ArgOpt<Address> = RAW_ADDRESS.opt();
    pub const RAW_KEY_GEN: ArgFlag = flag("raw");
    pub const RAW_PAYMENT_ADDRESS: Arg<PaymentAddress> = arg("payment-address");
    pub const RAW_PAYMENT_ADDRESS_OPT: ArgOpt<PaymentAddress> =
        RAW_PAYMENT_ADDRESS.opt();
    pub const RAW_PUBLIC_KEY: Arg<common::PublicKey> = arg("public-key");
    pub const RAW_PUBLIC_KEY_OPT: ArgOpt<common::PublicKey> =
        RAW_PUBLIC_KEY.opt();
    pub const RAW_PUBLIC_KEY_HASH: Arg<String> = arg("public-key-hash");
    pub const RAW_PUBLIC_KEY_HASH_OPT: ArgOpt<String> =
        RAW_PUBLIC_KEY_HASH.opt();
    pub const RECEIVER: Arg<String> = arg("receiver");
    pub const REFUND_TARGET: ArgOpt<WalletTransferTarget> =
        arg_opt("refund-target");
    pub const RELAYER: Arg<Address> = arg("relayer");
    pub const RETRIES: ArgOpt<u64> = arg_opt("retries");
    pub const SCHEME: ArgDefault<SchemeType> =
        arg_default("scheme", DefaultFn(|| SchemeType::Ed25519));
    pub const SHELL: Arg<Shell> = arg("shell");
    pub const SELF_BOND_AMOUNT: Arg<token::DenominatedAmount> =
        arg("self-bond-amount");
    pub const SENDER: Arg<String> = arg("sender");
    pub const SHIELDED: ArgFlag = flag("shielded");
    pub const SHOW_IBC_TOKENS: ArgFlag = flag("show-ibc-tokens");
    pub const SLIPPAGE: ArgOpt<Dec> = arg_opt("slippage-percentage");
    pub const SIGNING_KEYS: ArgMulti<WalletPublicKey, GlobStar> =
        arg_multi("signing-keys");
    pub const SIGNATURES: ArgMulti<PathBuf, GlobStar> = arg_multi("signatures");
    pub const SOURCE: Arg<WalletAddress> = arg("source");
    pub const SOURCE_OPT: ArgOpt<WalletAddress> = SOURCE.opt();
    pub const SOURCE_VALIDATOR: Arg<WalletAddress> = arg("source-validator");
    pub const SPENDING_KEY_SOURCE: Arg<WalletSpendingKey> = arg("source");
    pub const SPENDING_KEYS: ArgMulti<WalletSpendingKey, GlobStar> =
        arg_multi("spending-keys");
    pub const STEWARD: Arg<WalletAddress> = arg("steward");
    pub const STORAGE_KEY: Arg<storage::Key> = arg("storage-key");
    pub const SUSPEND_ACTION: ArgFlag = flag("suspend");
    pub const TARGET: Arg<WalletAddress> = arg("target");
    pub const TARGET_OPT: ArgOpt<WalletAddress> = arg_opt("target");
    pub const TEMPLATES_PATH: Arg<PathBuf> = arg("templates-path");
    pub const TIMEOUT_HEIGHT: ArgOpt<u64> = arg_opt("timeout-height");
    pub const TIMEOUT_SEC_OFFSET: ArgOpt<u64> = arg_opt("timeout-sec-offset");
    pub const TM_ADDRESS_OPT: ArgOpt<String> = arg_opt("tm-address");
    pub const TOKEN_OPT: ArgOpt<WalletAddress> = TOKEN.opt();
    pub const TOKEN_STR_OPT: ArgOpt<String> = TOKEN_STR.opt();
    pub const TOKEN: Arg<WalletAddress> = arg("token");
    pub const TOKEN_STR: Arg<String> = arg("token");
    pub const TRANSFER_SOURCE: Arg<WalletTransferSource> = arg("source");
    pub const TRANSFER_TARGET: Arg<WalletTransferTarget> = arg("target");
    pub const TRANSPARENT: ArgFlag = flag("transparent");
    pub const TX_HASH: Arg<String> = arg("tx-hash");
    pub const THRESHOLD: ArgOpt<u8> = arg_opt("threshold");
    pub const UNSAFE_DONT_ENCRYPT: ArgFlag = flag("unsafe-dont-encrypt");
    pub const UNSAFE_PURE_ZIP32: ArgFlag = flag("unsafe-pure-zip32");
    pub const UNSAFE_SHOW_SECRET: ArgFlag = flag("unsafe-show-secret");
    pub const USE_DEVICE: ArgFlag = flag("use-device");
    pub const VALIDATOR: Arg<WalletAddress> = arg("validator");
    pub const VALIDATOR_OPT: ArgOpt<WalletAddress> = VALIDATOR.opt();
    pub const VALIDATOR_NAME_OPT: ArgOpt<String> = arg_opt("name");
    pub const VALIDATOR_ACCOUNT_KEY: ArgOpt<WalletPublicKey> =
        arg_opt("account-key");
    pub const VALIDATOR_ACCOUNT_KEYS: ArgMulti<WalletPublicKey, GlobStar> =
        arg_multi("account-keys");
    pub const VALIDATOR_CONSENSUS_KEY: ArgOpt<WalletPublicKey> =
        arg_opt("consensus-key");
    pub const VALIDATOR_CODE_PATH: ArgOpt<PathBuf> =
        arg_opt("validator-code-path");
    pub const VALIDATOR_ETH_COLD_KEY: ArgOpt<WalletPublicKey> =
        arg_opt("eth-cold-key");
    pub const VALIDATOR_ETH_HOT_KEY: ArgOpt<WalletPublicKey> =
        arg_opt("eth-hot-key");
    pub const VALUE: Arg<String> = arg("value");
    pub const VOTER_OPT: ArgOpt<WalletAddress> = arg_opt("voter");
    pub const VIEWING_KEY: Arg<WalletViewingKey> = arg("key");
    pub const VIEWING_KEY_ALIAS: Arg<String> = arg("key");
    pub const VIEWING_KEYS: ArgMulti<WalletViewingKey, GlobStar> =
        arg_multi("viewing-keys");
    pub const VP: ArgOpt<String> = arg_opt("vp");
    pub const WAIT_FOR_LAST_QUERY_HEIGHT: ArgFlag =
        flag("wait-for-last-query-height");
    pub const WALLET_ALIAS_FORCE: ArgFlag = flag("wallet-alias-force");
    pub const WASM_CHECKSUMS_PATH: Arg<PathBuf> = arg("wasm-checksums-path");
    pub const WASM_DIR: ArgOpt<PathBuf> = arg_opt("wasm-dir");
    pub const WASM_PATH: ArgOpt<PathBuf> = arg_opt("wasm-path");
    pub const WEBSITE_OPT: ArgOpt<String> = arg_opt("website");
    pub const WITH_INDEXER: ArgOpt<String> = arg_opt("with-indexer");
    pub const WRAPPER_SIGNATURE_OPT: ArgOpt<PathBuf> = arg_opt("gas-signature");
    pub const TX_PATH: Arg<PathBuf> = arg("tx-path");
    pub const TX_PATH_OPT: ArgOpt<PathBuf> = TX_PATH.opt();
    pub const DEVICE_TRANSPORT: ArgDefault<DeviceTransport> = arg_default(
        "device-transport",
        DefaultFn(|| {
            if let Ok(val) = std::env::var(DEVICE_TRANSPORT_ENV_VAR) {
                return DeviceTransport::from_str(&val).unwrap();
            }
            DeviceTransport::default()
        }),
    );
    pub const DEVICE_TRANSPORT_ENV_VAR: &str = "NAMADA_DEVICE_TRANSPORT";

    /// Global command arguments
    #[derive(Clone, Debug)]
    pub struct Global {
        pub is_pre_genesis: bool,
        pub chain_id: Option<ChainId>,
        pub base_dir: PathBuf,
        pub wasm_dir: Option<PathBuf>,
    }

    impl Global {
        /// Parse global arguments
        pub fn parse(matches: &ArgMatches) -> Self {
            let is_pre_genesis = PRE_GENESIS.parse(matches);
            let chain_id = CHAIN_ID_OPT.parse(matches);
            let base_dir = BASE_DIR.parse(matches);
            let wasm_dir = WASM_DIR.parse(matches);
            Global {
                is_pre_genesis,
                chain_id,
                base_dir,
                wasm_dir,
            }
        }

        /// Add global args definition. Should be added to every top-level
        /// command.
        pub fn def(app: App) -> App {
            app.next_line_help(true)
                .arg(
                    CHAIN_ID_OPT
                        .def()
                        .global(true)
                        .help(wrap!("The chain ID.")),
                )
                .arg(BASE_DIR.def().global(true).help(wrap!(
                    "The base directory is where the nodes, client and wallet \
                     configuration and state is stored. This value can also \
                     be set via `NAMADA_BASE_DIR` environment variable, but \
                     the argument takes precedence, if specified. Defaults to \
                     `$XDG_DATA_HOME/namada` (`$HOME/.local/share/namada` \
                     where `XDG_DATA_HOME` is unset) on \
                     Unix,`$HOME/Library/Application Support/Namada` on Mac, \
                     and `%AppData%\\Namada` on Windows."
                )))
                .arg(WASM_DIR.def().global(true).help(wrap!(
                    "Directory with built WASM validity predicates, \
                     transactions. This value can also be set via \
                     `NAMADA_WASM_DIR` environment variable, but the argument \
                     takes precedence, if specified."
                )))
                .arg(
                    PRE_GENESIS
                        .def()
                        .global(true)
                        .help(wrap!("Dispatch pre-genesis specific logic.")),
                )
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerRun {
        pub start_time: Option<DateTimeUtc>,
        pub migration_path: Option<PathBuf>,
        pub migration_hash: Option<Hash>,
        pub migration_height: Option<BlockHeight>,
    }

    impl Args for LedgerRun {
        fn parse(matches: &ArgMatches) -> Self {
            let start_time = NAMADA_START_TIME.parse(matches);
            let migration_path = PATH_OPT.parse(matches);
            let migration_hash = HASH_OPT.parse(matches);
            let migration_height = BLOCK_HEIGHT_OPT.parse(matches);
            Self {
                start_time,
                migration_path,
                migration_hash: migration_hash
                    .map(|h| Hash::try_from(h).unwrap()),
                migration_height,
            }
        }

        fn def(app: App) -> App {
            app.arg(NAMADA_START_TIME.def().help(wrap!(
                "The start time of the ledger. Accepts a strict subset of \
                 RFC3339. A 'T' is accepted as the separator between the date \
                 and time components.\nHere is a valid timestamp: \
                 2023-01-20T12:12:12Z"
            )))
            .arg(
                PATH_OPT
                    .def()
                    .requires(HASH_OPT.name)
                    .requires(BLOCK_HEIGHT_OPT.name)
                    .help(wrap!("Optional path to a migrations JSON file.")),
            )
            .arg(
                HASH_OPT
                    .def()
                    .requires(PATH_OPT.name)
                    .requires(BLOCK_HEIGHT_OPT.name)
                    .help(wrap!(
                        "Hash to verify contents of optionally provided \
                         migrations file."
                    )),
            )
            .arg(
                BLOCK_HEIGHT_OPT
                    .def()
                    .requires(PATH_OPT.name)
                    .requires(HASH_OPT.name)
                    .help(wrap!(
                        "Height for which the optionally provided migration \
                         should be executed."
                    )),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerRunUntil {
        pub time: Option<DateTimeUtc>,
        pub action_at_height: ActionAtHeight,
    }

    impl Args for LedgerRunUntil {
        fn parse(matches: &ArgMatches) -> Self {
            Self {
                time: NAMADA_START_TIME.parse(matches),
                action_at_height: ActionAtHeight {
                    height: BLOCK_HEIGHT.parse(matches),
                    action: if HALT_ACTION.parse(matches) {
                        Action::Halt
                    } else {
                        Action::Suspend
                    },
                },
            }
        }

        fn def(app: App) -> App {
            app.arg(
                NAMADA_START_TIME
                    .def()
                    .help(wrap!("The start time of the ledger.")),
            )
            .arg(
                BLOCK_HEIGHT
                    .def()
                    .help(wrap!("The block height to run until.")),
            )
            .arg(
                HALT_ACTION
                    .def()
                    .help(wrap!("Halt at the given block height")),
            )
            .arg(
                SUSPEND_ACTION
                    .def()
                    .help(wrap!("Suspend consensus at the given block height")),
            )
            .group(
                ArgGroup::new("find_flags")
                    .args([HALT_ACTION.name, SUSPEND_ACTION.name])
                    .required(true),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerReset {
        pub full_reset: bool,
    }

    impl Args for LedgerReset {
        fn parse(matches: &ArgMatches) -> Self {
            Self {
                full_reset: FULL_RESET.parse(matches),
            }
        }

        fn def(app: App) -> App {
            app.arg(FULL_RESET.def().help(wrap!(
                "CAUTION: This will delete the wallet, make sure to back it \
                 up.\nDelete the chain's wallet including local and genesis \
                 configuration and validator key, if any."
            )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerDumpDb {
        pub block_height: Option<BlockHeight>,
        pub out_file_path: PathBuf,
        pub historic: bool,
    }

    impl Args for LedgerDumpDb {
        fn parse(matches: &ArgMatches) -> Self {
            let block_height = BLOCK_HEIGHT_OPT.parse(matches);
            let out_file_path = OUT_FILE_PATH_OPT
                .parse(matches)
                .unwrap_or_else(|| PathBuf::from("db_dump".to_string()));
            let historic = HISTORIC.parse(matches);

            Self {
                block_height,
                out_file_path,
                historic,
            }
        }

        fn def(app: App) -> App {
            app.arg(BLOCK_HEIGHT_OPT.def().help(wrap!(
                "The block height to dump. Defaults to latest committed
                block."
            )))
            .arg(OUT_FILE_PATH_OPT.def().help(wrap!(
                "Path for the output file (omitting file extension). Defaults \
                 to \"db_dump.{block_height}.toml\" in the current working \
                 directory."
            )))
            .arg(HISTORIC.def().help(wrap!(
                "If provided, dump also the diff of the last height"
            )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct LedgerQueryDb {
        pub key: storage::Key,
        pub hash: [u8; 32],
        pub cf: storage::DbColFam,
    }

    impl Args for LedgerQueryDb {
        fn parse(matches: &ArgMatches) -> Self {
            let key = storage::Key::parse(DB_KEY.parse(matches)).unwrap();
            let hex_hash = HASH.parse(matches);
            let hash: [u8; 32] = HEXUPPER
                .decode(hex_hash.to_uppercase().as_bytes())
                .unwrap()
                .try_into()
                .unwrap();
            let cf =
                storage::DbColFam::from_str(&DB_COLUMN_FAMILY.parse(matches))
                    .unwrap();
            Self { key, hash, cf }
        }

        fn def(app: App) -> App {
            app.arg(DB_KEY.def().help(wrap!("A database key to query")))
                .arg(HASH.def().help(wrap!(
                    "The hex encoded type hash of the value contained under \
                     the provided key."
                )))
                .arg(DB_COLUMN_FAMILY.def().help(wrap!(
                    "The column family under which the key is kept. Defaults \
                     to the subspace column family if none is provided."
                )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct UpdateValidatorLocalConfig {
        pub config_path: PathBuf,
    }

    impl Args for UpdateValidatorLocalConfig {
        fn parse(matches: &ArgMatches) -> Self {
            let config_path = DATA_PATH.parse(matches);
            Self { config_path }
        }

        fn def(app: App) -> App {
            app.arg(DATA_PATH.def().help(wrap!(
                "The path to the toml file containing the updated validator's \
                 local configuration."
            )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct UpdateLocalConfig {
        pub config_path: PathBuf,
    }

    impl Args for UpdateLocalConfig {
        fn parse(matches: &ArgMatches) -> Self {
            let config_path = DATA_PATH.parse(matches);
            Self { config_path }
        }

        fn def(app: App) -> App {
            app.arg(DATA_PATH.def().help(wrap!(
                "The path to the toml file containing the updated node's \
                 local configuration."
            )))
        }
    }

    /// Convert CLI args to SDK args, with contextual data.
    pub trait CliToSdk<SDK>: Args {
        /// Error type for fallible operations within the conversion.
        type Error;

        /// Convert CLI args to SDK args, with contextual data.
        fn to_sdk(self, ctx: &mut Context) -> Result<SDK, Self::Error>;

        /// Convert CLI args to SDK args with contextual data, returning
        /// the error up the call stack.
        fn infallible_to_sdk(self, ctx: &mut Context) -> SDK
        where
            Self: Sized,
            Self::Error: Into<std::convert::Infallible>,
        {
            // The `Err` pattern should be removed from 1.82 again: https://github.com/rust-lang/rust/issues/129352
            #[allow(unreachable_patterns)]
            match self.to_sdk(ctx).map_err(Into::into) {
                Ok(x) => x,
                Err(_) => unreachable!(),
            }
        }
    }

    /// Convert CLI args to SDK args, without contextual data.
    pub trait CliToSdkCtxless<SDK>: Args {
        /// Convert CLI args to SDK args, without contextual data.
        fn to_sdk_ctxless(self) -> SDK;
    }

    impl<CLI, SDK> CliToSdk<SDK> for CLI
    where
        CLI: Args + CliToSdkCtxless<SDK>,
    {
        type Error = std::convert::Infallible;

        #[inline]
        fn to_sdk(self, _: &mut Context) -> Result<SDK, Self::Error> {
            Ok(self.to_sdk_ctxless())
        }
    }

    impl CliToSdk<QueryResult<SdkTypes>> for QueryResult<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryResult<SdkTypes>, Self::Error> {
            Ok(QueryResult::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                tx_hash: self.tx_hash,
            })
        }
    }

    impl Args for QueryResult<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let tx_hash = TX_HASH.parse(matches);
            Self { query, tx_hash }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                TX_HASH.def().help(wrap!(
                    "The hash of the transaction being looked up."
                )),
            )
        }
    }

    impl CliToSdk<EthereumBridgePool<SdkTypes>> for EthereumBridgePool<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<EthereumBridgePool<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_chain_or_exit();
            Ok(EthereumBridgePool::<SdkTypes> {
                nut: self.nut,
                tx,
                asset: self.asset,
                recipient: self.recipient,
                sender: chain_ctx.get(&self.sender),
                amount: self.amount,
                fee_amount: self.fee_amount,
                fee_payer: self
                    .fee_payer
                    .map(|fee_payer| chain_ctx.get(&fee_payer)),
                fee_token: chain_ctx.get(&self.fee_token).into(),
                code_path: self.code_path,
            })
        }
    }

    impl Args for EthereumBridgePool<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let asset = ERC20.parse(matches);
            let recipient = BRIDGE_POOL_TARGET.parse(matches);
            let sender = SOURCE.parse(matches);
            let amount = InputAmount::Unvalidated(AMOUNT.parse(matches));
            let fee_amount =
                InputAmount::Unvalidated(BRIDGE_POOL_GAS_AMOUNT.parse(matches));
            let fee_payer = BRIDGE_POOL_GAS_PAYER.parse(matches);
            let fee_token = BRIDGE_POOL_GAS_TOKEN.parse(matches);
            let code_path = PathBuf::from(TX_BRIDGE_POOL_WASM);
            let nut = NUT.parse(matches);
            Self {
                tx,
                asset,
                recipient,
                sender,
                amount,
                fee_amount,
                fee_payer,
                fee_token,
                code_path,
                nut,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(
                    ERC20.def().help(wrap!(
                        "The Ethereum address of the ERC20 token."
                    )),
                )
                .arg(
                    BRIDGE_POOL_TARGET.def().help(wrap!(
                        "The Ethereum address receiving the tokens."
                    )),
                )
                .arg(
                    SOURCE
                        .def()
                        .help(wrap!("The Namada address sending the tokens.")),
                )
                .arg(AMOUNT.def().help(wrap!(
                    "The amount of tokens being sent across the bridge."
                )))
                .arg(BRIDGE_POOL_GAS_AMOUNT.def().help(wrap!(
                    "The amount of gas you wish to pay to have this transfer \
                     relayed to Ethereum."
                )))
                .arg(BRIDGE_POOL_GAS_PAYER.def().help(wrap!(
                    "The Namada address of the account paying the gas. By \
                     default, it is the same as the source."
                )))
                .arg(BRIDGE_POOL_GAS_TOKEN.def().help(wrap!(
                    "The token for paying the Bridge pool gas fees. Defaults \
                     to NAM."
                )))
                .arg(NUT.def().help(wrap!(
                    "Add Non Usable Tokens (NUTs) to the Bridge pool. These \
                     are usually obtained from invalid transfers to Namada."
                )))
        }
    }

    impl CliToSdk<RecommendBatch<SdkTypes>> for RecommendBatch<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<RecommendBatch<SdkTypes>, Self::Error> {
            let query = self.query.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_chain_or_exit();

            Ok(RecommendBatch::<SdkTypes> {
                query,
                max_gas: self.max_gas,
                gas: self.gas,
                conversion_table: {
                    let file = std::io::BufReader::new(
                        std::fs::File::open(self.conversion_table).expect(
                            "Failed to open the provided file to the \
                             conversion table",
                        ),
                    );
                    let table: HashMap<String, f64> =
                        serde_json::from_reader(file)
                            .expect("Failed to parse conversion table");
                    table
                        .into_iter()
                        .map(|(token, conversion_rate)| {
                            let token_from_ctx =
                                FromContext::<Address>::new(token);
                            let address = chain_ctx.get(&token_from_ctx);
                            let alias = token_from_ctx.raw;
                            (
                                address,
                                BpConversionTableEntry {
                                    alias,
                                    conversion_rate,
                                },
                            )
                        })
                        .collect()
                },
            })
        }
    }

    impl Args for RecommendBatch<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let max_gas = MAX_ETH_GAS.parse(matches);
            let gas = ETH_GAS.parse(matches);
            let conversion_table = CONVERSION_TABLE.parse(matches);
            Self {
                query,
                max_gas,
                gas,
                conversion_table,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(MAX_ETH_GAS.def().help(wrap!(
                    "The maximum amount Ethereum gas that can be spent during \
                     the relay call."
                )))
                .arg(ETH_GAS.def().help(wrap!(
                    "Under ideal conditions, relaying transfers will yield a \
                     net profit. If that is not possible, setting this \
                     optional value will result in a batch transfer that \
                     costs as close to the given value as possible without \
                     exceeding it."
                )))
                .arg(CONVERSION_TABLE.def().help(wrap!(
                    "Path to a JSON object containing a mapping between token \
                     aliases (or addresses) and their conversion rates in gwei"
                )))
        }
    }

    impl CliToSdkCtxless<BridgePoolProof<SdkTypes>> for BridgePoolProof<CliTypes> {
        fn to_sdk_ctxless(self) -> BridgePoolProof<SdkTypes> {
            BridgePoolProof::<SdkTypes> {
                ledger_address: self.ledger_address,
                transfers: self.transfers,
                relayer: self.relayer,
            }
        }
    }

    impl Args for BridgePoolProof<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let ledger_address = LEDGER_ADDRESS.parse(matches);
            let hashes = HASH_LIST.parse(matches);
            let relayer = RELAYER.parse(matches);
            Self {
                ledger_address,
                transfers: hashes
                    .split_whitespace()
                    .map(|hash| {
                        KeccakHash::try_from(hash).unwrap_or_else(|_| {
                            tracing::info!(
                                "Could not parse '{}' as a Keccak hash.",
                                hash
                            );
                            safe_exit(1)
                        })
                    })
                    .collect(),
                relayer,
            }
        }

        fn def(app: App) -> App {
            app.arg(LEDGER_ADDRESS.def().help(LEDGER_ADDRESS_ABOUT))
                .arg(HASH_LIST.def().help(wrap!(
                    "Whitespace separated Keccak hash list of transfers in \
                     the Bridge pool."
                )))
                .arg(RELAYER.def().help(wrap!(
                    "The rewards address for relaying this proof."
                )))
        }
    }

    impl CliToSdkCtxless<RelayBridgePoolProof<SdkTypes>>
        for RelayBridgePoolProof<CliTypes>
    {
        fn to_sdk_ctxless(self) -> RelayBridgePoolProof<SdkTypes> {
            RelayBridgePoolProof::<SdkTypes> {
                ledger_address: self.ledger_address,
                transfers: self.transfers,
                relayer: self.relayer,
                confirmations: self.confirmations,
                eth_rpc_endpoint: (),
                gas: self.gas,
                gas_price: self.gas_price,
                eth_addr: self.eth_addr,
                sync: self.sync,
            }
        }
    }

    impl Args for RelayBridgePoolProof<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let ledger_address = LEDGER_ADDRESS.parse(matches);
            let hashes = HASH_LIST.parse(matches);
            let relayer = RELAYER.parse(matches);
            let gas = ETH_GAS.parse(matches);
            let gas_price = ETH_GAS_PRICE.parse(matches);
            let eth_rpc_endpoint = ETH_RPC_ENDPOINT.parse(matches);
            let eth_addr = ETH_ADDRESS_OPT.parse(matches);
            let confirmations = ETH_CONFIRMATIONS.parse(matches);
            let sync = ETH_SYNC.parse(matches);
            Self {
                ledger_address,
                sync,
                transfers: hashes
                    .split(' ')
                    .map(|hash| {
                        KeccakHash::try_from(hash).unwrap_or_else(|_| {
                            tracing::info!(
                                "Could not parse '{}' as a Keccak hash.",
                                hash
                            );
                            safe_exit(1)
                        })
                    })
                    .collect(),
                relayer,
                gas,
                gas_price,
                eth_rpc_endpoint,
                eth_addr,
                confirmations,
            }
        }

        fn def(app: App) -> App {
            app.arg(LEDGER_ADDRESS.def().help(LEDGER_ADDRESS_ABOUT))
                .arg(HASH_LIST.def().help(wrap!(
                    "Whitespace separated Keccak hash list of transfers in \
                     the Bridge pool."
                )))
                .arg(RELAYER.def().help(wrap!(
                    "The rewards address for relaying this proof."
                )))
                .arg(ETH_ADDRESS_OPT.def().help(wrap!(
                    "The address of the Ethereum wallet to pay the gas fees. \
                     If unset, the default wallet is used."
                )))
                .arg(ETH_GAS.def().help(wrap!(
                    "The Ethereum gas that can be spent during the relay call."
                )))
                .arg(ETH_GAS_PRICE.def().help(wrap!(
                    "The price of Ethereum gas, during the relay call."
                )))
                .arg(
                    ETH_RPC_ENDPOINT
                        .def()
                        .help(wrap!("The Ethereum RPC endpoint.")),
                )
                .arg(ETH_CONFIRMATIONS.def().help(wrap!(
                    "The number of block confirmations on Ethereum."
                )))
                .arg(ETH_SYNC.def().help(wrap!(
                    "Synchronize with the network, or exit immediately, if \
                     the Ethereum node has fallen behind."
                )))
        }
    }

    impl CliToSdkCtxless<BridgeValidatorSet<SdkTypes>>
        for BridgeValidatorSet<CliTypes>
    {
        fn to_sdk_ctxless(self) -> BridgeValidatorSet<SdkTypes> {
            BridgeValidatorSet::<SdkTypes> {
                ledger_address: self.ledger_address,
                epoch: self.epoch,
            }
        }
    }

    impl Args for BridgeValidatorSet<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let ledger_address = LEDGER_ADDRESS.parse(matches);
            let epoch = EPOCH.parse(matches);
            Self {
                ledger_address,
                epoch,
            }
        }

        fn def(app: App) -> App {
            app.arg(LEDGER_ADDRESS.def().help(LEDGER_ADDRESS_ABOUT))
                .arg(EPOCH.def().help(wrap!(
                    "The epoch of the Bridge set of validators to query."
                )))
        }
    }

    impl CliToSdkCtxless<GovernanceValidatorSet<SdkTypes>>
        for GovernanceValidatorSet<CliTypes>
    {
        fn to_sdk_ctxless(self) -> GovernanceValidatorSet<SdkTypes> {
            GovernanceValidatorSet::<SdkTypes> {
                ledger_address: self.ledger_address,
                epoch: self.epoch,
            }
        }
    }

    impl Args for GovernanceValidatorSet<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let ledger_address = LEDGER_ADDRESS.parse(matches);
            let epoch = EPOCH.parse(matches);
            Self {
                ledger_address,
                epoch,
            }
        }

        fn def(app: App) -> App {
            app.arg(LEDGER_ADDRESS.def().help(LEDGER_ADDRESS_ABOUT))
                .arg(EPOCH.def().help(wrap!(
                    "The epoch of the Governance set of validators to query."
                )))
        }
    }

    impl CliToSdkCtxless<ValidatorSetProof<SdkTypes>>
        for ValidatorSetProof<CliTypes>
    {
        fn to_sdk_ctxless(self) -> ValidatorSetProof<SdkTypes> {
            ValidatorSetProof::<SdkTypes> {
                ledger_address: self.ledger_address,
                epoch: self.epoch,
            }
        }
    }

    impl Args for ValidatorSetProof<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let ledger_address = LEDGER_ADDRESS.parse(matches);
            let epoch = EPOCH.parse(matches);
            Self {
                ledger_address,
                epoch,
            }
        }

        fn def(app: App) -> App {
            app.arg(LEDGER_ADDRESS.def().help(LEDGER_ADDRESS_ABOUT))
                .arg(EPOCH.def().help(wrap!(
                    "The epoch of the set of validators to be proven."
                )))
        }
    }

    impl CliToSdkCtxless<ValidatorSetUpdateRelay<SdkTypes>>
        for ValidatorSetUpdateRelay<CliTypes>
    {
        fn to_sdk_ctxless(self) -> ValidatorSetUpdateRelay<SdkTypes> {
            ValidatorSetUpdateRelay::<SdkTypes> {
                daemon: self.daemon,
                ledger_address: self.ledger_address,
                confirmations: self.confirmations,
                eth_rpc_endpoint: (),
                epoch: self.epoch,
                gas: self.gas,
                gas_price: self.gas_price,
                eth_addr: self.eth_addr,
                sync: self.sync,
                retry_dur: self.retry_dur,
                success_dur: self.success_dur,
            }
        }
    }

    impl Args for ValidatorSetUpdateRelay<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let ledger_address = LEDGER_ADDRESS.parse(matches);
            let daemon = DAEMON_MODE.parse(matches);
            let epoch = EPOCH.parse(matches);
            let gas = ETH_GAS.parse(matches);
            let gas_price = ETH_GAS_PRICE.parse(matches);
            let eth_rpc_endpoint = ETH_RPC_ENDPOINT.parse(matches);
            let eth_addr = ETH_ADDRESS_OPT.parse(matches);
            let confirmations = ETH_CONFIRMATIONS.parse(matches);
            let sync = ETH_SYNC.parse(matches);
            let retry_dur =
                DAEMON_MODE_RETRY_DUR.parse(matches).map(|dur| dur.0);
            let success_dur =
                DAEMON_MODE_SUCCESS_DUR.parse(matches).map(|dur| dur.0);
            Self {
                ledger_address,
                sync,
                daemon,
                epoch,
                gas,
                gas_price,
                confirmations,
                eth_rpc_endpoint,
                eth_addr,
                retry_dur,
                success_dur,
            }
        }

        fn def(app: App) -> App {
            app.arg(LEDGER_ADDRESS.def().help(LEDGER_ADDRESS_ABOUT))
                .arg(DAEMON_MODE.def().help(wrap!(
                    "Run in daemon mode, which will continuously perform \
                     validator set updates."
                )))
                .arg(DAEMON_MODE_RETRY_DUR.def().help(wrap!(
                    "The amount of time to sleep between failed daemon mode \
                     relays."
                )))
                .arg(DAEMON_MODE_SUCCESS_DUR.def().help(wrap!(
                    "The amount of time to sleep between successful daemon \
                     mode relays."
                )))
                .arg(ETH_ADDRESS_OPT.def().help(wrap!(
                    "The address of the Ethereum wallet to pay the gas fees. \
                     If unset, the default wallet is used."
                )))
                .arg(EPOCH.def().help(wrap!(
                    "The epoch of the set of validators to relay."
                )))
                .arg(ETH_GAS.def().help(wrap!(
                    "The Ethereum gas that can be spent during the relay call."
                )))
                .arg(ETH_GAS_PRICE.def().help(wrap!(
                    "The price of Ethereum gas, during the relay call."
                )))
                .arg(
                    ETH_RPC_ENDPOINT
                        .def()
                        .help(wrap!("The Ethereum RPC endpoint.")),
                )
                .arg(ETH_CONFIRMATIONS.def().help(wrap!(
                    "The number of block confirmations on Ethereum."
                )))
                .arg(ETH_SYNC.def().help(wrap!(
                    "Synchronize with the network, or exit immediately, if \
                     the Ethereum node has fallen behind."
                )))
        }
    }

    impl CliToSdk<TxCustom<SdkTypes>> for TxCustom<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxCustom<SdkTypes>, Self::Error> {
            Ok(TxCustom::<SdkTypes> {
                tx: self.tx.to_sdk(ctx)?,
                code_path: self.code_path,
                data_path: self.data_path.map(|data_path| {
                    std::fs::read(data_path)
                        .expect("Expected a file at given path")
                }),
                serialized_tx: self.serialized_tx.map(|path| {
                    std::fs::read(path).expect("Expected a file at given path")
                }),
                owner: self
                    .owner
                    .map(|owner| ctx.borrow_chain_or_exit().get(&owner)),
                signatures: self
                    .signatures
                    .iter()
                    .map(|path| {
                        std::fs::read(path).map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!("Error reading signature file: {}", e),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                wrapper_signature: self
                    .wrapper_signature
                    .map(|path| {
                        std::fs::read(path).map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!("Error reading signature file: {}", e),
                            )
                        })
                    })
                    .transpose()?,
            })
        }
    }

    impl Args for TxCustom<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let code_path = CODE_PATH_OPT.parse(matches);
            let data_path = DATA_PATH_OPT.parse(matches);
            let serialized_tx = TX_PATH_OPT.parse(matches);
            let owner = OWNER_OPT.parse(matches);
            let signatures = SIGNATURES.parse(matches);
            let wrapper_signature = WRAPPER_SIGNATURE_OPT.parse(matches);
            Self {
                tx,
                code_path,
                data_path,
                serialized_tx,
                owner,
                signatures,
                wrapper_signature,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(
                    CODE_PATH_OPT
                        .def()
                        .help(wrap!("The path to the transaction's WASM code."))
                        .requires(DATA_PATH_OPT.name)
                        .conflicts_with_all([
                            SIGNATURES.name,
                            TX_PATH_OPT.name,
                            WRAPPER_SIGNATURE_OPT.name,
                        ]),
                )
                .arg(
                    DATA_PATH_OPT
                        .def()
                        .help(wrap!(
                            "The data file at this path containing arbitrary \
                             bytes will be passed to the transaction code \
                             when it's executed."
                        ))
                        .requires(CODE_PATH_OPT.name)
                        .conflicts_with_all([
                            SIGNATURES.name,
                            TX_PATH_OPT.name,
                            WRAPPER_SIGNATURE_OPT.name,
                        ]),
                )
                .arg(
                    TX_PATH_OPT
                        .def()
                        .help(wrap!(
                            "The path to a serialized transaction. It is \
                             expected that this transaction is contained in a \
                             .tx file, typically produced from a tx dump."
                        ))
                        .conflicts_with_all([
                            CODE_PATH_OPT.name,
                            DATA_PATH_OPT.name,
                        ]),
                )
                .arg(OWNER_OPT.def().help(wrap!(
                    "The optional address corresponding to the signatures or \
                     signing keys."
                )))
                .arg(
                    SIGNATURES
                        .def()
                        .help(wrap!(
                            "List of file paths containing a serialized \
                             signature to be attached to a transaction. \
                             Requires to provide a gas payer."
                        ))
                        .conflicts_with_all([
                            CODE_PATH_OPT.name,
                            DATA_PATH_OPT.name,
                        ]),
                )
                .arg(
                    WRAPPER_SIGNATURE_OPT
                        .def()
                        .help(wrap!(
                            "The file path containing a serialized signature \
                             of the entire transaction for gas payment."
                        ))
                        .conflicts_with(FEE_PAYER_OPT.name),
                )
        }
    }

    impl CliToSdk<TxTransparentTransfer<SdkTypes>>
        for TxTransparentTransfer<CliTypes>
    {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxTransparentTransfer<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let mut sources = vec![];
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            for transfer_data in self.sources {
                sources.push(TxTransparentSource {
                    source: chain_ctx.get(&transfer_data.source),
                    token: chain_ctx.get(&transfer_data.token),
                    amount: transfer_data.amount,
                });
            }
            let mut targets = vec![];
            for transfer_data in self.targets {
                targets.push(TxTransparentTarget {
                    target: chain_ctx.get(&transfer_data.target),
                    token: chain_ctx.get(&transfer_data.token),
                    amount: transfer_data.amount,
                });
            }

            Ok(TxTransparentTransfer::<SdkTypes> {
                tx,
                sources,
                targets,
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for TxTransparentTransfer<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let source = SOURCE.parse(matches);
            let target = TARGET.parse(matches);
            let token = TOKEN.parse(matches);
            let amount = InputAmount::Unvalidated(AMOUNT.parse(matches));
            let tx_code_path = PathBuf::from(TX_TRANSFER_WASM);
            let sources = vec![TxTransparentSource {
                source,
                token: token.clone(),
                amount,
            }];
            let targets = vec![TxTransparentTarget {
                target,
                token,
                amount,
            }];

            Self {
                tx,
                sources,
                targets,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(SOURCE.def().help(wrap!(
                    "The source account address. The source's key may be used \
                     to produce the signature."
                )))
                .arg(TARGET.def().help(wrap!("The target account address.")))
                .arg(TOKEN.def().help(wrap!("The token address.")))
                .arg(
                    AMOUNT
                        .def()
                        .help(wrap!("The amount to transfer in decimal.")),
                )
        }
    }

    impl CliToSdk<TxShieldedTransfer<SdkTypes>> for TxShieldedTransfer<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxShieldedTransfer<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let mut sources = vec![];
            let mut targets = vec![];
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            for transfer_data in self.sources {
                sources.push(TxShieldedSource {
                    source: chain_ctx.get_cached(&transfer_data.source),
                    token: chain_ctx.get(&transfer_data.token),
                    amount: transfer_data.amount,
                });
            }

            for transfer_data in self.targets {
                targets.push(TxShieldedTarget {
                    target: chain_ctx.get(&transfer_data.target),
                    token: chain_ctx.get(&transfer_data.token),
                    amount: transfer_data.amount,
                });
            }

            let gas_spending_key =
                self.gas_spending_key.map(|key| chain_ctx.get_cached(&key));

            Ok(TxShieldedTransfer::<SdkTypes> {
                tx,
                sources,
                targets,
                gas_spending_key,
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for TxShieldedTransfer<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let source = SPENDING_KEY_SOURCE.parse(matches);
            let target = PAYMENT_ADDRESS_TARGET.parse(matches);
            let token = TOKEN.parse(matches);
            let amount = InputAmount::Unvalidated(AMOUNT.parse(matches));
            let tx_code_path = PathBuf::from(TX_TRANSFER_WASM);
            let sources = vec![TxShieldedSource {
                source,
                token: token.clone(),
                amount,
            }];
            let targets = vec![TxShieldedTarget {
                target,
                token,
                amount,
            }];
            let gas_spending_key = GAS_SPENDING_KEY.parse(matches);

            Self {
                tx,
                sources,
                targets,
                gas_spending_key,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(
                    SPENDING_KEY_SOURCE
                        .def()
                        .help(wrap!("The source shielded spending key.")),
                )
                .arg(
                    PAYMENT_ADDRESS_TARGET
                        .def()
                        .help(wrap!("The shielded target account address.")),
                )
                .arg(TOKEN.def().help(wrap!("The token address.")))
                .arg(
                    AMOUNT
                        .def()
                        .help(wrap!("The amount to transfer in decimal.")),
                )
                .arg(GAS_SPENDING_KEY.def().help(wrap!(
                    "The optional spending key that will be used for gas \
                     payment. When not provided the source spending key will \
                     be used."
                )))
        }
    }

    impl CliToSdk<TxShieldingTransfer<SdkTypes>> for TxShieldingTransfer<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxShieldingTransfer<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let mut data = vec![];
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            for transfer_data in self.sources {
                data.push(TxTransparentSource {
                    source: chain_ctx.get(&transfer_data.source),
                    token: chain_ctx.get(&transfer_data.token),
                    amount: transfer_data.amount,
                });
            }

            let mut targets = vec![];
            for transfer_data in self.targets {
                targets.push(TxShieldedTarget {
                    target: chain_ctx.get(&transfer_data.target),
                    token: chain_ctx.get(&transfer_data.token),
                    amount: transfer_data.amount,
                });
            }

            Ok(TxShieldingTransfer::<SdkTypes> {
                tx,
                sources: data,
                targets,
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for TxShieldingTransfer<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let source = SOURCE.parse(matches);
            let target = PAYMENT_ADDRESS_TARGET.parse(matches);
            let token = TOKEN.parse(matches);
            let amount = InputAmount::Unvalidated(AMOUNT.parse(matches));
            let tx_code_path = PathBuf::from(TX_TRANSFER_WASM);
            let data = vec![TxTransparentSource {
                source,
                token: token.clone(),
                amount,
            }];
            let targets = vec![TxShieldedTarget {
                target,
                token,
                amount,
            }];

            Self {
                tx,
                sources: data,
                targets,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(SOURCE.def().help(wrap!(
                    "The transparent source account address. The source's key \
                     will be used to produce the signature."
                )))
                .arg(
                    PAYMENT_ADDRESS_TARGET
                        .def()
                        .help(wrap!("The target shielded account address.")),
                )
                .arg(TOKEN.def().help(wrap!("The token address.")))
                .arg(
                    AMOUNT
                        .def()
                        .help(wrap!("The amount to transfer in decimal.")),
                )
        }
    }

    impl CliToSdk<TxUnshieldingTransfer<SdkTypes>>
        for TxUnshieldingTransfer<CliTypes>
    {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxUnshieldingTransfer<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let mut data = vec![];
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            for transfer_data in self.targets {
                data.push(TxTransparentTarget {
                    target: chain_ctx.get(&transfer_data.target),
                    token: chain_ctx.get(&transfer_data.token),
                    amount: transfer_data.amount,
                });
            }

            let mut sources = vec![];
            for transfer_data in self.sources {
                sources.push(TxShieldedSource {
                    source: chain_ctx.get_cached(&transfer_data.source),
                    token: chain_ctx.get(&transfer_data.token),
                    amount: transfer_data.amount,
                });
            }
            let gas_spending_key =
                self.gas_spending_key.map(|key| chain_ctx.get_cached(&key));

            Ok(TxUnshieldingTransfer::<SdkTypes> {
                tx,
                targets: data,
                gas_spending_key,
                sources,
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for TxUnshieldingTransfer<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let source = SPENDING_KEY_SOURCE.parse(matches);
            let target = TARGET.parse(matches);
            let token = TOKEN.parse(matches);
            let amount = InputAmount::Unvalidated(AMOUNT.parse(matches));
            let tx_code_path = PathBuf::from(TX_TRANSFER_WASM);
            let data = vec![TxTransparentTarget {
                target,
                token: token.clone(),
                amount,
            }];
            let sources = vec![TxShieldedSource {
                source,
                token,
                amount,
            }];
            let gas_spending_key = GAS_SPENDING_KEY.parse(matches);

            Self {
                tx,
                sources,
                targets: data,
                gas_spending_key,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(
                    SPENDING_KEY_SOURCE
                        .def()
                        .help(wrap!("The source shielded spending key.")),
                )
                .arg(
                    TARGET
                        .def()
                        .help(wrap!("The transparent target account address.")),
                )
                .arg(TOKEN.def().help(wrap!("The token address.")))
                .arg(
                    AMOUNT
                        .def()
                        .help(wrap!("The amount to transfer in decimal.")),
                )
                .arg(GAS_SPENDING_KEY.def().help(wrap!(
                    "The optional spending key that will be used for gas \
                     payment. When not provided the source spending key will \
                     be used."
                )))
        }
    }

    impl CliToSdk<TxIbcTransfer<SdkTypes>> for TxIbcTransfer<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxIbcTransfer<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            let gas_spending_key =
                self.gas_spending_key.map(|key| chain_ctx.get_cached(&key));

            Ok(TxIbcTransfer::<SdkTypes> {
                tx,
                source: chain_ctx.get_cached(&self.source),
                receiver: self.receiver,
                token: chain_ctx.get(&self.token),
                amount: self.amount,
                port_id: self.port_id,
                channel_id: self.channel_id,
                timeout_height: self.timeout_height,
                timeout_sec_offset: self.timeout_sec_offset,
                refund_target: chain_ctx.get_opt(&self.refund_target),
                ibc_shielding_data: self.ibc_shielding_data,
                ibc_memo: self.ibc_memo,
                gas_spending_key,
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for TxIbcTransfer<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let source = TRANSFER_SOURCE.parse(matches);
            let receiver = RECEIVER.parse(matches);
            let token = TOKEN.parse(matches);
            let amount = InputAmount::Unvalidated(AMOUNT.parse(matches));
            let port_id = PORT_ID.parse(matches);
            let channel_id = CHANNEL_ID.parse(matches);
            let timeout_height = TIMEOUT_HEIGHT.parse(matches);
            let timeout_sec_offset = TIMEOUT_SEC_OFFSET.parse(matches);
            let refund_target = REFUND_TARGET.parse(matches);
            let ibc_shielding_data =
                IBC_SHIELDING_DATA_PATH.parse(matches).map(|path| {
                    let data = std::fs::read_to_string(path)
                        .expect("Failed to open IBC shielding data file");
                    namada_sdk::ibc::decode_ibc_shielding_data(data)
                        .expect("Failed to decode IBC shielding data")
                });
            let ibc_memo = IBC_MEMO.parse(matches);
            let gas_spending_key = GAS_SPENDING_KEY.parse(matches);
            let tx_code_path = PathBuf::from(TX_IBC_WASM);
            Self {
                tx,
                source,
                receiver,
                token,
                amount,
                port_id,
                channel_id,
                timeout_height,
                timeout_sec_offset,
                refund_target,
                ibc_shielding_data,
                ibc_memo,
                gas_spending_key,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(SOURCE.def().help(wrap!(
                    "The source account address. The source's key is used to \
                     produce the signature."
                )))
                .arg(RECEIVER.def().help(wrap!(
                    "The receiver address on the destination chain as a \
                     string."
                )))
                .arg(TOKEN.def().help(wrap!("The transfer token.")))
                .arg(
                    AMOUNT
                        .def()
                        .help(wrap!("The amount to transfer in decimal.")),
                )
                .arg(PORT_ID.def().help(wrap!("The port ID.")))
                .arg(CHANNEL_ID.def().help(wrap!("The channel ID.")))
                .arg(TIMEOUT_HEIGHT.def().help(wrap!(
                    "The timeout height of the destination chain."
                )))
                .arg(
                    TIMEOUT_SEC_OFFSET
                        .def()
                        .help(wrap!("The timeout as seconds.")),
                )
                .arg(REFUND_TARGET.def().help(wrap!(
                    "The refund target address to use if the IBC shielded \
                     transfer fails."
                )))
                .arg(IBC_SHIELDING_DATA_PATH.def().help(wrap!(
                    "Used only when shielding over IBC from one instance of \
                     the Namada blockchain to another. The file path of the \
                     IBC shielding data for the destination Namada chain. \
                     This can't be set with --ibc-memo at the same time."
                )))
                .arg(
                    IBC_MEMO
                        .def()
                        .help(wrap!("The memo for IBC transfer packet.")),
                )
                .arg(GAS_SPENDING_KEY.def().help(wrap!(
                    "The optional spending key that will be used for gas \
                     payment (if this is a shielded action).  When not \
                     provided the source spending key will be used."
                )))
        }
    }

    impl CliToSdk<TxOsmosisSwap<SdkTypes>> for TxOsmosisSwap<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxOsmosisSwap<SdkTypes>, Self::Error> {
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            let recipient = match self.recipient {
                Either::Left(r) => Either::Left(chain_ctx.get(&r)),
                Either::Right(r) => Either::Right(chain_ctx.get(&r)),
            };
            let overflow = self.overflow.map(|r| chain_ctx.get(&r));
            Ok(TxOsmosisSwap {
                transfer: self.transfer.to_sdk(ctx)?,
                output_denom: self.output_denom,
                recipient,
                overflow,
                slippage: self.slippage,
                local_recovery_addr: self.local_recovery_addr,
                route: self.route,
                osmosis_lcd_rpc: self.osmosis_lcd_rpc,
                osmosis_sqs_rpc: self.osmosis_sqs_rpc,
            })
        }
    }

    impl Args for TxOsmosisSwap<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let transfer = TxIbcTransfer::parse(matches);
            let osmosis_lcd_rpc = OSMOSIS_LCD_RPC.parse(matches);
            let osmosis_sqs_rpc = OSMOSIS_SQS_RPC.parse(matches);
            let output_denom = OUTPUT_DENOM.parse(matches);
            let maybe_trans_recipient = TARGET_OPT.parse(matches);
            let maybe_shielded_recipient =
                PAYMENT_ADDRESS_TARGET_OPT.parse(matches);
            let maybe_overflow = OVERFLOW_OPT.parse(matches);
            let slippage_percent = SLIPPAGE.parse(matches);
            if slippage_percent.is_some_and(|percent| {
                let zero = Dec::zero();
                let hundred = Dec::new(100, 0).unwrap();

                percent < zero || percent > hundred
            }) {
                panic!(
                    "The slippage percent must be a number between 0 and 100."
                )
            }
            let minimum_amount = MINIMUM_AMOUNT.parse(matches);
            let slippage = minimum_amount
                .map(|d| Slippage::MinOutputAmount(d.redenominate(0).amount()))
                .or_else(|| {
                    Some(Slippage::Twap {
                        slippage_percentage: slippage_percent?,
                    })
                });
            let local_recovery_addr = LOCAL_RECOVERY_ADDR.parse(matches);
            let route = match OSMOSIS_POOL_HOP.parse(matches) {
                r if r.is_empty() => None,
                r => Some(r),
            };
            Self {
                transfer,
                output_denom,
                recipient: if let Some(target) = maybe_trans_recipient {
                    Either::Left(target)
                } else {
                    Either::Right(maybe_shielded_recipient.unwrap())
                },
                overflow: maybe_overflow,
                slippage,
                local_recovery_addr,
                route,
                osmosis_lcd_rpc,
                osmosis_sqs_rpc,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<TxIbcTransfer<CliTypes>>()
                .arg(
                    OSMOSIS_LCD_RPC
                        .def()
                        .help(wrap!("URL pointing to an Osmosis lcd rpc.")),
                )
                .arg(
                    OSMOSIS_SQS_RPC
                        .def()
                        .help(wrap!("URL pointing to an Osmosis sqs rpc.")),
                )
                .arg(OSMOSIS_POOL_HOP.def().conflicts_with(SLIPPAGE.name).help(
                    wrap!(
                        "Individual hop of the route to take through Osmosis \
                         pools. This value takes the form \
                         <osmosis-pool-id>:<pool-output-denom>. When \
                         unspecified, the optimal route is queried on the fly."
                    ),
                ))
                .arg(OUTPUT_DENOM.def().help(wrap!(
                    "IBC trace path (on Namada) of the desired asset. This is \
                     a string of the form \
                     `transfer/<channel-X>/<base-denom>`, where `<channel-X>` \
                     is the channel that connects Namada to some counterparty \
                     chain."
                )))
                .arg(
                    TARGET_OPT
                        .def()
                        .conflicts_with(OVERFLOW_OPT.name)
                        .conflicts_with(PAYMENT_ADDRESS_TARGET_OPT.name)
                        .help(wrap!(
                            "Transparent Namada address that shall receive \
                             the swapped tokens."
                        )),
                )
                .arg(
                    PAYMENT_ADDRESS_TARGET_OPT
                        .def()
                        .conflicts_with(TARGET_OPT.name)
                        .help(wrap!(
                            "Namada payment address that shall receive the \
                             minimum amount of tokens swapped on Osmosis."
                        )),
                )
                .arg(OVERFLOW_OPT.def().help(wrap!(
                    "Transparent address that receives the amount of target \
                     asset exceeding the minimum trade amount. Only \
                     applicable when shielding assets that have been swapped \
                     on Osmosis. This address should not be linkable to any \
                     of the user's personal accounts, to maximize the privacy \
                     of the trade. If unspecified, a disposable address is \
                     generated."
                )))
                .arg(SLIPPAGE.def().help(wrap!(
                    "Slippage percentage, as a number between 0 and 100. \
                     Represents the maximum acceptable deviation from the \
                     expected price during a trade."
                )))
                .arg(MINIMUM_AMOUNT.def().conflicts_with(SLIPPAGE.name).help(
                    wrap!(
                        "Minimum amount of target asset that the trade should \
                         produce."
                    ),
                ))
                .arg(LOCAL_RECOVERY_ADDR.def().help(wrap!(
                    "Address on Osmosis from which to recover funds in case \
                     of failure."
                )))
                .group(
                    ArgGroup::new("transfer-target")
                        .args([
                            TARGET_OPT.name,
                            PAYMENT_ADDRESS_TARGET_OPT.name,
                        ])
                        .required(true),
                )
                .mut_arg(RECEIVER.name, |arg| {
                    arg.long("swap-contract").help(wrap!(
                        "Address of the Osmosis contract performing the swap. \
                         It will be the receiver of the IBC transfer."
                    ))
                })
        }
    }

    impl CliToSdk<TxInitAccount<SdkTypes>> for TxInitAccount<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxInitAccount<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            Ok(TxInitAccount::<SdkTypes> {
                tx,
                vp_code_path: self.vp_code_path,
                tx_code_path: self.tx_code_path,
                public_keys: self
                    .public_keys
                    .iter()
                    .map(|pk| chain_ctx.get(pk))
                    .collect(),
                threshold: self.threshold,
            })
        }
    }

    impl Args for TxInitAccount<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let vp_code_path = CODE_PATH_OPT
                .parse(matches)
                .unwrap_or_else(|| PathBuf::from(VP_USER_WASM));
            let tx_code_path = PathBuf::from(TX_INIT_ACCOUNT_WASM);
            let public_keys = PUBLIC_KEYS.parse(matches);
            let threshold = THRESHOLD.parse(matches);
            Self {
                tx,
                vp_code_path,
                public_keys,
                threshold,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(CODE_PATH_OPT.def().help(wrap!(
                    "The path to the validity predicate WASM code to be used \
                     for the new account. Uses the default user VP if none \
                     specified."
                )))
                .arg(PUBLIC_KEYS.def().help(wrap!(
                    "A list public keys to be associated with the new account \
                     in hexadecimal encoding."
                )))
                .arg(THRESHOLD.def().help(wrap!(
                    "The minimum number of signature to be provided for \
                     authorization. Must be less then the maximum number of \
                     public keys provided."
                )))
        }
    }

    impl CliToSdk<TxBecomeValidator<SdkTypes>> for TxBecomeValidator<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxBecomeValidator<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            Ok(TxBecomeValidator::<SdkTypes> {
                tx,
                scheme: self.scheme,
                address: chain_ctx.get(&self.address),
                consensus_key: self.consensus_key.map(|x| chain_ctx.get(&x)),
                eth_cold_key: self.eth_cold_key.map(|x| chain_ctx.get(&x)),
                eth_hot_key: self.eth_hot_key.map(|x| chain_ctx.get(&x)),
                protocol_key: self.protocol_key.map(|x| chain_ctx.get(&x)),
                commission_rate: self.commission_rate,
                max_commission_rate_change: self.max_commission_rate_change,
                email: self.email,
                description: self.description,
                website: self.website,
                discord_handle: self.discord_handle,
                avatar: self.avatar,
                name: self.name,
                unsafe_dont_encrypt: self.unsafe_dont_encrypt,
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for TxBecomeValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let address = ADDRESS.parse(matches);
            let scheme = SCHEME.parse(matches);
            let consensus_key = VALIDATOR_CONSENSUS_KEY.parse(matches);
            let eth_cold_key = VALIDATOR_ETH_COLD_KEY.parse(matches);
            let eth_hot_key = VALIDATOR_ETH_HOT_KEY.parse(matches);
            let protocol_key = PROTOCOL_KEY.parse(matches);
            let commission_rate = COMMISSION_RATE.parse(matches);
            let max_commission_rate_change =
                MAX_COMMISSION_RATE_CHANGE.parse(matches);
            let email = EMAIL.parse(matches);
            let description = DESCRIPTION_OPT.parse(matches);
            let website = WEBSITE_OPT.parse(matches);
            let discord_handle = DISCORD_OPT.parse(matches);
            let avatar = AVATAR_OPT.parse(matches);
            let name = VALIDATOR_NAME_OPT.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_BECOME_VALIDATOR_WASM);
            Self {
                tx,
                address,
                scheme,
                consensus_key,
                eth_cold_key,
                eth_hot_key,
                protocol_key,
                commission_rate,
                max_commission_rate_change,
                email,
                description,
                website,
                discord_handle,
                avatar,
                name,
                unsafe_dont_encrypt,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(ADDRESS.def().help(wrap!(
                    "Address of an account that will become a validator."
                )))
                .arg(SCHEME.def().help(wrap!(
                    "The key scheme/type used for the validator keys. \
                     Currently supports ed25519 and secp256k1."
                )))
                .arg(VALIDATOR_CONSENSUS_KEY.def().help(wrap!(
                    "A consensus key for the validator account. A new one \
                     will be generated if none given. Note that this must be \
                     ed25519."
                )))
                .arg(VALIDATOR_ETH_COLD_KEY.def().help(wrap!(
                    "An Eth cold key for the validator account. A new one \
                     will be generated if none given. Note that this must be \
                     secp256k1."
                )))
                .arg(VALIDATOR_ETH_HOT_KEY.def().help(wrap!(
                    "An Eth hot key for the validator account. A new one will \
                     be generated if none given. Note that this must be \
                     secp256k1."
                )))
                .arg(PROTOCOL_KEY.def().help(wrap!(
                    "A public key for signing protocol transactions. A new \
                     one will be generated if none given."
                )))
                .arg(COMMISSION_RATE.def().help(wrap!(
                    "The commission rate charged by the validator for \
                     delegation rewards. Expressed as a decimal between 0 and \
                     1. This is a required parameter."
                )))
                .arg(MAX_COMMISSION_RATE_CHANGE.def().help(wrap!(
                    "The maximum change per epoch in the commission rate \
                     charged by the validator for delegation rewards. \
                     Expressed as a decimal between 0 and 1. This is a \
                     required parameter."
                )))
                .arg(EMAIL.def().help(wrap!("The validator's email.")))
                .arg(
                    DESCRIPTION_OPT
                        .def()
                        .help(wrap!("The validator's description.")),
                )
                .arg(WEBSITE_OPT.def().help(wrap!("The validator's website.")))
                .arg(
                    DISCORD_OPT
                        .def()
                        .help(wrap!("The validator's discord handle.")),
                )
                .arg(AVATAR_OPT.def().help(wrap!("The validator's avatar.")))
                .arg(VALIDATOR_NAME_OPT.def().help(wrap!(
                    "The validator's name, used to identify the validator in \
                     online services."
                )))
                .arg(VALIDATOR_CODE_PATH.def().help(wrap!(
                    "The path to the validity predicate WASM code to be used \
                     for the validator account. Uses the default validator VP \
                     if none specified."
                )))
                .arg(UNSAFE_DONT_ENCRYPT.def().help(wrap!(
                    "UNSAFE: Do not encrypt the generated keypairs. Do not \
                     use this for keys used in a live network."
                )))
        }
    }

    impl CliToSdk<TxInitValidator<SdkTypes>> for TxInitValidator<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxInitValidator<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            Ok(TxInitValidator::<SdkTypes> {
                tx,
                scheme: self.scheme,
                account_keys: self
                    .account_keys
                    .iter()
                    .map(|x| chain_ctx.get(x))
                    .collect(),
                threshold: self.threshold,
                consensus_key: self.consensus_key.map(|x| chain_ctx.get(&x)),
                eth_cold_key: self.eth_cold_key.map(|x| chain_ctx.get(&x)),
                eth_hot_key: self.eth_hot_key.map(|x| chain_ctx.get(&x)),
                protocol_key: self.protocol_key.map(|x| chain_ctx.get(&x)),
                commission_rate: self.commission_rate,
                max_commission_rate_change: self.max_commission_rate_change,
                email: self.email,
                description: self.description,
                website: self.website,
                discord_handle: self.discord_handle,
                avatar: self.avatar,
                name: self.name,
                validator_vp_code_path: self
                    .validator_vp_code_path
                    .to_path_buf(),
                unsafe_dont_encrypt: self.unsafe_dont_encrypt,
                tx_init_account_code_path: self
                    .tx_init_account_code_path
                    .to_path_buf(),
                tx_become_validator_code_path: self
                    .tx_become_validator_code_path
                    .to_path_buf(),
            })
        }
    }

    impl Args for TxInitValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let scheme = SCHEME.parse(matches);
            let account_keys = VALIDATOR_ACCOUNT_KEYS.parse(matches);
            let consensus_key = VALIDATOR_CONSENSUS_KEY.parse(matches);
            let eth_cold_key = VALIDATOR_ETH_COLD_KEY.parse(matches);
            let eth_hot_key = VALIDATOR_ETH_HOT_KEY.parse(matches);
            let protocol_key = PROTOCOL_KEY.parse(matches);
            let commission_rate = COMMISSION_RATE.parse(matches);
            let max_commission_rate_change =
                MAX_COMMISSION_RATE_CHANGE.parse(matches);
            let email = EMAIL.parse(matches);
            let description = DESCRIPTION_OPT.parse(matches);
            let website = WEBSITE_OPT.parse(matches);
            let discord_handle = DISCORD_OPT.parse(matches);
            let avatar = AVATAR_OPT.parse(matches);
            let name = VALIDATOR_NAME_OPT.parse(matches);
            let validator_vp_code_path = VALIDATOR_CODE_PATH
                .parse(matches)
                .unwrap_or_else(|| PathBuf::from(VP_USER_WASM));
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let tx_init_account_code_path = PathBuf::from(TX_INIT_ACCOUNT_WASM);
            let tx_become_validator_code_path =
                PathBuf::from(TX_BECOME_VALIDATOR_WASM);
            let threshold = THRESHOLD.parse(matches);
            Self {
                tx,
                scheme,
                account_keys,
                threshold,
                consensus_key,
                eth_cold_key,
                eth_hot_key,
                protocol_key,
                commission_rate,
                max_commission_rate_change,
                email,
                description,
                website,
                discord_handle,
                avatar,
                name,
                validator_vp_code_path,
                unsafe_dont_encrypt,
                tx_init_account_code_path,
                tx_become_validator_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(SCHEME.def().help(wrap!(
                    "The key scheme/type used for the validator keys. \
                     Currently supports ed25519 and secp256k1."
                )))
                .arg(VALIDATOR_ACCOUNT_KEYS.def().help(wrap!(
                    "A list public keys to be associated with the new account \
                     in hexadecimal encoding. A new one will be generated if \
                     none given."
                )))
                .arg(VALIDATOR_CONSENSUS_KEY.def().help(wrap!(
                    "A consensus key for the validator account. A new one \
                     will be generated if none given. Note that this must be \
                     ed25519."
                )))
                .arg(VALIDATOR_ETH_COLD_KEY.def().help(wrap!(
                    "An Eth cold key for the validator account. A new one \
                     will be generated if none given. Note that this must be \
                     secp256k1."
                )))
                .arg(VALIDATOR_ETH_HOT_KEY.def().help(wrap!(
                    "An Eth hot key for the validator account. A new one will \
                     be generated if none given. Note that this must be \
                     secp256k1."
                )))
                .arg(PROTOCOL_KEY.def().help(wrap!(
                    "A public key for signing protocol transactions. A new \
                     one will be generated if none given."
                )))
                .arg(COMMISSION_RATE.def().help(wrap!(
                    "The commission rate charged by the validator for \
                     delegation rewards. Expressed as a decimal between 0 and \
                     1. This is a required parameter."
                )))
                .arg(MAX_COMMISSION_RATE_CHANGE.def().help(wrap!(
                    "The maximum change per epoch in the commission rate \
                     charged by the validator for delegation rewards. \
                     Expressed as a decimal between 0 and 1. This is a \
                     required parameter."
                )))
                .arg(EMAIL.def().help(wrap!("The validator's email.")))
                .arg(
                    DESCRIPTION_OPT
                        .def()
                        .help(wrap!("The validator's description.")),
                )
                .arg(WEBSITE_OPT.def().help(wrap!("The validator's website.")))
                .arg(
                    DISCORD_OPT
                        .def()
                        .help(wrap!("The validator's discord handle.")),
                )
                .arg(AVATAR_OPT.def().help(wrap!("The validator's avatar.")))
                .arg(VALIDATOR_NAME_OPT.def().help(wrap!(
                    "The validator's alias, used to identify the validator in \
                     online services."
                )))
                .arg(VALIDATOR_CODE_PATH.def().help(wrap!(
                    "The path to the validity predicate WASM code to be used \
                     for the validator account. Uses the default validator VP \
                     if none specified."
                )))
                .arg(UNSAFE_DONT_ENCRYPT.def().help(wrap!(
                    "UNSAFE: Do not encrypt the generated keypairs. Do not \
                     use this for keys used in a live network."
                )))
                .arg(THRESHOLD.def().help(wrap!(
                    "The minimum number of signature to be provided for \
                     authorization. Must be less then the maximum number of \
                     public keys provided."
                )))
        }
    }

    impl CliToSdk<TxUpdateAccount<SdkTypes>> for TxUpdateAccount<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxUpdateAccount<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            Ok(TxUpdateAccount::<SdkTypes> {
                tx,
                vp_code_path: self.vp_code_path,
                tx_code_path: self.tx_code_path,
                addr: chain_ctx.get(&self.addr),
                public_keys: self
                    .public_keys
                    .iter()
                    .map(|pk| chain_ctx.get(pk))
                    .collect(),
                threshold: self.threshold,
            })
        }
    }

    impl Args for TxUpdateAccount<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let vp_code_path = CODE_PATH_OPT.parse(matches);
            let addr = ADDRESS.parse(matches);
            let tx_code_path = PathBuf::from(TX_UPDATE_ACCOUNT_WASM);
            let public_keys = PUBLIC_KEYS.parse(matches);
            let threshold = THRESHOLD.parse(matches);
            Self {
                tx,
                vp_code_path,
                addr,
                tx_code_path,
                public_keys,
                threshold,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(CODE_PATH_OPT.def().help(wrap!(
                    "The path to the new validity predicate WASM code."
                )))
                .arg(ADDRESS.def().help(wrap!(
                    "The account's address. It's key is used to produce the \
                     signature."
                )))
                .arg(PUBLIC_KEYS.def().help(wrap!(
                    "A list public keys to be associated with the new account \
                     in hexadecimal encoding."
                )))
                .arg(THRESHOLD.def().help(wrap!(
                    "The minimum number of signature to be provided for \
                     authorization. Must be less then the maximum number of \
                     public keys provided."
                )))
        }
    }

    impl CliToSdk<Bond<SdkTypes>> for Bond<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<Bond<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_chain_or_exit();

            Ok(Bond::<SdkTypes> {
                tx,
                validator: chain_ctx.get(&self.validator),
                amount: self.amount,
                source: self.source.map(|x| chain_ctx.get(&x)),
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for Bond<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let amount = AMOUNT.parse(matches);
            let amount = amount
                .canonical()
                .increase_precision(NATIVE_MAX_DECIMAL_PLACES.into())
                .unwrap_or_else(|e| {
                    println!("Could not parse bond amount: {:?}", e);
                    safe_exit(1);
                })
                .amount();
            let source = SOURCE_OPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_BOND_WASM);
            Self {
                tx,
                validator,
                amount,
                source,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help(wrap!("Validator address.")))
                .arg(
                    AMOUNT
                        .def()
                        .help(wrap!("Amount of tokens to stake in a bond.")),
                )
                .arg(SOURCE_OPT.def().help(wrap!(
                    "Source address for delegations. For self-bonds, the \
                     validator is also the source."
                )))
        }
    }

    impl CliToSdk<Unbond<SdkTypes>> for Unbond<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<Unbond<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_chain_or_exit();

            Ok(Unbond::<SdkTypes> {
                tx,
                validator: chain_ctx.get(&self.validator),
                amount: self.amount,
                source: self.source.map(|x| chain_ctx.get(&x)),
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for Unbond<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let amount = AMOUNT.parse(matches);
            let amount = amount
                .canonical()
                .increase_precision(NATIVE_MAX_DECIMAL_PLACES.into())
                .unwrap_or_else(|e| {
                    println!("Could not parse bond amount: {:?}", e);
                    safe_exit(1);
                })
                .amount();
            let source = SOURCE_OPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_UNBOND_WASM);
            Self {
                tx,
                validator,
                amount,
                source,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help(wrap!("Validator address.")))
                .arg(
                    AMOUNT
                        .def()
                        .help(wrap!("Amount of tokens to unbond from a bond.")),
                )
                .arg(SOURCE_OPT.def().help(wrap!(
                    "Source address for unbonding from delegations. For \
                     unbonding from self-bonds, the validator is also the \
                     source."
                )))
        }
    }

    impl CliToSdk<UpdateStewardCommission<SdkTypes>>
        for UpdateStewardCommission<CliTypes>
    {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<UpdateStewardCommission<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let commission = std::fs::read(self.commission)?;

            Ok(UpdateStewardCommission::<SdkTypes> {
                tx,
                steward: ctx.borrow_chain_or_exit().get(&self.steward),
                commission,
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for UpdateStewardCommission<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let steward = STEWARD.parse(matches);
            let commission = DATA_PATH.parse(matches);
            let tx_code_path = PathBuf::from(TX_UPDATE_STEWARD_COMMISSION);
            Self {
                tx,
                steward,
                commission,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(STEWARD.def().help(wrap!("Steward address.")))
                .arg(DATA_PATH.def().help(wrap!(
                    "The path to the file that describes the commission \
                     split. The file must contain a map from namada address \
                     to a percentage. Percentages must sum to 1 or less."
                )))
        }
    }

    impl CliToSdk<ResignSteward<SdkTypes>> for ResignSteward<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<ResignSteward<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;

            Ok(ResignSteward::<SdkTypes> {
                tx,
                steward: ctx.borrow_chain_or_exit().get(&self.steward),
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for ResignSteward<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let steward = STEWARD.parse(matches);
            let tx_code_path = PathBuf::from(TX_RESIGN_STEWARD);
            Self {
                tx,
                steward,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(STEWARD.def().help(wrap!("Steward address.")))
        }
    }

    impl CliToSdk<Redelegate<SdkTypes>> for Redelegate<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<Redelegate<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_chain_or_exit();

            Ok(Redelegate::<SdkTypes> {
                tx,
                src_validator: chain_ctx.get(&self.src_validator),
                dest_validator: chain_ctx.get(&self.dest_validator),
                owner: chain_ctx.get(&self.owner),
                amount: self.amount,
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for Redelegate<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let src_validator = SOURCE_VALIDATOR.parse(matches);
            let dest_validator = DESTINATION_VALIDATOR.parse(matches);
            let owner = OWNER.parse(matches);
            let amount = AMOUNT.parse(matches);
            let amount = amount
                .canonical()
                .increase_precision(NATIVE_MAX_DECIMAL_PLACES.into())
                .unwrap_or_else(|e| {
                    println!("Could not parse bond amount: {:?}", e);
                    safe_exit(1);
                })
                .amount();
            let tx_code_path = PathBuf::from(TX_REDELEGATE_WASM);
            Self {
                tx,
                src_validator,
                dest_validator,
                owner,
                amount,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(SOURCE_VALIDATOR.def().help(wrap!(
                    "Source validator address for the redelegation."
                )))
                .arg(DESTINATION_VALIDATOR.def().help(wrap!(
                    "Destination validator address for the redelegation."
                )))
                .arg(OWNER.def().help(wrap!(
                    "Delegator (owner) address of the bonds that are being \
                     redelegated."
                )))
                .arg(
                    AMOUNT.def().help(wrap!("Amount of tokens to redelegate.")),
                )
        }
    }

    impl CliToSdk<InitProposal<SdkTypes>> for InitProposal<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<InitProposal<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let proposal_data = std::fs::read(self.proposal_data)?;

            Ok(InitProposal::<SdkTypes> {
                tx,
                proposal_data,
                is_pgf_stewards: self.is_pgf_stewards,
                is_pgf_funding: self.is_pgf_funding,
                tx_code_path: self.tx_code_path,
            })
        }
    }

    impl Args for InitProposal<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let proposal_data = DATA_PATH.parse(matches);
            let is_pgf_stewards = PROPOSAL_PGF_STEWARD.parse(matches);
            let is_pgf_funding = PROPOSAL_PGF_FUNDING.parse(matches);
            let tx_code_path = PathBuf::from(TX_INIT_PROPOSAL);

            Self {
                tx,
                proposal_data,
                tx_code_path,
                is_pgf_stewards,
                is_pgf_funding,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(DATA_PATH.def().help(wrap!(
                    "The data path file (json) that describes the proposal."
                )))
                .arg(
                    PROPOSAL_PGF_STEWARD
                        .def()
                        .help(wrap!(
                            "Flag if the proposal is of type pgf-stewards. \
                             Used to elect/remove stewards."
                        ))
                        .conflicts_with(PROPOSAL_PGF_FUNDING.name),
                )
                .arg(
                    PROPOSAL_PGF_FUNDING
                        .def()
                        .help(wrap!(
                            "Flag if the proposal is of type pgf-funding. \
                             Used to control continuous/retro PGF fundings."
                        ))
                        .conflicts_with(PROPOSAL_PGF_STEWARD.name),
                )
        }
    }

    impl CliToSdk<VoteProposal<SdkTypes>> for VoteProposal<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<VoteProposal<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;

            Ok(VoteProposal::<SdkTypes> {
                tx,
                proposal_id: self.proposal_id,
                vote: self.vote,
                voter_address: ctx
                    .borrow_chain_or_exit()
                    .get(&self.voter_address),
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for VoteProposal<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let proposal_id = PROPOSAL_ID.parse(matches);
            let vote = PROPOSAL_VOTE.parse(matches);
            let voter_address = ADDRESS.parse(matches);
            let tx_code_path = PathBuf::from(TX_VOTE_PROPOSAL);

            Self {
                tx,
                proposal_id,
                vote,
                voter_address,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(PROPOSAL_ID.def().help(wrap!("The proposal identifier.")))
                .arg(PROPOSAL_VOTE.def().help(wrap!(
                    "The vote for the proposal. Either yay, nay, or abstain."
                )))
                .arg(ADDRESS.def().help(wrap!("The address of the voter.")))
        }
    }

    impl CliToSdk<RevealPk<SdkTypes>> for RevealPk<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<RevealPk<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            Ok(RevealPk::<SdkTypes> {
                tx,
                public_key: chain_ctx.get(&self.public_key),
            })
        }
    }

    impl Args for RevealPk<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let public_key = PUBLIC_KEY.parse(matches);

            Self { tx, public_key }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(PUBLIC_KEY.def().help(wrap!("A public key to reveal.")))
        }
    }

    impl CliToSdk<Complete> for Complete {
        type Error = std::io::Error;

        fn to_sdk(self, _ctx: &mut Context) -> Result<Complete, Self::Error> {
            Ok(Complete { shell: self.shell })
        }
    }

    impl Args for Complete {
        fn parse(matches: &ArgMatches) -> Self {
            let shell = SHELL.parse(matches);
            Self { shell }
        }

        fn def(app: App) -> App {
            app.arg(
                SHELL
                    .def()
                    .help(wrap!("The shell to generate the completions for.")),
            )
        }
    }

    impl CliToSdk<QueryProposal<SdkTypes>> for QueryProposal<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryProposal<SdkTypes>, Self::Error> {
            Ok(QueryProposal::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                proposal_id: self.proposal_id,
            })
        }
    }

    impl Args for QueryProposal<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let proposal_id = PROPOSAL_ID_OPT.parse(matches);

            Self { query, proposal_id }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(PROPOSAL_ID_OPT.def().help(wrap!(
                    "The ID number of the proposal. This argument is \
                     optional. If not provided, then the most recent 10 \
                     proposals will be displayed."
                )))
        }
    }

    impl CliToSdk<QueryProposalVotes<SdkTypes>> for QueryProposalVotes<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryProposalVotes<SdkTypes>, Self::Error> {
            Ok(QueryProposalVotes::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                proposal_id: self.proposal_id,
                voter: self.voter.map(|x| ctx.borrow_chain_or_exit().get(&x)),
            })
        }
    }

    impl Args for QueryProposalVotes<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let proposal_id = PROPOSAL_ID.parse(matches);
            let voter = VOTER_OPT.parse(matches);

            Self {
                query,
                proposal_id,
                voter,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(
                    PROPOSAL_ID_OPT
                        .def()
                        .help(wrap!("The proposal identifier.")),
                )
                .arg(
                    VOTER_OPT
                        .def()
                        .help(wrap!("The address of the proposal voter.")),
                )
        }
    }

    #[derive(Clone, Debug)]
    pub struct QueryProposalResult<C: NamadaTypes = SdkTypes> {
        /// Common query args
        pub query: Query<C>,
        /// Proposal id
        pub proposal_id: u64,
    }

    impl CliToSdk<QueryProposalResult<SdkTypes>> for QueryProposalResult<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryProposalResult<SdkTypes>, Self::Error> {
            Ok(QueryProposalResult::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                proposal_id: self.proposal_id,
            })
        }
    }

    impl Args for QueryProposalResult<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let proposal_id = PROPOSAL_ID.parse(matches);

            Self { query, proposal_id }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(PROPOSAL_ID.def().help(wrap!("The proposal identifier.")))
        }
    }

    impl CliToSdk<QueryProtocolParameters<SdkTypes>>
        for QueryProtocolParameters<CliTypes>
    {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryProtocolParameters<SdkTypes>, Self::Error> {
            Ok(QueryProtocolParameters::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
            })
        }
    }

    impl Args for QueryProtocolParameters<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);

            Self { query }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
        }
    }

    impl Args for QueryPgf<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);

            Self { query }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
        }
    }

    impl CliToSdk<QueryPgf<SdkTypes>> for QueryPgf<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryPgf<SdkTypes>, Self::Error> {
            Ok(QueryPgf::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
            })
        }
    }

    impl CliToSdk<Withdraw<SdkTypes>> for Withdraw<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<Withdraw<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_chain_or_exit();

            Ok(Withdraw::<SdkTypes> {
                tx,
                validator: chain_ctx.get(&self.validator),
                source: self.source.map(|x| chain_ctx.get(&x)),
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for Withdraw<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let source = SOURCE_OPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_WITHDRAW_WASM);
            Self {
                tx,
                validator,
                source,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help(wrap!("Validator address.")))
                .arg(SOURCE_OPT.def().help(wrap!(
                    "Source address for withdrawing from delegations. For \
                     withdrawing from self-bonds, this arg does not need to \
                     be supplied."
                )))
        }
    }

    impl CliToSdk<ClaimRewards<SdkTypes>> for ClaimRewards<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<ClaimRewards<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_chain_or_exit();

            Ok(ClaimRewards::<SdkTypes> {
                tx,
                validator: chain_ctx.get(&self.validator),
                source: self.source.map(|x| chain_ctx.get(&x)),
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for ClaimRewards<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let source = SOURCE_OPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_CLAIM_REWARDS_WASM);
            Self {
                tx,
                validator,
                source,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help(wrap!("Validator address.")))
                .arg(SOURCE_OPT.def().help(wrap!(
                    "Source address for claiming rewards for a bond. For \
                     self-bonds, the validator is also the source."
                )))
        }
    }

    impl CliToSdk<QueryConversions<SdkTypes>> for QueryConversions<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryConversions<SdkTypes>, Self::Error> {
            Ok(QueryConversions::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                token: self.token.map(|x| ctx.borrow_chain_or_exit().get(&x)),
                epoch: self.epoch,
                dump_tree: self.dump_tree,
            })
        }
    }

    impl Args for QueryConversions<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let token = TOKEN_OPT.parse(matches);
            let epoch = MASP_EPOCH.parse(matches);
            let dump_tree = DUMP_CONVERSION_TREE.parse(matches);
            Self {
                query,
                epoch,
                token,
                dump_tree,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(MASP_EPOCH.def().help(wrap!(
                    "The masp epoch for which to query conversions."
                )))
                .arg(TOKEN_OPT.def().help(wrap!(
                    "The token address for which to query conversions."
                )))
                .arg(DUMP_CONVERSION_TREE.def().help(wrap!(
                    "Dumps the full conversion tree if the flag is set."
                )))
        }
    }

    impl CliToSdk<QueryAccount<SdkTypes>> for QueryAccount<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryAccount<SdkTypes>, Self::Error> {
            Ok(QueryAccount::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                owner: ctx.borrow_chain_or_exit().get(&self.owner),
            })
        }
    }

    impl Args for QueryAccount<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let owner = OWNER.parse(matches);
            Self { query, owner }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                OWNER
                    .def()
                    .help(wrap!("The substorage space address to query."))
                    .required(true),
            )
        }
    }

    impl CliToSdk<QueryBalance<SdkTypes>> for QueryBalance<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryBalance<SdkTypes>, Self::Error> {
            let query = self.query.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            Ok(QueryBalance::<SdkTypes> {
                query,
                owner: chain_ctx.get_cached(&self.owner),
                token: chain_ctx.get(&self.token),
                no_conversions: self.no_conversions,
                height: self.height,
            })
        }
    }

    impl Args for QueryBalance<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let owner = BALANCE_OWNER.parse(matches);
            let token = TOKEN.parse(matches);
            let no_conversions = NO_CONVERSIONS.parse(matches);
            let height = BLOCK_HEIGHT_OPT.parse(matches);
            Self {
                query,
                owner,
                token,
                no_conversions,
                height,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(
                    BALANCE_OWNER.def().help(wrap!(
                        "The account address whose balance to query."
                    )),
                )
                .arg(
                    TOKEN.def().help(wrap!(
                        "The token's address whose balance to query."
                    )),
                )
                .arg(NO_CONVERSIONS.def().help(wrap!(
                    "Whether not to automatically perform conversions."
                )))
                .arg(BLOCK_HEIGHT_OPT.def().help(wrap!(
                    "The block height at which to query the balance. \
                     (Optional)"
                )))
        }
    }

    impl CliToSdk<QueryShieldingRewardsEstimate<SdkTypes>>
        for QueryShieldingRewardsEstimate<CliTypes>
    {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryShieldingRewardsEstimate<SdkTypes>, Self::Error>
        {
            let query = self.query.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            Ok(QueryShieldingRewardsEstimate::<SdkTypes> {
                query,
                owner: chain_ctx.get_cached(&self.owner),
            })
        }
    }

    impl Args for QueryShieldingRewardsEstimate<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let owner = VIEWING_KEY.parse(matches);
            Self { query, owner }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                VIEWING_KEY
                    .def()
                    .help(wrap!("The viewing key whose rewards to estimate.")),
            )
        }
    }

    impl CliToSdk<QueryBonds<SdkTypes>> for QueryBonds<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryBonds<SdkTypes>, Self::Error> {
            let query = self.query.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_chain_or_exit();

            Ok(QueryBonds::<SdkTypes> {
                query,
                owner: self.owner.map(|x| chain_ctx.get(&x)),
                validator: self.validator.map(|x| chain_ctx.get(&x)),
            })
        }
    }

    impl Args for QueryBonds<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let owner = OWNER_OPT.parse(matches);
            let validator = VALIDATOR_OPT.parse(matches);
            Self {
                query,
                owner,
                validator,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(OWNER_OPT.def().help(wrap!(
                    "The owner account address whose bonds to query."
                )))
                .arg(VALIDATOR_OPT.def().help(wrap!(
                    "The validator's address whose bonds to query."
                )))
        }
    }

    impl CliToSdk<QueryBondedStake<SdkTypes>> for QueryBondedStake<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryBondedStake<SdkTypes>, Self::Error> {
            Ok(QueryBondedStake::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                validator: self
                    .validator
                    .map(|x| ctx.borrow_chain_or_exit().get(&x)),
                epoch: self.epoch,
            })
        }
    }

    impl Args for QueryBondedStake<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let validator = VALIDATOR_OPT.parse(matches);
            let epoch = EPOCH.parse(matches);
            Self {
                query,
                validator,
                epoch,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(VALIDATOR_OPT.def().help(wrap!(
                    "The validator's address whose bonded stake to query."
                )))
                .arg(EPOCH.def().help(wrap!(
                    "The epoch at which to query (corresponding to the last \
                     committed block, if not specified)."
                )))
        }
    }

    impl CliToSdk<QueryValidatorState<SdkTypes>> for QueryValidatorState<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryValidatorState<SdkTypes>, Self::Error> {
            Ok(QueryValidatorState::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                epoch: self.epoch,
            })
        }
    }

    impl Args for QueryValidatorState<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let epoch = EPOCH.parse(matches);
            Self {
                query,
                validator,
                epoch,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(VALIDATOR.def().help(wrap!(
                    "The validator's address whose state is queried."
                )))
                .arg(EPOCH.def().help(wrap!(
                    "The epoch at which to query (corresponding to the last \
                     committed block, if not specified)."
                )))
        }
    }

    impl CliToSdk<CommissionRateChange<SdkTypes>>
        for CommissionRateChange<CliTypes>
    {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<CommissionRateChange<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;

            Ok(CommissionRateChange::<SdkTypes> {
                tx,
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                rate: self.rate,
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for CommissionRateChange<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let rate = COMMISSION_RATE.parse(matches);
            let tx_code_path = PathBuf::from(TX_CHANGE_COMMISSION_WASM);
            Self {
                tx,
                validator,
                rate,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help(wrap!(
                    "The validator's address whose commission rate to change."
                )))
                .arg(
                    COMMISSION_RATE
                        .def()
                        .help(wrap!("The desired new commission rate.")),
                )
        }
    }

    impl CliToSdk<ConsensusKeyChange<SdkTypes>> for ConsensusKeyChange<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<ConsensusKeyChange<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            Ok(ConsensusKeyChange::<SdkTypes> {
                tx,
                validator: chain_ctx.get(&self.validator),
                consensus_key: self.consensus_key.map(|x| chain_ctx.get(&x)),
                unsafe_dont_encrypt: self.unsafe_dont_encrypt,
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for ConsensusKeyChange<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let consensus_key = VALIDATOR_CONSENSUS_KEY.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_CHANGE_CONSENSUS_KEY_WASM);
            Self {
                tx,
                validator,
                consensus_key,
                unsafe_dont_encrypt,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help(wrap!(
                    "The validator's address whose consensus key to change."
                )))
                .arg(VALIDATOR_CONSENSUS_KEY.def().help(wrap!(
                    "The desired new consensus key. A new one will be \
                     generated if none given. Note this key must be ed25519."
                )))
                .arg(UNSAFE_DONT_ENCRYPT.def().help(wrap!(
                    "UNSAFE: Do not encrypt the generated keypairs. Do not \
                     use this for keys used in a live network."
                )))
        }
    }

    impl CliToSdk<MetaDataChange<SdkTypes>> for MetaDataChange<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<MetaDataChange<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;

            Ok(MetaDataChange::<SdkTypes> {
                tx,
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                email: self.email,
                description: self.description,
                website: self.website,
                discord_handle: self.discord_handle,
                avatar: self.avatar,
                name: self.name,
                commission_rate: self.commission_rate,
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for MetaDataChange<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let email = EMAIL_OPT.parse(matches);
            let description = DESCRIPTION_OPT.parse(matches);
            let website = WEBSITE_OPT.parse(matches);
            let discord_handle = DISCORD_OPT.parse(matches);
            let avatar = AVATAR_OPT.parse(matches);
            let name = VALIDATOR_NAME_OPT.parse(matches);
            let commission_rate = COMMISSION_RATE_OPT.parse(matches);
            let tx_code_path = PathBuf::from(TX_CHANGE_METADATA_WASM);
            Self {
                tx,
                validator,
                email,
                description,
                website,
                discord_handle,
                avatar,
                name,
                commission_rate,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>()
                .arg(VALIDATOR.def().help(wrap!(
                    "The validator's address whose commission rate to change."
                )))
                .arg(EMAIL_OPT.def().help(wrap!(
                    "The desired new validator email. To remove the existing \
                     email, pass an empty string to this argument."
                )))
                .arg(DESCRIPTION_OPT.def().help(wrap!(
                    "The desired new validator description. To remove the \
                     existing description, pass an empty string to this \
                     argument."
                )))
                .arg(WEBSITE_OPT.def().help(wrap!(
                    "The desired new validator website. To remove the \
                     existing website, pass an empty string to this argument."
                )))
                .arg(DISCORD_OPT.def().help(wrap!(
                    "The desired new validator discord handle. To remove the \
                     existing discord handle, pass an empty string to this \
                     argument."
                )))
                .arg(AVATAR_OPT.def().help(wrap!(
                    "The desired new validator avatar url. To remove the \
                     existing avatar, pass an empty string to this argument."
                )))
                .arg(VALIDATOR_NAME_OPT.def().help(wrap!(
                    "The desired new validator name, used to identify the \
                     validator in online services. To remove the existing \
                     validator alias, pass an empty string to this argument."
                )))
                .arg(
                    COMMISSION_RATE_OPT
                        .def()
                        .help(wrap!("The desired new commission rate.")),
                )
        }
    }

    impl CliToSdk<TxUnjailValidator<SdkTypes>> for TxUnjailValidator<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxUnjailValidator<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;

            Ok(TxUnjailValidator::<SdkTypes> {
                tx,
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for TxUnjailValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let tx_code_path = PathBuf::from(TX_UNJAIL_VALIDATOR_WASM);
            Self {
                tx,
                validator,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>().arg(
                VALIDATOR.def().help(wrap!(
                    "The address of the jailed validator to unjail."
                )),
            )
        }
    }

    impl CliToSdk<TxDeactivateValidator<SdkTypes>>
        for TxDeactivateValidator<CliTypes>
    {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxDeactivateValidator<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;

            Ok(TxDeactivateValidator::<SdkTypes> {
                tx,
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for TxDeactivateValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let tx_code_path = PathBuf::from(TX_DEACTIVATE_VALIDATOR_WASM);
            Self {
                tx,
                validator,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>().arg(
                VALIDATOR
                    .def()
                    .help(wrap!("The address of the validator to deactivate.")),
            )
        }
    }

    impl CliToSdk<TxReactivateValidator<SdkTypes>>
        for TxReactivateValidator<CliTypes>
    {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<TxReactivateValidator<SdkTypes>, Self::Error> {
            let tx = self.tx.to_sdk(ctx)?;

            Ok(TxReactivateValidator::<SdkTypes> {
                tx,
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                tx_code_path: self.tx_code_path.to_path_buf(),
            })
        }
    }

    impl Args for TxReactivateValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx = Tx::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let tx_code_path = PathBuf::from(TX_REACTIVATE_VALIDATOR_WASM);
            Self {
                tx,
                validator,
                tx_code_path,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Tx<CliTypes>>().arg(
                VALIDATOR
                    .def()
                    .help(wrap!("The address of the validator to reactivate.")),
            )
        }
    }

    impl Args for ShieldedSync<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let ledger_address = CONFIG_RPC_LEDGER_ADDRESS.parse(matches);
            let last_query_height = BLOCK_HEIGHT_TO_OPT.parse(matches);
            let spending_keys = DATED_SPENDING_KEYS.parse(matches);
            let viewing_keys = DATED_VIEWING_KEYS.parse(matches);
            let with_indexer = WITH_INDEXER.parse(matches);
            let wait_for_last_query_height =
                WAIT_FOR_LAST_QUERY_HEIGHT.parse(matches);
            let max_concurrent_fetches = MAX_CONCURRENT_FETCHES.parse(matches);
            let retry_strategy = match RETRIES.parse(matches) {
                Some(times) => RetryStrategy::Times(times),
                None => RetryStrategy::Forever,
            };
            let block_batch_size = BLOCK_BATCH.parse(matches);
            Self {
                ledger_address,
                last_query_height,
                spending_keys,
                viewing_keys,
                with_indexer,
                wait_for_last_query_height,
                max_concurrent_fetches,
                retry_strategy,
                block_batch_size,
            }
        }

        fn def(app: App) -> App {
            app.arg(CONFIG_RPC_LEDGER_ADDRESS.def().help(LEDGER_ADDRESS_ABOUT))
                .arg(BLOCK_HEIGHT_TO_OPT.def().help(wrap!(
                    "Option block height to sync up to. Default is latest."
                )))
                .arg(DATED_SPENDING_KEYS.def().help(wrap!(
                    "List of new spending keys with which to check note \
                     ownership. These will be added to the shielded context. \
                     Appending \"<<$BLOCKHEIGHT\" to the end of each key adds \
                     a birthday."
                )))
                .arg(DATED_VIEWING_KEYS.def().help(wrap!(
                    "List of new viewing keys with which to check note \
                     ownership. These will be added to the shielded context. \
                     Appending \"<<$BLOCKHEIGHT\" to the end of each key adds \
                     a birthday."
                )))
                .arg(WITH_INDEXER.def().help(wrap!(
                    "Address of a `namada-masp-indexer` live instance. If \
                     present, the shielded sync will be performed using data \
                     retrieved from the given indexer."
                )))
                .arg(WAIT_FOR_LAST_QUERY_HEIGHT.def().help(wrap!(
                    "Wait until the last height to sync is available instead \
                     of returning early from the shielded sync."
                )))
                .arg(MAX_CONCURRENT_FETCHES.def().help(wrap!(
                    "Maximum number of fetch jobs that will ever execute \
                     concurrently during the shielded sync."
                )))
                .arg(RETRIES.def().help(wrap!(
                    "Maximum number of times to retry fetching. If no \
                     argument is provided, defaults to retrying forever."
                )))
                .arg(BLOCK_BATCH.def().help(wrap!(
                    "Number of blocks fetched per concurrent fetch job. The \
                     default is 10."
                )))
        }
    }

    impl CliToSdk<ShieldedSync<SdkTypes>> for ShieldedSync<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<ShieldedSync<SdkTypes>, Self::Error> {
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            Ok(ShieldedSync {
                block_batch_size: self.block_batch_size,
                max_concurrent_fetches: self.max_concurrent_fetches,
                wait_for_last_query_height: self.wait_for_last_query_height,
                ledger_address: chain_ctx.get(&self.ledger_address),
                last_query_height: self.last_query_height,
                spending_keys: self
                    .spending_keys
                    .iter()
                    .map(|sk| chain_ctx.get_cached(sk))
                    .collect(),
                viewing_keys: self
                    .viewing_keys
                    .iter()
                    .map(|vk| chain_ctx.get_cached(vk))
                    .collect(),
                with_indexer: self.with_indexer,
                retry_strategy: self.retry_strategy,
            })
        }
    }

    impl CliToSdk<GenIbcShieldingTransfer<SdkTypes>>
        for GenIbcShieldingTransfer<CliTypes>
    {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<GenIbcShieldingTransfer<SdkTypes>, Self::Error> {
            let query = self.query.to_sdk(ctx)?;
            let chain_ctx = ctx.borrow_chain_or_exit();

            Ok(GenIbcShieldingTransfer::<SdkTypes> {
                query,
                output_folder: self.output_folder,
                target: chain_ctx.get(&self.target),
                amount: self.amount,
                expiration: self.expiration,
                asset: match self.asset {
                    IbcShieldingTransferAsset::LookupNamadaAddress {
                        port_id,
                        channel_id,
                        token,
                    } => IbcShieldingTransferAsset::LookupNamadaAddress {
                        port_id,
                        channel_id,
                        token,
                    },
                    IbcShieldingTransferAsset::Address(addr) => {
                        IbcShieldingTransferAsset::Address(chain_ctx.get(&addr))
                    }
                },
            })
        }
    }

    impl Args for GenIbcShieldingTransfer<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let output_folder = OUTPUT_FOLDER_PATH.parse(matches);
            let target = TRANSFER_TARGET.parse(matches);
            let token = TOKEN_STR.parse(matches);
            let amount = InputAmount::Unvalidated(AMOUNT.parse(matches));
            let expiration = EXPIRATION_OPT.parse(matches);
            let port_id = PORT_ID.parse(matches);
            let channel_id = CHANNEL_ID.parse(matches);
            let no_expiration = NO_EXPIRATION.parse(matches);
            let expiration = if no_expiration {
                TxExpiration::NoExpiration
            } else {
                match expiration {
                    Some(exp) => TxExpiration::Custom(exp),
                    None => TxExpiration::Default,
                }
            };

            Self {
                query,
                output_folder,
                target,
                amount,
                expiration,
                asset: IbcShieldingTransferAsset::LookupNamadaAddress {
                    port_id,
                    channel_id,
                    token,
                },
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(OUTPUT_FOLDER_PATH.def().help(wrap!(
                    "The output folder path where the artifact will be stored."
                )))
                .arg(TRANSFER_TARGET.def().help(wrap!("The target address.")))
                .arg(TOKEN.def().help(wrap!("The transfer token.")))
                .arg(
                    AMOUNT
                        .def()
                        .help(wrap!("The amount to transfer in decimal.")),
                )
                .arg(
                    EXPIRATION_OPT
                        .def()
                        .help(wrap!(
                            "The expiration datetime of the masp transaction, \
                             after which the tx won't be accepted anymore. If \
                             not provided, a default will be set. Example: \
                             2012-12-12T12:12:12Z"
                        ))
                        .conflicts_with_all([NO_EXPIRATION.name]),
                )
                .arg(
                    NO_EXPIRATION
                        .def()
                        .help(wrap!(
                            "Force the construction of the transaction \
                             without an expiration (highly discouraged)."
                        ))
                        .conflicts_with_all([EXPIRATION_OPT.name]),
                )
                .arg(PORT_ID.def().help(wrap!(
                    "The port ID via which the token is received."
                )))
                .arg(CHANNEL_ID.def().help(wrap!(
                    "The channel ID via which the token is received."
                )))
        }
    }

    impl CliToSdk<QueryCommissionRate<SdkTypes>> for QueryCommissionRate<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryCommissionRate<SdkTypes>, Self::Error> {
            Ok(QueryCommissionRate::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                epoch: self.epoch,
            })
        }
    }

    impl Args for QueryCommissionRate<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let validator = VALIDATOR.parse(matches);
            let epoch = EPOCH.parse(matches);
            Self {
                query,
                validator,
                epoch,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(VALIDATOR.def().help(wrap!(
                    "The validator's address whose commission rate to query."
                )))
                .arg(EPOCH.def().help(wrap!(
                    "The epoch at which to query (corresponding to the last \
                     committed block, if not specified)."
                )))
        }
    }

    impl CliToSdk<QueryMetaData<SdkTypes>> for QueryMetaData<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryMetaData<SdkTypes>, Self::Error> {
            Ok(QueryMetaData::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
            })
        }
    }

    impl Args for QueryMetaData<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let validator = VALIDATOR.parse(matches);
            Self { query, validator }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(VALIDATOR.def().help(wrap!(
                    "The validator's address whose metadata to query."
                )))
        }
    }

    impl CliToSdk<QuerySlashes<SdkTypes>> for QuerySlashes<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QuerySlashes<SdkTypes>, Self::Error> {
            Ok(QuerySlashes::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                validator: self
                    .validator
                    .map(|x| ctx.borrow_chain_or_exit().get(&x)),
            })
        }
    }

    impl Args for QuerySlashes<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let validator = VALIDATOR_OPT.parse(matches);
            Self { query, validator }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>().arg(
                VALIDATOR_OPT.def().help(wrap!(
                    "The validator's address whose slashes to query."
                )),
            )
        }
    }

    impl CliToSdk<QueryRewards<SdkTypes>> for QueryRewards<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryRewards<SdkTypes>, Self::Error> {
            Ok(QueryRewards::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                validator: ctx.borrow_chain_or_exit().get(&self.validator),
                source: self.source.map(|x| ctx.borrow_chain_or_exit().get(&x)),
                epoch: self.epoch,
            })
        }
    }

    impl Args for QueryRewards<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let source = SOURCE_OPT.parse(matches);
            let validator = VALIDATOR.parse(matches);
            let epoch = EPOCH.parse(matches);
            Self {
                query,
                source,
                validator,
                epoch,
            }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(SOURCE_OPT.def().help(wrap!(
                    "Source address for the rewards query. For self-bonds, \
                     this arg does not need to be supplied."
                )))
                .arg(
                    VALIDATOR.def().help(wrap!(
                        "Validator address for the rewards query."
                    )),
                )
                .arg(EPOCH.def().help(wrap!(
                    "The epoch at which to query (corresponding to the last \
                     committed block, if not specified). Note: when querying \
                     by epoch, this returns the accumulated rewards that were \
                     available to claim at the start of the epoch."
                )))
        }
    }

    impl Args for QueryDelegations<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let owner = OWNER.parse(matches);
            Self { query, owner }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(OWNER.def().help(wrap!(
                    "The address of the owner of the delegations to find."
                )))
        }
    }

    impl CliToSdk<QueryDelegations<SdkTypes>> for QueryDelegations<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryDelegations<SdkTypes>, Self::Error> {
            Ok(QueryDelegations::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                owner: ctx.borrow_chain_or_exit().get(&self.owner),
            })
        }
    }

    impl Args for QueryTotalSupply<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let token = TOKEN.parse(matches);
            Self { query, token }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(TOKEN.def().help(wrap!("The token address.")))
        }
    }

    impl CliToSdk<QueryTotalSupply<SdkTypes>> for QueryTotalSupply<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryTotalSupply<SdkTypes>, Self::Error> {
            Ok(QueryTotalSupply::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                token: ctx.borrow_chain_or_exit().get(&self.token),
            })
        }
    }

    impl Args for QueryEffNativeSupply<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            Self { query }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
        }
    }

    impl CliToSdk<QueryEffNativeSupply<SdkTypes>>
        for QueryEffNativeSupply<CliTypes>
    {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryEffNativeSupply<SdkTypes>, Self::Error> {
            Ok(QueryEffNativeSupply::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
            })
        }
    }

    impl Args for QueryStakingRewardsRate<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            Self { query }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
        }
    }

    impl CliToSdk<QueryStakingRewardsRate<SdkTypes>>
        for QueryStakingRewardsRate<CliTypes>
    {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryStakingRewardsRate<SdkTypes>, Self::Error> {
            Ok(QueryStakingRewardsRate::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
            })
        }
    }

    impl Args for QueryFindValidator<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let tm_addr = TM_ADDRESS_OPT.parse(matches);
            let validator_addr = VALIDATOR_OPT.parse(matches);

            let addr = match (tm_addr, validator_addr) {
                (Some(tm_addr), None) => Either::Left(tm_addr),
                (None, Some(validator_addr)) => Either::Right(validator_addr),
                _ => unreachable!(
                    "Wrong arguments supplied, CLI should prevent this"
                ),
            };
            Self { query, addr }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(
                    TM_ADDRESS_OPT
                        .def()
                        .help(wrap!(
                            "The address of the validator in Tendermint."
                        ))
                        .conflicts_with(VALIDATOR_OPT.name),
                )
                .arg(
                    VALIDATOR_OPT
                        .def()
                        .help(wrap!("The native address of the validator."))
                        .conflicts_with(TM_ADDRESS_OPT.name),
                )
        }
    }

    impl CliToSdk<QueryFindValidator<SdkTypes>> for QueryFindValidator<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryFindValidator<SdkTypes>, Self::Error> {
            Ok(QueryFindValidator::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                addr: self.addr.map_right(|validator_addr| {
                    ctx.borrow_chain_or_exit().get(&validator_addr)
                }),
            })
        }
    }

    impl Args for QueryIbcRateLimit<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let query = Query::parse(matches);
            let token = TOKEN.parse(matches);

            Self { query, token }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(TOKEN.def().help(wrap!("The IBC token.")))
        }
    }

    impl CliToSdk<QueryIbcRateLimit<SdkTypes>> for QueryIbcRateLimit<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryIbcRateLimit<SdkTypes>, Self::Error> {
            Ok(QueryIbcRateLimit::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                token: ctx.borrow_chain_or_exit().get(&self.token),
            })
        }
    }

    impl CliToSdk<QueryRawBytes<SdkTypes>> for QueryRawBytes<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<QueryRawBytes<SdkTypes>, Self::Error> {
            Ok(QueryRawBytes::<SdkTypes> {
                query: self.query.to_sdk(ctx)?,
                storage_key: self.storage_key,
            })
        }
    }

    impl Args for QueryRawBytes<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let storage_key = STORAGE_KEY.parse(matches);
            let query = Query::parse(matches);
            Self { storage_key, query }
        }

        fn def(app: App) -> App {
            app.add_args::<Query<CliTypes>>()
                .arg(STORAGE_KEY.def().help(wrap!("Storage key")))
        }
    }

    /// The concrete types being used in the CLI
    #[derive(Clone, Debug)]
    pub struct CliTypes;

    impl NamadaTypes for CliTypes {
        type AddrOrNativeToken = WalletAddrOrNativeToken;
        type Address = WalletAddress;
        type BalanceOwner = WalletBalanceOwner;
        type BlockHeight = BlockHeight;
        type BpConversionTable = PathBuf;
        type ConfigRpcTendermintAddress = ConfigRpcAddress;
        type Data = PathBuf;
        type DatedSpendingKey = WalletDatedSpendingKey;
        type DatedViewingKey = WalletDatedViewingKey;
        type EthereumAddress = String;
        type Keypair = WalletKeypair;
        type MaspIndexerAddress = String;
        type PaymentAddress = WalletPaymentAddr;
        type PublicKey = WalletPublicKey;
        type SpendingKey = WalletSpendingKey;
        type TendermintAddress = tendermint_rpc::Url;
        type TransferSource = WalletTransferSource;
        type TransferTarget = WalletTransferTarget;
        type ViewingKey = WalletViewingKey;
    }

    impl CliToSdk<Tx<SdkTypes>> for Tx<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<Tx<SdkTypes>, Self::Error> {
            let ctx = ctx.borrow_mut_chain_or_exit();

            Ok(Tx::<SdkTypes> {
                dry_run: self.dry_run,
                dry_run_wrapper: self.dry_run_wrapper,
                dump_tx: self.dump_tx,
                dump_wrapper_tx: self.dump_wrapper_tx,
                output_folder: self.output_folder,
                force: self.force,
                broadcast_only: self.broadcast_only,
                ledger_address: ctx.get(&self.ledger_address),
                initialized_account_alias: self.initialized_account_alias,
                wallet_alias_force: self.wallet_alias_force,
                fee_amount: self.fee_amount,
                fee_token: ctx.get(&self.fee_token).into(),
                gas_limit: self.gas_limit,
                signing_keys: self
                    .signing_keys
                    .iter()
                    .map(|key| ctx.get(key))
                    .collect(),
                tx_reveal_code_path: self.tx_reveal_code_path,
                password: self.password,
                expiration: self.expiration,
                chain_id: self
                    .chain_id
                    .or_else(|| Some(ctx.config.ledger.chain_id.clone())),
                wrapper_fee_payer: self.wrapper_fee_payer.map(|x| ctx.get(&x)),
                memo: self.memo,
                use_device: self.use_device,
                device_transport: self.device_transport,
            })
        }
    }

    impl Args for Tx<CliTypes> {
        fn def(app: App) -> App {
            app.arg(
                DRY_RUN_TX
                    .def()
                    .help(wrap!("Simulate the transaction application."))
                    .conflicts_with(DRY_RUN_WRAPPER_TX.name)
                    .conflicts_with(USE_DEVICE.name),
            )
            .arg(
                DRY_RUN_WRAPPER_TX
                    .def()
                    .help(wrap!(
                        "Simulate the complete transaction application. This \
                         estimates the gas cost of the transaction."
                    ))
                    .conflicts_with(DRY_RUN_TX.name),
            )
            .arg(
                DUMP_TX
                    .def()
                    .help(wrap!("Dump raw transaction bytes to a file."))
                    .conflicts_with(DUMP_WRAPPER_TX.name),
            )
            .arg(
                DUMP_WRAPPER_TX
                    .def()
                    .help(wrap!("Dump wrapper transaction bytes to a file."))
                    .conflicts_with(DUMP_TX.name),
            )
            .arg(FORCE.def().help(wrap!(
                "Submit the transaction even if it doesn't pass client checks."
            )))
            .arg(BROADCAST_ONLY.def().help(wrap!(
                "Do not wait for the transaction to be applied. This will \
                 return once the transaction is added to the mempool."
            )))
            .arg(
                CONFIG_RPC_LEDGER_ADDRESS
                    .def()
                    .help(LEDGER_ADDRESS_ABOUT)
                    // This used to be "ledger-address", alias for compatibility
                    .alias("ledger-address"),
            )
            .arg(ALIAS_OPT.def().help(wrap!(
                "If any new account is initialized by the tx, use the given \
                 alias to save it in the wallet. If multiple accounts are \
                 initialized, the alias will be the prefix of each new \
                 address joined with a number."
            )))
            .arg(FEE_AMOUNT_OPT.def().help(wrap!(
                "The amount being paid, per gas unit, for the inclusion of \
                 this transaction"
            )))
            .arg(FEE_TOKEN.def().help(wrap!("The token for paying the gas")))
            .arg(GAS_LIMIT.def().help(wrap!(
                "The maximum amount of gas the transaction can use."
            )))
            .arg(WALLET_ALIAS_FORCE.def().help(wrap!(
                "Override the alias without confirmation if it already exists."
            )))
            .arg(
                EXPIRATION_OPT
                    .def()
                    .help(wrap!(
                        "The expiration datetime of the transaction, after \
                         which the tx won't be accepted anymore. If not \
                         provided, a default will be set. Example: \
                         2012-12-12T12:12:12Z"
                    ))
                    .conflicts_with_all([NO_EXPIRATION.name]),
            )
            .arg(
                NO_EXPIRATION
                    .def()
                    .help(wrap!(
                        "Force the construction of the transaction without an \
                         expiration (highly discouraged)."
                    ))
                    .conflicts_with_all([EXPIRATION_OPT.name]),
            )
            .arg(SIGNING_KEYS.def().help(wrap!(
                "Sign the transaction with the key for the given public key, \
                 public key hash or alias from your wallet. Do not provide \
                 this argument if the source of the transaction is a shielded \
                 address as it isn't needed and it would leak information."
            )))
            .arg(OUTPUT_FOLDER_PATH.def().help(wrap!(
                "The output folder path where the artifact will be stored."
            )))
            .arg(CHAIN_ID_OPT.def().help(wrap!("The chain ID.")))
            .arg(FEE_PAYER_OPT.def().help(wrap!(
                "The implicit address of the gas payer. It defaults to the \
                 address associated to the first key passed to \
                 --signing-keys. Do not provide this argument if you intend \
                 to pay fees via the MASP (recommended for transactions where \
                 the source is a shielded address)."
            )))
            .arg(
                USE_DEVICE
                    .def()
                    .help(wrap!(
                        "Use an attached hardware wallet device to sign the \
                         transaction."
                    ))
                    .conflicts_with(DRY_RUN_TX.name),
            )
            .arg(DEVICE_TRANSPORT.def().help(wrap!(
                "Select transport for hardware wallet from \"hid\" (default) \
                 or \"tcp\"."
            )))
            .arg(
                MEMO_OPT
                    .def()
                    .help(wrap!("Attach a plaintext memo to the transaction.")),
            )
        }

        fn parse(matches: &ArgMatches) -> Self {
            let dry_run = DRY_RUN_TX.parse(matches);
            let dry_run_wrapper = DRY_RUN_WRAPPER_TX.parse(matches);
            let dump_tx = DUMP_TX.parse(matches);
            let dump_wrapper_tx = DUMP_WRAPPER_TX.parse(matches);
            let force = FORCE.parse(matches);
            let broadcast_only = BROADCAST_ONLY.parse(matches);
            let ledger_address = CONFIG_RPC_LEDGER_ADDRESS.parse(matches);
            let initialized_account_alias = ALIAS_OPT.parse(matches);
            let fee_amount =
                FEE_AMOUNT_OPT.parse(matches).map(InputAmount::Unvalidated);
            let fee_token = FEE_TOKEN.parse(matches);
            let gas_limit = GAS_LIMIT.parse(matches);
            let wallet_alias_force = WALLET_ALIAS_FORCE.parse(matches);
            let expiration = EXPIRATION_OPT.parse(matches);
            let signing_keys = SIGNING_KEYS.parse(matches);
            let tx_reveal_code_path = PathBuf::from(TX_REVEAL_PK);
            let chain_id = CHAIN_ID_OPT.parse(matches);
            let password = None;
            let memo = MEMO_OPT.parse(matches).map(String::into_bytes);
            let wrapper_fee_payer = FEE_PAYER_OPT.parse(matches);
            let output_folder = OUTPUT_FOLDER_PATH.parse(matches);
            let use_device = USE_DEVICE.parse(matches);
            let no_expiration = NO_EXPIRATION.parse(matches);
            let expiration = if no_expiration {
                TxExpiration::NoExpiration
            } else {
                match expiration {
                    Some(exp) => TxExpiration::Custom(exp),
                    None => TxExpiration::Default,
                }
            };
            let device_transport = DEVICE_TRANSPORT.parse(matches);
            Self {
                dry_run,
                dry_run_wrapper,
                dump_tx,
                dump_wrapper_tx,
                force,
                broadcast_only,
                ledger_address,
                initialized_account_alias,
                wallet_alias_force,
                fee_amount,
                fee_token,
                gas_limit,
                expiration,
                signing_keys,
                tx_reveal_code_path,
                password,
                chain_id,
                wrapper_fee_payer,
                output_folder,
                memo,
                use_device,
                device_transport,
            }
        }
    }

    impl CliToSdk<Query<SdkTypes>> for Query<CliTypes> {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<Query<SdkTypes>, Self::Error> {
            let chain_ctx = ctx.borrow_mut_chain_or_exit();
            Ok(Query::<SdkTypes> {
                ledger_address: chain_ctx.get(&self.ledger_address),
            })
        }
    }

    impl Args for Query<CliTypes> {
        fn def(app: App) -> App {
            app.arg(
                CONFIG_RPC_LEDGER_ADDRESS
                    .def()
                    .help(LEDGER_ADDRESS_ABOUT)
                    // This used to be "ledger-address", alias for compatibility
                    .alias("ledger-address"),
            )
        }

        fn parse(matches: &ArgMatches) -> Self {
            let ledger_address = CONFIG_RPC_LEDGER_ADDRESS.parse(matches);
            Self { ledger_address }
        }
    }

    impl CliToSdkCtxless<QueryWithoutCtx<SdkTypes>> for QueryWithoutCtx<CliTypes> {
        fn to_sdk_ctxless(self) -> QueryWithoutCtx<SdkTypes> {
            QueryWithoutCtx::<SdkTypes> {
                ledger_address: self.ledger_address,
            }
        }
    }

    impl Args for QueryWithoutCtx<CliTypes> {
        fn def(app: App) -> App {
            app.arg(
                LEDGER_ADDRESS
                    .def()
                    .help(LEDGER_ADDRESS_ABOUT)
                    // This used to be "ledger-address", alias for compatibility
                    .alias("ledger-address"),
            )
        }

        fn parse(matches: &ArgMatches) -> Self {
            let ledger_address = LEDGER_ADDRESS.parse(matches);
            Self { ledger_address }
        }
    }

    impl CliToSdk<PayAddressGen> for PayAddressGen {
        type Error = std::convert::Infallible;

        fn to_sdk(
            self,
            _ctx: &mut Context,
        ) -> Result<PayAddressGen, Self::Error> {
            Ok(PayAddressGen {
                alias: self.alias,
                alias_force: self.alias_force,
                viewing_key: self.viewing_key,
                diversifier_index: self.diversifier_index,
            })
        }
    }

    impl Args for PayAddressGen {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS.parse(matches);
            let alias_force = ALIAS_FORCE.parse(matches);
            let diversifier_index = DIVERSIFIER_INDEX.parse(matches);
            let viewing_key = VIEWING_KEY_ALIAS.parse(matches);
            Self {
                alias,
                alias_force,
                diversifier_index,
                viewing_key,
            }
        }

        fn def(app: App) -> App {
            app.arg(ALIAS.def().help(wrap!(
                "An alias to be associated with the payment address."
            )))
            .arg(ALIAS_FORCE.def().help(wrap!(
                "Override the alias without confirmation if it already exists."
            )))
            .arg(DIVERSIFIER_INDEX.def().help(wrap!(
                "Set the viewing key's current diversifier index beforehand."
            )))
            .arg(VIEWING_KEY.def().help(wrap!("The viewing key.")))
        }
    }

    impl Args for KeyDerive {
        fn parse(matches: &ArgMatches) -> Self {
            let scheme = SCHEME.parse(matches);
            let shielded = SHIELDED.parse(matches);
            let alias = ALIAS.parse(matches);
            let alias_force = ALIAS_FORCE.parse(matches);
            let birthday = BIRTHDAY.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let derivation_path = HD_DERIVATION_PATH.parse(matches);
            let allow_non_compliant =
                HD_ALLOW_NON_COMPLIANT_DERIVATION_PATH.parse(matches);
            let prompt_bip39_passphrase =
                HD_PROMPT_BIP39_PASSPHRASE.parse(matches);
            let use_device = USE_DEVICE.parse(matches);
            let device_transport = DEVICE_TRANSPORT.parse(matches);
            let unsafe_pure_zip32 = UNSAFE_PURE_ZIP32.parse(matches);
            Self {
                scheme,
                shielded,
                alias,
                alias_force,
                unsafe_dont_encrypt,
                unsafe_pure_zip32,
                derivation_path,
                allow_non_compliant,
                prompt_bip39_passphrase,
                use_device,
                device_transport,
                birthday,
            }
        }

        fn def(app: App) -> App {
            app.arg(SCHEME.def().conflicts_with(SHIELDED.name).help(wrap!(
                "For the transparent pool, the type of key that should be \
                 derived. Argument must be either ed25519 or secp256k1. If \
                 none provided, the default key scheme is ed25519.\nNot \
                 applicable for the shielded pool."
            )))
            .arg(
                SHIELDED.def().help(wrap!(
                    "Derive a spending key for the shielded pool."
                )),
            )
            .arg(ALIAS.def().help(wrap!("The key and address alias.")))
            .arg(
                ALIAS_FORCE.def().help(wrap!(
                    "Force overwrite the alias if it already exists."
                )),
            )
            .arg(BIRTHDAY.def().help(wrap!(
                "A block height after which this key is being created. Used \
                 for optimizing MASP operations. If none is provided, \
                 defaults to the first block height."
            )))
            .arg(UNSAFE_DONT_ENCRYPT.def().help(wrap!(
                "UNSAFE: Do not encrypt the keypair. Do not use this for keys \
                 used in a live network."
            )))
            .arg(USE_DEVICE.def().help(wrap!(
                "Derive an address and public key from the seed stored on the \
                 connected hardware wallet."
            )))
            .arg(DEVICE_TRANSPORT.def().help(wrap!(
                "Select transport for hardware wallet from \"hid\" (default) \
                 or \"tcp\"."
            )))
            .arg(HD_DERIVATION_PATH.def().help(wrap!(
                "HD key derivation path. Use keyword `default` to refer to a \
                 scheme default path:\n- m/44'/60'/0'/0/0 for the transparent \
                 secp256k1 scheme\n- m/44'/877'/0'/0'/0' for the transparent \
                 ed25519 scheme\n- m/32'/877'/0' for the shielded \
                 setting\nFor ed25519 scheme, all path indices will be \
                 promoted to hardened indexes. If none is specified, the \
                 scheme default path is used."
            )))
            .arg(HD_ALLOW_NON_COMPLIANT_DERIVATION_PATH.def().help(wrap!(
                "Allow non-compliant HD derivation path. The compliant \
                 derivation path schemes include:\n- \
                 m/44'/60'/account'/change/address_index for the transparent \
                 secp256k1 scheme\n- \
                 m/44'/877'/account'/change'/address_index' for the \
                 transparent ed25519 scheme\n- m/32'/877'/account' and\n- \
                 m/32'/877'/account'/address_index for the shielded setting"
            )))
            .group(
                ArgGroup::new("requires_group")
                    .args([HD_ALLOW_NON_COMPLIANT_DERIVATION_PATH.name])
                    .requires(HD_DERIVATION_PATH.name),
            )
            .arg(HD_PROMPT_BIP39_PASSPHRASE.def().help(wrap!(
                "Use an additional passphrase for HD-key generation."
            )))
            .arg(
                UNSAFE_PURE_ZIP32
                    .def()
                    .requires(SHIELDED.name)
                    .conflicts_with(USE_DEVICE.name)
                    .help(wrap!(
                        "Use the deprecated pure ZIP 32 algorithm to derive \
                         shielded keys. This flag is necessary if importing a \
                         mnemonic code that was generated on Namada 1.0.0 or \
                         before."
                    )),
            )
        }
    }

    impl Args for KeyGen {
        fn parse(matches: &ArgMatches) -> Self {
            let scheme = SCHEME.parse(matches);
            let shielded = SHIELDED.parse(matches);
            let raw = RAW_KEY_GEN.parse(matches);
            let alias = ALIAS.parse(matches);
            let alias_force = ALIAS_FORCE.parse(matches);
            let birthday = BIRTHDAY.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let derivation_path = HD_DERIVATION_PATH.parse(matches);
            let allow_non_compliant =
                HD_ALLOW_NON_COMPLIANT_DERIVATION_PATH.parse(matches);
            let prompt_bip39_passphrase =
                HD_PROMPT_BIP39_PASSPHRASE.parse(matches);
            Self {
                scheme,
                shielded,
                raw,
                alias,
                alias_force,
                birthday,
                unsafe_dont_encrypt,
                derivation_path,
                allow_non_compliant,
                prompt_bip39_passphrase,
            }
        }

        fn def(app: App) -> App {
            app.arg(SCHEME.def().conflicts_with(SHIELDED.name).help(wrap!(
                "For the transparent pool, the type of key that should be \
                 generated. Argument must be either ed25519 or secp256k1. If \
                 none provided, the default key scheme is ed25519.\nNot \
                 applicable for the shielded pool."
            )))
            .arg(
                SHIELDED.def().help(wrap!(
                    "Generate a spending key for the shielded pool."
                )),
            )
            .arg(
                RAW_KEY_GEN
                    .def()
                    .conflicts_with(HD_DERIVATION_PATH.name)
                    .help(wrap!(
                        "Generate a random non-HD secret / spending key. No \
                         mnemonic code is generated."
                    )),
            )
            .arg(ALIAS.def().help(wrap!("The key and address alias.")))
            .arg(ALIAS_FORCE.def().help(wrap!(
                "Override the alias without confirmation if it already exists."
            )))
            .arg(BIRTHDAY.def().help(wrap!(
                "A block height after which this key is being created. Used \
                 for optimizing MASP operations. If none is provided, \
                 defaults to the first block height."
            )))
            .arg(UNSAFE_DONT_ENCRYPT.def().help(wrap!(
                "UNSAFE: Do not encrypt the keypair. Do not use this for keys \
                 used in a live network."
            )))
            .arg(HD_DERIVATION_PATH.def().help(wrap!(
                "HD key derivation path. Use keyword `default` to refer to a \
                 scheme default path:\n- m/44'/60'/0'/0/0 for the transparent \
                 secp256k1 scheme\n- m/44'/877'/0'/0'/0' for the transparent \
                 ed25519 scheme\n- m/32'/877'/0' for the shielded \
                 setting\nFor ed25519 scheme, all path indices will be \
                 promoted to hardened indexes. If none is specified, the \
                 scheme default path is used."
            )))
            .arg(HD_ALLOW_NON_COMPLIANT_DERIVATION_PATH.def().help(wrap!(
                "Allow non-compliant HD derivation path. The compliant \
                 derivation path schemes include:\n- \
                 m/44'/60'/account'/change/address_index for the transparent \
                 secp256k1 scheme\n- \
                 m/44'/877'/account'/change'/address_index' for the \
                 transparent ed25519 scheme\n- m/32'/877'/account' and\n- \
                 m/32'/877'/account'/address_index for the shielded setting"
            )))
            .group(
                ArgGroup::new("requires_group")
                    .args([HD_ALLOW_NON_COMPLIANT_DERIVATION_PATH.name])
                    .requires(HD_DERIVATION_PATH.name),
            )
            .arg(HD_PROMPT_BIP39_PASSPHRASE.def().help(wrap!(
                "Use an additional passphrase for HD-key generation."
            )))
        }
    }

    impl Args for KeyAddressList {
        fn parse(matches: &ArgMatches) -> Self {
            let transparent_only = TRANSPARENT.parse(matches);
            let shielded_only = SHIELDED.parse(matches);
            let keys_only = LIST_FIND_KEYS_ONLY.parse(matches);
            let addresses_only = LIST_FIND_ADDRESSES_ONLY.parse(matches);
            let decrypt = DECRYPT.parse(matches);
            let unsafe_show_secret = UNSAFE_SHOW_SECRET.parse(matches);
            Self {
                transparent_only,
                shielded_only,
                keys_only,
                addresses_only,
                decrypt,
                unsafe_show_secret,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                TRANSPARENT
                    .def()
                    .help(wrap!("List transparent keys / addresses only.")),
            )
            .arg(SHIELDED.def().help(wrap!(
                "List keys / addresses of the shielded pool only."
            )))
            .group(
                ArgGroup::new("only_group_1")
                    .args([TRANSPARENT.name, SHIELDED.name]),
            )
            .arg(LIST_FIND_KEYS_ONLY.def().help(wrap!("List keys only.")))
            .arg(
                LIST_FIND_ADDRESSES_ONLY
                    .def()
                    .help(wrap!("List addresses only.")),
            )
            .group(ArgGroup::new("only_group_2").args([
                LIST_FIND_KEYS_ONLY.name,
                LIST_FIND_ADDRESSES_ONLY.name,
            ]))
            .arg(
                DECRYPT
                    .def()
                    .help(wrap!("Decrypt keys that are encrypted.")),
            )
            .arg(
                UNSAFE_SHOW_SECRET
                    .def()
                    .help(wrap!("UNSAFE: Print the secret / spending keys.")),
            )
        }
    }

    impl Args for KeyAddressFind {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS_OPT.parse(matches);
            let address = RAW_ADDRESS_OPT.parse(matches);
            let public_key = RAW_PUBLIC_KEY_OPT.parse(matches);
            let public_key_hash = RAW_PUBLIC_KEY_HASH_OPT.parse(matches);
            let payment_address = RAW_PAYMENT_ADDRESS_OPT.parse(matches);
            let keys_only = LIST_FIND_KEYS_ONLY.parse(matches);
            let addresses_only = LIST_FIND_ADDRESSES_ONLY.parse(matches);
            let decrypt = DECRYPT.parse(matches);
            let unsafe_show_secret = UNSAFE_SHOW_SECRET.parse(matches);
            Self {
                alias,
                address,
                public_key,
                public_key_hash,
                payment_address,
                keys_only,
                addresses_only,
                decrypt,
                unsafe_show_secret,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                ALIAS_OPT.def().help(wrap!(
                    "An alias associated with the keys / addresses."
                )),
            )
            .arg(RAW_ADDRESS_OPT.def().help(wrap!(
                "The bech32m encoded string of a transparent address."
            )))
            .arg(RAW_PUBLIC_KEY_OPT.def().help(wrap!(
                "A public key associated with the transparent keypair."
            )))
            .arg(RAW_PUBLIC_KEY_HASH_OPT.def().help(wrap!(
                "A public key hash associated with the transparent keypair."
            )))
            .arg(RAW_PAYMENT_ADDRESS_OPT.def().help(wrap!(
                "The bech32m encoded string of a shielded payment address."
            )))
            .group(
                ArgGroup::new("addr_find_args")
                    .args([
                        ALIAS_OPT.name,
                        RAW_ADDRESS_OPT.name,
                        RAW_PUBLIC_KEY_OPT.name,
                        RAW_PUBLIC_KEY_HASH_OPT.name,
                        RAW_PAYMENT_ADDRESS_OPT.name,
                    ])
                    .required(true),
            )
            .arg(LIST_FIND_KEYS_ONLY.def().help(wrap!("Find keys only.")))
            .arg(
                LIST_FIND_ADDRESSES_ONLY
                    .def()
                    .help(wrap!("Find addresses only.")),
            )
            .group(ArgGroup::new("only_group").args([
                LIST_FIND_KEYS_ONLY.name,
                LIST_FIND_ADDRESSES_ONLY.name,
            ]))
            .arg(PRE_GENESIS.def().help(wrap!(
                "Use pre-genesis wallet, instead of for the current chain, if \
                 any."
            )))
            .arg(
                DECRYPT
                    .def()
                    .help(wrap!("Decrypt keys that are encrypted.")),
            )
            .arg(
                UNSAFE_SHOW_SECRET
                    .def()
                    .help(wrap!("UNSAFE: Print the secret / spending key.")),
            )
        }
    }

    impl Args for KeyAddressAdd {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS.parse(matches);
            let alias_force = ALIAS_FORCE.parse(matches);
            let birthday = BIRTHDAY.parse(matches);
            let value = VALUE.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            Self {
                alias,
                alias_force,
                birthday,
                value,
                unsafe_dont_encrypt,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                ALIAS.def().help(wrap!(
                    "An alias to be associated with the new entry."
                )),
            )
            .arg(ALIAS_FORCE.def().help(wrap!(
                "Override the alias without confirmation if it already exists."
            )))
            .arg(BIRTHDAY.def().help(wrap!(
                "A block height after which this key is being created. Used \
                 for optimizing MASP operations. If none is provided, \
                 defaults to the first block height."
            )))
            .arg(VALUE.def().help(wrap!(
                "Any value of the following:\n- transparent pool secret \
                 key\n- transparent pool public key\n- transparent pool \
                 address\n- shielded pool spending key\n- shielded pool \
                 viewing key\n- shielded pool payment address "
            )))
            .arg(UNSAFE_DONT_ENCRYPT.def().help(wrap!(
                "UNSAFE: Do not encrypt the added keys. Do not use this for \
                 keys used in a live network."
            )))
        }
    }

    impl Args for KeyAddressRemove {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS.parse(matches);
            let do_it = DO_IT.parse(matches);
            Self { alias, do_it }
        }

        fn def(app: App) -> App {
            app.arg(ALIAS.def().help(wrap!("An alias to be removed.")))
                .arg(
                    DO_IT
                        .def()
                        .help(wrap!("Confirm alias removal."))
                        .required(true),
                )
        }
    }

    impl Args for KeyExport {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS.parse(matches);
            Self { alias }
        }

        fn def(app: App) -> App {
            app.arg(
                ALIAS
                    .def()
                    .help(wrap!("The alias of the key you wish to export.")),
            )
        }
    }

    impl Args for KeyConvert {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS.parse(matches);
            Self { alias }
        }

        fn def(app: App) -> App {
            app.arg(
                ALIAS
                    .def()
                    .help(wrap!("The alias of the key you wish to export.")),
            )
        }
    }

    impl Args for KeyImport {
        fn parse(matches: &ArgMatches) -> Self {
            let file_path = FILE_PATH.parse(matches);
            let alias = ALIAS.parse(matches);
            let alias_force = ALIAS_FORCE.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            Self {
                alias,
                alias_force,
                file_path,
                unsafe_dont_encrypt,
            }
        }

        fn def(app: App) -> App {
            app.arg(FILE_PATH.def().help(wrap!(
                "Path to the file containing the key you wish to import."
            )))
            .arg(ALIAS.def().help(wrap!("The alias assigned to the.")))
            .arg(ALIAS_FORCE.def().help(wrap!(
                "An alias to be associated with the imported entry."
            )))
            .arg(UNSAFE_DONT_ENCRYPT.def().help(wrap!(
                "UNSAFE: Do not encrypt the imported keys. Do not use this \
                 for keys used in a live network."
            )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct JoinNetwork {
        pub chain_id: ChainId,
        pub genesis_validator: Option<String>,
        pub pre_genesis_path: Option<PathBuf>,
        pub allow_duplicate_ip: bool,
        pub add_persistent_peers: bool,
    }

    impl Args for JoinNetwork {
        fn parse(matches: &ArgMatches) -> Self {
            let chain_id = CHAIN_ID.parse(matches);
            let genesis_validator = GENESIS_VALIDATOR.parse(matches);
            let pre_genesis_path = PRE_GENESIS_PATH.parse(matches);
            let allow_duplicate_ip = ALLOW_DUPLICATE_IP.parse(matches);
            let add_persistent_peers = ADD_PERSISTENT_PEERS.parse(matches);
            Self {
                chain_id,
                genesis_validator,
                pre_genesis_path,
                allow_duplicate_ip,
                add_persistent_peers,
            }
        }

        fn def(app: App) -> App {
            app.arg(CHAIN_ID.def().help(wrap!("The chain ID. The chain must be known in the repository: \
                                          https://github.com/heliaxdev/anoma-network-config")))
                .arg(GENESIS_VALIDATOR.def().help(wrap!("The alias of the genesis validator that you want to set up as, if any.")))
                .arg(PRE_GENESIS_PATH.def().help(wrap!("The path to the pre-genesis directory for genesis validator, if any. Defaults to \"{base-dir}/pre-genesis/{genesis-validator}\".")))
            .arg(ALLOW_DUPLICATE_IP.def().help(wrap!(
                "Toggle to disable guard against peers connecting from the \
                 same IP. This option shouldn't be used in mainnet.")
            ))
            .arg(ADD_PERSISTENT_PEERS.def().help(
                "Whether to add persistent peers to the P2P config of CometBFT, \
                 derived from the list of genesis validators.",
            ))
        }
    }

    #[derive(Clone, Debug)]
    pub struct PkToTmAddress {
        pub public_key: common::PublicKey,
    }

    impl Args for PkToTmAddress {
        fn parse(matches: &ArgMatches) -> Self {
            let public_key = RAW_PUBLIC_KEY.parse(matches);
            Self { public_key }
        }

        fn def(app: App) -> App {
            app.arg(RAW_PUBLIC_KEY.def().help(wrap!(
                "The consensus public key to be converted to Tendermint \
                 address."
            )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct SignOffline<C: NamadaTypes = SdkTypes> {
        pub tx_path: PathBuf,
        pub secret_keys: Vec<C::Keypair>,
        pub owner: Option<C::Address>,
        pub wrapper_signer: Option<C::Keypair>,
        pub output_folder_path: Option<PathBuf>,
    }

    impl Args for SignOffline<CliTypes> {
        fn parse(matches: &ArgMatches) -> Self {
            let tx_path = DATA_PATH.parse(matches);
            let secret_keys = PRIVATE_KEYS.parse(matches);
            let owner = OWNER_OPT.parse(matches);
            let wrapper_signer = PRIVATE_KEY_OPT.parse(matches);
            let output_folder_path = OUTPUT_FOLDER_PATH.parse(matches);

            Self {
                tx_path,
                secret_keys,
                owner,
                wrapper_signer,
                output_folder_path,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                DATA_PATH
                    .def()
                    .help(wrap!("The path to the serialized transaction.")),
            )
            .arg(PRIVATE_KEYS.def().help(wrap!(
                "The set of private keys to use to sign the transaction. The \
                 order matters."
            )))
            .arg(OWNER_OPT.def().help(wrap!("The optional owner's address.")))
            .arg(PRIVATE_KEY_OPT.def().help(
                "The optional signer of the wrapper transaction for gas \
                 payment",
            ))
            .arg(
                OUTPUT_FOLDER_PATH
                    .def()
                    .help("Folder to where serialize the signatures"),
            )
        }
    }

    impl CliToSdk<SignOffline<SdkTypes>> for SignOffline<CliTypes> {
        type Error = std::io::Error;

        fn to_sdk(
            self,
            ctx: &mut Context,
        ) -> Result<SignOffline<SdkTypes>, Self::Error> {
            let chain_ctx = ctx.borrow_mut_chain_or_exit();

            Ok(SignOffline::<SdkTypes> {
                tx_path: self.tx_path,
                secret_keys: self
                    .secret_keys
                    .iter()
                    .map(|key| chain_ctx.get_cached(key))
                    .collect(),
                owner: self.owner.map(|owner| chain_ctx.get(&owner)),
                wrapper_signer: self
                    .wrapper_signer
                    .map(|key| chain_ctx.get_cached(&key)),
                output_folder_path: self.output_folder_path,
            })
        }
    }

    #[derive(Clone, Debug)]
    pub struct DefaultBaseDir {}

    impl Args for DefaultBaseDir {
        fn parse(_matches: &ArgMatches) -> Self {
            Self {}
        }

        fn def(app: App) -> App {
            app
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidateWasm {
        pub code_path: PathBuf,
    }

    impl Args for ValidateWasm {
        fn parse(matches: &ArgMatches) -> Self {
            let code_path = CODE_PATH.parse(matches);
            Self { code_path }
        }

        fn def(app: App) -> App {
            app.arg(
                CODE_PATH
                    .def()
                    .help(wrap!("The path to the wasm file to validate.")),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct DeriveIbcToken {
        pub ibc_denom: String,
    }

    impl Args for DeriveIbcToken {
        fn parse(matches: &ArgMatches) -> Self {
            let ibc_denom: String = IBC_DENOM.parse(matches);
            Self { ibc_denom }
        }

        fn def(app: App) -> App {
            app.arg(IBC_DENOM.def().help(wrap!(
                "The IBC token string, in the format of \
                 'transfer/channel-<num>/<name>"
            )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct PubKeyToAddr {
        pub public_key: common::PublicKey,
    }

    impl Args for PubKeyToAddr {
        fn parse(matches: &ArgMatches) -> Self {
            let public_key: common::PublicKey = RAW_PUBLIC_KEY.parse(matches);
            Self { public_key }
        }

        fn def(app: App) -> App {
            app.arg(RAW_PUBLIC_KEY.def().help(wrap!(
                "The raw public key to be converted into an implicit address"
            )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitNetwork {
        pub templates_path: PathBuf,
        pub wasm_checksums_path: PathBuf,
        pub chain_id_prefix: ChainIdPrefix,
        pub genesis_time: DateTimeUtc,
        pub consensus_timeout_commit: Timeout,
        pub archive_dir: Option<PathBuf>,
    }

    impl Args for InitNetwork {
        fn parse(matches: &ArgMatches) -> Self {
            let templates_path = TEMPLATES_PATH.parse(matches);
            let wasm_checksums_path = WASM_CHECKSUMS_PATH.parse(matches);
            let chain_id_prefix = CHAIN_ID_PREFIX.parse(matches);
            let genesis_time = GENESIS_TIME.parse(matches);
            let consensus_timeout_commit =
                CONSENSUS_TIMEOUT_COMMIT.parse(matches);
            let archive_dir = ARCHIVE_DIR.parse(matches);
            Self {
                templates_path,
                wasm_checksums_path,
                chain_id_prefix,
                genesis_time,
                consensus_timeout_commit,
                archive_dir,
            }
        }

        fn def(app: App) -> App {
            app.arg(TEMPLATES_PATH.def().help(wrap!(
                "Path to the directory with genesis templates to be used to \
                 initialize the network."
            )))
            .arg(
                WASM_CHECKSUMS_PATH
                    .def()
                    .help(wrap!("Path to the WASM checksums file.")),
            )
            .arg(CHAIN_ID_PREFIX.def().help(wrap!(
                "The chain ID prefix. Up to 19 alphanumeric, '.', '-' or '_' \
                 characters."
            )))
            .arg(GENESIS_TIME.def().help(wrap!(
                "The start time of the network in RFC 3339 and ISO 8601 \
                 format. For example: \"2021-12-31T00:00:00Z\"."
            )))
            .arg(CONSENSUS_TIMEOUT_COMMIT.def().help(wrap!(
                "The Tendermint consensus timeout_commit configuration as \
                 e.g. `1s` or `1000ms`. Defaults to 10 seconds."
            )))
            .arg(ARCHIVE_DIR.def().help(wrap!(
                "Specify a directory into which to store the archive. Default \
                 is the current working directory."
            )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct DeriveGenesisAddresses {
        pub genesis_txs_path: PathBuf,
    }

    impl Args for DeriveGenesisAddresses {
        fn parse(matches: &ArgMatches) -> Self {
            let genesis_txs_path = PATH.parse(matches);
            Self { genesis_txs_path }
        }

        fn def(app: App) -> App {
            app.arg(
                PATH.def().help(wrap!("Path to the genesis txs toml file.")),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitGenesisEstablishedAccount {
        pub vp: String,
        pub wallet_aliases: Vec<String>,
        pub threshold: u8,
        pub output_path: PathBuf,
    }

    impl Args for InitGenesisEstablishedAccount {
        fn parse(matches: &ArgMatches) -> Self {
            use crate::config::genesis::utils::VP_USER;
            let wallet_aliases = ALIAS_MANY.parse(matches);
            let vp = VP.parse(matches).unwrap_or_else(|| VP_USER.to_string());
            let threshold = THRESHOLD.parse(matches).unwrap_or(1);
            let output_path = PATH.parse(matches);
            Self {
                wallet_aliases,
                vp,
                threshold,
                output_path,
            }
        }

        fn def(app: App) -> App {
            app.arg(ALIAS_MANY.def().help(wrap!(
                "Comma separated list of aliases of the keys to use from the \
                 wallet."
            )))
            .arg(THRESHOLD.def().help(wrap!(
                "The minimum number of signatures to be provided for \
                 authorization. Must be less than or equal to the maximum \
                 number of key aliases provided."
            )))
            .arg(VP.def().help(wrap!(
                "The validity predicate of the account. Defaults to `vp_user`."
            )))
            .arg(PATH.def().help(wrap!(
                "The path of the .toml file to write the established account \
                 transaction to. Overwrites the file if it exists."
            )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct GenesisBond {
        pub source: AddrOrPk,
        pub validator: EstablishedAddress,
        pub bond_amount: token::DenominatedAmount,
        pub output: PathBuf,
    }

    impl Args for GenesisBond {
        fn parse(matches: &ArgMatches) -> Self {
            let validator = GENESIS_VALIDATOR_ADDRESS.parse(matches);
            let source =
                GENESIS_BOND_SOURCE.parse(matches).unwrap_or_else(|| {
                    AddrOrPk::Address(Address::Established(validator.clone()))
                });
            let bond_amount = AMOUNT.parse(matches);
            let output = PATH.parse(matches);
            Self {
                source,
                validator,
                bond_amount,
                output,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                GENESIS_VALIDATOR_ADDRESS
                    .def()
                    .help(wrap!("Validator address.")),
            )
            .arg(
                AMOUNT
                    .def()
                    .help(wrap!("Amount of tokens to stake in a bond.")),
            )
            .arg(GENESIS_BOND_SOURCE.def().help(wrap!(
                "Source address for delegations. For self-bonds, the \
                 validator is also the source."
            )))
            .arg(
                PATH.def()
                    .help(wrap!("Output toml file to write transactions to.")),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct InitGenesisValidator {
        pub alias: String,
        pub commission_rate: Dec,
        pub max_commission_rate_change: Dec,
        pub net_address: SocketAddr,
        pub unsafe_dont_encrypt: bool,
        pub key_scheme: SchemeType,
        pub self_bond_amount: token::DenominatedAmount,
        pub email: String,
        pub description: Option<String>,
        pub website: Option<String>,
        pub discord_handle: Option<String>,
        pub avatar: Option<String>,
        pub name: Option<String>,
        pub address: EstablishedAddress,
        pub tx_path: PathBuf,
    }

    impl Args for InitGenesisValidator {
        fn parse(matches: &ArgMatches) -> Self {
            let alias = ALIAS.parse(matches);
            let commission_rate = COMMISSION_RATE.parse(matches);
            let max_commission_rate_change =
                MAX_COMMISSION_RATE_CHANGE.parse(matches);
            let net_address = NET_ADDRESS.parse(matches);
            let unsafe_dont_encrypt = UNSAFE_DONT_ENCRYPT.parse(matches);
            let key_scheme = SCHEME.parse(matches);
            // this must be an amount of native tokens
            let self_bond_amount = SELF_BOND_AMOUNT.parse(matches);
            let email = EMAIL.parse(matches);
            let description = DESCRIPTION_OPT.parse(matches);
            let website = WEBSITE_OPT.parse(matches);
            let discord_handle = DISCORD_OPT.parse(matches);
            let avatar = AVATAR_OPT.parse(matches);
            let name = VALIDATOR_NAME_OPT.parse(matches);
            let address = RAW_ADDRESS_ESTABLISHED.parse(matches);
            let tx_path = PATH.parse(matches);
            Self {
                alias,
                net_address,
                unsafe_dont_encrypt,
                key_scheme,
                commission_rate,
                max_commission_rate_change,
                self_bond_amount,
                email,
                description,
                website,
                discord_handle,
                avatar,
                name,
                tx_path,
                address,
            }
        }

        fn def(app: App) -> App {
            app.arg(ALIAS.def().help(wrap!("The validator address alias.")))
                .arg(RAW_ADDRESS_ESTABLISHED.def().help(wrap!(
                    "The address of an established account to be promoted to \
                     a validator."
                )))
                .arg(PATH.def().help(wrap!(
                    "The .toml file containing an established account tx from \
                     which to create a validator."
                )))
                .arg(NET_ADDRESS.def().help(wrap!(
                    "Static {host:port} of your validator node's P2P address. \
                     Namada uses port `26656` for P2P connections by default, \
                     but you can configure a different value."
                )))
                .arg(COMMISSION_RATE.def().help(wrap!(
                    "The commission rate charged by the validator for \
                     delegation rewards. This is a required parameter."
                )))
                .arg(MAX_COMMISSION_RATE_CHANGE.def().help(wrap!(
                    "The maximum change per epoch in the commission rate \
                     charged by the validator for delegation rewards. This is \
                     a required parameter."
                )))
                .arg(UNSAFE_DONT_ENCRYPT.def().help(wrap!(
                    "UNSAFE: Do not encrypt the generated keypairs. Do not \
                     use this for keys used in a live network."
                )))
                .arg(SCHEME.def().help(wrap!(
                    "The key scheme/type used for the validator keys. \
                     Currently supports ed25519 and secp256k1."
                )))
                .arg(SELF_BOND_AMOUNT.def().help(wrap!(
                    "The amount of native token to self-bond in PoS."
                )))
                .arg(EMAIL.def().help(wrap!(
                    "The email address of the validator. This is a required \
                     parameter."
                )))
                .arg(DESCRIPTION_OPT.def().help(wrap!(
                    "The validator's description. This is an optional \
                     parameter."
                )))
                .arg(WEBSITE_OPT.def().help(wrap!(
                    "The validator's website. This is an optional parameter."
                )))
                .arg(DISCORD_OPT.def().help(wrap!(
                    "The validator's discord handle. This is an optional \
                     parameter."
                )))
                .arg(AVATAR_OPT.def().help(wrap!(
                    "The validator's avatar. This is an optional parameter."
                )))
                .arg(VALIDATOR_NAME_OPT.def().help(wrap!(
                    "The validator's name, used to identify the validator in \
                     online services. This is an optional parameter."
                )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct ValidateGenesisTemplates {
        /// Templates dir
        pub path: PathBuf,
    }

    impl Args for ValidateGenesisTemplates {
        fn parse(matches: &ArgMatches) -> Self {
            let path = PATH.parse(matches);
            Self { path }
        }

        fn def(app: App) -> App {
            app.arg(
                PATH.def().help(wrap!(
                    "Path to the directory with the template files."
                )),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct TestGenesis {
        /// Templates dir
        pub path: PathBuf,
        pub wasm_dir: PathBuf,
        pub check_can_sign: Vec<AddrOrPk>,
    }

    impl Args for TestGenesis {
        fn parse(matches: &ArgMatches) -> Self {
            let path = PATH.parse(matches);
            let wasm_dir = WASM_DIR.parse(matches).unwrap_or_default();
            let check_can_sign = CHECK_CAN_SIGN.parse(matches);
            Self {
                path,
                wasm_dir,
                check_can_sign,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                PATH.def().help(wrap!(
                    "Path to the directory with the template files."
                )),
            )
            .arg(WASM_DIR.def().help(wrap!(
                "Optional wasm directory to provide as part of verifying \
                 genesis template files"
            )))
            .arg(CHECK_CAN_SIGN.def().help(wrap!(
                "Check that the pre-genesis wallet is able to sign with the \
                 given keys and/or keys associated with the given addresses. \
                 A pre-genesis wallet must be present in the base directory."
            )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct DryRunProposal {
        pub wasm_path: PathBuf,
    }

    impl Args for DryRunProposal {
        fn parse(matches: &ArgMatches) -> Self {
            let wasm_path = WASM_PATH.parse(matches).unwrap_or_default();
            Self { wasm_path }
        }

        fn def(app: App) -> App {
            app.arg(
                WASM_PATH
                    .def()
                    .help(wrap!("Path to the wasm file to execute.")),
            )
        }
    }

    #[derive(Clone, Debug)]
    pub struct SignGenesisTxs {
        pub path: PathBuf,
        pub output: Option<PathBuf>,
        pub validator_alias: Option<String>,
        pub use_device: bool,
        pub device_transport: DeviceTransport,
    }

    impl Args for SignGenesisTxs {
        fn parse(matches: &ArgMatches) -> Self {
            let path = PATH.parse(matches);
            let output = OUTPUT.parse(matches);
            let validator_alias = ALIAS_OPT.parse(matches);
            let use_device = USE_DEVICE.parse(matches);
            let device_transport = DEVICE_TRANSPORT.parse(matches);
            Self {
                path,
                output,
                validator_alias,
                use_device,
                device_transport,
            }
        }

        fn def(app: App) -> App {
            app.arg(
                PATH.def().help(wrap!(
                    "Path to the unsigned transactions TOML file."
                )),
            )
            .arg(OUTPUT.def().help(wrap!(
                "Save the output to a TOML file. When not supplied, the \
                 signed transactions will be printed to stdout instead."
            )))
            .arg(
                ALIAS_OPT
                    .def()
                    .help(wrap!("Optional alias to a validator wallet.")),
            )
            .arg(USE_DEVICE.def().help(wrap!(
                "Derive an address and public key from the seed stored on the \
                 connected hardware wallet."
            )))
            .arg(DEVICE_TRANSPORT.def().help(wrap!(
                "Select transport for hardware wallet from \"hid\" (default) \
                 or \"tcp\"."
            )))
        }
    }

    #[derive(Clone, Debug)]
    pub struct MigrationJson {
        pub path: PathBuf,
    }

    impl Args for MigrationJson {
        fn parse(matches: &ArgMatches) -> Self {
            let path = PATH.parse(matches);

            Self { path }
        }

        fn def(app: App) -> App {
            app.arg(PATH.def().help(wrap!(
                "Path to the migrations JSON file. Requires the binary to be \
                 built with the \"migrations\" feature."
            )))
        }
    }
}

pub fn namada_cli(version: &'static str) -> (cmds::Namada, String) {
    let app = namada_app(version);
    let matches = app.get_matches();
    let raw_sub_cmd =
        matches.subcommand().map(|(raw, _matches)| raw.to_string());
    let result = cmds::Namada::parse(&matches);
    match (result, raw_sub_cmd) {
        (Some(cmd), Some(raw_sub)) => return (cmd, raw_sub),
        _ => {
            namada_app(version).print_help().unwrap();
        }
    }
    safe_exit(2);
}

/// Namada node commands with loaded [`Context`] where required
pub enum NamadaNode {
    Ledger(cmds::Ledger, Context),
    Config(cmds::Config, Context),
    Utils(cmds::NodeUtils, args::Global),
}

pub fn namada_node_cli(version: &'static str) -> Result<NamadaNode> {
    let app = namada_node_app(version);
    let matches = app.clone().get_matches();
    match Cmd::parse(&matches) {
        Some(cmd) => {
            let global_args = args::Global::parse(&matches);
            match cmd {
                cmds::NamadaNode::Ledger(sub_cmd) => {
                    let context = Context::new::<CliIo>(global_args)?;
                    Ok(NamadaNode::Ledger(sub_cmd, context))
                }
                cmds::NamadaNode::Config(sub_cmd) => {
                    let context = Context::new::<CliIo>(global_args)?;
                    Ok(NamadaNode::Config(sub_cmd, context))
                }
                cmds::NamadaNode::Utils(sub_cmd) => {
                    Ok(NamadaNode::Utils(sub_cmd, global_args))
                }
            }
        }
        None => {
            let mut app = app;
            app.print_help().unwrap();
            safe_exit(2);
        }
    }
}

/// Namada client commands with loaded [`Context`] where required
pub enum NamadaClient {
    WithoutContext(Box<(cmds::ClientUtils, args::Global)>),
    WithContext(Box<(cmds::NamadaClientWithContext, Context)>),
}

pub fn namada_client_cli(version: &'static str) -> Result<NamadaClient> {
    let app = namada_client_app(version);
    let matches = app.clone().get_matches();
    match Cmd::parse(&matches) {
        Some(cmd) => {
            let global_args = args::Global::parse(&matches);
            match cmd {
                cmds::NamadaClient::WithContext(sub_cmd) => {
                    let context = Context::new::<CliIo>(global_args)?;
                    Ok(NamadaClient::WithContext(Box::new((sub_cmd, context))))
                }
                cmds::NamadaClient::WithoutContext(sub_cmd) => {
                    Ok(NamadaClient::WithoutContext(Box::new((
                        sub_cmd,
                        global_args,
                    ))))
                }
            }
        }
        None => {
            let mut app = app;
            app.print_help().unwrap();
            safe_exit(2);
        }
    }
}

pub fn namada_wallet_cli(
    version: &'static str,
) -> Result<(cmds::NamadaWallet, Context)> {
    let app = namada_wallet_app(version);
    cmds::NamadaWallet::parse_or_print_help(app)
}

pub enum NamadaRelayer {
    EthBridgePoolWithCtx(Box<(cmds::EthBridgePoolWithCtx, Context)>),
    EthBridgePoolWithoutCtx(cmds::EthBridgePoolWithoutCtx),
    ValidatorSet(cmds::ValidatorSet),
}

pub fn namada_relayer_cli(version: &'static str) -> Result<NamadaRelayer> {
    let app = namada_relayer_app(version);
    let matches = app.clone().get_matches();
    match Cmd::parse(&matches) {
        Some(cmd) => match cmd {
            cmds::NamadaRelayer::EthBridgePool(
                cmds::EthBridgePool::WithContext(sub_cmd),
            ) => {
                let global_args = args::Global::parse(&matches);
                let context = Context::new::<StdIo>(global_args)?;
                Ok(NamadaRelayer::EthBridgePoolWithCtx(Box::new((
                    sub_cmd, context,
                ))))
            }
            cmds::NamadaRelayer::EthBridgePool(
                cmds::EthBridgePool::WithoutContext(sub_cmd),
            ) => Ok(NamadaRelayer::EthBridgePoolWithoutCtx(sub_cmd)),
            cmds::NamadaRelayer::ValidatorSet(sub_cmd) => {
                Ok(NamadaRelayer::ValidatorSet(sub_cmd))
            }
        },
        None => {
            let mut app = app;
            app.print_help().unwrap();
            safe_exit(2);
        }
    }
}

pub fn namada_app(version: &'static str) -> App {
    let app = App::new(APP_NAME)
        .version(version)
        .about("Namada command line interface.")
        .color(ColorChoice::Auto)
        .subcommand_required(true)
        .arg_required_else_help(true);
    cmds::Namada::add_sub(args::Global::def(app))
}

pub fn namada_node_app(version: &'static str) -> App {
    let app = App::new(APP_NAME)
        .version(version)
        .about("Namada node command line interface.")
        .color(ColorChoice::Auto)
        .subcommand_required(true)
        .arg_required_else_help(true);
    cmds::NamadaNode::add_sub(args::Global::def(app))
}

pub fn namada_client_app(version: &'static str) -> App {
    let app = App::new(APP_NAME)
        .version(version)
        .about("Namada client command line interface.")
        .color(ColorChoice::Auto)
        .subcommand_required(true)
        .arg_required_else_help(true);
    cmds::NamadaClient::add_sub(args::Global::def(app))
}

pub fn namada_wallet_app(version: &'static str) -> App {
    let app = App::new(APP_NAME)
        .version(version)
        .about("Namada wallet command line interface.")
        .color(ColorChoice::Auto)
        .subcommand_required(true)
        .arg_required_else_help(true);
    cmds::NamadaWallet::add_sub(args::Global::def(app))
}

pub fn namada_relayer_app(version: &'static str) -> App {
    let app = App::new(APP_NAME)
        .version(version)
        .about("Namada relayer command line interface.")
        .subcommand_required(true);
    cmds::NamadaRelayer::add_sub(args::Global::def(app))
}
