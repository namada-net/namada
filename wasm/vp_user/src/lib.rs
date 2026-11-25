//! A basic user VP supports both non-validator and validator accounts.
//!
//! This VP currently provides a signature verification against a public key for
//! sending tokens (receiving tokens is permissive).
//!
//! It allows to bond, unbond and withdraw tokens to and from PoS system with a
//! valid signature(s).
//!
//! For validator a tx to change a validator's commission rate or metadata
//! requires a valid signature(s) only from the validator.
//!
//! Any other storage key changes are allowed only with a valid signature.

use booleans::BoolResultUnitExt;
use namada_vp_prelude::tx::action::*;
use namada_vp_prelude::*;

#[validity_predicate]
fn validate_tx(
    ctx: &Ctx,
    tx: BatchedTx,
    addr: Address,
    keys_changed: BTreeSet<storage::Key>,
    verifiers: BTreeSet<Address>,
) -> VpResult {
    debug_log!(
        "vp_user called with user addr: {}, key_changed: {:?}, verifiers: {:?}",
        addr,
        keys_changed,
        verifiers
    );

    let BatchedTx { tx, ref cmt } = tx;
    // Check if this is a governance proposal first
    let is_gov_proposal = tx
        .data(cmt)
        .and_then(|tx_data| {
            let proposal_id = u64::try_from_slice(&tx_data).ok()?;
            Some(is_proposal_accepted(ctx, proposal_id))
        })
        .transpose()?
        .unwrap_or(false);
    if is_gov_proposal {
        // Any change from governance is allowed without further checks
        return Ok(());
    }

    let mut gadget = VerifySigGadget::new();

    // Find the actions applied in the tx
    let actions = ctx.read_actions().into_vp_error()?;

    // Require authorization by signature when the source of an action is this
    // VP's address
    for action in actions {
        match action {
            Action::Pos(pos_action) => match pos_action {
                PosAction::BecomeValidator(source)
                | PosAction::DeactivateValidator(source)
                | PosAction::ReactivateValidator(source)
                | PosAction::Unjail(source)
                | PosAction::CommissionChange(source)
                | PosAction::MetadataChange(source)
                | PosAction::ConsensusKeyChange(source)
                | PosAction::Redelegation(Redelegation {
                    owner: source, ..
                }) => gadget.verify_signatures_when(
                    || source == addr,
                    ctx,
                    &tx,
                    cmt,
                    &addr,
                )?,
                PosAction::Bond(Bond {
                    source, validator, ..
                })
                | PosAction::Unbond(Unbond {
                    source, validator, ..
                })
                | PosAction::Withdraw(Withdraw { source, validator })
                | PosAction::ClaimRewards(ClaimRewards {
                    validator,
                    source,
                    receiver: _,
                }) => {
                    let source = source.unwrap_or(validator);
                    gadget.verify_signatures_when(
                        || source == addr,
                        ctx,
                        &tx,
                        cmt,
                        &addr,
                    )?
                }
            },
            Action::Gov(
                GovAction::InitProposal { author: source }
                | GovAction::VoteProposal { voter: source, .. },
            )
            | Action::Pgf(
                PgfAction::ResignSteward(source)
                | PgfAction::UpdateStewardCommission(source),
            ) => gadget.verify_signatures_when(
                || source == addr,
                ctx,
                &tx,
                cmt,
                &addr,
            )?,
            Action::Masp(MaspAction::MaspAuthorizer(source)) => gadget
                .verify_signatures_when(
                    || source == addr,
                    ctx,
                    &tx,
                    cmt,
                    &addr,
                )?,
            Action::Masp(MaspAction::MaspSectionRef(_)) => (),
            Action::IbcShielding => (),
        }
    }

    keys_changed.iter().try_for_each(|key| {
        let key_type: KeyType = key.into();
        let mut validate_change = || match key_type {
            KeyType::TokenBalance { owner, .. } => {
                if owner == &addr {
                    let pre: token::Amount =
                        ctx.read_pre(key).into_vp_error()?.unwrap_or_default();
                    let post: token::Amount =
                        ctx.read_post(key).into_vp_error()?.unwrap_or_default();
                    let change =
                        post.change().checked_sub(pre.change()).unwrap();
                    gadget.verify_signatures_when(
                        // NB: debit has to signed, credit doesn't
                        || change.is_negative(),
                        ctx,
                        &tx,
                        cmt,
                        &addr,
                    )?;
                    let sign = if change.non_negative() { "" } else { "-" };
                    debug_log!("token key: {key}, change: {sign}{change:?}");
                } else {
                    // If this is not the owner, allow any change
                    debug_log!(
                        "This address ({}) is not of owner ({}) of token key: \
                         {}",
                        addr,
                        owner,
                        key
                    );
                }
                Ok(())
            }
            KeyType::TokenMinted => {
                verifiers.contains(&address::MULTITOKEN).ok_or_else(|| {
                    VpError::Erased(
                        "The Multitoken VP should have been a verifier for \
                         this transaction, since a token was minted"
                            .into(),
                    )
                })
            }
            KeyType::TokenMinter(minter_addr) => gadget.verify_signatures_when(
                || minter_addr == &addr,
                ctx,
                &tx,
                cmt,
                &addr,
            ),
            KeyType::Vp(owner) => {
                let vp_overwritten: bool =
                    ctx.has_key_post(key).into_vp_error()?;
                gadget.verify_signatures_when(
                    || owner == &addr && vp_overwritten,
                    ctx,
                    &tx,
                    cmt,
                    &addr,
                )
            }
            KeyType::Masp | KeyType::Ibc => Ok(()),
            KeyType::Unknown => {
                // Unknown changes require a valid signature
                gadget.verify_signatures(ctx, &tx, cmt, &addr)
            }
        };
        validate_change().inspect_err(|reason| {
            log_string(format!(
                "Modification on key {key} failed vp_user: {reason}"
            ));
        })
    })
}

enum KeyType<'a> {
    TokenBalance { owner: &'a Address },
    TokenMinted,
    TokenMinter(&'a Address),
    Vp(&'a Address),
    Masp,
    Ibc,
    Unknown,
}

impl<'a> From<&'a storage::Key> for KeyType<'a> {
    fn from(key: &'a storage::Key) -> KeyType<'a> {
        if let Some([_, owner]) =
            token::storage_key::is_any_token_balance_key(key)
        {
            Self::TokenBalance { owner }
        } else if token::storage_key::is_any_minted_balance_key(key).is_some() {
            Self::TokenMinted
        } else if let Some(minter) = token::storage_key::is_any_minter_key(key)
        {
            Self::TokenMinter(minter)
        } else if let Some(address) = key.is_validity_predicate() {
            Self::Vp(address)
        } else if token::storage_key::is_masp_key(key) {
            Self::Masp
        } else if ibc::is_ibc_key(key) {
            Self::Ibc
        } else {
            Self::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic;

    use address::testing::arb_non_internal_address;
    use namada_test_utils::TestWasms;
    use namada_tests::governance;
    use namada_tests::governance::parameters::GovernanceParameters;
    // Use this as `#[test]` annotation to enable logging
    use namada_tests::log::test;
    use namada_tests::native_vp::pos::init_pos;
    use namada_tests::tx::data::{self, TxType};
    use namada_tests::tx::{
        self, Authorization, Code, Data, TestTxEnv, tx_host_env,
    };
    use namada_tests::vp::vp_host_env::storage::Key;
    use namada_tests::vp::*;
    use namada_tx_prelude::chain::Epoch;
    use namada_tx_prelude::dec::Dec;
    use namada_tx_prelude::proof_of_stake::parameters::{
        OwnedPosParams, PosParams,
    };
    use namada_tx_prelude::proof_of_stake::types::GenesisValidator;
    use namada_tx_prelude::{StorageWrite, TxEnv};
    use namada_vp_prelude::account::AccountPublicKeysMap;
    use namada_vp_prelude::key::RefTo;
    use proof_of_stake::jail_validator;
    use proptest::prelude::*;
    use storage::testing::arb_account_storage_key_no_vp;

    use super::*;

    /// Test that no-op transaction (i.e. no storage modifications) accepted.
    #[test]
    fn test_no_op_transaction() {
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let addr: Address = address::testing::established_address_1();
        let keys_changed: BTreeSet<storage::Key> = BTreeSet::default();
        let verifiers: BTreeSet<Address> = BTreeSet::default();

        // The VP env must be initialized before calling `validate_tx`
        vp_host_env::init();

        assert!(
            validate_tx(
                &CTX,
                tx_data.batch_first_tx(),
                addr,
                keys_changed,
                verifiers
            )
            .is_ok()
        );
    }

    /// Test that a credit transfer is accepted.
    #[test]
    fn test_credit_transfer_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let source = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &source, &token]);

        // Credit the tokens to the source before running the transaction to be
        // able to transfer from it
        tx_env.credit_tokens(&source, &token, amount);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );

        // Add the receiver's address to the verifier set as this address is not
        // part of the verifier set from a transfer function
        tx_env.verifiers.insert(vp_owner.clone());

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                &source,
                address,
                &token,
                amount.amount(),
            )
            .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(
                &CTX,
                tx_data.batch_first_tx(),
                vp_owner,
                keys_changed,
                verifiers
            )
            .is_ok()
        );
    }

    /// Test that a debit transfer without a valid signature is rejected.
    #[test]
    fn test_unsigned_debit_transfer_rejected() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let target = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );
        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                address,
                &target,
                &token,
                amount.amount(),
            )
            .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            panic::catch_unwind(|| {
                validate_tx(
                    &CTX,
                    tx_data.batch_first_tx(),
                    vp_owner,
                    keys_changed,
                    verifiers,
                )
            })
            .err()
            .map(|a| a.downcast_ref::<String>().cloned().unwrap())
            .unwrap()
            .contains("InvalidSectionSignature")
        );
    }

    /// Test that a debit transfer with a valid signature is accepted.
    #[test]
    fn test_signed_debit_transfer_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = keypair.ref_to();
        let target = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                address,
                &target,
                &token,
                amount.amount(),
            )
            .unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.batched_tx.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_keys(vec![keypair]),
            None,
        )));
        let signed_tx = tx.batch_first_tx();
        vp_env.batched_tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }

    /// Test that a non-validator PoS action that must be authorized is rejected
    /// without a valid signature.
    #[test]
    fn test_unsigned_non_validator_pos_action_rejected() {
        // Init PoS genesis
        let pos_params = OwnedPosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let eth_cold_key = key::testing::keypair_3().ref_to();
        let eth_hot_key = key::testing::keypair_4().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator.clone(),
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key,
            eth_cold_key,
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = address::testing::established_address_2();
        let target = address::testing::established_address_3();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();
        let bond_amount = token::Amount::from_uint(5_098_123, 0).unwrap();
        let unbond_amount = token::Amount::from_uint(3_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&target, &token]);
        tx_env.init_account_storage(&vp_owner, vec![public_key], 1);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);

        // Initialize VP environment from non-validator PoS actions
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
            // Bond the tokens, then unbond some of them
            tx::ctx()
                .bond_tokens(Some(&vp_owner), &validator, bond_amount)
                .unwrap();
            tx::ctx()
                .unbond_tokens(Some(&vp_owner), &validator, unbond_amount)
                .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            panic::catch_unwind(|| {
                validate_tx(
                    &CTX,
                    tx_data.batch_first_tx(),
                    vp_owner,
                    keys_changed,
                    verifiers,
                )
            })
            .err()
            .map(|a| a.downcast_ref::<String>().cloned().unwrap())
            .unwrap()
            .contains("InvalidSectionSignature")
        );
    }

    /// Test unjailing of a validator that causes a consensus validator to be
    /// demoted to the below-capacity set. Probing a bug as seen in the SE.
    #[test]
    fn test_unjail_with_demotion() {
        // Genesis validators
        let pos_params = PosParams {
            owned: OwnedPosParams {
                max_validator_slots: 2,
                ..Default::default()
            },
            max_proposal_period: GovernanceParameters::default()
                .max_proposal_period,
        };

        // Common
        let protocol_key = key::testing::keypair_1().ref_to();
        let eth_cold_key = key::testing::keypair_1().ref_to();
        let eth_hot_key = key::testing::keypair_1().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        // Unique
        let (validator1, validator2, validator3) = (
            address::testing::established_address_1(),
            address::testing::established_address_2(),
            address::testing::established_address_3(),
        );
        let (stake1, stake2, stake3) = (
            token::Amount::native_whole(1),
            token::Amount::native_whole(2),
            token::Amount::native_whole(3),
        );
        let (sk1, sk2, sk3) = (
            key::testing::keypair_2(),
            key::testing::keypair_3(),
            key::testing::keypair_4(),
        );
        let (ck1, ck2, ck3) = (sk1.ref_to(), sk2.ref_to(), sk3.ref_to());
        let genesis_validators = [
            GenesisValidator {
                address: validator1.clone(),
                tokens: stake1,
                consensus_key: ck1.clone(),
                protocol_key: protocol_key.clone(),
                commission_rate,
                max_commission_rate_change,
                eth_hot_key: eth_hot_key.clone(),
                eth_cold_key: eth_cold_key.clone(),
                metadata: Default::default(),
            },
            GenesisValidator {
                address: validator3.clone(),
                tokens: stake3,
                consensus_key: ck3.clone(),
                protocol_key: protocol_key.clone(),
                commission_rate,
                max_commission_rate_change,
                eth_hot_key: eth_hot_key.clone(),
                eth_cold_key: eth_cold_key.clone(),
                metadata: Default::default(),
            },
            GenesisValidator {
                address: validator2.clone(),
                tokens: stake2,
                consensus_key: ck2.clone(),
                protocol_key,
                commission_rate,
                max_commission_rate_change,
                eth_hot_key,
                eth_cold_key,
                metadata: Default::default(),
            },
        ];

        println!("\nValidator1: {}", &validator1);
        println!("Validator2: {}", &validator2);
        println!("Validator3: {}\n", &validator3);

        // Init PoS storage
        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();
        // Set the validator accounts' keys
        tx_env.init_account_storage(&validator1, vec![ck1], 1);
        tx_env.init_account_storage(&validator2, vec![ck2], 1);
        tx_env.init_account_storage(&validator3, vec![ck3.clone()], 1);
        let token = address::testing::nam();

        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Jail validator3

        jail_validator::<_, governance::Store<_>>(
            &mut tx_env.state,
            &pos_params,
            &validator3,
            Epoch(0),
            Epoch(0),
        )
        .unwrap();

        // Initialize VP environment
        vp_host_env::init_from_tx(validator3.clone(), tx_env, |_address| {
            // Unjail validator3
            tx::ctx().unjail_validator(&validator3).unwrap()
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![ck3]);

        let mut vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        tx_data.set_code(Code::new(vec![], None));
        tx_data.add_section(Section::Authorization(Authorization::new(
            vec![tx_data.raw_header_hash()],
            pks_map.index_keys(vec![sk3]),
            None,
        )));
        let signed_tx = tx_data.batch_first_tx();
        vp_env.batched_tx = signed_tx.clone();

        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = vp_env.get_verifiers();
        assert!(verifiers.contains(&address::POS));
        assert!(verifiers.contains(&validator3));
        assert_eq!(verifiers.len(), 2);

        // The other validators whose state may be affected by unjailing must
        // not be part of the verifier set
        assert!(!verifiers.contains(&validator1));
        assert!(!verifiers.contains(&validator2));

        vp_host_env::set(vp_env);
        // The validator3 VP must accept the authorized tx
        assert!(
            validate_tx(
                &CTX,
                signed_tx,
                validator3,
                keys_changed.clone(),
                verifiers.clone()
            )
            .is_ok()
        );
    }

    /// Test that a PoS action to become validator that must be authorized is
    /// rejected without a valid signature.
    #[test]
    fn test_unsigned_become_validator_pos_action_rejected() {
        // Init PoS genesis
        let pos_params = OwnedPosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let eth_cold_key = key::testing::keypair_3().ref_to();
        let eth_hot_key = key::testing::keypair_4().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator,
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key,
            eth_cold_key,
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = address::testing::established_address_2();

        // Spawn the accounts to be able to modify their storage
        tx_env.init_account_storage(&vp_owner, vec![public_key], 1);

        // Initialize VP environment from PoS action to become a validator
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            let consensus_key = key::common::PublicKey::Ed25519(
                key::testing::gen_keypair::<key::ed25519::SigScheme>().ref_to(),
            );
            let protocol_key = key::common::PublicKey::Ed25519(
                key::testing::gen_keypair::<key::ed25519::SigScheme>().ref_to(),
            );
            let eth_cold_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to();
            let eth_hot_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to();
            let commission_rate = Dec::new(5, 2).unwrap();
            let max_commission_rate_change = Dec::new(1, 2).unwrap();
            let args = data::pos::BecomeValidator {
                address: address.clone(),
                consensus_key,
                eth_cold_key,
                eth_hot_key,
                protocol_key,
                commission_rate,
                max_commission_rate_change,
                email: "cucumber@tastes.good".to_string(),
                description: None,
                website: None,
                discord_handle: None,
                avatar: None,
                name: None,
            };
            tx::ctx().become_validator(args).unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            panic::catch_unwind(|| {
                validate_tx(
                    &CTX,
                    tx_data.batch_first_tx(),
                    vp_owner,
                    keys_changed,
                    verifiers,
                )
            })
            .err()
            .map(|a| a.downcast_ref::<String>().cloned().unwrap())
            .unwrap()
            .contains("InvalidSectionSignature")
        );
    }

    /// Test that a validator PoS action that must be authorized is rejected
    /// without a valid signature.
    #[test]
    fn test_unsigned_validator_pos_action_rejected() {
        // Init PoS genesis
        let pos_params = OwnedPosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let eth_cold_key = key::testing::keypair_3().ref_to();
        let eth_hot_key = key::testing::keypair_4().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator.clone(),
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key,
            eth_cold_key,
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let target = address::testing::established_address_3();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();
        let bond_amount = token::Amount::from_uint(5_098_123, 0).unwrap();
        let unbond_amount = token::Amount::from_uint(3_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&target, &token]);
        tx_env.init_account_storage(&validator, vec![public_key], 1);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Credit the tokens to the validator before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&validator, &token, amount);

        // Validator PoS actions
        vp_host_env::init_from_tx(validator.clone(), tx_env, |_address| {
            // Bond the tokens, then unbond some of them
            tx::ctx()
                .bond_tokens(Some(&validator), &validator, bond_amount)
                .unwrap();
            tx::ctx()
                .unbond_tokens(Some(&validator), &validator, unbond_amount)
                .unwrap();
            tx::ctx().deactivate_validator(&validator).unwrap();
            tx::ctx()
                .change_validator_metadata(
                    &validator,
                    Some("email".to_owned()),
                    Some("desc".to_owned()),
                    Some("website".to_owned()),
                    Some("discord".to_owned()),
                    Some("avatar".to_owned()),
                    Some("name".to_owned()),
                    Some(Dec::new(6, 2).unwrap()),
                )
                .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            panic::catch_unwind(|| {
                validate_tx(
                    &CTX,
                    tx_data.batch_first_tx(),
                    validator,
                    keys_changed,
                    verifiers,
                )
            })
            .err()
            .map(|a| a.downcast_ref::<String>().cloned().unwrap())
            .unwrap()
            .contains("InvalidSectionSignature")
        );
    }

    /// Test that a non-validator PoS action that must be authorized is accepted
    /// with a valid signature.
    #[test]
    fn test_signed_non_validator_pos_action_accepted() {
        // Init PoS genesis
        let pos_params = OwnedPosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator.clone(),
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key: key::common::PublicKey::Secp256k1(
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to(),
            ),
            eth_cold_key: key::common::PublicKey::Secp256k1(
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to(),
            ),
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = address::testing::established_address_2();
        let target = address::testing::established_address_3();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();
        let bond_amount = token::Amount::from_uint(5_098_123, 0).unwrap();
        let unbond_amount = token::Amount::from_uint(3_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&target, &token]);
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);

        // Initialize VP environment from non-validator PoS actions
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
            // Bond the tokens, then unbond some of them
            tx::ctx()
                .bond_tokens(Some(&vp_owner), &validator, bond_amount)
                .unwrap();
            tx::ctx()
                .unbond_tokens(Some(&vp_owner), &validator, unbond_amount)
                .unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.batched_tx.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_keys(vec![secret_key]),
            None,
        )));
        let signed_tx = tx.batch_first_tx();
        vp_env.batched_tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }

    /// Test that a signed PoS action to become validator that must be
    /// authorized is accepted with a valid signature.
    #[test]
    fn test_signed_become_validator_pos_action_accepted() {
        // Init PoS genesis
        let pos_params = OwnedPosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let eth_cold_key = key::testing::keypair_3().ref_to();
        let eth_hot_key = key::testing::keypair_4().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator,
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key,
            eth_cold_key,
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = address::testing::established_address_2();

        // Spawn the accounts to be able to modify their storage
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // Initialize VP environment from PoS action to become a validator
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            let consensus_key = key::common::PublicKey::Ed25519(
                key::testing::gen_keypair::<key::ed25519::SigScheme>().ref_to(),
            );
            let protocol_key = key::common::PublicKey::Ed25519(
                key::testing::gen_keypair::<key::ed25519::SigScheme>().ref_to(),
            );
            let eth_cold_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to();
            let eth_hot_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to();
            let commission_rate = Dec::new(5, 2).unwrap();
            let max_commission_rate_change = Dec::new(1, 2).unwrap();
            let args = data::pos::BecomeValidator {
                address: address.clone(),
                consensus_key,
                eth_cold_key,
                eth_hot_key,
                protocol_key,
                commission_rate,
                max_commission_rate_change,
                email: "cucumber@tastes.good".to_string(),
                description: None,
                website: None,
                discord_handle: None,
                avatar: None,
                name: None,
            };
            tx::ctx().become_validator(args).unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.batched_tx.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_keys(vec![secret_key]),
            None,
        )));
        let signed_tx = tx.batch_first_tx();
        vp_env.batched_tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }

    /// Test that a validator PoS action that must be authorized is accepted
    /// with a valid signature.
    #[test]
    fn test_signed_validator_pos_action_accepted() {
        // Init PoS genesis
        let pos_params = OwnedPosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator.clone(),
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key: key::common::PublicKey::Secp256k1(
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to(),
            ),
            eth_cold_key: key::common::PublicKey::Secp256k1(
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to(),
            ),
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let target = address::testing::established_address_3();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();
        let bond_amount = token::Amount::from_uint(5_098_123, 0).unwrap();
        let unbond_amount = token::Amount::from_uint(3_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&target, &token]);
        tx_env.init_account_storage(&validator, vec![public_key.clone()], 1);

        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&validator, &token, amount);

        // Validator PoS actions
        vp_host_env::init_from_tx(validator.clone(), tx_env, |_address| {
            // Bond the tokens, then unbond some of them
            tx::ctx()
                .bond_tokens(Some(&validator), &validator, bond_amount)
                .unwrap();
            tx::ctx()
                .unbond_tokens(Some(&validator), &validator, unbond_amount)
                .unwrap();
            tx::ctx().deactivate_validator(&validator).unwrap();
            tx::ctx()
                .change_validator_metadata(
                    &validator,
                    Some("email".to_owned()),
                    Some("desc".to_owned()),
                    Some("website".to_owned()),
                    Some("discord".to_owned()),
                    Some("avatar".to_owned()),
                    Some("name".to_owned()),
                    Some(Dec::new(6, 2).unwrap()),
                )
                .unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.batched_tx.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_keys(vec![secret_key]),
            None,
        )));
        let signed_tx = tx.batch_first_tx();
        vp_env.batched_tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, validator, keys_changed, verifiers)
                .is_ok()
        );
    }

    /// Test that a transfer on with accounts other than self is accepted.
    #[test]
    fn test_transfer_between_other_parties_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let source = address::testing::established_address_2();
        let target = address::testing::established_address_3();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &source, &target, &token]);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&source, &token, amount);

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            tx::ctx().insert_verifier(address).unwrap();
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                &source,
                &target,
                &token,
                amount.amount(),
            )
            .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(
                &CTX,
                tx_data.batch_first_tx(),
                vp_owner,
                keys_changed,
                verifiers
            )
            .is_ok()
        );
    }

    prop_compose! {
        /// Generates an account address and a storage key inside its storage.
        fn arb_account_storage_subspace_key()
            // Generate an address
            (address in arb_non_internal_address())
            // Generate a storage key other than its VP key (VP cannot be
            // modified directly via `write`, it has to be modified via
            // `tx::update_validity_predicate`.
            (storage_key in arb_account_storage_key_no_vp(address.clone()),
            // Use the generated address too
            address in Just(address))
        -> (Address, Key) {
            (address, storage_key)
        }
    }

    proptest! {
        /// Test that an unsigned tx that performs arbitrary storage writes or
        /// deletes to the account is rejected.
        #[test]
        fn test_unsigned_arb_storage_write_rejected(
            (vp_owner, storage_key) in arb_account_storage_subspace_key(),
            // Generate bytes to write. If `None`, delete from the key instead
            storage_value in any::<Option<Vec<u8>>>(),
        ) {
            // Initialize a tx environment
            let mut tx_env = TestTxEnv::default();

            // Spawn all the accounts in the storage key to be able to modify
            // their storage
            let storage_key_addresses = storage_key.find_addresses();
            tx_env.spawn_accounts(storage_key_addresses);

            // Initialize VP environment from a transaction
            vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
                // Write or delete some data in the transaction
                if let Some(value) = &storage_value {
                    tx::ctx().write(&storage_key, value).unwrap();
                } else {
                    tx::ctx().delete(&storage_key).unwrap();
                }
            });

            let vp_env = vp_host_env::take();
            let mut tx_data = Tx::from_type(TxType::Raw);
            tx_data.set_data(Data::new(vec![]));
            let keys_changed: BTreeSet<storage::Key> =
                vp_env.all_touched_storage_keys();
            let verifiers: BTreeSet<Address> = BTreeSet::default();
            vp_host_env::set(vp_env);
            assert!(
                panic::catch_unwind(|| {
                    validate_tx(&CTX, tx_data.batch_first_tx(), vp_owner, keys_changed, verifiers)
                })
                .err()
                .map(|a| a.downcast_ref::<String>().cloned().unwrap())
                .unwrap()
                .contains("InvalidSectionSignature")
            );
        }
    }

    proptest! {
        /// Test that a signed tx that performs arbitrary storage writes or
        /// deletes to the account is accepted.
        #[test]
        fn test_signed_arb_storage_write(
            (vp_owner, storage_key) in arb_account_storage_subspace_key(),
            // Generate bytes to write. If `None`, delete from the key instead
            storage_value in any::<Option<Vec<u8>>>(),
        ) {
            // Initialize a tx environment
            let mut tx_env = TestTxEnv::default();

            let keypair = key::testing::keypair_1();
            let public_key = keypair.ref_to();

            // Spawn all the accounts in the storage key to be able to modify
            // their storage
            let storage_key_addresses = storage_key.find_addresses();
            tx_env.spawn_accounts(storage_key_addresses);
            tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

            // Initialize VP environment from a transaction
            vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
                // Write or delete some data in the transaction
                if let Some(value) = &storage_value {
                    tx::ctx().write(&storage_key, value).unwrap();
                } else {
                    tx::ctx().delete(&storage_key).unwrap();
                }
            });

            let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

            let mut vp_env = vp_host_env::take();
            let mut tx = vp_env.batched_tx.tx.clone();
            tx.set_code(Code::new(vec![], None));
            tx.set_data(Data::new(vec![]));
            tx.add_section(Section::Authorization(Authorization::new(
                vec![tx.raw_header_hash()],
                pks_map.index_keys(vec![keypair]),
                None,
            )));
            let signed_tx = tx.batch_first_tx();
            vp_env.batched_tx= signed_tx.clone();
            let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
            let verifiers: BTreeSet<Address> = BTreeSet::default();
            vp_host_env::set(vp_env);
            assert!(validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers).is_ok());
        }
    }

    /// Test that a validity predicate update without a valid signature is
    /// rejected.
    #[test]
    fn test_unsigned_vp_update_rejected() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let vp_hash = sha256(&vp_code);
        // for the update
        tx_env.store_wasm_code(vp_code);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, vp_hash, &None)
                .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        tx_data.set_code(Code::new(vec![], None));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            panic::catch_unwind(|| {
                validate_tx(
                    &CTX,
                    tx_data.batch_first_tx(),
                    vp_owner,
                    keys_changed,
                    verifiers,
                )
            })
            .err()
            .map(|a| a.downcast_ref::<String>().cloned().unwrap())
            .unwrap()
            .contains("InvalidSectionSignature")
        );
    }

    /// Test that a validity predicate update with a valid signature is
    /// accepted.
    #[test]
    fn test_signed_vp_update_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();
        tx_env.init_parameters(None, None, None);

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = keypair.ref_to();
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let vp_hash = sha256(&vp_code);
        // for the update
        tx_env.store_wasm_code(vp_code);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, vp_hash, &None)
                .unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.batched_tx.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_keys(vec![keypair]),
            None,
        )));
        let signed_tx = tx.batch_first_tx();
        vp_env.batched_tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }

    /// Test that a validity predicate update is accepted if allowed
    #[test]
    fn test_signed_vp_update_allowed_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = keypair.ref_to();
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let vp_hash = sha256(&vp_code);
        // for the update
        tx_env.store_wasm_code(vp_code);

        tx_env.init_parameters(None, Some(vec![vp_hash.to_string()]), None);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, vp_hash, &None)
                .unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.batched_tx.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_keys(vec![keypair]),
            None,
        )));
        let signed_tx = tx.batch_first_tx();
        vp_env.batched_tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }

    // Test malleability attacks on memo sections
    #[test]
    fn test_tampered_memo_section() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = keypair.ref_to();
        let target = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );

        // Initialize VP environment from a transaction that requires a
        // signature check
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                address,
                &target,
                &token,
                amount.amount(),
            )
            .unwrap();
        });
        let mut vp_env = vp_host_env::take();
        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut tx = vp_env.batched_tx.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        let (_, memo_hash) = tx.add_memo(&[1, 2, 3]);
        tx.push_default_inner_tx();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_memo(&[1, 2, 3]);
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_keys(vec![keypair]),
            None,
        )));

        // Tamper with the first memo section
        let memo_section = tx
            .sections
            .iter_mut()
            .find(|sec| sec.get_hash() == memo_hash)
            .unwrap();
        let mut bytes = memo_section.extra_data().unwrap();
        *bytes.last_mut().unwrap() = 4;
        *memo_section = Section::ExtraData(Code::new(bytes, None));

        let signed_tx = tx.clone().batch_first_tx();
        vp_env.batched_tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);

        // 1. Tampared memo section of the current inner tx causes tx rejection
        //    when validating the signature
        let err = validate_tx(
            &CTX,
            signed_tx.clone(),
            vp_owner.clone(),
            keys_changed,
            verifiers,
        )
        .unwrap_err();
        if let VpError::Erased(msg) = err {
            assert_eq!(
                msg,
                format!("Memo section with hash {} is missing", memo_hash)
            );
        } else {
            panic!("Got wrong error message");
        }

        // 2. If signature is not checked, a tampered memo section should not
        //    cause rejection
        assert!(
            validate_tx(
                &CTX,
                signed_tx,
                vp_owner.clone(),
                Default::default(),
                Default::default(),
            )
            .is_ok()
        );

        // 3. If the memo section of another inner tx has been tampered with the
        //    current inner tx does not get rejected
        let mut tx_env = TestTxEnv::default();
        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = keypair.ref_to();
        let target = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );

        // Initialize VP environment from a transaction that requires a
        // signature check
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                address,
                &target,
                &token,
                amount.amount(),
            )
            .unwrap();
        });
        let mut vp_env = vp_host_env::take();
        let second_inner_tx = tx.header.batch.get_index(1).unwrap().clone();
        let signed_tx = tx.batch_tx(second_inner_tx);
        vp_env.batched_tx = signed_tx.clone();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(
                &CTX,
                signed_tx,
                vp_owner,
                Default::default(),
                Default::default(),
            )
            .is_ok()
        );
    }
}
