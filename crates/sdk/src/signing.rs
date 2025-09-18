//! Functions to sign transactions

#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::fmt::Display;

use borsh::BorshDeserialize;
use data_encoding::HEXLOWER;
use itertools::Itertools;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::components::sapling::fees::{
    InputView, OutputView,
};
use namada_account::{AccountPublicKeysMap, InitAccount, UpdateAccount};
use namada_core::address::{Address, ImplicitAddress, MASP};
use namada_core::arith::checked;
use namada_core::collections::{HashMap, HashSet};
use namada_core::ibc::primitives::IntoHostTime;
use namada_core::key::common::{CommonPublicKey, CommonSignature};
use namada_core::key::*;
use namada_core::masp::{AssetData, MaspTxId, PaymentAddress};
use namada_core::tendermint::Time as TmTime;
use namada_core::time::DateTimeUtc;
use namada_core::token::{Amount, DenominatedAmount};
use namada_governance::storage::proposal::{
    InitProposalData, ProposalType, VoteProposalData,
};
use namada_governance::storage::vote::ProposalVote;
use namada_ibc::core::channel::types::timeout::{
    TimeoutHeight, TimeoutTimestamp,
};
use namada_ibc::{MsgNftTransfer, MsgTransfer};
use namada_io::*;
use namada_parameters::storage as parameter_storage;
use namada_token as token;
use namada_token::storage_key::balance_key;
use namada_tx::data::pgf::UpdateStewardCommission;
use namada_tx::data::pos;
use namada_tx::data::pos::BecomeValidator;
use namada_tx::{
    Authorization, MaspBuilder, Section, SignatureIndex, Signer, Tx,
};
use namada_tx::{Authorization, MaspBuilder, Section, SignatureIndex, Tx};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::args::SdkTypes;
use crate::borsh::BorshSerializeExt;
use crate::error::{EncodingError, Error, TxSubmitError};
use crate::eth_bridge_pool::PendingTransfer;
use crate::governance::storage::proposal::{AddRemove, PGFAction, PGFTarget};
use crate::rpc::validate_amount;
use crate::tx::{
    Commitment, TX_BECOME_VALIDATOR_WASM, TX_BOND_WASM, TX_BRIDGE_POOL_WASM,
    TX_CHANGE_COMMISSION_WASM, TX_CHANGE_CONSENSUS_KEY_WASM,
    TX_CHANGE_METADATA_WASM, TX_CLAIM_REWARDS_WASM,
    TX_DEACTIVATE_VALIDATOR_WASM, TX_IBC_WASM, TX_INIT_ACCOUNT_WASM,
    TX_INIT_PROPOSAL, TX_REACTIVATE_VALIDATOR_WASM, TX_REDELEGATE_WASM,
    TX_RESIGN_STEWARD, TX_REVEAL_PK, TX_TRANSFER_WASM, TX_UNBOND_WASM,
    TX_UNJAIL_VALIDATOR_WASM, TX_UPDATE_ACCOUNT_WASM,
    TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM,
    VP_USER_WASM,
};
pub use crate::wallet::store::AddressVpType;
use crate::wallet::{Wallet, WalletIo};
use crate::{Namada, args, rpc};

/// A structure holding the signing data to craft a transaction
#[derive(Clone, PartialEq)]
pub struct SigningTxData {
    /// The address owning the transaction
    pub owner: Option<Address>,
    /// The public keys associated to an account
    pub public_keys: HashSet<common::PublicKey>,
    /// The threshold associated to an account
    pub threshold: u8,
    /// The public keys to index map associated to an account
    pub account_public_keys_map: Option<AccountPublicKeysMap>,
    /// ID of the Transaction needing signing
    pub shielded_hash: Option<MaspTxId>,
    /// List of serialized signatures to attach to the transaction
    pub signatures: Vec<Vec<u8>>,
}

/// The fee's authorization
#[derive(Clone)]
pub enum FeeAuthorization {
    /// A wrapper signer
    Signer {
        /// The wrapper signer
        pubkey: common::PublicKey,
        /// Flag to mark a disposable fee payer
        disposable_fee_payer: bool,
    },
    /// A serialized signature
    Signature(Vec<u8>),
}

/// A structure holding the signing data for a wrapper transaction
#[derive(Clone)]
pub struct SigningWrapperData {
    /// The signing data for each one of the inner transactions of this batch
    pub signing_data: Vec<SigningTxData>,
    /// The signing data for the wrapper itself
    pub fee_auth: FeeAuthorization,
}

impl SigningWrapperData {
    /// Returns the fee payer's public key if provided, otherwise returns an
    /// error.
    pub fn fee_payer_or_err(&self) -> Result<&common::PublicKey, Error> {
        match &self.fee_auth {
            FeeAuthorization::Signer { pubkey, .. } => Ok(pubkey),
            FeeAuthorization::Signature(_) => Err(Error::Other(
                "Expected wrapper signer, found wrapper signature".to_string(),
            )),
        }
    }

    /// Returns whether fees will be paid from a disposable address
    pub fn disposable_fee_payer(&self) -> bool {
        match self.fee_auth {
            FeeAuthorization::Signer {
                pubkey: _,
                disposable_fee_payer,
            } => disposable_fee_payer,
            FeeAuthorization::Signature(_) => false,
        }
    }
}

#[allow(missing_docs)]
#[derive(Clone)]
pub enum SigningData {
    Inner(SigningTxData),
    Wrapper(SigningWrapperData),
}

impl SigningData {
    pub(crate) fn into_components(
        self,
    ) -> (Vec<SigningTxData>, Option<FeeAuthorization>) {
        match self {
            SigningData::Inner(signing_tx_data) => {
                (vec![signing_tx_data], None)
            }
            SigningData::Wrapper(signing_wrapper_data) => (
                signing_wrapper_data.signing_data,
                Some(signing_wrapper_data.fee_auth),
            ),
        }
    }

    /// Returns a reference to the inner [`SigningTxData`]. In case of multiple
    /// instances it returns the first one (if any)
    pub fn signing_tx_data(&self) -> Option<&SigningTxData> {
        match self {
            SigningData::Inner(signing_tx_data) => Some(signing_tx_data),
            SigningData::Wrapper(signing_wrapper_data) => {
                signing_wrapper_data.signing_data.first()
            }
        }
    }
}

/// Find the public key for the given address and try to load the keypair
/// for it from the wallet.
///
/// If the keypair is encrypted but a password is not
/// supplied, then it is interactively prompted. Errors if the key cannot be
/// found or loaded.
pub async fn find_pk(
    context: &impl Namada,
    addr: &Address,
) -> Result<common::PublicKey, Error> {
    match addr {
        Address::Established(_) => {
            display_line!(
                context.io(),
                "Looking-up public key of {} from the ledger...",
                addr.encode()
            );
            rpc::get_public_key_at(context.client(), addr, 0)
                .await?
                .ok_or(Error::Other(format!(
                    "No public key found for the address {}",
                    addr.encode()
                )))
        }
        Address::Implicit(ImplicitAddress(pkh)) => Ok(context
            .wallet_mut()
            .await
            .find_public_key_by_pkh(pkh)
            .map_err(|err| {
                Error::Other(format!(
                    "Unable to load the keypair from the wallet for the \
                     implicit address {}. Failed with: {}",
                    addr.encode(),
                    err
                ))
            })?),
        Address::Internal(_) => other_err(format!(
            "Internal address {} doesn't have any signing keys.",
            addr
        )),
    }
}

/// Load the secret key corresponding to the given public key from the wallet.
///
/// If the keypair is encrypted but a password is not supplied, then it is
/// interactively prompted. Errors if the key cannot be found or loaded.
pub fn find_key_by_pk<U: WalletIo>(
    wallet: &mut Wallet<U>,
    args: &args::Tx,
    public_key: &common::PublicKey,
) -> Result<common::SecretKey, Error> {
    wallet
        .find_key_by_pk(public_key, args.password.clone())
        .map_err(|err| {
            Error::Other(format!(
                "Unable to load the keypair from the wallet for public key \
                 {}. Failed with: {}",
                public_key, err
            ))
        })
}

/// Given CLI arguments and some defaults, determine the rightful transaction
/// signer.
///
/// Return the given signing key or public key of the given signer if
/// possible. If no explicit signer given, use the `default`. If no `default`
/// is given, an `Error` is returned.
async fn inner_tx_signers(
    context: &impl Namada,
    mut signing_keys: Vec<common::PublicKey>,
    default_signer: Option<&Address>,
) -> Result<HashSet<common::PublicKey>, Error> {
    if let Some(signer) = default_signer {
        // Use the signer determined by the caller, fetch the signing key and
        // apply it
        signing_keys.push(find_pk(context, signer).await?)
    }

    Ok(signing_keys.into_iter().collect())
}

/// The different parts of a transaction that can be signed. Note that it's
/// impossible to sign the fee header without signing the raw header.
#[derive(Eq, Hash, PartialEq)]
pub enum Signable {
    /// Fee and raw header
    FeeRawHeader,
    /// Raw header
    RawHeader,
}

/// Causes sign_tx to attempt signing using only the software wallet
pub async fn default_sign(
    _tx: Tx,
    pubkey: common::PublicKey,
    _parts: Signable,
    _user: (),
) -> Result<Tx, Error> {
    Err(Error::Other(format!(
        "unable to sign transaction with {}",
        pubkey
    )))
}

/// When mocking signatures, if a key is in a hardware wallet,
/// use this function instead to mock the signature
fn mock_hw_sig(tx: &mut Tx, pk: common::PublicKey, signable: Signable) {
    let targets = match signable {
        Signable::FeeRawHeader => {
            vec![tx.sechashes(), vec![tx.raw_header_hash()]]
        }
        Signable::RawHeader => vec![vec![tx.raw_header_hash()]],
    };
    tx.protocol_filter();
    let sig = match pk {
        CommonPublicKey::Ed25519(_) => {
            // this key has no effect other than to satisfy api constraints
            let kp = ed25519::SigScheme::from_bytes([0; 32]);
            CommonSignature::Ed25519(ed25519::SigScheme::mock(&kp))
        }
        CommonPublicKey::Secp256k1(_) => {
            // this key has no effect other than to satisfy api constraints
            const SECRET_KEY_HEX: &str = "c2c72dfbff11dfb4e9d5b0a20c620c58b15bb7552753601f043db91331b0db15";
            let sk_bytes = HEXLOWER.decode(SECRET_KEY_HEX.as_bytes()).unwrap();
            let kp =
                secp256k1::SecretKey::try_from_slice(&sk_bytes[..]).unwrap();
            CommonSignature::Secp256k1(secp256k1::SigScheme::mock(&kp))
        }
    };
    for t in targets {
        let mut signatures = BTreeMap::new();
        signatures.insert(0, sig.clone());
        tx.add_section(Section::Authorization(Authorization {
            targets: t,
            signer: Signer::PubKeys(vec![pk.clone()]),
            signatures,
        }));
    }
}

/// Sign a transaction with a given signing key or public key of a given signer.
/// If no explicit signer given, use the `default`. If no `default` is given,
/// Error.
///
/// Optionally sign the wrapper header separately.
///
/// If this is not a dry run, the tx is put in a wrapper and returned along with
/// hashes needed for monitoring the tx on chain.
///
/// If it is a dry run, it is not put in a wrapper, but returned as is.
pub async fn sign_tx<D, F, U>(
    wallet: &RwLock<Wallet<U>>,
    args: &args::Tx,
    tx: &mut Tx,
    signing_data: SigningData,
    sign: impl Fn(Tx, common::PublicKey, Signable, D) -> F,
    user_data: D,
) -> Result<(), Error>
where
    D: Clone + MaybeSend,
    U: WalletIo,
    F: std::future::Future<Output = Result<Tx, Error>>,
{
    let (signing_data, fee_auth) = signing_data.into_components();
    for signing_tx_data in signing_data {
        let mut used_pubkeys = HashSet::new();

        // First try to sign the raw header with the supplied signatures
        let signatures = signing_tx_data
            .signatures
            .iter()
            .map(|bytes| {
                let sigidx =
                    SignatureIndex::try_from_json_bytes(bytes).unwrap();
                used_pubkeys.insert(sigidx.pubkey.clone());
                sigidx
            })
            .collect();
        tx.add_signatures(signatures);

        // Then try to sign the raw header with private keys in the software
        // wallet
        if let Some(account_public_keys_map) =
            signing_tx_data.account_public_keys_map
        {
            let mut wallet = wallet.write().await;
            let mut signing_tx_keypairs = vec![];

            for public_key in &signing_tx_data.public_keys {
                if !used_pubkeys.contains(public_key) {
                    let Ok(secret_key) =
                        find_key_by_pk(&mut wallet, args, public_key)
                    else {
                        // If the secret key is not found, continue because the
                        // hardware wallet may still be able to sign this
                        continue;
                    };
                    used_pubkeys.insert(public_key.clone());
                    signing_tx_keypairs.push(secret_key);
                }
            }

            if !signing_tx_keypairs.is_empty() {
                if args.dry_run.is_some() {
                    tx.mock(
                        signing_tx_keypairs,
                        account_public_keys_map,
                        signing_tx_data.owner,
                    )
                } else {
                    tx.sign_raw(
                        signing_tx_keypairs,
                        account_public_keys_map,
                        signing_tx_data.owner,
                    )
                };
            }
        }

        // Then try to sign the raw header using the hardware wallet
        for pubkey in &signing_tx_data.public_keys {
            if !used_pubkeys.contains(pubkey) {
                match &fee_auth {
                    Some(FeeAuthorization::Signer {
                        pubkey: fee_payer,
                        ..
                    }) if pubkey == fee_payer => {
                        // We will sign the inner tx together with the wrapper,
                        // we can anticipate the accounting of this signature
                        used_pubkeys.insert(pubkey.clone());
                    }
                    _ => {
                        if args.dry_run.is_some() {
                            mock_hw_sig(
                                tx,
                                pubkey.clone(),
                                Signable::RawHeader,
                            );
                            used_pubkeys.insert(pubkey.clone());
                        } else if let Ok(ntx) = sign(
                            tx.clone(),
                            pubkey.clone(),
                            Signable::RawHeader,
                            user_data.clone(),
                        )
                        .await
                        {
                            *tx = ntx;
                            used_pubkeys.insert(pubkey.clone());
                        }
                    }
                }
            }
        }

        // Then make sure that the number of public keys used exceeds the
        // threshold
        let used_pubkeys_len = used_pubkeys
            .len()
            .try_into()
            .expect("Public keys associated with account exceed 127");
        if used_pubkeys_len < signing_tx_data.threshold {
            return Err(Error::from(TxSubmitError::MissingSigningKeys(
                signing_tx_data.threshold,
                used_pubkeys_len,
            )));
        }
    }

    // Before signing the wrapper tx prune all the possible duplicated sections
    // (including duplicated raw signatures)
    tx.prune_duplicated_sections();

    // Then try signing the wrapper header (fee payer) if requested. Check if
    // there's a provided wrapper signature, otherwise sign with the
    // software wallet or use the fallback
    match &fee_auth {
        Some(FeeAuthorization::Signer {
            pubkey,
            disposable_fee_payer: _,
        }) => {
            let key = {
                // Lock the wallet just long enough to extract a key from it
                // without interfering with the sign closure
                // call
                let mut wallet = wallet.write().await;
                find_key_by_pk(&mut *wallet, args, pubkey)
            };
            match key {
                Ok(fee_payer_keypair) => {
                    if args.dry_run.is_some() {
                        tx.mock_sign_wrapper(fee_payer_keypair);
                    } else {
                        tx.sign_wrapper(fee_payer_keypair);
                    }
                }
                Err(_) => {
                    if args.dry_run.is_some() {
                        mock_hw_sig(tx, pubkey.clone(), Signable::FeeRawHeader);
                    } else {
                        *tx = sign(
                            tx.clone(),
                            pubkey.clone(),
                            Signable::FeeRawHeader,
                            user_data,
                        )
                        .await?;
                    }
                }
            }
        }
        Some(FeeAuthorization::Signature(sig_bytes)) => {
            let auth = serde_json::from_slice(sig_bytes).map_err(|e| {
                Error::Encode(EncodingError::Serde(e.to_string()))
            })?;
            tx.add_section(Section::Authorization(auth));
        }
        _ => (),
    }
    // Remove redundant sections now that the signing process is complete.
    // Though this call might be redundant in circumstances, it is placed here
    // as a safeguard to prevent the transmission of private data to the
    // network.
    tx.protocol_filter();

    Ok(())
}

/// Return the necessary data regarding an account to be able to generate
/// signature sections for both the inner and the wrapper transaction
pub async fn aux_signing_data(
    context: &impl Namada,
    wrap_tx: &args::Wrapper,
    owner: Option<Address>,
    signing_keys: Vec<common::PublicKey>,
    disposable_gas_payer: bool,
    signatures: Vec<Vec<u8>>,
) -> Result<SigningWrapperData, Error> {
    let public_keys =
        inner_tx_signers(context, signing_keys, owner.as_ref()).await?;

    let (account_public_keys_map, threshold) = match &owner {
        Some(owner @ Address::Established(_)) => {
            let account =
                rpc::get_account_info(context.client(), owner).await?;
            if let Some(account) = account {
                (Some(account.clone().public_keys_map), account.threshold)
            } else {
                return Err(Error::from(TxSubmitError::InvalidAccount(
                    owner.encode(),
                )));
            }
        }
        Some(Address::Implicit(_)) => (
            Some(AccountPublicKeysMap::from_iter(public_keys.clone())),
            1u8,
        ),
        Some(owner @ Address::Internal(_)) => {
            return Err(Error::from(TxSubmitError::InvalidAccount(
                owner.encode(),
            )));
        }
        None => (
            Some(AccountPublicKeysMap::from_iter(public_keys.clone())),
            0u8,
        ),
    };
    let fee_auth = match wrap_tx {
        args::Wrapper {
            wrapper_fee_payer: Some(pubkey),
            ..
        } => FeeAuthorization::Signer {
            pubkey: pubkey.to_owned(),
            disposable_fee_payer: false,
        },
        _ => {
            // FIXME: in theory though we want to leave freedom to the user,
            // just guide them, look at where we print the other warning message
            // and add this one as well, then mention this thing in the PR
            if let Some(pubkey) = public_keys.first() {
                FeeAuthorization::Signer {
                    pubkey: pubkey.to_owned(),
                    disposable_fee_payer: false,
                }
                // NOTE: the disposable gas_payer is always overridden by
                // signing inputs
            } else if disposable_gas_payer {
                FeeAuthorization::Signer {
                    pubkey: gen_disposable_signing_key(context).await,
                    disposable_fee_payer: true,
                }
            } else {
                return Err(Error::Tx(TxSubmitError::InvalidFeePayer));
            }
        }
    };

    let signing_inner_data = SigningTxData {
        owner,
        public_keys,
        threshold,
        account_public_keys_map,
        shielded_hash: None,
        signatures,
    };

    Ok(SigningWrapperData {
        signing_data: vec![signing_inner_data],
        fee_auth,
    })
}

/// Return the necessary data regarding an account to be able to generate a
/// signature section for the inner transaction only
pub async fn aux_inner_signing_data(
    context: &impl Namada,
    signing_keys: Vec<common::PublicKey>,
    owner: Option<Address>,
    signatures: Vec<Vec<u8>>,
) -> Result<SigningTxData, Error> {
    let public_keys =
        inner_tx_signers(context, signing_keys, owner.as_ref()).await?;

    let (account_public_keys_map, threshold) = match &owner {
        Some(owner @ Address::Established(_)) => {
            let account =
                rpc::get_account_info(context.client(), owner).await?;
            if let Some(account) = account {
                (Some(account.clone().public_keys_map), account.threshold)
            } else {
                return Err(Error::from(TxSubmitError::InvalidAccount(
                    owner.encode(),
                )));
            }
        }
        Some(Address::Implicit(_)) => (
            Some(AccountPublicKeysMap::from_iter(public_keys.clone())),
            1u8,
        ),
        Some(owner @ Address::Internal(_)) => {
            return Err(Error::from(TxSubmitError::InvalidAccount(
                owner.encode(),
            )));
        }
        None => (
            Some(AccountPublicKeysMap::from_iter(public_keys.clone())),
            0u8,
        ),
    };

    Ok(SigningTxData {
        owner,
        public_keys,
        threshold,
        account_public_keys_map,
        shielded_hash: None,
        signatures,
    })
}

/// The transaction's signatures produced via the offline signing procedure
pub struct OfflineSignatures {
    /// Inner txs' signatures
    pub signatures: Vec<SignatureIndex>,
    /// Optional wrapper signature
    pub wrapper_signature: Option<Authorization>,
}

/// Generates the transaction's signatures for offline signing purposes. This
/// allows to sign both the inner transactions of the batch as well as the
/// wrapper transaction and it supports multisignatures.
///
/// This function might need to modify the transaction by attaching the inner tx
/// signatures to correctly produce the wrapper signature: since this change is
/// only needed for the sake of this function and should not be propagated to
/// the caller, this function consumes the actual tx.
pub async fn generate_tx_signatures(
    mut tx: Tx,
    secret_keys: Vec<namada_core::key::common::SecretKey>,
    owner: Option<Address>,
    wrapper_signer: Option<namada_core::key::common::SecretKey>,
) -> Result<OfflineSignatures, Error> {
    let account_public_keys_map = AccountPublicKeysMap::from_iter(
        secret_keys.iter().map(|sk| sk.to_public()),
    );

    let signatures = tx.compute_section_signature(
        &secret_keys,
        &account_public_keys_map,
        owner,
    );

    // Generate wrapper signature if requested
    let wrapper_signature = wrapper_signer
        .map(|wrapper_signer| {
            // Depends if we want to return an error or not?
            if tx.header.wrapper().is_some() {
                // Wrapper signature must be computed over the raw signatures
                // too
                tx.add_signatures(signatures.clone());
                tx.protocol_filter();
                Ok(Authorization::new(
                    tx.sechashes(),
                    [(0, wrapper_signer)].into_iter().collect(),
                    None,
                ))
            } else {
                Err(Error::Other(
                    "A gas payer was provided but the transaction is not a \
                     wrapper"
                        .to_string(),
                ))
            }
        })
        .transpose()?;

    Ok(OfflineSignatures {
        signatures,
        wrapper_signature,
    })
}

/// Generate a disposable signing key.
pub async fn gen_disposable_signing_key(
    context: &impl Namada,
) -> common::PublicKey {
    context
        .wallet_mut()
        .await
        .gen_disposable_signing_key(&mut OsRng)
        .to_public()
}

/// Information about the post-fee balance of the tx's source. Used to correctly
/// handle balance validation in the inner tx
#[derive(Debug)]
pub struct TxSourcePostBalance {
    /// The balance of the tx source after the tx has been applied
    pub post_balance: Amount,
    /// The source address of the tx
    pub source: Address,
    /// The token of the tx
    pub token: Address,
}

/// Validate the fee amount and token
pub async fn validate_fee<N: Namada>(
    context: &N,
    args::Wrapper {
        fee_amount,
        fee_token,
        ..
    }: &args::Wrapper<SdkTypes>,
    force: bool,
) -> Result<DenominatedAmount, Error> {
    let gas_cost_key = parameter_storage::get_gas_cost_key();
    let minimum_fee = match rpc::query_storage_value::<
        _,
        BTreeMap<Address, Amount>,
    >(context.client(), &gas_cost_key)
    .await
    .and_then(|map| {
        map.get(fee_token).map(ToOwned::to_owned).ok_or_else(|| {
            Error::Other(format!(
                "Could not retrieve from storage the gas cost for token {}",
                fee_token
            ))
        })
    }) {
        Ok(amount) => amount,
        Err(e) => {
            if !force {
                return Err(e);
            } else {
                token::Amount::zero()
            }
        }
    };
    let validated_minimum_fee =
        context.denominate_amount(fee_token, minimum_fee).await;

    let fee_amount = match fee_amount {
        Some(amount) => {
            let validated_fee_amount =
                validate_amount(context, *amount, fee_token, force)
                    .await
                    .expect("Expected to be able to validate fee");

            if validated_fee_amount >= validated_minimum_fee {
                validated_fee_amount
            } else if !force {
                // Update the fee amount if it's not enough
                display_line!(
                    context.io(),
                    "The provided gas price {} is less than the minimum \
                     amount required {}, changing it to match the minimum",
                    validated_fee_amount.to_string(),
                    validated_minimum_fee.to_string()
                );
                validated_minimum_fee
            } else {
                validated_fee_amount
            }
        }
        None => validated_minimum_fee,
    };

    Ok(fee_amount)
}

/// Validate the fee of the transaction in case of a transparent fee payer,
/// computing the updated post balance
pub async fn validate_transparent_fee<N: Namada>(
    context: &N,
    args: &args::Wrapper<SdkTypes>,
    force: bool,
    fee_payer: &common::PublicKey,
) -> Result<(DenominatedAmount, TxSourcePostBalance), Error> {
    let fee_amount = validate_fee(context, args, force).await?;
    let args::Wrapper {
        fee_token,
        gas_limit,
        ..
    } = args;
    let fee_payer_address = Address::from(fee_payer);

    let balance_key = balance_key(fee_token, &fee_payer_address);
    #[allow(clippy::disallowed_methods)]
    let balance = rpc::query_storage_value::<_, token::Amount>(
        context.client(),
        &balance_key,
    )
    .await
    .unwrap_or_default();

    let total_fee =
        checked!(fee_amount.amount() * u64::from(gas_limit.to_owned()))?;
    let mut updated_balance = TxSourcePostBalance {
        post_balance: balance,
        source: fee_payer_address.clone(),
        token: fee_token.clone(),
    };

    match total_fee.checked_sub(balance) {
        Some(diff) if !diff.is_zero() => {
            let token_addr = fee_token.clone();
            if !force {
                let fee_amount =
                    context.format_amount(&token_addr, total_fee).await;

                let balance = context.format_amount(&token_addr, balance).await;
                return Err(Error::from(TxSubmitError::BalanceTooLowForFees(
                    fee_payer_address,
                    token_addr,
                    fee_amount,
                    balance,
                )));
            }

            updated_balance.post_balance = Amount::zero();
        }
        _ => {
            updated_balance.post_balance =
                checked!(updated_balance.post_balance - total_fee)?;
        }
    };

    Ok((fee_amount, updated_balance))
}

#[allow(clippy::result_large_err)]
fn other_err<T>(string: String) -> Result<T, Error> {
    Err(Error::Other(string))
}

/// Represents the transaction data that is displayed on a Ledger device
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct LedgerVector {
    /// String blob
    pub blob: String,
    /// Index integer
    pub index: u64,
    /// Name
    pub name: String,
    /// Regular output
    pub output: Vec<String>,
    /// Expert-mode output
    pub output_expert: Vec<String>,
    /// Is valid?
    pub valid: bool,
}

/// Adds a Ledger output line describing a given transaction amount and address
fn make_ledger_amount_addr(
    tokens: &HashMap<Address, &str>,
    output: &mut Vec<String>,
    amount: DenominatedAmount,
    token: &Address,
    prefix: &str,
) {
    if let Some(token) = tokens.get(token) {
        output.push(format!(
            "{}Amount : {} {}",
            prefix,
            token,
            to_ledger_decimal_variable_token(amount),
        ));
    } else {
        output.extend(vec![
            format!("{}Token : {}", prefix, token),
            format!(
                "{}Amount : {}",
                prefix,
                to_ledger_decimal_variable_token(amount)
            ),
        ]);
    }
}

/// Adds a Ledger output line describing a given transaction amount and asset
/// type
async fn make_ledger_amount_asset(
    tokens: &HashMap<Address, &str>,
    output: &mut Vec<String>,
    amount: u64,
    token: &AssetType,
    assets: &HashMap<AssetType, AssetData>,
    prefix: &str,
) {
    if let Some(decoded) = assets.get(token) {
        let amount = DenominatedAmount::new(
            token::Amount::from_masp_denominated(amount, decoded.position),
            decoded.denom,
        );
        // If the AssetType can be decoded, then at least display Addressees
        if let Some(token) = tokens.get(&decoded.token) {
            output.push(format!(
                "{}Amount : {} {}",
                prefix,
                token,
                to_ledger_decimal_variable_token(amount),
            ));
        } else {
            output.extend(vec![
                format!("{}Token : {}", prefix, decoded.token),
                format!(
                    "{}Amount : {}",
                    prefix,
                    to_ledger_decimal_variable_token(amount),
                ),
            ]);
        }
    } else {
        // Otherwise display the raw AssetTypes
        output.extend(vec![
            format!("{}Token : {}", prefix, token),
            format!("{}Amount : {}.0", prefix, amount,),
        ]);
    }
}

/// Split the lines in the vector that are longer than the Ledger device's
/// character width
fn format_outputs(output: &mut Vec<String>) {
    const MAX_KEY_LEN: usize = 39;
    const MAX_VALUE_LEN: usize = 39;

    let mut i = 0;
    let mut pos = 0;
    // Break down each line that is too long one-by-one
    while pos < output.len() {
        let curr_line = output[pos].clone();
        let (key, mut value) =
            curr_line.split_once(':').unwrap_or(("", &curr_line));
        // Truncate the key length to the declared maximum
        let key = key.trim().chars().take(MAX_KEY_LEN - 1).collect::<String>();
        // Trim value because we will insert spaces later
        value = value.trim();
        if value.chars().count() < MAX_VALUE_LEN {
            // No need to split the line in this case
            output[pos] = format!("{} | {} : {}", i, key, value);
            pos += 1;
        } else {
            // Line is too long so split it up. Repeat the key on each line
            output.remove(pos);
            let part_count = (value.chars().count() + MAX_VALUE_LEN - 2)
                / (MAX_VALUE_LEN - 1);
            for (idx, part) in value
                .chars()
                .chunks(MAX_VALUE_LEN - 1)
                .into_iter()
                .enumerate()
            {
                let line = format!(
                    "{} | {} [{}/{}] : {}",
                    i,
                    key,
                    idx + 1,
                    part_count,
                    part.collect::<String>(),
                );
                output.insert(pos, line);
                pos += 1;
            }
        }
        i += 1;
    }
}

/// Adds a Ledger output for the senders and destinations for transparent and
/// MASP transactions
async fn make_ledger_token_transfer_endpoints(
    tokens: &HashMap<Address, &str>,
    output: &mut Vec<String>,
    transfer: &token::Transfer,
    builder: Option<&MaspBuilder>,
    assets: &HashMap<AssetType, AssetData>,
) -> Result<(), Error> {
    for (owner, amount) in transfer.sources.clone() {
        // MASP inputs will be printed below
        if owner.owner != MASP {
            output.push(format!("Sender : {}", owner.owner));
            make_ledger_amount_addr(
                tokens,
                output,
                amount,
                &owner.token,
                "Sending ",
            );
        }
    }
    if let Some(builder) = builder {
        for sapling_input in builder.builder.sapling_inputs() {
            let pa = sapling_input.address().ok_or_else(|| {
                Error::Other("unable to load vp code".to_string())
            })?;
            let pa = PaymentAddress::from(pa);
            output.push(format!("Sender : {}", pa));
            make_ledger_amount_asset(
                tokens,
                output,
                sapling_input.value(),
                &sapling_input.asset_type(),
                assets,
                "Sending ",
            )
            .await;
        }
    }
    for (owner, amount) in transfer.targets.clone() {
        // MASP outputs will be printed below
        if owner.owner != MASP {
            output.push(format!("Destination : {}", owner.owner));
            make_ledger_amount_addr(
                tokens,
                output,
                amount,
                &owner.token,
                "Receiving ",
            );
        }
    }
    if let Some(builder) = builder {
        for sapling_output in builder.builder.sapling_outputs() {
            let pa = PaymentAddress::from(sapling_output.address());
            output.push(format!("Destination : {}", pa));
            make_ledger_amount_asset(
                tokens,
                output,
                sapling_output.value(),
                &sapling_output.asset_type(),
                assets,
                "Receiving ",
            )
            .await;
        }
    }

    Ok(())
}

/// Convert decimal numbers into the format used by Ledger when the token is
/// known to it. Specifically remove all insignificant zeros occurring after
/// decimal point.
fn to_ledger_decimal_whitelisted_token(amount: &str) -> String {
    if amount.contains('.') {
        let mut amount = amount.trim_end_matches('0').to_string();
        if amount.ends_with('.') {
            amount.pop();
        }
        amount
    } else {
        amount.to_string()
    }
}

/// Convert decimal numbers into the format used by Ledger when the token is
/// unknown to it. Specifically remove all insignificant zeros occurring after
/// decimal point. But unless the denomination is zero, always leave at least a
/// ".0" to indicate that the smallest unit representation is not being used.
fn to_ledger_decimal_variable_token(amount: DenominatedAmount) -> String {
    let mut amount_str = amount.to_string();
    if amount_str.contains('.') {
        let mut amount = amount_str.trim_end_matches('0').to_string();
        if amount.ends_with('.') {
            amount.push('0');
        }
        amount
    } else if u8::from(amount.denom()) > 0 {
        amount_str.push_str(".0");
        amount_str
    } else {
        amount_str
    }
}

/// A ProposalVote wrapper that prints the spending cap with Ledger decimal
/// formatting.
struct LedgerProposalVote<'a>(&'a ProposalVote);

impl Display for LedgerProposalVote<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            ProposalVote::Yay => write!(f, "yay"),
            ProposalVote::Nay => write!(f, "nay"),
            ProposalVote::Abstain => write!(f, "abstain"),
        }
    }
}

fn proposal_type_to_ledger_vector(
    proposal_type: &ProposalType,
    tx: &Tx,
    output: &mut Vec<String>,
) -> Result<(), Error> {
    match proposal_type {
        ProposalType::Default => {
            output.push("Proposal type : Default".to_string())
        }
        ProposalType::DefaultWithWasm(hash) => {
            output.push("Proposal type : Default".to_string());
            let extra = tx
                .get_section(hash)
                .and_then(|x| Section::extra_data_sec(x.as_ref()))
                .ok_or_else(|| {
                    Error::Other("unable to load vp code".to_string())
                })?
                .code
                .hash();
            output
                .push(format!("Proposal hash : {}", HEXLOWER.encode(&extra.0)));
        }
        ProposalType::PGFSteward(actions) => {
            output.push("Proposal type : PGF Steward".to_string());
            let mut actions = actions.iter().collect::<Vec<_>>();
            // Print the test vectors in the same order as the serializations
            actions.sort();
            for action in actions {
                match action {
                    AddRemove::Add(addr) => {
                        output.push(format!("Add : {}", addr))
                    }
                    AddRemove::Remove(addr) => {
                        output.push(format!("Remove : {}", addr))
                    }
                }
            }
        }
        ProposalType::PGFPayment(actions) => {
            output.push("Proposal type : PGF Payment".to_string());
            for action in actions {
                match action {
                    PGFAction::Continuous(AddRemove::Add(
                        PGFTarget::Internal(target),
                    )) => {
                        output.push(
                            "PGF Action : Add Continuous Payment".to_string(),
                        );
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal_whitelisted_token(
                                &target.amount.to_string_native()
                            )
                        ));
                    }
                    PGFAction::Continuous(AddRemove::Add(PGFTarget::Ibc(
                        target,
                    ))) => {
                        output.push(
                            "PGF Action : Add Continuous Payment".to_string(),
                        );
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal_whitelisted_token(
                                &target.amount.to_string_native()
                            )
                        ));
                        output.push(format!("Port ID: {}", target.port_id));
                        output
                            .push(format!("Channel ID: {}", target.channel_id));
                    }
                    PGFAction::Continuous(AddRemove::Remove(
                        PGFTarget::Internal(target),
                    )) => {
                        output.push(
                            "PGF Action : Remove Continuous Payment"
                                .to_string(),
                        );
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal_whitelisted_token(
                                &target.amount.to_string_native()
                            )
                        ));
                    }
                    PGFAction::Continuous(AddRemove::Remove(
                        PGFTarget::Ibc(target),
                    )) => {
                        output.push(
                            "PGF Action : Remove Continuous Payment"
                                .to_string(),
                        );
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal_whitelisted_token(
                                &target.amount.to_string_native()
                            )
                        ));
                        output.push(format!("Port ID: {}", target.port_id));
                        output
                            .push(format!("Channel ID: {}", target.channel_id));
                    }
                    PGFAction::Retro(PGFTarget::Internal(target)) => {
                        output.push("PGF Action : Retro Payment".to_string());
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal_whitelisted_token(
                                &target.amount.to_string_native()
                            )
                        ));
                    }
                    PGFAction::Retro(PGFTarget::Ibc(target)) => {
                        output.push("PGF Action : Retro Payment".to_string());
                        output.push(format!("Target: {}", target.target));
                        output.push(format!(
                            "Amount: NAM {}",
                            to_ledger_decimal_whitelisted_token(
                                &target.amount.to_string_native()
                            )
                        ));
                        output.push(format!("Port ID: {}", target.port_id));
                        output
                            .push(format!("Channel ID: {}", target.channel_id));
                    }
                }
            }
        }
    }
    Ok(())
}

// Find the MASP Builder that was used to construct the given Transaction.
// Additionally record how to decode AssetTypes using information from the
// builder.
fn find_masp_builder<'a>(
    tx: &'a Tx,
    shielded_section_hash: Option<MaspTxId>,
    asset_types: &mut HashMap<AssetType, AssetData>,
) -> Result<Option<&'a MaspBuilder>, std::io::Error> {
    for section in &tx.sections {
        match section {
            Section::MaspBuilder(builder)
                if Some(builder.target) == shielded_section_hash =>
            {
                for decoded in &builder.asset_types {
                    asset_types.insert(decoded.encode()?, decoded.clone());
                }
                return Ok(Some(builder));
            }
            _ => {}
        }
    }
    Ok(None)
}

// Format the date-time for the Ledger device
fn format_timestamp(datetime: DateTimeUtc) -> String {
    let mut datetime = datetime.0.to_string();
    let mut secfrac_width = None;
    for (i, ch) in datetime.char_indices() {
        if ch == '.' {
            secfrac_width = Some(0);
        } else if let Some(secfrac_width) = &mut secfrac_width {
            if ch.is_ascii_digit() {
                *secfrac_width += 1;
            } else {
                let trailing = "0".repeat(9 - *secfrac_width);
                datetime.insert_str(i, &trailing);
                break;
            }
        }
    }
    datetime
}

// Format the timeout timestamp for the Ledger device
fn format_timeout_timestamp(timestamp: &TimeoutTimestamp) -> String {
    match timestamp {
        TimeoutTimestamp::Never => "no timestamp".to_string(),
        TimeoutTimestamp::At(timestamp) => {
            let tm_time: TmTime =
                timestamp.into_host_time().expect("invalid timestamp");
            tm_time.to_rfc3339()
        }
    }
}

// Format the timeout height for the Ledger device
fn format_timeout_height(height: &TimeoutHeight) -> String {
    match height {
        TimeoutHeight::Never => "no timeout".to_string(),
        TimeoutHeight::At(height) => height.to_string(),
    }
}

/// Converts the given transaction to the form that is displayed on the Ledger
/// device
pub async fn to_ledger_vector(
    tokens: &HashMap<Address, &str>,
    tx: &Tx,
) -> Result<LedgerVector, Error> {
    let mut tv = LedgerVector {
        blob: HEXLOWER.encode(&tx.serialize_to_vec()),
        index: 0,
        valid: true,
        name: "Custom_0".to_string(),
        ..Default::default()
    };

    for cmt in tx.commitments() {
        // FIXME: need to push some string to differentiate between the
        // different txs of the bundle?
        let code_sec = tx
            .get_section(cmt.code_sechash())
            .ok_or_else(|| {
                Error::Other(
                    "expected tx code section to be present".to_string(),
                )
            })?
            .code_sec()
            .ok_or_else(|| {
                Error::Other("expected section to have code tag".to_string())
            })?;
        tv.output_expert.push(format!(
            "Code hash : {}",
            HEXLOWER.encode(&code_sec.code.hash().0)
        ));

        if code_sec.tag == Some(TX_INIT_ACCOUNT_WASM.to_string()) {
            let init_account = InitAccount::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;
            tv.name = "Init_Account_0".to_string();

            let extra = tx
                .get_section(&init_account.vp_code_hash)
                .and_then(|x| Section::extra_data_sec(x.as_ref()))
                .ok_or_else(|| {
                    Error::Other("unable to load vp code".to_string())
                })?;
            let vp_code = if extra.tag == Some(VP_USER_WASM.to_string()) {
                "User".to_string()
            } else {
                HEXLOWER.encode(&extra.code.hash().0)
            };
            tv.output.extend(vec![format!("Type : Init Account")]);
            tv.output.extend(
                init_account
                    .public_keys
                    .iter()
                    .map(|k| format!("Public key : {}", k)),
            );
            tv.output.extend(vec![
                format!("Threshold : {}", init_account.threshold),
                format!("VP type : {}", vp_code),
            ]);

            tv.output_expert.extend(
                init_account
                    .public_keys
                    .iter()
                    .map(|k| format!("Public key : {}", k)),
            );
            tv.output_expert.extend(vec![
                format!("Threshold : {}", init_account.threshold),
                format!("VP type : {}", HEXLOWER.encode(&extra.code.hash().0)),
            ]);
        } else if code_sec.tag == Some(TX_BECOME_VALIDATOR_WASM.to_string()) {
            let init_validator = BecomeValidator::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Become_Validator_0".to_string();

            tv.output
                .extend(vec!["Type : Become Validator".to_string()]);
            tv.output.extend(vec![
                format!("Address : {}", init_validator.address),
                format!("Consensus key : {}", init_validator.consensus_key),
                format!("Ethereum cold key : {}", init_validator.eth_cold_key),
                format!("Ethereum hot key : {}", init_validator.eth_hot_key),
                format!("Protocol key : {}", init_validator.protocol_key),
                format!("Commission rate : {}", init_validator.commission_rate),
                format!(
                    "Maximum commission rate change : {}",
                    init_validator.max_commission_rate_change,
                ),
                format!("Email : {}", init_validator.email),
            ]);
            if let Some(name) = &init_validator.name {
                tv.output.push(format!("Name : {}", name));
            }
            if let Some(description) = &init_validator.description {
                tv.output.push(format!("Description : {}", description));
            }
            if let Some(website) = &init_validator.website {
                tv.output.push(format!("Website : {}", website));
            }
            if let Some(discord_handle) = &init_validator.discord_handle {
                tv.output
                    .push(format!("Discord handle : {}", discord_handle));
            }
            if let Some(avatar) = &init_validator.avatar {
                tv.output.push(format!("Avatar : {}", avatar));
            }

            tv.output_expert.extend(vec![
                format!("Address : {}", init_validator.address),
                format!("Consensus key : {}", init_validator.consensus_key),
                format!("Ethereum cold key : {}", init_validator.eth_cold_key),
                format!("Ethereum hot key : {}", init_validator.eth_hot_key),
                format!("Protocol key : {}", init_validator.protocol_key),
                format!("Commission rate : {}", init_validator.commission_rate),
                format!(
                    "Maximum commission rate change : {}",
                    init_validator.max_commission_rate_change
                ),
                format!("Email : {}", init_validator.email),
            ]);
            if let Some(name) = &init_validator.name {
                tv.output_expert.push(format!("Name : {}", name));
            }
            if let Some(description) = &init_validator.description {
                tv.output_expert
                    .push(format!("Description : {}", description));
            }
            if let Some(website) = &init_validator.website {
                tv.output_expert.push(format!("Website : {}", website));
            }
            if let Some(discord_handle) = &init_validator.discord_handle {
                tv.output_expert
                    .push(format!("Discord handle : {}", discord_handle));
            }
            if let Some(avatar) = &init_validator.avatar {
                tv.output_expert.push(format!("Avatar : {}", avatar));
            }
        } else if code_sec.tag == Some(TX_INIT_PROPOSAL.to_string()) {
            let init_proposal_data = InitProposalData::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Init_Proposal_0".to_string();

            let extra = tx
                .get_section(&init_proposal_data.content)
                .and_then(|x| Section::extra_data_sec(x.as_ref()))
                .expect("unable to load vp code")
                .code
                .hash();

            tv.output.push("Type : Init proposal".to_string());
            proposal_type_to_ledger_vector(
                &init_proposal_data.r#type,
                tx,
                &mut tv.output,
            )?;
            tv.output.extend(vec![
                format!("Author : {}", init_proposal_data.author),
                format!(
                    "Voting start epoch : {}",
                    init_proposal_data.voting_start_epoch
                ),
                format!(
                    "Voting end epoch : {}",
                    init_proposal_data.voting_end_epoch
                ),
                format!(
                    "Activation epoch : {}",
                    init_proposal_data.activation_epoch
                ),
                format!("Content : {}", HEXLOWER.encode(&extra.0)),
            ]);

            proposal_type_to_ledger_vector(
                &init_proposal_data.r#type,
                tx,
                &mut tv.output_expert,
            )?;
            tv.output_expert.extend(vec![
                format!("Author : {}", init_proposal_data.author),
                format!(
                    "Voting start epoch : {}",
                    init_proposal_data.voting_start_epoch
                ),
                format!(
                    "Voting end epoch : {}",
                    init_proposal_data.voting_end_epoch
                ),
                format!(
                    "Activation epoch : {}",
                    init_proposal_data.activation_epoch
                ),
                format!("Content : {}", HEXLOWER.encode(&extra.0)),
            ]);
        } else if code_sec.tag == Some(TX_VOTE_PROPOSAL.to_string()) {
            let vote_proposal = VoteProposalData::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Vote_Proposal_0".to_string();

            tv.output.extend(vec![
                format!("Type : Vote Proposal"),
                format!("ID : {}", vote_proposal.id),
                format!("Vote : {}", LedgerProposalVote(&vote_proposal.vote)),
                format!("Voter : {}", vote_proposal.voter),
            ]);

            tv.output_expert.extend(vec![
                format!("ID : {}", vote_proposal.id),
                format!("Vote : {}", LedgerProposalVote(&vote_proposal.vote)),
                format!("Voter : {}", vote_proposal.voter),
            ]);
        } else if code_sec.tag == Some(TX_REVEAL_PK.to_string()) {
            let public_key = common::PublicKey::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Reveal_Pubkey_0".to_string();

            tv.output.extend(vec![
                format!("Type : Reveal Pubkey"),
                format!("Public key : {}", public_key),
            ]);

            tv.output_expert
                .extend(vec![format!("Public key : {}", public_key)]);
        } else if code_sec.tag == Some(TX_UPDATE_ACCOUNT_WASM.to_string()) {
            let update_account = UpdateAccount::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Update_Account_0".to_string();
            tv.output.extend(vec![
                format!("Type : Update Account"),
                format!("Address : {}", update_account.addr),
            ]);
            tv.output.extend(
                update_account
                    .public_keys
                    .iter()
                    .map(|k| format!("Public key : {}", k)),
            );
            if update_account.threshold.is_some() {
                tv.output.extend(vec![format!(
                    "Threshold : {}",
                    update_account.threshold.unwrap()
                )])
            }

            let vp_code_data = match &update_account.vp_code_hash {
                Some(hash) => {
                    let extra = tx
                        .get_section(hash)
                        .and_then(|x| Section::extra_data_sec(x.as_ref()))
                        .ok_or_else(|| {
                            Error::Other("unable to load vp code".to_string())
                        })?;
                    let vp_code = if extra.tag == Some(VP_USER_WASM.to_string())
                    {
                        "User".to_string()
                    } else {
                        HEXLOWER.encode(&extra.code.hash().0)
                    };
                    Some((vp_code, extra.code.hash()))
                }
                None => None,
            };
            if let Some((vp_code, _)) = &vp_code_data {
                tv.output.extend(vec![format!("VP type : {}", vp_code)]);
            }
            tv.output_expert
                .extend(vec![format!("Address : {}", update_account.addr)]);
            tv.output_expert.extend(
                update_account
                    .public_keys
                    .iter()
                    .map(|k| format!("Public key : {}", k)),
            );
            if let Some(threshold) = update_account.threshold {
                tv.output_expert
                    .extend(vec![format!("Threshold : {}", threshold,)])
            }
            if let Some((_, extra_code_hash)) = vp_code_data {
                tv.output_expert.extend(vec![format!(
                    "VP type : {}",
                    HEXLOWER.encode(&extra_code_hash.0)
                )]);
            }
        } else if code_sec.tag == Some(TX_TRANSFER_WASM.to_string()) {
            let transfer = token::Transfer::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;
            tv.name = "Transfer_0".to_string();
            tv.output.push("Type : Transfer".to_string());

            // To facilitate lookups of MASP AssetTypes
            let mut asset_types = HashMap::new();
            let builder = find_masp_builder(
                tx,
                transfer.shielded_section_hash,
                &mut asset_types,
            )
            .map_err(|_| Error::Other("Invalid Data".to_string()))?;
            make_ledger_token_transfer_endpoints(
                tokens,
                &mut tv.output,
                &transfer,
                builder,
                &asset_types,
            )
            .await?;
            make_ledger_token_transfer_endpoints(
                tokens,
                &mut tv.output_expert,
                &transfer,
                builder,
                &asset_types,
            )
            .await?;
        } else if code_sec.tag == Some(TX_IBC_WASM.to_string()) {
            let data = tx
                .data(cmt)
                .ok_or_else(|| Error::Other("Invalid Data".to_string()))?;

            if let Ok(transfer) =
                MsgTransfer::<token::Transfer>::try_from_slice(data.as_ref())
            {
                tv.name = "IBC_Transfer_0".to_string();
                tv.output.push("Type : IBC Transfer".to_string());
                let transfer_token = format!(
                    "{} {}",
                    transfer.message.packet_data.token.amount,
                    transfer.message.packet_data.token.denom
                );
                tv.output.extend(vec![
                    format!("Source port : {}", transfer.message.port_id_on_a),
                    format!(
                        "Source channel : {}",
                        transfer.message.chan_id_on_a
                    ),
                    format!("Token : {}", transfer_token),
                    format!("Sender : {}", transfer.message.packet_data.sender),
                    format!(
                        "Receiver : {}",
                        transfer.message.packet_data.receiver
                    ),
                    format!(
                        "Timeout height : {}",
                        format_timeout_height(
                            &transfer.message.timeout_height_on_b
                        )
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        format_timeout_timestamp(
                            &transfer.message.timeout_timestamp_on_b
                        ),
                    ),
                ]);
                tv.output_expert.extend(vec![
                    format!("Source port : {}", transfer.message.port_id_on_a),
                    format!(
                        "Source channel : {}",
                        transfer.message.chan_id_on_a
                    ),
                    format!("Token : {}", transfer_token),
                    format!("Sender : {}", transfer.message.packet_data.sender),
                    format!(
                        "Receiver : {}",
                        transfer.message.packet_data.receiver
                    ),
                ]);
                if !transfer.message.packet_data.memo.to_string().is_empty() {
                    tv.output_expert.push(format!(
                        "Memo : {}",
                        transfer.message.packet_data.memo
                    ));
                }
                tv.output_expert.extend(vec![
                    format!(
                        "Timeout height : {}",
                        format_timeout_height(
                            &transfer.message.timeout_height_on_b
                        )
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        format_timeout_timestamp(
                            &transfer.message.timeout_timestamp_on_b
                        ),
                    ),
                ]);
                if let Some(transfer) = transfer.transfer {
                    // To facilitate lookups of MASP AssetTypes
                    let mut asset_types = HashMap::new();
                    let builder = find_masp_builder(
                        tx,
                        transfer.shielded_section_hash,
                        &mut asset_types,
                    )
                    .map_err(|_| Error::Other("Invalid Data".to_string()))?;
                    make_ledger_token_transfer_endpoints(
                        tokens,
                        &mut tv.output,
                        &transfer,
                        builder,
                        &asset_types,
                    )
                    .await?;
                    make_ledger_token_transfer_endpoints(
                        tokens,
                        &mut tv.output_expert,
                        &transfer,
                        builder,
                        &asset_types,
                    )
                    .await?;
                }
            } else if let Ok(transfer) =
                MsgNftTransfer::<token::Transfer>::try_from_slice(data.as_ref())
            {
                tv.name = "IBC_NFT_Transfer_0".to_string();
                tv.output.push("Type : IBC NFT Transfer".to_string());
                tv.output.extend(vec![
                    format!("Source port : {}", transfer.message.port_id_on_a),
                    format!(
                        "Source channel : {}",
                        transfer.message.chan_id_on_a
                    ),
                    format!(
                        "Class ID: {}",
                        transfer.message.packet_data.class_id
                    ),
                ]);
                if let Some(class_uri) = &transfer.message.packet_data.class_uri
                {
                    tv.output.push(format!("Class URI: {}", class_uri));
                }
                if let Some(class_data) =
                    &transfer.message.packet_data.class_data
                {
                    tv.output.push(format!("Class data: {}", class_data));
                }
                for (idx, token_id) in
                    transfer.message.packet_data.token_ids.0.iter().enumerate()
                {
                    tv.output.push(format!("Token ID: {}", token_id));
                    if let Some(token_uris) =
                        &transfer.message.packet_data.token_uris
                    {
                        tv.output.push(format!(
                            "Token URI: {}",
                            token_uris.get(idx).ok_or_else(|| Error::Other(
                                "Invalid Data".to_string()
                            ))?,
                        ));
                    }
                    if let Some(token_data) =
                        &transfer.message.packet_data.token_data
                    {
                        tv.output.push(format!(
                            "Token data: {}",
                            token_data.get(idx).ok_or_else(|| Error::Other(
                                "Invalid Data".to_string()
                            ))?,
                        ));
                    }
                }
                tv.output.extend(vec![
                    format!("Sender : {}", transfer.message.packet_data.sender),
                    format!(
                        "Receiver : {}",
                        transfer.message.packet_data.receiver
                    ),
                ]);
                tv.output.extend(vec![
                    format!(
                        "Timeout height : {}",
                        format_timeout_height(
                            &transfer.message.timeout_height_on_b
                        )
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        format_timeout_timestamp(
                            &transfer.message.timeout_timestamp_on_b
                        ),
                    ),
                ]);
                tv.output_expert.extend(vec![
                    format!("Source port : {}", transfer.message.port_id_on_a),
                    format!(
                        "Source channel : {}",
                        transfer.message.chan_id_on_a
                    ),
                    format!(
                        "Class ID: {}",
                        transfer.message.packet_data.class_id
                    ),
                ]);
                if let Some(class_uri) = &transfer.message.packet_data.class_uri
                {
                    tv.output_expert.push(format!("Class URI: {}", class_uri));
                }
                if let Some(class_data) =
                    &transfer.message.packet_data.class_data
                {
                    tv.output_expert
                        .push(format!("Class data: {}", class_data));
                }
                for (idx, token_id) in
                    transfer.message.packet_data.token_ids.0.iter().enumerate()
                {
                    tv.output_expert.push(format!("Token ID: {}", token_id));
                    if let Some(token_uris) =
                        &transfer.message.packet_data.token_uris
                    {
                        tv.output_expert.push(format!(
                            "Token URI: {}",
                            token_uris.get(idx).ok_or_else(|| Error::Other(
                                "Invalid Data".to_string()
                            ))?,
                        ));
                    }
                    if let Some(token_data) =
                        &transfer.message.packet_data.token_data
                    {
                        tv.output_expert.push(format!(
                            "Token data: {}",
                            token_data.get(idx).ok_or_else(|| Error::Other(
                                "Invalid Data".to_string()
                            ))?,
                        ));
                    }
                }
                tv.output_expert.extend(vec![
                    format!("Sender : {}", transfer.message.packet_data.sender),
                    format!(
                        "Receiver : {}",
                        transfer.message.packet_data.receiver
                    ),
                ]);
                if let Some(memo) = &transfer.message.packet_data.memo {
                    if !memo.to_string().is_empty() {
                        tv.output_expert.push(format!("Memo: {}", memo));
                    }
                }
                tv.output_expert.extend(vec![
                    format!(
                        "Timeout height : {}",
                        format_timeout_height(
                            &transfer.message.timeout_height_on_b
                        )
                    ),
                    format!(
                        "Timeout timestamp : {}",
                        format_timeout_timestamp(
                            &transfer.message.timeout_timestamp_on_b
                        ),
                    ),
                ]);
                if let Some(transfer) = transfer.transfer {
                    // To facilitate lookups of MASP AssetTypes
                    let mut asset_types = HashMap::new();
                    let builder = find_masp_builder(
                        tx,
                        transfer.shielded_section_hash,
                        &mut asset_types,
                    )
                    .map_err(|_| Error::Other("Invalid Data".to_string()))?;
                    make_ledger_token_transfer_endpoints(
                        tokens,
                        &mut tv.output,
                        &transfer,
                        builder,
                        &asset_types,
                    )
                    .await?;
                    make_ledger_token_transfer_endpoints(
                        tokens,
                        &mut tv.output_expert,
                        &transfer,
                        builder,
                        &asset_types,
                    )
                    .await?;
                }
            } else {
                return Result::Err(Error::Other("Invalid Data".to_string()));
            }
        } else if code_sec.tag == Some(TX_BOND_WASM.to_string()) {
            let bond = pos::Bond::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Bond_0".to_string();

            tv.output.push("Type : Bond".to_string());
            if let Some(source) = bond.source.as_ref() {
                tv.output.push(format!("Source : {}", source));
            }
            tv.output.extend(vec![
                format!("Validator : {}", bond.validator),
                format!(
                    "Amount : NAM {}",
                    to_ledger_decimal_whitelisted_token(
                        &bond.amount.to_string_native()
                    )
                ),
            ]);

            if let Some(source) = bond.source.as_ref() {
                tv.output_expert.push(format!("Source : {}", source));
            }
            tv.output_expert.extend(vec![
                format!("Validator : {}", bond.validator),
                format!(
                    "Amount : NAM {}",
                    to_ledger_decimal_whitelisted_token(
                        &bond.amount.to_string_native()
                    )
                ),
            ]);
        } else if code_sec.tag == Some(TX_UNBOND_WASM.to_string()) {
            let unbond = pos::Unbond::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Unbond_0".to_string();

            tv.output.push("Type : Unbond".to_string());
            if let Some(source) = unbond.source.as_ref() {
                tv.output.push(format!("Source : {}", source));
            }
            tv.output.extend(vec![
                format!("Validator : {}", unbond.validator),
                format!(
                    "Amount : NAM {}",
                    to_ledger_decimal_whitelisted_token(
                        &unbond.amount.to_string_native()
                    )
                ),
            ]);

            if let Some(source) = unbond.source.as_ref() {
                tv.output_expert.push(format!("Source : {}", source));
            }
            tv.output_expert.extend(vec![
                format!("Validator : {}", unbond.validator),
                format!(
                    "Amount : NAM {}",
                    to_ledger_decimal_whitelisted_token(
                        &unbond.amount.to_string_native()
                    )
                ),
            ]);
        } else if code_sec.tag == Some(TX_WITHDRAW_WASM.to_string()) {
            let withdraw = pos::Withdraw::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Withdraw_0".to_string();

            tv.output.push("Type : Withdraw".to_string());
            if let Some(source) = withdraw.source.as_ref() {
                tv.output.push(format!("Source : {}", source));
            }
            tv.output
                .push(format!("Validator : {}", withdraw.validator));

            if let Some(source) = withdraw.source.as_ref() {
                tv.output_expert.push(format!("Source : {}", source));
            }
            tv.output_expert
                .push(format!("Validator : {}", withdraw.validator));
        } else if code_sec.tag == Some(TX_CLAIM_REWARDS_WASM.to_string()) {
            let claim = pos::Withdraw::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Claim_Rewards_0".to_string();

            tv.output.push("Type : Claim Rewards".to_string());
            if let Some(source) = claim.source.as_ref() {
                tv.output.push(format!("Source : {}", source));
            }
            tv.output.push(format!("Validator : {}", claim.validator));

            if let Some(source) = claim.source.as_ref() {
                tv.output_expert.push(format!("Source : {}", source));
            }
            tv.output_expert
                .push(format!("Validator : {}", claim.validator));
        } else if code_sec.tag == Some(TX_CHANGE_COMMISSION_WASM.to_string()) {
            let commission_change = pos::CommissionChange::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Change_Commission_0".to_string();

            tv.output.extend(vec![
                format!("Type : Change commission"),
                format!("New rate : {}", commission_change.new_rate),
                format!("Validator : {}", commission_change.validator),
            ]);

            tv.output_expert.extend(vec![
                format!("New rate : {}", commission_change.new_rate),
                format!("Validator : {}", commission_change.validator),
            ]);
        } else if code_sec.tag == Some(TX_CHANGE_METADATA_WASM.to_string()) {
            let metadata_change = pos::MetaDataChange::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Change_MetaData_0".to_string();

            tv.output.extend(vec!["Type : Change metadata".to_string()]);

            let mut other_items = vec![];
            other_items
                .push(format!("Validator : {}", metadata_change.validator));
            if let Some(name) = metadata_change.name {
                other_items.push(format!("Name : {}", name));
            }
            if let Some(email) = metadata_change.email {
                other_items.push(format!("Email : {}", email));
            }
            if let Some(description) = metadata_change.description {
                other_items.push(format!("Description : {}", description));
            }
            if let Some(website) = metadata_change.website {
                other_items.push(format!("Website : {}", website));
            }
            if let Some(discord_handle) = metadata_change.discord_handle {
                other_items
                    .push(format!("Discord handle : {}", discord_handle));
            }
            if let Some(avatar) = metadata_change.avatar {
                other_items.push(format!("Avatar : {}", avatar));
            }
            if let Some(commission_rate) = metadata_change.commission_rate {
                other_items
                    .push(format!("Commission rate : {}", commission_rate));
            }

            tv.output.extend(other_items.clone());
            tv.output_expert.extend(other_items);
        } else if code_sec.tag == Some(TX_CHANGE_CONSENSUS_KEY_WASM.to_string())
        {
            let consensus_key_change = pos::ConsensusKeyChange::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Change_Consensus_Key_0".to_string();

            tv.output.extend(vec![
                format!("Type : Change consensus key"),
                format!(
                    "New consensus key : {}",
                    consensus_key_change.consensus_key
                ),
                format!("Validator : {}", consensus_key_change.validator),
            ]);

            tv.output_expert.extend(vec![
                format!(
                    "New consensus key : {}",
                    consensus_key_change.consensus_key
                ),
                format!("Validator : {}", consensus_key_change.validator),
            ]);
        } else if code_sec.tag == Some(TX_UNJAIL_VALIDATOR_WASM.to_string()) {
            let address = Address::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Unjail_Validator_0".to_string();

            tv.output.extend(vec![
                format!("Type : Unjail Validator"),
                format!("Validator : {}", address),
            ]);

            tv.output_expert.push(format!("Validator : {}", address));
        } else if code_sec.tag == Some(TX_DEACTIVATE_VALIDATOR_WASM.to_string())
        {
            let address = Address::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Deactivate_Validator_0".to_string();

            tv.output.extend(vec![
                format!("Type : Deactivate Validator"),
                format!("Validator : {}", address),
            ]);

            tv.output_expert.push(format!("Validator : {}", address));
        } else if code_sec.tag == Some(TX_REACTIVATE_VALIDATOR_WASM.to_string())
        {
            let address = Address::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Reactivate_Validator_0".to_string();

            tv.output.extend(vec![
                format!("Type : Reactivate Validator"),
                format!("Validator : {}", address),
            ]);

            tv.output_expert.push(format!("Validator : {}", address));
        } else if code_sec.tag == Some(TX_REDELEGATE_WASM.to_string()) {
            let redelegation = pos::Redelegation::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Redelegate_0".to_string();

            tv.output.extend(vec![
                format!("Type : Redelegate"),
                format!("Source Validator : {}", redelegation.src_validator),
                format!(
                    "Destination Validator : {}",
                    redelegation.dest_validator
                ),
                format!("Owner : {}", redelegation.owner),
                format!(
                    "Amount : {}",
                    to_ledger_decimal_whitelisted_token(
                        &redelegation.amount.to_string_native()
                    )
                ),
            ]);

            tv.output_expert.extend(vec![
                format!("Source Validator : {}", redelegation.src_validator),
                format!(
                    "Destination Validator : {}",
                    redelegation.dest_validator
                ),
                format!("Owner : {}", redelegation.owner),
                format!(
                    "Amount : {}",
                    to_ledger_decimal_whitelisted_token(
                        &redelegation.amount.to_string_native()
                    )
                ),
            ]);
        } else if code_sec.tag == Some(TX_UPDATE_STEWARD_COMMISSION.to_string())
        {
            let update = UpdateStewardCommission::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Update_Steward_Commission_0".to_string();
            tv.output.extend(vec![
                format!("Type : Update Steward Commission"),
                format!("Steward : {}", update.steward),
            ]);
            for (address, dec) in update.commission.iter() {
                tv.output.push(format!("Validator : {}", address));
                tv.output.push(format!("Commission Rate : {}", dec));
            }

            tv.output_expert
                .push(format!("Steward : {}", update.steward));
            for (address, dec) in update.commission.iter() {
                tv.output_expert.push(format!("Validator : {}", address));
                tv.output_expert.push(format!("Commission Rate : {}", dec));
            }
        } else if code_sec.tag == Some(TX_RESIGN_STEWARD.to_string()) {
            let address = Address::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Resign_Steward_0".to_string();

            tv.output.extend(vec![
                format!("Type : Resign Steward"),
                format!("Steward : {}", address),
            ]);

            tv.output_expert.push(format!("Steward : {}", address));
        } else if code_sec.tag == Some(TX_BRIDGE_POOL_WASM.to_string()) {
            let transfer = PendingTransfer::try_from_slice(
                &tx.data(cmt)
                    .ok_or_else(|| Error::Other("Invalid Data".to_string()))?,
            )
            .map_err(|err| {
                Error::from(EncodingError::Conversion(err.to_string()))
            })?;

            tv.name = "Bridge_Pool_Transfer_0".to_string();

            tv.output.extend(vec![
                format!("Type : Bridge Pool Transfer"),
                format!("Transfer Kind : {}", transfer.transfer.kind),
                format!("Transfer Sender : {}", transfer.transfer.sender),
                format!("Transfer Recipient : {}", transfer.transfer.recipient),
                format!("Transfer Asset : {}", transfer.transfer.asset),
                format!("Transfer Amount : {}", transfer.transfer.amount),
                format!("Gas Payer : {}", transfer.gas_fee.payer),
                format!("Gas Token : {}", transfer.gas_fee.token),
                format!("Gas Amount : {}", transfer.gas_fee.amount),
            ]);

            tv.output_expert.extend(vec![
                format!("Transfer Kind : {}", transfer.transfer.kind),
                format!("Transfer Sender : {}", transfer.transfer.sender),
                format!("Transfer Recipient : {}", transfer.transfer.recipient),
                format!("Transfer Asset : {}", transfer.transfer.asset),
                format!("Transfer Amount : {}", transfer.transfer.amount),
                format!("Gas Payer : {}", transfer.gas_fee.payer),
                format!("Gas Token : {}", transfer.gas_fee.token),
                format!("Gas Amount : {}", transfer.gas_fee.amount),
            ]);
        } else {
            tv.name = "Custom_0".to_string();
            tv.output.push("Type : Custom".to_string());
        }

        if cmt.memo_sechash() != &namada_core::hash::Hash::default() {
            match tx
                .get_section(cmt.memo_sechash())
                .unwrap()
                .extra_data_sec()
                .unwrap()
                .code
            {
                Commitment::Hash(hash) => {
                    tv.output.push(format!(
                        "Memo Hash : {}",
                        HEXLOWER.encode(&hash.0)
                    ));
                    tv.output_expert.push(format!(
                        "Memo Hash : {}",
                        HEXLOWER.encode(&hash.0)
                    ));
                }
                Commitment::Id(id) => {
                    let memo = String::from_utf8(id).map_err(|err| {
                        Error::from(EncodingError::Conversion(err.to_string()))
                    })?;
                    if !memo.is_empty() {
                        tv.output.push(format!("Memo : {}", memo));
                        tv.output_expert.push(format!("Memo : {}", memo));
                    }
                }
            }
        }

        if let Some(wrapper) = tx.header.wrapper() {
            let fee_amount_per_gas_unit = to_ledger_decimal_variable_token(
                wrapper.fee.amount_per_gas_unit,
            );
            let fee_limit = to_ledger_decimal_variable_token(
                wrapper
                    .get_tx_fee()
                    .map_err(|e| Error::Other(format!("{}", e)))?,
            );
            tv.output_expert.extend(vec![
                format!("Chain ID : {}", tx.header.chain_id),
                format!(
                    "Timestamp : {}",
                    format_timestamp(tx.header.timestamp)
                ),
                format!("Pubkey : {}", wrapper.pk),
                format!("Gas limit : {}", u64::from(wrapper.gas_limit)),
            ]);
            if let Some(token) = tokens.get(&wrapper.fee.token) {
                tv.output.push(format!("Fee : {} {}", token, fee_limit));
                tv.output_expert.push(format!(
                    "Fees/gas unit : {} {}",
                    token, fee_amount_per_gas_unit,
                ));
            } else {
                tv.output.extend(vec![
                    format!("Fee token : {}", wrapper.fee.token),
                    format!("Fee : {}", fee_limit),
                ]);
                tv.output_expert.extend(vec![
                    format!("Fee token : {}", wrapper.fee.token),
                    format!("Fees/gas unit : {}", fee_amount_per_gas_unit),
                ]);
            }
        }
    }

    // Finally, index each line and break those that are too long
    format_outputs(&mut tv.output);
    format_outputs(&mut tv.output_expert);
    Ok(tv)
}

#[cfg(test)]
mod test_signing {
    use core::str::FromStr;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use masp_primitives::consensus::BlockHeight;
    use masp_primitives::transaction::components::sapling::builder::SaplingMetadata;
    use namada_core::address::InternalAddress;
    use namada_core::chain::ChainId;
    use namada_core::hash::Hash;
    use namada_core::ibc::PGFIbcTarget;
    use namada_core::ibc::core::host::types::identifiers::{ChannelId, PortId};
    use namada_core::masp::TxIdInner;
    use namada_core::token::{Denomination, MaspDigitPos};
    use namada_governance::storage::proposal::PGFInternalTarget;
    use namada_io::client::EncodedResponseQuery;
    use namada_tx::{Code, Data};
    use namada_wallet::test_utils::TestWalletUtils;
    use tendermint_rpc::SimpleRequest;
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
    use tokio::sync::{Mutex, RwLockReadGuard, RwLockWriteGuard};

    use super::*;
    use crate::args::InputAmount;
    use crate::masp::fs::FsShieldedUtils;
    use crate::masp::{ShieldedContext, WalletMap};
    use crate::token::Account;

    fn arbitrary_args() -> args::Tx {
        args::Tx {
            dry_run: None,
            dump_tx: None,
            output_folder: None,
            force: false,
            ledger_address: tendermint_rpc::Url::from_str(
                "http://127.0.0.1:42",
            )
            .expect("Test failed"),
            initialized_account_alias: None,
            wallet_alias_force: false,
            wrap_tx: Some(args::Wrapper {
                broadcast_only: false,
                fee_amount: None,
                wrapper_fee_payer: None,
                fee_token: Address::Internal(InternalAddress::Governance),
                gas_limit: namada_tx::data::GasLimit::from(2),
            }),
            expiration: Default::default(),
            chain_id: None,
            signing_keys: vec![],
            tx_reveal_code_path: Default::default(),
            password: Some(zeroize::Zeroizing::new("bingbong123".to_string())),
            memo: None,
            use_device: false,
            device_transport: Default::default(),
        }
    }

    pub struct TestNamadaImpl {
        wallet: RwLock<Wallet<TestWalletUtils>>,
        client: TestClient,
        io: StdIo,
    }

    impl TestNamadaImpl {
        fn new(
            paths: Option<HashSet<String>>,
        ) -> (Self, UnboundedSender<Option<EncodedResponseQuery>>) {
            let (send, recv) = tokio::sync::mpsc::unbounded_channel();
            (
                Self {
                    wallet: RwLock::new(Wallet::new(
                        TestWalletUtils,
                        Default::default(),
                    )),
                    client: TestClient {
                        channel: Arc::new(Mutex::new(recv)),
                        paths: paths.unwrap_or_default(),
                    },
                    io: StdIo,
                },
                send,
            )
        }
    }
    pub struct TestClient {
        channel: Arc<Mutex<UnboundedReceiver<Option<EncodedResponseQuery>>>>,
        paths: HashSet<String>,
    }

    #[cfg_attr(feature = "async-send", async_trait::async_trait)]
    #[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
    impl Client for TestClient {
        type Error = std::io::Error;

        async fn request(
            &self,
            path: String,
            _: Option<Vec<u8>>,
            _: Option<namada_core::chain::BlockHeight>,
            _: bool,
        ) -> Result<EncodedResponseQuery, Self::Error> {
            if !self.paths.contains(&path) {
                return Err(std::io::Error::other("oh noes"));
            }
            match self.channel.lock().await.recv().await {
                Some(Some(resp)) => Ok(resp),
                _ => Err(std::io::Error::other("oh noes")),
            }
        }

        async fn perform<R>(
            &self,
            _: R,
        ) -> Result<R::Output, tendermint_rpc::Error>
        where
            R: SimpleRequest,
        {
            unimplemented!()
        }
    }

    impl NamadaIo for TestNamadaImpl {
        type Client = TestClient;
        type Io = StdIo;

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
    impl Namada for TestNamadaImpl {
        type ShieldedUtils = FsShieldedUtils;
        type WalletUtils = TestWalletUtils;

        async fn wallet_mut(
            &self,
        ) -> RwLockWriteGuard<'_, Wallet<Self::WalletUtils>> {
            self.wallet.write().await
        }

        async fn wallet(
            &self,
        ) -> RwLockReadGuard<'_, Wallet<Self::WalletUtils>> {
            self.wallet.read().await
        }

        fn wallet_lock(&self) -> &RwLock<Wallet<Self::WalletUtils>> {
            &self.wallet
        }

        async fn shielded(
            &self,
        ) -> RwLockReadGuard<'_, ShieldedContext<Self::ShieldedUtils>> {
            unimplemented!()
        }

        async fn shielded_mut(
            &self,
        ) -> RwLockWriteGuard<'_, ShieldedContext<Self::ShieldedUtils>>
        {
            unimplemented!()
        }

        fn native_token(&self) -> Address {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn test_find_pk_failure() {
        let (context, _) = TestNamadaImpl::new(None);
        let secret_key = common::SecretKey::Ed25519(testing::gen_keypair::<
            ed25519::SigScheme,
        >());
        let public_key = secret_key.to_public();
        let addr = Address::Implicit(ImplicitAddress::from(&public_key));

        let Error::Other(msg) =
            find_pk(&context, &addr).await.expect_err("Test failed")
        else {
            panic!("Test failed")
        };

        assert_eq!(
            msg,
            format!(
                "Unable to load the keypair from the wallet for the implicit \
                 address {}. Failed with: No key matching {} found",
                addr.encode(),
                PublicKeyHash::from(&public_key),
            ),
        );

        let addr = Address::Internal(InternalAddress::Governance);
        let Error::Other(msg) =
            find_pk(&context, &addr).await.expect_err("Test failed")
        else {
            panic!("Test failed")
        };
        assert_eq!(
            msg,
            format!("Internal address {} doesn't have any signing keys.", addr)
        );
    }

    #[test]
    fn test_find_key_by_pk_failure() {
        let mut wallet =
            Wallet::<TestWalletUtils>::new(TestWalletUtils, Default::default());
        let args = arbitrary_args();
        let secret_key = common::SecretKey::Ed25519(testing::gen_keypair::<
            ed25519::SigScheme,
        >());
        let public_key = secret_key.to_public();
        find_key_by_pk(&mut wallet, &args, &public_key)
            .expect_err("Test failed");
    }

    /// Test the unhappy flows in trying to validate
    /// the fee token and amounts, both with and without
    /// the force argument set.
    #[tokio::test]
    async fn test_validate_fee() {
        let (context, client_handle) =
            TestNamadaImpl::new(Some(HashSet::from([format!(
                "/shell/value/{}",
                parameter_storage::get_gas_cost_key()
            )])));
        let mut args = arbitrary_args();

        // we should fail to validate the fee due to an unresponsive client
        client_handle.send(None).expect("Test failed");
        let Error::Query(crate::error::QueryError::NoResponse(msg)) =
            validate_fee(&context, args.wrap_tx.as_ref().unwrap(), args.force)
                .await
                .expect_err("Test failed")
        else {
            panic!("Test failed");
        };
        assert_eq!(msg, "oh noes");

        // enabling force should return a default fee even though the
        // client is unresponsive
        client_handle.send(None).expect("Test failed");
        args.force = true;
        let fee =
            validate_fee(&context, args.wrap_tx.as_ref().unwrap(), args.force)
                .await
                .expect("Test failed");
        assert_eq!(fee, DenominatedAmount::new(Amount::zero(), 0.into()));
        let args::Wrapper {
            broadcast_only,
            wrapper_fee_payer,
            fee_token,
            gas_limit,
            ..
        } = args.wrap_tx.as_ref().unwrap().to_owned();

        // now validation should the minimum fee from the client instead of
        // the args as force is false
        args.force = false;
        client_handle
            .send(Some(EncodedResponseQuery {
                data: BTreeMap::from([(fee_token.clone(), Amount::from(100))])
                    .serialize_to_vec(),
                info: "".to_string(),
                proof: None,
                height: Default::default(),
            }))
            .expect("Test failed");
        args.wrap_tx = Some(args::Wrapper {
            broadcast_only,
            wrapper_fee_payer,
            fee_token,
            gas_limit,
            fee_amount: Some(InputAmount::Validated(DenominatedAmount::new(
                Amount::from_u64(1),
                0.into(),
            ))),
        });
        let fee =
            validate_fee(&context, args.wrap_tx.as_ref().unwrap(), args.force)
                .await
                .expect("Test failed");
        assert_eq!(fee, DenominatedAmount::new(Amount::from(100), 0.into()));

        // now validation should ignore the minimum fee from the client
        // as force is true
        args.force = true;
        let args::Wrapper {
            broadcast_only,
            wrapper_fee_payer,
            fee_token,
            gas_limit,
            ..
        } = args.wrap_tx.as_ref().unwrap().to_owned();
        client_handle
            .send(Some(EncodedResponseQuery {
                data: BTreeMap::from([(fee_token.clone(), Amount::from(100))])
                    .serialize_to_vec(),
                info: "".to_string(),
                proof: None,
                height: Default::default(),
            }))
            .expect("Test failed");
        args.wrap_tx = Some(args::Wrapper {
            broadcast_only,
            wrapper_fee_payer,
            fee_token,
            gas_limit,
            fee_amount: Some(InputAmount::Validated(DenominatedAmount::new(
                Amount::from_u64(1),
                0.into(),
            ))),
        });
        let fee = validate_fee(&context, &args.wrap_tx.unwrap(), args.force)
            .await
            .expect("Test failed");
        assert_eq!(fee, DenominatedAmount::new(Amount::from(1), 0.into()));
    }

    /// Test that we correctly catch when a fee payer does not have
    /// enough balahce to pay the minimum fees.
    #[tokio::test]
    async fn test_insufficient_funds_for_fee() {
        let args = arbitrary_args();
        // the minimum fee is set above the fee in the args.
        let (context, client_handle) =
            TestNamadaImpl::new(Some(HashSet::from([format!(
                "/shell/value/{}",
                parameter_storage::get_gas_cost_key()
            )])));
        client_handle
            .send(Some(EncodedResponseQuery {
                data: BTreeMap::from([(
                    args.wrap_tx.as_ref().unwrap().fee_token.clone(),
                    Amount::from(100),
                )])
                .serialize_to_vec(),
                info: "".to_string(),
                proof: None,
                height: Default::default(),
            }))
            .expect("Test failed");
        let secret_key = common::SecretKey::Ed25519(testing::gen_keypair::<
            ed25519::SigScheme,
        >());
        let public_key = secret_key.to_public();

        assert_matches!(
            validate_transparent_fee(
                &context,
                &args.wrap_tx.unwrap(),
                args.force,
                &public_key
            )
            .await,
            Err(Error::Tx(TxSubmitError::BalanceTooLowForFees(_, _, _, _)))
        );
    }

    /// Test that if the signing callback (usually the hardward wallet)
    /// fails to sign the inner transaction (but fees are signed), the function
    /// returns an error for not meeting the threshold of required signatures.
    #[tokio::test]
    async fn test_sign_tx_hw_failure() {
        let wallet =
            Wallet::<TestWalletUtils>::new(TestWalletUtils, Default::default());
        let args = arbitrary_args();
        let secret_key = common::SecretKey::Ed25519(testing::gen_keypair::<
            ed25519::SigScheme,
        >());
        let public_key = secret_key.to_public();
        let secret_key_fee =
            common::SecretKey::Ed25519(testing::gen_keypair::<
                ed25519::SigScheme,
            >());
        let public_key_fee = secret_key_fee.to_public();
        let mut tx = Tx::new(ChainId::default(), None);
        let signing_data = SigningWrapperData {
            signing_data: vec![SigningTxData {
                owner: None,
                public_keys: [public_key.clone()].into(),
                threshold: 1,
                account_public_keys_map: Some(Default::default()),
                shielded_hash: None,
                signatures: vec![],
            }],
            fee_auth: FeeAuthorization::Signer {
                pubkey: public_key_fee.clone(),
                disposable_fee_payer: false,
            },
        };

        let Error::Tx(TxSubmitError::MissingSigningKeys(1, 0)) = sign_tx(
            &RwLock::new(wallet),
            &args,
            &mut tx,
            SigningData::Wrapper(signing_data),
            |tx, pk, _, _| {
                let pkf = public_key_fee.clone();
                async move {
                    if pk == pkf.clone() {
                        Ok(tx)
                    } else {
                        Err(Error::Other(
                            "Uh oh, hardware wallet is borked".to_string(),
                        ))
                    }
                }
            },
            (),
        )
        .await
        .expect_err("Test failed") else {
            panic!("Test failed");
        };

        // This should now work
        let wallet =
            Wallet::<TestWalletUtils>::new(TestWalletUtils, Default::default());
        let signing_data = SigningWrapperData {
            signing_data: vec![SigningTxData {
                owner: None,
                public_keys: [public_key.clone()].into(),
                threshold: 1,
                account_public_keys_map: Some(Default::default()),
                shielded_hash: None,
                signatures: vec![],
            }],
            fee_auth: FeeAuthorization::Signer {
                pubkey: public_key.clone(),
                disposable_fee_payer: false,
            },
        };
        sign_tx(
            &RwLock::new(wallet),
            &args,
            &mut tx,
            SigningData::Wrapper(signing_data),
            |tx, _, _, _| async { Ok(tx) },
            (),
        )
        .await
        .expect("Test failed");
    }

    #[tokio::test]
    async fn test_make_transfer_endpoints() {
        let tf = token::Transfer {
            sources: BTreeMap::from([(
                Account {
                    owner: Address::Internal(InternalAddress::Governance),
                    token: Address::Internal(InternalAddress::Governance),
                },
                DenominatedAmount::new(Amount::from_u64(1), 0.into()),
            )]),
            targets: BTreeMap::from([(
                Account {
                    owner: Address::Internal(InternalAddress::Pgf),
                    token: Address::Internal(InternalAddress::Pgf),
                },
                DenominatedAmount::new(Amount::from_u64(2), 0.into()),
            )]),
            shielded_section_hash: None,
        };
        let tokens = HashMap::from([
            (Address::Internal(InternalAddress::Governance), "SuperMoney"),
            (Address::Internal(InternalAddress::Pgf), "BloodMoney"),
        ]);

        let mut output = vec![];
        // test with token aliases
        make_ledger_token_transfer_endpoints(
            &tokens,
            &mut output,
            &tf,
            None,
            &Default::default(),
        )
        .await
        .expect("Test failed");
        let expected = vec![
            format!(
                "Sender : {}",
                Address::Internal(InternalAddress::Governance)
            ),
            "Sending Amount : SuperMoney 1".to_string(),
            format!(
                "Destination : {}",
                Address::Internal(InternalAddress::Pgf)
            ),
            "Receiving Amount : BloodMoney 2".to_string(),
        ];
        assert_eq!(output, expected);
        output.clear();

        // test without token aliases
        make_ledger_token_transfer_endpoints(
            &Default::default(),
            &mut output,
            &tf,
            None,
            &Default::default(),
        )
        .await
        .expect("Test failed");
        let expected = vec![
            format!(
                "Sender : {}",
                Address::Internal(InternalAddress::Governance)
            ),
            format!(
                "Sending Token : {}",
                Address::Internal(InternalAddress::Governance)
            ),
            "Sending Amount : 1".to_string(),
            format!(
                "Destination : {}",
                Address::Internal(InternalAddress::Pgf)
            ),
            format!(
                "Receiving Token : {}",
                Address::Internal(InternalAddress::Pgf)
            ),
            "Receiving Amount : 2".to_string(),
        ];
        assert_eq!(output, expected);
    }

    /// Test the `to_ledger_vector` function correctly
    /// extracts and validates the presence of a code section
    #[tokio::test]
    async fn test_to_ledger_vector_code_sections() {
        let wallet = HashMap::new();
        let mut tx = Tx::new(ChainId::default(), None);
        // an empty tx should work correctly
        to_ledger_vector(&wallet, &tx).await.expect("Test failed");

        tx.push_default_inner_tx();
        // should fail due to missing code section
        let Error::Other(msg) = to_ledger_vector(&wallet, &tx)
            .await
            .expect_err("Test failed")
        else {
            panic!("Test failed")
        };
        assert_eq!(msg, "expected tx code section to be present".to_string());
        tx.add_code(vec![1u8, 1, 1, 1], None);

        // this tx should work correctly
        to_ledger_vector(&wallet, &tx).await.expect("Test failed");

        // making the commitment point to the wrong section type
        // should cause the tx to fail
        {
            let mut tx_malformed = tx.clone();
            let cmts = std::mem::take(&mut tx_malformed.header.batch);
            let mut cmt = cmts.first().expect("Test failed").clone();
            for section in tx_malformed.sections.iter_mut() {
                if section.get_hash() == cmt.code_hash {
                    *section = Section::Data(Data::new(vec![1u8; 4]));
                    cmt.code_hash = section.get_hash();
                }
            }
            tx_malformed.header.batch = HashSet::from([cmt]);

            let Error::Other(msg) = to_ledger_vector(&wallet, &tx_malformed)
                .await
                .expect_err("Test failed")
            else {
                panic!("Test failed")
            };
            assert_eq!(msg, "expected section to have code tag")
        }
        // since the code for each possible tag is invalid, these should all
        // fail
        for tag in [
            TX_INIT_ACCOUNT_WASM,
            TX_BECOME_VALIDATOR_WASM,
            TX_UNJAIL_VALIDATOR_WASM,
            TX_DEACTIVATE_VALIDATOR_WASM,
            TX_REACTIVATE_VALIDATOR_WASM,
            TX_REDELEGATE_WASM,
            TX_UPDATE_STEWARD_COMMISSION,
            TX_RESIGN_STEWARD,
            TX_BRIDGE_POOL_WASM,
        ] {
            let mut tx_malformed = tx.clone();
            let cmts = std::mem::take(&mut tx_malformed.header.batch);
            let mut cmt = cmts.first().expect("Test failed").clone();
            for section in tx_malformed.sections.iter_mut() {
                if section.get_hash() == cmt.code_hash {
                    if let Section::Code(data) = section {
                        data.tag = Some(tag.to_string());
                        cmt.code_hash = section.get_hash();
                    }
                }
            }
            tx_malformed.header.batch = HashSet::from([cmt]);
            let Error::Other(msg) = to_ledger_vector(&wallet, &tx_malformed)
                .await
                .expect_err("Test failed")
            else {
                panic!("Test failed")
            };
            assert_eq!(msg, "Invalid Data");
        }
    }

    /// Test the `find_masp_builder` function that extracts
    /// the masp builder and populates the asset data map.
    #[test]
    fn test_find_masp_builder() {
        let mut tx = Tx::new(ChainId::default(), None);
        let mut asset_types = Default::default();
        let shielded_section_hash = MaspTxId::from(TxIdInner::from_bytes([
            0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        // no masp builder present
        assert_eq!(
            find_masp_builder(
                &tx,
                Some(shielded_section_hash),
                &mut asset_types
            )
            .expect("Test failed"),
            None
        );
        assert!(asset_types.is_empty());

        let assets = HashSet::from([
            AssetData {
                token: Address::Internal(InternalAddress::Governance),
                denom: Denomination(1),
                position: MaspDigitPos::Zero,
                epoch: None,
            },
            AssetData {
                token: Address::Internal(InternalAddress::ReplayProtection),
                denom: Denomination(2),
                position: MaspDigitPos::One,
                epoch: None,
            },
        ]);
        let masp_builder = MaspBuilder {
            target: MaspTxId::from(TxIdInner::from_bytes([
                0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ])),
            asset_types: assets.clone(),
            metadata: SaplingMetadata::empty(),
            builder: masp_primitives::transaction::builder::Builder::new(
                masp_primitives::consensus::TestNetwork,
                BlockHeight::from_u32(1),
            )
            .map_builder(WalletMap),
        };
        tx.add_masp_builder(masp_builder);

        // we pass in no shield section hash
        assert_eq!(
            find_masp_builder(&tx, None, &mut asset_types)
                .expect("Test failed"),
            None
        );
        assert!(asset_types.is_empty());

        // we pass in a non-matching section hash
        assert_eq!(
            find_masp_builder(
                &tx,
                Some(MaspTxId::from(TxIdInner::from_bytes([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]))),
                &mut asset_types
            )
            .expect("Test failed"),
            None
        );
        assert!(asset_types.is_empty());

        // now we should find the builder
        find_masp_builder(&tx, Some(shielded_section_hash), &mut asset_types)
            .expect("Test failed")
            .expect("Test failed");
        assert_eq!(
            asset_types
                .values()
                .cloned()
                .collect::<HashSet<AssetData>>(),
            assets,
        );
    }

    /// Test that we strip decimal zeros and possibly
    /// the decimal point before displaying on Ledger device
    #[test]
    fn test_to_ledger_decimal() {
        assert_eq!(
            to_ledger_decimal_whitelisted_token("1.2"),
            "1.2".to_string(),
        );

        assert_eq!(to_ledger_decimal_whitelisted_token("10"), "10".to_string(),);

        assert_eq!(
            to_ledger_decimal_whitelisted_token("10.10"),
            "10.1".to_string(),
        );

        assert_eq!(
            to_ledger_decimal_whitelisted_token("2.000"),
            "2".to_string(),
        );

        assert_eq!(to_ledger_decimal_whitelisted_token("2."), "2".to_string(),)
    }

    /// Test the validation of the `proposal_type_to_ledger_vector` function.
    #[test]
    fn test_proposal_type_to_ledger_vector() {
        let mut tx = Tx::new(ChainId::default(), None);
        let mut output = vec![];
        // default proposal should always pass
        proposal_type_to_ledger_vector(
            &ProposalType::Default,
            &tx,
            &mut output,
        )
        .expect("Test failed");
        assert_eq!(output, vec!["Proposal type : Default".to_string()]);
        output.clear();

        // we should fail as the section hashes does not exist in the tx
        let Error::Other(msg) = proposal_type_to_ledger_vector(
            &ProposalType::DefaultWithWasm(Hash::default()),
            &tx,
            &mut output,
        )
        .expect_err("Test failed") else {
            panic!("Test failed")
        };
        assert_eq!(msg, "unable to load vp code");
        assert_eq!(output, vec!["Proposal type : Default".to_string()]);
        output.clear();

        // this should fail as the section hash points to the wrong kind of
        // section
        let wrong_sec_hash = tx
            .add_section(Section::Code(Code::new(vec![1u8; 4], None)))
            .get_hash();
        let Error::Other(msg) = proposal_type_to_ledger_vector(
            &ProposalType::DefaultWithWasm(wrong_sec_hash),
            &tx,
            &mut output,
        )
        .expect_err("Test failed") else {
            panic!("Test failed")
        };
        assert_eq!(msg, "unable to load vp code");
        assert_eq!(output, vec!["Proposal type : Default".to_string()]);
        output.clear();

        // this should succeed
        let sec_hash = tx
            .add_section(Section::ExtraData(Code::new(vec![1u8; 4], None)))
            .get_hash();
        proposal_type_to_ledger_vector(
            &ProposalType::DefaultWithWasm(sec_hash),
            &tx,
            &mut output,
        )
        .expect("Test failed");
        let hash =
            HEXLOWER.encode(&Code::new(vec![1u8; 4], None).code.hash().0);
        assert_eq!(
            output,
            vec![
                "Proposal type : Default".to_string(),
                format!("Proposal hash : {hash}",)
            ]
        );
        output.clear();

        // The actions should be sorted
        let addr = Address::Internal(InternalAddress::Governance);
        proposal_type_to_ledger_vector(
            &ProposalType::PGFSteward(BTreeSet::from([
                AddRemove::Remove(addr.clone()),
                AddRemove::Add(addr.clone()),
            ])),
            &tx,
            &mut output,
        )
        .expect("Test failed");
        assert_eq!(
            output,
            vec![
                "Proposal type : PGF Steward".to_string(),
                format!("Add : {addr}"),
                format!("Remove : {addr}"),
            ]
        );
        output.clear();

        // PGF payments
        proposal_type_to_ledger_vector(
            &ProposalType::PGFPayment(BTreeSet::from([PGFAction::Continuous(
                AddRemove::Add(PGFTarget::Internal(PGFInternalTarget {
                    target: addr.clone(),
                    amount: Amount::zero(),
                })),
            )])),
            &tx,
            &mut output,
        )
        .expect("Test failed");
        assert_eq!(
            output,
            vec![
                "Proposal type : PGF Payment".to_string(),
                "PGF Action : Add Continuous Payment".to_string(),
                format!("Target: {addr}"),
                "Amount: NAM 0".to_string(),
            ],
        );
        output.clear();
        proposal_type_to_ledger_vector(
            &ProposalType::PGFPayment(BTreeSet::from([PGFAction::Continuous(
                AddRemove::Remove(PGFTarget::Internal(PGFInternalTarget {
                    target: addr.clone(),
                    amount: Amount::zero(),
                })),
            )])),
            &tx,
            &mut output,
        )
        .expect("Test failed");
        assert_eq!(
            output,
            vec![
                "Proposal type : PGF Payment".to_string(),
                "PGF Action : Remove Continuous Payment".to_string(),
                format!("Target: {addr}"),
                "Amount: NAM 0".to_string(),
            ],
        );
        output.clear();

        proposal_type_to_ledger_vector(
            &ProposalType::PGFPayment(BTreeSet::from([PGFAction::Retro(
                PGFTarget::Internal(PGFInternalTarget {
                    target: addr.clone(),
                    amount: Amount::zero(),
                }),
            )])),
            &tx,
            &mut output,
        )
        .expect("Test failed");
        assert_eq!(
            output,
            vec![
                "Proposal type : PGF Payment".to_string(),
                "PGF Action : Retro Payment".to_string(),
                format!("Target: {addr}"),
                "Amount: NAM 0".to_string(),
            ],
        );
        output.clear();

        proposal_type_to_ledger_vector(
            &ProposalType::PGFPayment(BTreeSet::from([PGFAction::Continuous(
                AddRemove::Add(PGFTarget::Ibc(PGFIbcTarget {
                    target: "bloop".to_string(),
                    amount: Default::default(),
                    port_id: PortId::transfer(),
                    channel_id: ChannelId::new(16),
                })),
            )])),
            &tx,
            &mut output,
        )
        .expect("Test failed");
        assert_eq!(
            output,
            vec![
                "Proposal type : PGF Payment".to_string(),
                "PGF Action : Add Continuous Payment".to_string(),
                "Target: bloop".to_string(),
                "Amount: NAM 0".to_string(),
                "Port ID: transfer".to_string(),
                "Channel ID: channel-16".to_string(),
            ],
        );
        output.clear();

        proposal_type_to_ledger_vector(
            &ProposalType::PGFPayment(BTreeSet::from([PGFAction::Continuous(
                AddRemove::Remove(PGFTarget::Ibc(PGFIbcTarget {
                    target: "bloop".to_string(),
                    amount: Default::default(),
                    port_id: PortId::transfer(),
                    channel_id: ChannelId::new(16),
                })),
            )])),
            &tx,
            &mut output,
        )
        .expect("Test failed");
        assert_eq!(
            output,
            vec![
                "Proposal type : PGF Payment".to_string(),
                "PGF Action : Remove Continuous Payment".to_string(),
                "Target: bloop".to_string(),
                "Amount: NAM 0".to_string(),
                "Port ID: transfer".to_string(),
                "Channel ID: channel-16".to_string(),
            ],
        );
        output.clear();

        proposal_type_to_ledger_vector(
            &ProposalType::PGFPayment(BTreeSet::from([PGFAction::Retro(
                PGFTarget::Ibc(PGFIbcTarget {
                    target: "bloop".to_string(),
                    amount: Default::default(),
                    port_id: PortId::transfer(),
                    channel_id: ChannelId::new(16),
                }),
            )])),
            &tx,
            &mut output,
        )
        .expect("Test failed");
        assert_eq!(
            output,
            vec![
                "Proposal type : PGF Payment".to_string(),
                "PGF Action : Retro Payment".to_string(),
                "Target: bloop".to_string(),
                "Amount: NAM 0".to_string(),
                "Port ID: transfer".to_string(),
                "Channel ID: channel-16".to_string(),
            ],
        );
        output.clear();
    }
}
