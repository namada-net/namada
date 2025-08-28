//! MASP verification wrappers.
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
pub mod bridge_tree;
mod shielded_sync;
pub mod shielded_wallet;
#[cfg(test)]
mod test_utils;
mod wallet_migrations;

use std::collections::BTreeMap;
use std::fmt::{self, Debug};

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::asset_type::AssetType;
#[cfg(feature = "mainnet")]
use masp_primitives::consensus::MainNetwork as Network;
#[cfg(not(feature = "mainnet"))]
use masp_primitives::consensus::TestNetwork as Network;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::merkle_tree::{IncrementalWitness, MerklePath};
use masp_primitives::sapling::keys::FullViewingKey;
use masp_primitives::sapling::{Diversifier, Node, ViewingKey};
use masp_primitives::transaction::Transaction;
use masp_primitives::transaction::builder::{self, *};
use masp_primitives::transaction::components::sapling::builder::SaplingMetadata;
use masp_primitives::transaction::components::{I128Sum, ValueSum};
use masp_primitives::zip32::{
    ExtendedFullViewingKey, ExtendedKey,
    ExtendedSpendingKey as MaspExtendedSpendingKey, PseudoExtendedKey,
};
use masp_proofs::prover::LocalTxProver;
use namada_core::address::Address;
use namada_core::collections::{HashMap, HashSet};
use namada_core::dec::Dec;
use namada_core::masp::*;
use namada_core::token;
use namada_core::token::Denomination;
use namada_core::uint::Uint;
use namada_io::{MaybeSend, MaybeSync};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use rand_core::{CryptoRng, RngCore};
pub use shielded_wallet::{NotePosition, ShieldedWallet};
use thiserror::Error;

use self::utils::MaspIndexedTx;
#[cfg(not(target_family = "wasm"))]
pub use crate::masp::shielded_sync::MaspLocalTaskEnv;
pub use crate::masp::shielded_sync::dispatcher::{Dispatcher, DispatcherCache};
pub use crate::masp::shielded_sync::{
    ShieldedSyncConfig, ShieldedSyncConfigBuilder, utils,
};
pub use crate::masp::wallet_migrations::{VersionedWallet, VersionedWalletRef};
pub use crate::validation::{
    CONVERT_NAME, ENV_VAR_MASP_PARAMS_DIR, OUTPUT_NAME, PVKs, SPEND_NAME,
    partial_deauthorize, preload_verifying_keys,
};

/// Randomness seed for MASP integration tests to build proofs with
/// deterministic rng.
pub const ENV_VAR_MASP_TEST_SEED: &str = "NAMADA_MASP_TEST_SEED";

/// The network to use for MASP
pub const NETWORK: Network = Network;

/// Shielded transfer
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer)]
pub struct ShieldedTransfer {
    /// Shielded transfer builder
    pub builder: Builder<(), ExtendedFullViewingKey, ()>,
    /// MASP transaction
    pub masp_tx: Transaction,
    /// Metadata
    pub metadata: SaplingMetadata,
    /// Epoch in which the transaction was created
    pub epoch: MaspEpoch,
}

/// The data for a masp fee payment
#[allow(missing_docs)]
#[derive(Debug)]
pub struct MaspFeeData {
    pub source: PseudoExtendedKey,
    pub target: Address,
    pub token: Address,
    pub amount: token::DenominatedAmount,
}

/// The data for a single masp transfer
#[allow(missing_docs)]
#[derive(Debug, Default)]
pub struct MaspTransferData {
    pub sources: Vec<(TransferSource, Address, token::DenominatedAmount)>,
    pub targets: Vec<(TransferTarget, Address, token::DenominatedAmount)>,
}

/// Data to log the error of a single masp transaction
#[derive(Debug)]
pub struct MaspDataLogEntry {
    /// Token to be spent.
    pub token: Address,
    /// How many tokens are missing.
    pub shortfall: token::DenominatedAmount,
}

impl fmt::Display for MaspDataLogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { token, shortfall } = self;
        write!(f, "{shortfall} {token} missing")
    }
}

/// Data to log the error of a batch of masp transactions
#[derive(Debug)]
pub struct MaspDataLog {
    /// The error batch
    pub batch: Vec<MaspDataLogEntry>,
}

impl From<Vec<MaspDataLogEntry>> for MaspDataLog {
    #[inline]
    fn from(batch: Vec<MaspDataLogEntry>) -> Self {
        Self { batch }
    }
}

impl fmt::Display for MaspDataLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { batch } = self;

        if let Some(err) = batch.first() {
            write!(f, "{err}")?;
        } else {
            return Ok(());
        }

        for err in &batch[1..] {
            write!(f, ", {err}")?;
        }

        Ok(())
    }
}

/// Represents the data used to construct a MASP Transfer
pub struct MaspTxCombinedData {
    /// Sources of assets going into the transfer
    source_data: HashMap<TransferSource, ValueSum<Address, token::Amount>>,
    /// Destinations of assets going out of the transfer
    target_data: HashMap<TransferTarget, ValueSum<Address, token::Amount>>,
    /// The denominations of the various tokens used in the transfer
    denoms: HashMap<Address, Denomination>,
}

/// Shielded pool data for a token
#[allow(missing_docs)]
#[derive(Debug, BorshSerialize, BorshDeserialize, BorshDeserializer)]
pub struct MaspTokenRewardData {
    pub name: String,
    pub address: Address,
    pub max_reward_rate: Dec,
    pub kp_gain: Dec,
    pub kd_gain: Dec,
    pub locked_amount_target: Uint,
}

/// A return type for gen_shielded_transfer
#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug)]
pub enum TransferErr {
    /// Build error for masp errors
    #[error("Transaction builder error: {error}")]
    Build {
        /// Builder error returned from the masp library
        error: builder::Error<std::convert::Infallible>,
    },
    /// Insufficient funds error
    #[error("Insufficient funds: {0}")]
    InsufficientFunds(MaspDataLog),
    /// Generic error
    #[error("{0}")]
    General(String),
}

/// Freeze a Builder into the format necessary for inclusion in a Tx. This is
/// the format used by hardware wallets to validate a MASP Transaction.
pub struct WalletMap;

impl<P1>
    masp_primitives::transaction::components::sapling::builder::MapBuilder<
        P1,
        PseudoExtendedKey,
        (),
        ExtendedFullViewingKey,
    > for WalletMap
{
    fn map_params(&self, _s: P1) {}

    fn map_key(&self, s: PseudoExtendedKey) -> ExtendedFullViewingKey {
        s.to_viewing_key()
    }
}

impl<P1, N1>
    MapBuilder<P1, PseudoExtendedKey, N1, (), ExtendedFullViewingKey, ()>
    for WalletMap
{
    fn map_notifier(&self, _s: N1) {}
}

/// Abstracts platform specific details away from the logic of shielded pool
/// operations.
#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
pub trait ShieldedUtils:
    Sized + BorshDeserialize + BorshSerialize + Default + Clone
{
    /// Get a MASP transaction prover
    fn local_tx_prover(&self) -> LocalTxProver;

    /// Load up the currently saved ShieldedContext
    async fn load<U: ShieldedUtils + MaybeSend>(
        &self,
        ctx: &mut ShieldedWallet<U>,
        force_confirmed: bool,
    ) -> std::io::Result<()>;

    /// Save the given ShieldedContext for future loads
    async fn save<'a, U: ShieldedUtils + MaybeSync>(
        &'a self,
        ctx: VersionedWalletRef<'a, U>,
        sync_status: ContextSyncStatus,
    ) -> std::io::Result<()>;

    /// Save a cache of data as part of shielded sync if that
    /// process gets interrupted.
    async fn cache_save(&self, _cache: &DispatcherCache)
    -> std::io::Result<()>;

    /// Load a cache of data as part of shielded sync if that
    /// process gets interrupted.
    async fn cache_load(&self) -> std::io::Result<DispatcherCache>;
}

/// Make a ViewingKey that can view notes encrypted by given ExtendedSpendingKey
pub fn to_viewing_key(esk: &MaspExtendedSpendingKey) -> FullViewingKey {
    ExtendedFullViewingKey::from(esk).fvk
}

/// Generate a valid diversifier, i.e. one that has a diversified base. Return
/// also this diversified base.
pub fn find_valid_diversifier<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (Diversifier, masp_primitives::jubjub::SubgroupPoint) {
    let mut diversifier;
    let g_d;
    // Keep generating random diversifiers until one has a diversified base
    loop {
        let mut d = [0; 11];
        rng.fill_bytes(&mut d);
        diversifier = Diversifier(d);
        if let Some(val) = diversifier.g_d() {
            g_d = val;
            break;
        }
    }
    (diversifier, g_d)
}

/// a masp change
#[derive(BorshSerialize, BorshDeserialize, BorshDeserializer, Debug, Clone)]
pub struct MaspChange {
    /// the token address
    pub asset: Address,
    /// the change in the token
    pub change: token::Change,
}

/// a masp amount
pub type MaspAmount = ValueSum<(Option<MaspEpoch>, Address), token::Change>;

/// A type tracking the notes used to construct a shielded transfer. Used to
/// avoid reusing the same notes multiple times which would lead to an invalid
/// transaction
pub type SpentNotesTracker = HashMap<ViewingKey, HashSet<NotePosition>>;

/// Represents the amount used of different conversions
pub type Conversions =
    BTreeMap<AssetType, (AllowedConversion, MerklePath<Node>)>;

/// Represents the changes that were made to a list of transparent accounts
pub type TransferDelta = HashMap<Address, MaspChange>;

/// Represents the changes that were made to a list of shielded accounts
pub type TransactionDelta = HashMap<ViewingKey, I128Sum>;

/// Maps a shielded tx to the index of its first output note.
pub type NoteIndex = BTreeMap<MaspIndexedTx, NotePosition>;

/// Maps the note index (in the commitment tree) to a witness
pub type WitnessMap = HashMap<NotePosition, IncrementalWitness<Node>>;

#[derive(Copy, Clone, BorshSerialize, BorshDeserialize, Debug, Default)]
/// The possible sync states of the shielded context
pub enum ContextSyncStatus {
    /// The context contains data that has been confirmed by the protocol
    #[default]
    Confirmed,
    /// The context possibly contains data that has not yet been confirmed by
    /// the protocol and could be incomplete or invalid
    Speculative,
}

#[cfg(test)]
mod tests {
    use masp_primitives::ff::Field;
    use masp_proofs::bls12_381::Bls12;

    use super::*;

    /// quick and dirty test. will fail on size check
    #[test]
    #[should_panic(expected = "parameter file size is not correct")]
    fn test_wrong_masp_params() {
        use std::io::Write;

        let tempdir = tempfile::tempdir()
            .expect("expected a temp dir")
            .into_path();
        let fake_params_paths =
            [SPEND_NAME, OUTPUT_NAME, CONVERT_NAME].map(|p| tempdir.join(p));
        for path in &fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            f.write_all(b"fake params")
                .expect("expected a writable temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        unsafe {
            std::env::set_var(ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str())
        };
        // should panic here
        masp_proofs::load_parameters(
            &fake_params_paths[0],
            &fake_params_paths[1],
            &fake_params_paths[2],
        );
    }

    /// a more involved test, using dummy parameters with the right
    /// size but the wrong hash.
    #[test]
    #[should_panic(expected = "parameter file is not correct")]
    fn test_wrong_masp_params_hash() {
        use masp_primitives::ff::PrimeField;
        use masp_proofs::bellman::groth16::{
            Parameters, generate_random_parameters,
        };
        use masp_proofs::bellman::{Circuit, ConstraintSystem, SynthesisError};
        use masp_proofs::bls12_381::Scalar;

        struct FakeCircuit<E: PrimeField> {
            x: E,
        }

        impl<E: PrimeField> Circuit<E> for FakeCircuit<E> {
            fn synthesize<CS: ConstraintSystem<E>>(
                self,
                cs: &mut CS,
            ) -> Result<(), SynthesisError> {
                let x = cs.alloc(|| "x", || Ok(self.x)).unwrap();
                cs.enforce(
                    || {
                        "this is an extra long constraint name so that rustfmt \
                         is ok with wrapping the params of enforce()"
                    },
                    |lc| lc + x,
                    |lc| lc + x,
                    |lc| lc + x,
                );
                Ok(())
            }
        }

        let dummy_circuit = FakeCircuit { x: Scalar::ZERO };
        let mut rng = rand::thread_rng();
        let fake_params: Parameters<Bls12> =
            generate_random_parameters(dummy_circuit, &mut rng)
                .expect("expected to generate fake params");

        let tempdir = tempfile::tempdir()
            .expect("expected a temp dir")
            .into_path();
        // TODO: get masp to export these consts
        let fake_params_paths = [
            (SPEND_NAME, 49848572u64),
            (OUTPUT_NAME, 16398620u64),
            (CONVERT_NAME, 22570940u64),
        ]
        .map(|(p, s)| (tempdir.join(p), s));
        for (path, size) in &fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            fake_params
                .write(&mut f)
                .expect("expected a writable temp file");
            // the dummy circuit has one constraint, and therefore its
            // params should always be smaller than the large masp
            // circuit params. so this truncate extends the file, and
            // extra bytes at the end do not make it invalid.
            f.set_len(*size)
                .expect("expected to truncate the temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        unsafe {
            std::env::set_var(ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str())
        };
        // should panic here
        masp_proofs::load_parameters(
            &fake_params_paths[0].0,
            &fake_params_paths[1].0,
            &fake_params_paths[2].0,
        );
    }
}

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for transactions
pub mod testing {
    use std::ops::AddAssign;
    use std::sync::Mutex;

    use masp_primitives::consensus::BranchId;
    use masp_primitives::consensus::testing::arb_height;
    use masp_primitives::constants::{
        spending_key_generator, value_commitment_randomness_generator,
    };
    use masp_primitives::ff::PrimeField;
    use masp_primitives::group::GroupEncoding;
    use masp_primitives::group::prime::PrimeCurveAffine;
    use masp_primitives::jubjub;
    use masp_primitives::keys::OutgoingViewingKey;
    use masp_primitives::memo::MemoBytes;
    use masp_primitives::sapling::note_encryption::{
        PreparedIncomingViewingKey, try_sapling_note_decryption,
    };
    use masp_primitives::sapling::prover::TxProver;
    use masp_primitives::sapling::redjubjub::{
        PrivateKey, PublicKey, Signature,
    };
    use masp_primitives::sapling::{Note, ProofGenerationKey, Rseed};
    use masp_primitives::transaction::components::sapling::builder::RngBuildParams;
    use masp_primitives::transaction::components::transparent::testing::arb_transparent_address;
    use masp_primitives::transaction::components::{
        GROTH_PROOF_SIZE, OutputDescription, TxOut, U64Sum,
    };
    use masp_primitives::transaction::fees::fixed::FeeRule;
    use masp_primitives::transaction::{
        Authorization, Authorized, TransparentAddress,
    };
    use masp_proofs::bellman::groth16::Proof;
    use masp_proofs::bls12_381;
    use masp_proofs::bls12_381::{Bls12, G1Affine, G2Affine};
    use namada_core::address::testing::arb_address;
    use namada_core::token::MaspDigitPos;
    use namada_core::token::testing::arb_denomination;
    use proptest::prelude::*;
    use proptest::test_runner::TestRng;
    use proptest::{collection, option, prop_compose};

    use super::*;

    /// This function computes `value` in the exponent of the value commitment
    /// base
    fn masp_compute_value_balance(
        asset_type: AssetType,
        value: i128,
    ) -> Option<jubjub::ExtendedPoint> {
        // Compute the absolute value (failing if -i128::MAX is
        // the value)
        let abs = match value.checked_abs() {
            Some(a) => a as u128,
            None => return None,
        };

        // Is it negative? We'll have to negate later if so.
        let is_negative = value.is_negative();

        // Compute it in the exponent
        let mut abs_bytes = [0u8; 32];
        abs_bytes[0..16].copy_from_slice(&abs.to_le_bytes());
        let mut value_balance = asset_type.value_commitment_generator()
            * jubjub::Fr::from_bytes(&abs_bytes).unwrap();

        // Negate if necessary
        if is_negative {
            value_balance = -value_balance;
        }

        // Convert to unknown order point
        Some(value_balance.into())
    }

    /// A context object for creating the Sapling components of a Zcash
    /// transaction.
    pub struct SaplingProvingContext {
        bsk: jubjub::Fr,
        // (sum of the Spend value commitments) - (sum of the Output value
        // commitments)
        cv_sum: jubjub::ExtendedPoint,
    }

    /// An implementation of TxProver that does everything except generating
    /// valid zero-knowledge proofs. Uses the supplied source of randomness to
    /// carry out its operations.
    pub struct MockTxProver<R: RngCore>(pub Mutex<R>);

    impl<R: RngCore> TxProver for MockTxProver<R> {
        type SaplingProvingContext = SaplingProvingContext;

        fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext {
            SaplingProvingContext {
                bsk: jubjub::Fr::zero(),
                cv_sum: jubjub::ExtendedPoint::identity(),
            }
        }

        fn spend_proof(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            proof_generation_key: ProofGenerationKey,
            _diversifier: Diversifier,
            _rseed: Rseed,
            ar: jubjub::Fr,
            asset_type: AssetType,
            value: u64,
            _anchor: bls12_381::Scalar,
            _merkle_path: MerklePath<Node>,
            rcv: jubjub::Fr,
        ) -> Result<
            ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey),
            (),
        > {
            // Accumulate the value commitment randomness in the context
            {
                let mut tmp = rcv;
                tmp.add_assign(&ctx.bsk);

                // Update the context
                ctx.bsk = tmp;
            }

            // Construct the value commitment
            let value_commitment = asset_type.value_commitment(value, rcv);

            // This is the result of the re-randomization, we compute it for the
            // caller
            let rk = PublicKey(proof_generation_key.ak.into())
                .randomize(ar, spending_key_generator());

            // Compute value commitment
            let value_commitment: jubjub::ExtendedPoint =
                value_commitment.commitment().into();

            // Accumulate the value commitment in the context
            ctx.cv_sum += value_commitment;

            let mut zkproof = [0u8; GROTH_PROOF_SIZE];
            let proof = Proof::<Bls12> {
                a: G1Affine::generator(),
                b: G2Affine::generator(),
                c: G1Affine::generator(),
            };
            proof
                .write(&mut zkproof[..])
                .expect("should be able to serialize a proof");
            Ok((zkproof, value_commitment, rk))
        }

        fn output_proof(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            _esk: jubjub::Fr,
            _payment_address: masp_primitives::sapling::PaymentAddress,
            _rcm: jubjub::Fr,
            asset_type: AssetType,
            value: u64,
            rcv: jubjub::Fr,
        ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint) {
            // Accumulate the value commitment randomness in the context
            {
                let mut tmp = rcv.neg(); // Outputs subtract from the total.
                tmp.add_assign(&ctx.bsk);

                // Update the context
                ctx.bsk = tmp;
            }

            // Construct the value commitment for the proof instance
            let value_commitment = asset_type.value_commitment(value, rcv);

            // Compute the actual value commitment
            let value_commitment_point: jubjub::ExtendedPoint =
                value_commitment.commitment().into();

            // Accumulate the value commitment in the context. We do this to
            // check internal consistency.
            ctx.cv_sum -= value_commitment_point; // Outputs subtract from the total.

            let mut zkproof = [0u8; GROTH_PROOF_SIZE];
            let proof = Proof::<Bls12> {
                a: G1Affine::generator(),
                b: G2Affine::generator(),
                c: G1Affine::generator(),
            };
            proof
                .write(&mut zkproof[..])
                .expect("should be able to serialize a proof");

            (zkproof, value_commitment_point)
        }

        fn convert_proof(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            allowed_conversion: AllowedConversion,
            value: u64,
            _anchor: bls12_381::Scalar,
            _merkle_path: MerklePath<Node>,
            rcv: jubjub::Fr,
        ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint), ()>
        {
            // Accumulate the value commitment randomness in the context
            {
                let mut tmp = rcv;
                tmp.add_assign(&ctx.bsk);

                // Update the context
                ctx.bsk = tmp;
            }

            // Construct the value commitment
            let value_commitment =
                allowed_conversion.value_commitment(value, rcv);

            // Compute value commitment
            let value_commitment: jubjub::ExtendedPoint =
                value_commitment.commitment().into();

            // Accumulate the value commitment in the context
            ctx.cv_sum += value_commitment;

            let mut zkproof = [0u8; GROTH_PROOF_SIZE];
            let proof = Proof::<Bls12> {
                a: G1Affine::generator(),
                b: G2Affine::generator(),
                c: G1Affine::generator(),
            };
            proof
                .write(&mut zkproof[..])
                .expect("should be able to serialize a proof");

            Ok((zkproof, value_commitment))
        }

        fn binding_sig(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            assets_and_values: &I128Sum,
            sighash: &[u8; 32],
        ) -> Result<Signature, ()> {
            // Initialize secure RNG
            let mut rng = self.0.lock().unwrap();

            // Grab the current `bsk` from the context
            let bsk = PrivateKey(ctx.bsk);

            // Grab the `bvk` using DerivePublic.
            let bvk = PublicKey::from_private(
                &bsk,
                value_commitment_randomness_generator(),
            );

            // In order to check internal consistency, let's use the accumulated
            // value commitments (as the verifier would) and apply
            // value_balance to compare against our derived bvk.
            {
                let final_bvk = assets_and_values
                    .components()
                    .map(|(asset_type, value_balance)| {
                        // Compute value balance for each asset
                        // Error for bad value balances (-INT128_MAX value)
                        masp_compute_value_balance(*asset_type, *value_balance)
                    })
                    .try_fold(ctx.cv_sum, |tmp, value_balance| {
                        // Compute cv_sum minus sum of all value balances
                        Result::<_, ()>::Ok(tmp - value_balance.ok_or(())?)
                    })?;

                // The result should be the same, unless the provided
                // valueBalance is wrong.
                if bvk.0 != final_bvk {
                    return Err(());
                }
            }

            // Construct signature message
            let mut data_to_be_signed = [0u8; 64];
            data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
            data_to_be_signed[32..64].copy_from_slice(&sighash[..]);

            // Sign
            Ok(bsk.sign(
                &data_to_be_signed,
                &mut *rng,
                value_commitment_randomness_generator(),
            ))
        }
    }

    #[derive(Debug, Clone)]
    /// Adapts a CSPRNG from a PRNG for proptesting
    pub struct TestCsprng<R: RngCore>(pub R);

    impl<R: RngCore> CryptoRng for TestCsprng<R> {}

    impl<R: RngCore> RngCore for TestCsprng<R> {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }

        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), rand::Error> {
            self.0.try_fill_bytes(dest)
        }
    }

    prop_compose! {
        /// Expose a random number generator
        pub fn arb_rng()(rng in Just(()).prop_perturb(|(), rng| rng)) -> TestRng {
            rng
        }
    }

    prop_compose! {
        /// Generate an arbitrary output description with the given value
        pub fn arb_output_description(
            asset_type: AssetType,
            value: u64,
        )(
            mut rng in arb_rng().prop_map(TestCsprng),
        ) -> (Option<OutgoingViewingKey>, masp_primitives::sapling::PaymentAddress, AssetType, u64, MemoBytes) {
            let mut spending_key_seed = [0; 32];
            rng.fill_bytes(&mut spending_key_seed);
            let spending_key = MaspExtendedSpendingKey::master(spending_key_seed.as_ref());

            let viewing_key = ExtendedFullViewingKey::from(&spending_key).fvk.vk;
            let (div, _g_d) = find_valid_diversifier(&mut rng);
            let payment_addr = viewing_key
                .to_payment_address(div)
                .expect("a PaymentAddress");

            (None, payment_addr, asset_type, value, MemoBytes::empty())
        }
    }

    prop_compose! {
        /// Generate an arbitrary spend description with the given value
        pub fn arb_spend_description(
            asset_type: AssetType,
            value: u64,
        )(
            address in arb_transparent_address(),
            expiration_height in arb_height(BranchId::MASP, &Network),
            mut rng in arb_rng().prop_map(TestCsprng),
            bparams_rng in arb_rng().prop_map(TestCsprng),
            prover_rng in arb_rng().prop_map(TestCsprng),
        ) -> (PseudoExtendedKey, Diversifier, Note, Node) {
            let mut spending_key_seed = [0; 32];
            rng.fill_bytes(&mut spending_key_seed);
            let spending_key = MaspExtendedSpendingKey::master(spending_key_seed.as_ref());

            let viewing_key = ExtendedFullViewingKey::from(&spending_key).fvk.vk;
            let (div, _g_d) = find_valid_diversifier(&mut rng);
            let payment_addr = viewing_key
                .to_payment_address(div)
                .expect("a PaymentAddress");

            let mut builder = Builder::<Network, PseudoExtendedKey>::new(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
            );
            // Add a transparent input to support our desired shielded output
            builder.add_transparent_input(TxOut { asset_type, value, address }).unwrap();
            // Finally add the shielded output that we need
            builder.add_sapling_output(None, payment_addr, asset_type, value, MemoBytes::empty()).unwrap();
            // Build a transaction in order to get its shielded outputs
            let (transaction, metadata) = builder.build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut RngBuildParams::new(bparams_rng),
            ).unwrap();
            // Extract the shielded output from the transaction
            let shielded_output = &transaction
                .sapling_bundle()
                .unwrap()
                .shielded_outputs[metadata.output_index(0).unwrap()];

            // Let's now decrypt the constructed notes
            let (note, pa, _memo) = try_sapling_note_decryption::<_, OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>>(
                &NETWORK,
                1.into(),
                &PreparedIncomingViewingKey::new(&viewing_key.ivk()),
                shielded_output,
            ).unwrap();
            assert_eq!(payment_addr, pa);
            // Make a path to out new note
            let node = Node::new(shielded_output.cmu.to_repr());
            (PseudoExtendedKey::from(spending_key), div, note, node)
        }
    }

    prop_compose! {
        /// Generate an arbitrary MASP denomination
        pub fn arb_masp_digit_pos()(denom in 0..4u8) -> MaspDigitPos {
            MaspDigitPos::try_from(denom).unwrap()
        }
    }

    prop_compose! {
        /// Arbitrarily partition the given vector of integers into sets and sum
        /// them
        pub fn arb_partition(values: Vec<u64>)(buckets in usize::from(!values.is_empty())..=values.len())(
            values in Just(values.clone()),
            assigns in collection::vec(0..buckets, values.len()),
            buckets in Just(buckets),
        ) -> Vec<u64> {
            let mut buckets = vec![0; buckets];
            for (bucket, value) in assigns.iter().zip(values) {
                buckets[*bucket] += value;
            }
            buckets
        }
    }

    prop_compose! {
        /// Generate arbitrary spend descriptions with the given asset type
        /// partitioning the given values
        pub fn arb_spend_descriptions(
            asset: AssetData,
            values: Vec<u64>,
        )(partition in arb_partition(values))(
            spend_description in partition
                .iter()
                .map(|value| arb_spend_description(
                    encode_asset_type(
                        asset.token.clone(),
                        asset.denom,
                        asset.position,
                        asset.epoch,
                    ).unwrap(),
                    *value,
                )).collect::<Vec<_>>()
        ) -> Vec<(PseudoExtendedKey, Diversifier, Note, Node)> {
            spend_description
        }
    }

    prop_compose! {
        /// Generate arbitrary output descriptions with the given asset type
        /// partitioning the given values
        pub fn arb_output_descriptions(
            asset: AssetData,
            values: Vec<u64>,
        )(partition in arb_partition(values))(
            output_description in partition
                .iter()
                .map(|value| arb_output_description(
                    encode_asset_type(
                        asset.token.clone(),
                        asset.denom,
                        asset.position,
                        asset.epoch,
                    ).unwrap(),
                    *value,
                )).collect::<Vec<_>>()
        ) -> Vec<(Option<OutgoingViewingKey>, masp_primitives::sapling::PaymentAddress, AssetType, u64, MemoBytes)> {
            output_description
        }
    }

    prop_compose! {
        /// Generate arbitrary spend descriptions with the given asset type
        /// partitioning the given values
        pub fn arb_txouts(
            asset: AssetData,
            values: Vec<u64>,
            address: TransparentAddress,
        )(
            partition in arb_partition(values),
        ) -> Vec<TxOut> {
            partition
                .iter()
                .map(|value| TxOut {
                    asset_type: encode_asset_type(
                        asset.token.clone(),
                        asset.denom,
                        asset.position,
                        asset.epoch,
                    ).unwrap(),
                    value: *value,
                    address,
                }).collect::<Vec<_>>()
        }
    }

    prop_compose! {
        /// Generate an arbitrary masp epoch
        pub fn arb_masp_epoch()(epoch: u64) -> MaspEpoch{
            MaspEpoch::new(epoch)
        }
    }

    prop_compose! {
        /// Generate an arbitrary pre-asset type
        pub fn arb_pre_asset_type()(
            token in arb_address(),
            denom in arb_denomination(),
            position in arb_masp_digit_pos(),
            epoch in option::of(arb_masp_epoch()),
        ) -> AssetData {
            AssetData {
                token,
                denom,
                position,
                epoch,
            }
        }
    }
}

#[cfg(feature = "std")]
/// Implementation of MASP functionality depending on a standard filesystem
pub mod fs {
    use std::env;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::path::PathBuf;

    use super::*;
    use crate::masp::wallet_migrations::{VersionedWallet, v0};
    use crate::validation::{
        CONVERT_NAME, ENV_VAR_MASP_PARAMS_DIR, OUTPUT_NAME, SPEND_NAME,
        get_params_dir,
    };

    /// Shielded context file name
    const FILE_NAME: &str = "shielded.dat";
    const TMP_FILE_PREFIX: &str = "shielded.tmp";
    const SPECULATIVE_FILE_NAME: &str = "speculative_shielded.dat";
    const SPECULATIVE_TMP_FILE_PREFIX: &str = "speculative_shielded.tmp";
    const CACHE_FILE_NAME: &str = "shielded_sync.cache";
    const CACHE_FILE_TMP_PREFIX: &str = "shielded_sync.cache.tmp";

    #[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
    /// An implementation of ShieldedUtils for standard filesystems
    pub struct FsShieldedUtils {
        #[borsh(skip)]
        pub(crate) context_dir: PathBuf,
    }

    impl FsShieldedUtils {
        /// Initialize a shielded transaction context that identifies notes
        /// decryptable by any viewing key in the given set
        pub fn new(context_dir: PathBuf) -> ShieldedWallet<Self> {
            // Make sure that MASP parameters are downloaded to enable MASP
            // transaction building and verification later on
            let params_dir = get_params_dir();
            let spend_path = params_dir.join(SPEND_NAME);
            let convert_path = params_dir.join(CONVERT_NAME);
            let output_path = params_dir.join(OUTPUT_NAME);
            if !(spend_path.exists()
                && convert_path.exists()
                && output_path.exists())
            {
                #[allow(clippy::print_stdout)]
                {
                    println!("MASP parameters not present, downloading...");
                }
                masp_proofs::download_masp_parameters(None)
                    .expect("MASP parameters not present or downloadable");
                #[allow(clippy::print_stdout)]
                {
                    println!(
                        "MASP parameter download complete, resuming \
                         execution..."
                    );
                }
            }
            // Finally initialize a shielded context with the supplied directory

            let sync_status =
                if std::fs::read(context_dir.join(SPECULATIVE_FILE_NAME))
                    .is_ok()
                {
                    // Load speculative state
                    ContextSyncStatus::Speculative
                } else {
                    ContextSyncStatus::Confirmed
                };

            let utils = Self { context_dir };
            ShieldedWallet {
                utils,
                sync_status,
                ..Default::default()
            }
        }

        /// Write to a file ensuring that all contents of the file
        /// were written by a single process (in case of multiple
        /// concurrent write attempts).
        ///
        /// N.B. This is not the same as a file lock. If multiple
        /// concurrent writes take place, this code ensures that
        /// the result of exactly one will be persisted.
        ///
        /// N.B. This only truly works if each process uses
        /// to a *unique* tmp file name.
        fn atomic_file_write(
            &self,
            tmp_file_name: impl AsRef<std::path::Path>,
            file_name: impl AsRef<std::path::Path>,
            data: impl BorshSerialize,
        ) -> std::io::Result<()> {
            let tmp_path = self.context_dir.join(&tmp_file_name);
            {
                // First serialize the shielded context into a temporary file.
                // Inability to create this file implies a simultaneuous write
                // is in progress. In this case, immediately
                // fail. This is unproblematic because the data
                // intended to be stored can always be re-fetched
                // from the blockchain.
                let mut ctx_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(tmp_path.clone())?;
                let mut bytes = Vec::new();
                data.serialize(&mut bytes).unwrap_or_else(|e| {
                    panic!(
                        "cannot serialize data to {} with error: {}",
                        file_name.as_ref().to_string_lossy(),
                        e,
                    )
                });
                ctx_file.write_all(&bytes[..])?;
            }
            // Atomically update the old shielded context file with new data.
            // Atomicity is required to prevent other client instances from
            // reading corrupt data.
            std::fs::rename(tmp_path, self.context_dir.join(file_name))
        }
    }

    impl Default for FsShieldedUtils {
        fn default() -> Self {
            Self {
                context_dir: PathBuf::from(FILE_NAME),
            }
        }
    }

    #[cfg_attr(feature = "async-send", async_trait::async_trait)]
    #[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
    impl ShieldedUtils for FsShieldedUtils {
        fn local_tx_prover(&self) -> LocalTxProver {
            if let Ok(params_dir) = env::var(ENV_VAR_MASP_PARAMS_DIR) {
                let params_dir = PathBuf::from(params_dir);
                let spend_path = params_dir.join(SPEND_NAME);
                let convert_path = params_dir.join(CONVERT_NAME);
                let output_path = params_dir.join(OUTPUT_NAME);
                LocalTxProver::new(&spend_path, &output_path, &convert_path)
            } else {
                LocalTxProver::with_default_location()
                    .expect("unable to load MASP Parameters")
            }
        }

        /// Try to load the last saved shielded context from the given context
        /// directory. If this fails, then leave the current context unchanged.
        async fn load<U: ShieldedUtils + MaybeSend>(
            &self,
            ctx: &mut ShieldedWallet<U>,
            force_confirmed: bool,
        ) -> std::io::Result<()> {
            // Try to load shielded context from file
            let file_name = if force_confirmed {
                FILE_NAME
            } else {
                match ctx.sync_status {
                    ContextSyncStatus::Confirmed => FILE_NAME,
                    ContextSyncStatus::Speculative => SPECULATIVE_FILE_NAME,
                }
            };
            let mut ctx_file =
                match File::open(self.context_dir.join(file_name)) {
                    Ok(file) => file,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        // a missing file means there is nothing to load.
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                };
            let mut bytes = Vec::new();
            ctx_file.read_to_end(&mut bytes)?;
            // Fill the supplied context with the deserialized object
            let wallet =
                match VersionedWallet::<U>::deserialize(&mut &bytes[..]) {
                    Ok(w) => w,
                    Err(_) => VersionedWallet::V0(
                        v0::ShieldedWallet::<U>::deserialize(&mut &bytes[..])?,
                    ),
                }
                .migrate()
                .map_err(std::io::Error::other)?;
            *ctx = ShieldedWallet {
                utils: ctx.utils.clone(),
                ..wallet
            };
            Ok(())
        }

        /// Save this confirmed shielded context into its associated context
        /// directory. At the same time, delete the speculative file if present
        async fn save<'a, U: ShieldedUtils + MaybeSync>(
            &'a self,
            ctx: VersionedWalletRef<'a, U>,
            sync_status: ContextSyncStatus,
        ) -> std::io::Result<()> {
            let (tmp_file_pref, file_name) = match sync_status {
                ContextSyncStatus::Confirmed => (TMP_FILE_PREFIX, FILE_NAME),
                ContextSyncStatus::Speculative => {
                    (SPECULATIVE_TMP_FILE_PREFIX, SPECULATIVE_FILE_NAME)
                }
            };
            let tmp_file_name = {
                let t = tempfile::Builder::new()
                    .prefix(tmp_file_pref)
                    .tempfile()?;
                t.path().file_name().unwrap().to_owned()
            };
            self.atomic_file_write(tmp_file_name, file_name, ctx)?;

            // Remove the speculative file if present since it's state is
            // overruled by the confirmed one we just saved
            if let ContextSyncStatus::Confirmed = sync_status {
                let _ = std::fs::remove_file(
                    self.context_dir.join(SPECULATIVE_FILE_NAME),
                );
            }

            Ok(())
        }

        async fn cache_save(
            &self,
            cache: &DispatcherCache,
        ) -> std::io::Result<()> {
            let tmp_file_name = {
                let t = tempfile::Builder::new()
                    .prefix(CACHE_FILE_TMP_PREFIX)
                    .tempfile()?;
                t.path().file_name().unwrap().to_owned()
            };

            self.atomic_file_write(tmp_file_name, CACHE_FILE_NAME, cache)
        }

        async fn cache_load(&self) -> std::io::Result<DispatcherCache> {
            let file_name = self.context_dir.join(CACHE_FILE_NAME);
            let mut file = File::open(file_name)?;
            DispatcherCache::try_from_reader(&mut file)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Test that trying to load a missing file does not
        /// change the context
        #[tokio::test]
        async fn test_missing_file_no_op() {
            let utils = FsShieldedUtils {
                context_dir: PathBuf::from("does/not/exist"),
            };
            assert!(!utils.context_dir.exists());
            let mut shielded = ShieldedWallet {
                utils,
                ..Default::default()
            };
            assert!(
                shielded
                    .utils
                    .clone()
                    .load(&mut shielded, false)
                    .await
                    .is_ok()
            );
        }

        /// Test that if the backing file isn't versioned but contains V0 data,
        /// we can still successfully load it.
        #[tokio::test]
        async fn test_non_versioned_file() {
            let temp = tempfile::tempdir().expect("Test failed");
            let utils = FsShieldedUtils {
                context_dir: temp.path().to_path_buf(),
            };

            let mut shielded = ShieldedWallet {
                utils: utils.clone(),
                ..Default::default()
            };

            let serialized = {
                let mut bytes: Vec<u8> = Vec::new();
                let shielded = v0::ShieldedWallet {
                    utils,
                    spents: HashSet::from([42]),
                    ..Default::default()
                };
                BorshSerialize::serialize(&shielded, &mut bytes)
                    .expect("Test failed");
                bytes
            };

            std::fs::write(temp.path().join(FILE_NAME), &serialized)
                .expect("Test failed");
            shielded
                .utils
                .clone()
                .load(&mut shielded, true)
                .await
                .expect("Test failed");
            assert_eq!(shielded.spents, HashSet::from([NotePosition(42)]));
        }

        #[tokio::test]
        async fn test_happy_flow() {
            let temp = tempfile::tempdir().expect("Test failed");
            let utils = FsShieldedUtils {
                context_dir: temp.path().to_path_buf(),
            };

            let mut shielded = ShieldedWallet {
                utils: utils.clone(),
                ..Default::default()
            };

            let serialized = {
                let mut bytes: Vec<u8> = Vec::new();
                let shielded = ShieldedWallet {
                    utils,
                    spents: HashSet::from([NotePosition(42)]),
                    ..Default::default()
                };
                BorshSerialize::serialize(
                    &VersionedWalletRef::V2(&shielded),
                    &mut bytes,
                )
                .expect("Test failed");
                bytes
            };

            std::fs::write(temp.path().join(FILE_NAME), &serialized)
                .expect("Test failed");
            shielded
                .utils
                .clone()
                .load(&mut shielded, true)
                .await
                .expect("Test failed");
            assert_eq!(shielded.spents, HashSet::from([NotePosition(42)]));
        }

        /// Check that we error out if the file cannot be loaded and migrated
        #[tokio::test]
        async fn test_load_fail() {
            let temp = tempfile::tempdir().expect("Test failed");
            let utils = FsShieldedUtils {
                context_dir: temp.path().to_path_buf(),
            };

            let mut shielded = ShieldedWallet {
                utils: utils.clone(),
                ..Default::default()
            };

            let serialized = {
                let mut bytes: Vec<u8> = Vec::new();
                let shielded = "bloopity bloop doop doop";
                BorshSerialize::serialize(&shielded, &mut bytes)
                    .expect("Test failed");
                bytes
            };

            std::fs::write(temp.path().join(FILE_NAME), &serialized)
                .expect("Test failed");
            assert!(
                shielded
                    .utils
                    .clone()
                    .load(&mut shielded, true)
                    .await
                    .is_err()
            );
        }
    }
}
