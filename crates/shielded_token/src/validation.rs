//! MASP verification wrappers.

use std::env;
use std::ops::Deref;
use std::path::PathBuf;

use lazy_static::lazy_static;
use masp_primitives::bls12_381::Bls12;
use masp_primitives::transaction::components::TxOut;
use masp_primitives::transaction::components::sapling::{
    Authorized as SaplingAuthorized, Bundle as SaplingBundle,
};
use masp_primitives::transaction::components::transparent::builder::TransparentBuilder;
use masp_primitives::transaction::sighash::{SignableInput, signature_hash};
use masp_primitives::transaction::txid::TxIdDigester;
use masp_primitives::transaction::{
    Authorization, Authorized, Transaction, TransactionData, Unauthorized,
};
use masp_primitives::zip32::ExtendedSpendingKey;
use masp_proofs::bellman::groth16::VerifyingKey;
use masp_proofs::sapling::BatchValidator;
use namada_gas::Gas;
use rand_core::OsRng;
use smooth_operator::checked;

use crate::{Error, Result};

// TODO these could be exported from masp_proof crate
/// Spend circuit name
pub const SPEND_NAME: &str = "masp-spend.params";
/// Output circuit name
pub const OUTPUT_NAME: &str = "masp-output.params";
/// Convert circuit name
pub const CONVERT_NAME: &str = "masp-convert.params";

/// Env var to point to a dir with MASP parameters. When not specified,
/// the default OS specific path is used.
pub const ENV_VAR_MASP_PARAMS_DIR: &str = "NAMADA_MASP_PARAMS_DIR";

/// Get the path to MASP parameters from [`ENV_VAR_MASP_PARAMS_DIR`] env var or
/// use the default.
pub fn get_params_dir() -> PathBuf {
    if let Ok(params_dir) = env::var(ENV_VAR_MASP_PARAMS_DIR) {
        #[allow(clippy::print_stdout)]
        {
            println!("Using {} as masp parameter folder.", params_dir);
        }
        PathBuf::from(params_dir)
    } else {
        masp_proofs::default_params_folder().unwrap()
    }
}

/// Represents an authorization where the Sapling bundle is authorized and the
/// transparent bundle is unauthorized.
pub struct PartialAuthorized;

impl Authorization for PartialAuthorized {
    type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
    type TransparentAuth =
        <Unauthorized<ExtendedSpendingKey> as Authorization>::TransparentAuth;
}

/// MASP verifying keys
pub struct PVKs {
    /// spend verifying key
    pub spend_vk: VerifyingKey<Bls12>,
    /// convert verifying key
    pub convert_vk: VerifyingKey<Bls12>,
    /// output verifying key
    pub output_vk: VerifyingKey<Bls12>,
}

lazy_static! {
    /// MASP verifying keys load from parameters
    static ref VERIFIYING_KEYS: PVKs =
        {
        let params_dir = get_params_dir();
        let [spend_path, convert_path, output_path] =
            [SPEND_NAME, CONVERT_NAME, OUTPUT_NAME].map(|p| params_dir.join(p));

        #[cfg(feature = "download-params")]
        if !spend_path.exists() || !convert_path.exists() || !output_path.exists() {
            let paths = masp_proofs::download_masp_parameters(None).expect(
                "MASP parameters were not present, expected the download to \
                succeed",
            );
            if paths.spend != spend_path
                || paths.convert != convert_path
                || paths.output != output_path
            {
                panic!(
                    "unrecoverable: downloaded missing masp params, but to an \
                    unfamiliar path"
                )
            }
        }
        // size and blake2b checked here
        let params = masp_proofs::load_parameters(
            spend_path.as_path(),
            output_path.as_path(),
            convert_path.as_path(),
        );
        PVKs {
            spend_vk: params.spend_params.vk,
            convert_vk: params.convert_params.vk,
            output_vk: params.output_params.vk
        }
    };
}

/// Make sure the MASP params are present and load verifying keys into memory
pub fn preload_verifying_keys() -> &'static PVKs {
    &VERIFIYING_KEYS
}

fn load_pvks() -> &'static PVKs {
    &VERIFIYING_KEYS
}

/// Verify a shielded transaction.
pub fn verify_shielded_tx<F>(
    transaction: &Transaction,
    consume_verify_gas: F,
) -> Result<()>
where
    F: Fn(Gas) -> Result<()>,
{
    tracing::debug!("entered verify_shielded_tx()");

    let sapling_bundle = if let Some(bundle) = transaction.sapling_bundle() {
        bundle
    } else {
        return Err(Error::new_const("no sapling bundle"));
    };
    let tx_data = transaction.deref();

    // Partially deauthorize the transparent bundle
    let unauth_tx_data = match partial_deauthorize(tx_data) {
        Some(tx_data) => tx_data,
        None => {
            return Err(Error::new_const("Failed to partially de-authorize"));
        }
    };

    let txid_parts = unauth_tx_data.digest(TxIdDigester);
    // the commitment being signed is shared across all Sapling inputs; once
    // V4 transactions are deprecated this should just be the txid, but
    // for now we need to continue to compute it here.
    let sighash =
        signature_hash(&unauth_tx_data, &SignableInput::Shielded, &txid_parts);
    tracing::debug!("sighash computed");

    let PVKs {
        spend_vk,
        convert_vk,
        output_vk,
    } = load_pvks();

    #[cfg(not(feature = "testing"))]
    let mut ctx = BatchValidator::new();
    #[cfg(feature = "testing")]
    let mut ctx = testing::MockBatchValidator::default();

    // Charge gas before check bundle
    charge_masp_check_bundle_gas(sapling_bundle, &consume_verify_gas)?;

    if !ctx.check_bundle(sapling_bundle.to_owned(), sighash.as_ref().to_owned())
    {
        tracing::debug!("failed check bundle");
        return Err(Error::new_const("Invalid sapling bundle"));
    }
    tracing::debug!("passed check bundle");

    // Charge gas before final validation
    charge_masp_validate_gas(sapling_bundle, consume_verify_gas)?;
    if !ctx.validate(spend_vk, convert_vk, output_vk, OsRng) {
        return Err(Error::new_const("Invalid proofs or signatures"));
    }
    Ok(())
}

/// Partially deauthorize the transparent bundle
pub fn partial_deauthorize(
    tx_data: &TransactionData<Authorized>,
) -> Option<TransactionData<PartialAuthorized>> {
    let transp = tx_data.transparent_bundle().and_then(|x| {
        let mut tb = TransparentBuilder::empty();
        for vin in &x.vin {
            tb.add_input(TxOut {
                asset_type: vin.asset_type,
                value: vin.value,
                address: vin.address,
            })
            .ok()?;
        }
        for vout in &x.vout {
            tb.add_output(&vout.address, vout.asset_type, vout.value)
                .ok()?;
        }
        tb.build()
    });
    if tx_data.transparent_bundle().is_some() != transp.is_some() {
        return None;
    }
    Some(TransactionData::from_parts(
        tx_data.version(),
        tx_data.consensus_branch_id(),
        tx_data.lock_time(),
        tx_data.expiry_height(),
        transp,
        tx_data.sapling_bundle().cloned(),
    ))
}

// Charge gas for the final validation, taking advtange of concurrency for
// proofs verification but not for signatures
fn charge_masp_validate_gas<F>(
    sapling_bundle: &SaplingBundle<SaplingAuthorized>,
    consume_verify_gas: F,
) -> Result<()>
where
    F: Fn(Gas) -> Result<()>,
{
    // Signatures gas
    consume_verify_gas(
        checked!(
            // Add one for the binding signature
            ((sapling_bundle.shielded_spends.len() as u64) + 1)
                * namada_gas::MASP_VERIFY_SIG_GAS
        )?
        .into(),
    )?;

    // If at least one note is present charge the fixed costs. Then charge the
    // variable cost for every other note, amortized on the fixed expected
    // number of cores
    if let Some(remaining_notes) =
        sapling_bundle.shielded_spends.len().checked_sub(1)
    {
        consume_verify_gas(namada_gas::MASP_FIXED_SPEND_GAS.into())?;
        consume_verify_gas(
            checked!(
                namada_gas::MASP_VARIABLE_SPEND_GAS * remaining_notes as u64
            )?
            .into(),
        )?;
    }

    if let Some(remaining_notes) =
        sapling_bundle.shielded_converts.len().checked_sub(1)
    {
        consume_verify_gas(namada_gas::MASP_FIXED_CONVERT_GAS.into())?;
        consume_verify_gas(
            checked!(
                namada_gas::MASP_VARIABLE_CONVERT_GAS * remaining_notes as u64
            )?
            .into(),
        )?;
    }

    if let Some(remaining_notes) =
        sapling_bundle.shielded_outputs.len().checked_sub(1)
    {
        consume_verify_gas(namada_gas::MASP_FIXED_OUTPUT_GAS.into())?;
        consume_verify_gas(
            checked!(
                namada_gas::MASP_VARIABLE_OUTPUT_GAS * remaining_notes as u64
            )?
            .into(),
        )?;
    }

    Ok(())
}

// Charge gas for the check_bundle operation which does not leverage concurrency
fn charge_masp_check_bundle_gas<F>(
    sapling_bundle: &SaplingBundle<SaplingAuthorized>,
    consume_verify_gas: F,
) -> Result<()>
where
    F: Fn(Gas) -> Result<()>,
{
    consume_verify_gas(
        checked!(
            (sapling_bundle.shielded_spends.len() as u64)
                * namada_gas::MASP_SPEND_CHECK_GAS
        )?
        .into(),
    )?;

    consume_verify_gas(
        checked!(
            (sapling_bundle.shielded_converts.len() as u64)
                * namada_gas::MASP_CONVERT_CHECK_GAS
        )?
        .into(),
    )?;

    consume_verify_gas(
        checked!(
            (sapling_bundle.shielded_outputs.len() as u64)
                * namada_gas::MASP_OUTPUT_CHECK_GAS
        )?
        .into(),
    )
}

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for transactions
pub mod testing {
    use masp_primitives::transaction::components::sapling::Bundle;
    use masp_proofs::bellman::groth16;
    use rand_core::{CryptoRng, RngCore};

    use super::*;

    /// A context object for verifying the Sapling components of MASP
    /// transactions. Same as BatchValidator, but always assumes the
    /// proofs and signatures to be valid.
    pub struct MockBatchValidator {
        inner: BatchValidator,
    }

    impl Default for MockBatchValidator {
        fn default() -> Self {
            MockBatchValidator {
                inner: BatchValidator::new(),
            }
        }
    }

    impl MockBatchValidator {
        /// Checks the bundle against Sapling-specific consensus rules, and adds
        /// its proof and signatures to the validator.
        ///
        /// Returns `false` if the bundle doesn't satisfy all of the consensus
        /// rules. This `BatchValidator` can continue to be used
        /// regardless, but some or all of the proofs and signatures
        /// from this bundle may have already been added to the batch even if
        /// it fails other consensus rules.
        pub fn check_bundle(
            &mut self,
            bundle: Bundle<
                masp_primitives::transaction::components::sapling::Authorized,
            >,
            sighash: [u8; 32],
        ) -> bool {
            self.inner.check_bundle(bundle, sighash)
        }

        /// Batch-validates the accumulated bundles.
        ///
        /// Returns `true` if every proof and signature in every bundle added to
        /// the batch validator is valid, or `false` if one or more are
        /// invalid. No attempt is made to figure out which of the
        /// accumulated bundles might be invalid; if that information is
        /// desired, construct separate [`BatchValidator`]s for sub-batches of
        /// the bundles.
        pub fn validate<R: RngCore + CryptoRng>(
            self,
            _spend_vk: &groth16::VerifyingKey<Bls12>,
            _convert_vk: &groth16::VerifyingKey<Bls12>,
            _output_vk: &groth16::VerifyingKey<Bls12>,
            mut _rng: R,
        ) -> bool {
            true
        }
    }
}

#[cfg(all(test, not(feature = "testing")))]
mod tests {
    use std::ops::AddAssign;
    use std::sync::Mutex;

    use masp_primitives::asset_type::AssetType;
    use masp_primitives::consensus::{BlockHeight, TestNetwork as Network};
    use masp_primitives::constants::{
        spending_key_generator, value_commitment_randomness_generator,
    };
    use masp_primitives::convert::AllowedConversion;
    use masp_primitives::group::GroupEncoding;
    use masp_primitives::group::prime::PrimeCurveAffine;
    use masp_primitives::memo::MemoBytes;
    use masp_primitives::merkle_tree::MerklePath;
    use masp_primitives::sapling::prover::TxProver;
    use masp_primitives::sapling::redjubjub::{
        PrivateKey, PublicKey, Signature,
    };
    use masp_primitives::sapling::{Diversifier, Node, PaymentAddress, Rseed};
    use masp_primitives::transaction::TransparentAddress;
    use masp_primitives::transaction::builder::Builder;
    use masp_primitives::transaction::components::sapling::builder::RngBuildParams;
    use masp_primitives::transaction::components::{
        GROTH_PROOF_SIZE, I128Sum, TxOut, U64Sum,
    };
    use masp_primitives::transaction::fees::fixed::FeeRule;
    use masp_primitives::zip32::{
        ExtendedFullViewingKey, ExtendedSpendingKey, PseudoExtendedKey,
    };
    use masp_primitives::{bls12_381, jubjub};
    use masp_proofs::bellman::groth16::Proof;
    use masp_proofs::bls12_381::{Bls12, G1Affine, G2Affine};
    use rand_core::{CryptoRng, OsRng, RngCore};

    use super::{
        CONVERT_NAME, OUTPUT_NAME, SPEND_NAME, get_params_dir,
        preload_verifying_keys, verify_shielded_tx,
    };
    use crate::Error;

    fn find_valid_diversifier<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> (Diversifier, jubjub::SubgroupPoint) {
        let mut diversifier;
        let g_d;
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

    fn masp_compute_value_balance(
        asset_type: AssetType,
        value: i128,
    ) -> Option<jubjub::ExtendedPoint> {
        let abs = match value.checked_abs() {
            Some(a) => a as u128,
            None => return None,
        };
        let is_negative = value.is_negative();
        let mut abs_bytes = [0u8; 32];
        abs_bytes[0..16].copy_from_slice(&abs.to_le_bytes());
        let mut value_balance = asset_type.value_commitment_generator()
            * jubjub::Fr::from_bytes(&abs_bytes).unwrap();
        if is_negative {
            value_balance = -value_balance;
        }
        Some(value_balance.into())
    }

    struct SaplingProvingContext {
        bsk: jubjub::Fr,
        cv_sum: jubjub::ExtendedPoint,
    }

    struct MockTxProver<R: RngCore>(Mutex<R>);

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
            proof_generation_key: masp_primitives::sapling::ProofGenerationKey,
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
            {
                let mut tmp = rcv;
                tmp.add_assign(&ctx.bsk);
                ctx.bsk = tmp;
            }
            let value_commitment = asset_type.value_commitment(value, rcv);
            let rk = PublicKey(proof_generation_key.ak.into())
                .randomize(ar, spending_key_generator());
            let value_commitment: jubjub::ExtendedPoint =
                value_commitment.commitment().into();
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
            _payment_address: PaymentAddress,
            _rcm: jubjub::Fr,
            asset_type: AssetType,
            value: u64,
            rcv: jubjub::Fr,
        ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint) {
            {
                let mut tmp = rcv.neg();
                tmp.add_assign(&ctx.bsk);
                ctx.bsk = tmp;
            }
            let value_commitment = asset_type.value_commitment(value, rcv);
            let value_commitment_point: jubjub::ExtendedPoint =
                value_commitment.commitment().into();
            ctx.cv_sum -= value_commitment_point;
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
            {
                let mut tmp = rcv;
                tmp.add_assign(&ctx.bsk);
                ctx.bsk = tmp;
            }
            let value_commitment =
                allowed_conversion.value_commitment(value, rcv);
            let value_commitment: jubjub::ExtendedPoint =
                value_commitment.commitment().into();
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
            let mut rng = self.0.lock().unwrap();
            let bsk = PrivateKey(ctx.bsk);
            let bvk = PublicKey::from_private(
                &bsk,
                value_commitment_randomness_generator(),
            );
            {
                let final_bvk = assets_and_values
                    .components()
                    .map(|(asset_type, value_balance)| {
                        masp_compute_value_balance(*asset_type, *value_balance)
                    })
                    .try_fold(ctx.cv_sum, |tmp, value_balance| {
                        Result::<_, ()>::Ok(tmp - value_balance.ok_or(())?)
                    })?;
                if bvk.0 != final_bvk {
                    return Err(());
                }
            }
            let mut data_to_be_signed = [0u8; 64];
            data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
            data_to_be_signed[32..64].copy_from_slice(&sighash[..]);
            Ok(bsk.sign(
                &data_to_be_signed,
                &mut *rng,
                value_commitment_randomness_generator(),
            ))
        }
    }

    /// Ensure MASP parameters are present on disk, downloading them if
    /// necessary.
    fn ensure_masp_params() {
        let params_dir = get_params_dir();
        let spend_path = params_dir.join(SPEND_NAME);
        let convert_path = params_dir.join(CONVERT_NAME);
        let output_path = params_dir.join(OUTPUT_NAME);
        if !spend_path.exists()
            || !convert_path.exists()
            || !output_path.exists()
        {
            masp_proofs::download_masp_parameters(None)
                .expect("download MASP parameters");
        }
    }

    /// Regression test for the `masp_proofs` 3.0.8 bug where `BatchValidator`
    /// accepts any proof whose elements are valid curve points, even if the
    /// proof does not satisfy the Groth16 verification equation.
    ///
    /// A shielded transaction is built with fake ZK proofs (generator
    /// elements) but real value commitments and binding signatures.
    /// `verify_shielded_tx` must reject it with "Invalid proofs or
    /// signatures".
    #[test]
    fn test_verify_shielded_tx_rejects_fake_zk_proofs() {
        ensure_masp_params();
        preload_verifying_keys();

        let mut rng = OsRng;

        // Generate a spending key and derive a payment address
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let spending_key = ExtendedSpendingKey::master(&seed);
        let viewing_key = ExtendedFullViewingKey::from(&spending_key).fvk.vk;
        let (div, _g_d) = find_valid_diversifier(&mut rng);
        let payment_addr = viewing_key
            .to_payment_address(div)
            .expect("a PaymentAddress");

        // Create an asset type and transparent address
        let asset_type =
            AssetType::new(b"test_token").expect("valid asset type");
        let address = TransparentAddress([12u8; 20]);
        let value: u64 = 100;

        // Build a shielding transaction: transparent input -> sapling output
        let mut builder = Builder::<Network, PseudoExtendedKey>::new(
            Network,
            BlockHeight::from_u32(1),
        );
        builder
            .add_transparent_input(TxOut {
                asset_type,
                value,
                address,
            })
            .unwrap();
        builder
            .add_sapling_output(
                None,
                payment_addr,
                asset_type,
                value,
                MemoBytes::empty(),
            )
            .unwrap();

        let prover = MockTxProver(Mutex::new(OsRng));
        let (transaction, _metadata) = builder
            .build(
                &prover,
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut RngBuildParams::new(OsRng),
            )
            .expect("build transaction");

        // verify_shielded_tx must reject the fake ZK proofs
        let result = verify_shielded_tx(&transaction, |_| Ok(()));

        assert!(
            matches!(
                result,
                Err(Error::SimpleMessage("Invalid proofs or signatures"))
            ),
            "Expected verify_shielded_tx to reject fake ZK proofs with \
             \"Invalid proofs or signatures\", got: {:?}",
            result
        );
    }
}
