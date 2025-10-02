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
    Authorization, Authorized, TransactionData, Unauthorized,
};
use masp_primitives::zip32::ExtendedSpendingKey;
use masp_proofs::bellman::groth16::VerifyingKey;
use masp_proofs::sapling::BatchValidator;
use namada_core::masp::MaspTxData;
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
    transaction: &impl MaspTxData,
    consume_verify_gas: F,
) -> Result<()>
where
    F: Fn(Gas) -> Result<()>,
{
    let Some(transaction) = transaction.verifiable_tx() else {
        return Ok(());
    };

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
