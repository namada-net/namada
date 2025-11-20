//! VP for protocol parameters

use std::collections::BTreeSet;
use std::marker::PhantomData;

use namada_core::address::Address;
use namada_core::booleans::BoolResultUnitExt;
use namada_systems::governance;
use namada_tx::BatchedTxRef;
use namada_vp_env::{Error, Key, Result, VpEnv};

use crate::storage;

/// Parameters VP
pub struct ParametersVp<'ctx, CTX, Gov> {
    /// Generic types for VP context and DI
    pub _marker: PhantomData<(&'ctx CTX, Gov)>,
}

impl<'ctx, CTX, Gov> ParametersVp<'ctx, CTX, Gov>
where
    CTX: VpEnv<'ctx>,
    Gov: governance::Read<<CTX as VpEnv<'ctx>>::Pre>,
{
    /// Run the validity predicate
    pub fn validate_tx(
        ctx: &'ctx CTX,
        batched_tx: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        keys_changed.iter().try_for_each(|key| {
            let key_type: KeyType = key.into();
            let data = if let Some(data) = batched_tx.tx.data(batched_tx.cmt) {
                data
            } else {
                return Err(Error::new_const(
                    "Parameter changes require tx data to be present",
                ));
            };
            match key_type {
                KeyType::PARAMETER | KeyType::UNKNOWN_PARAMETER => {
                    let is_gov = Gov::is_proposal_accepted(&ctx.pre(), &data)?
                        .ext_ok_or_else(|| {
                            Error::new_alloc(format!(
                                "Attempted to change a protocol parameter \
                                 from outside of a governance proposal, or \
                                 from a non-accepted governance proposal: \
                                 {key}",
                            ))
                        });
                    is_gov.and_then(|()| {
                        // ensure that new parameters can be decoded
                        let _ = crate::read(&ctx.post())?;
                        Ok(())
                    })
                }
                KeyType::UNKNOWN => Ok(()),
            }
        })
    }
}

#[allow(clippy::upper_case_acronyms)]
enum KeyType {
    #[allow(clippy::upper_case_acronyms)]
    PARAMETER,
    #[allow(clippy::upper_case_acronyms)]
    #[allow(non_camel_case_types)]
    UNKNOWN_PARAMETER,
    #[allow(clippy::upper_case_acronyms)]
    UNKNOWN,
}

impl From<&Key> for KeyType {
    fn from(value: &Key) -> Self {
        if storage::is_protocol_parameter_key(value) {
            KeyType::PARAMETER
        } else if storage::is_parameter_key(value) {
            KeyType::UNKNOWN_PARAMETER
        } else {
            KeyType::UNKNOWN
        }
    }
}
